"""Strict Multimodal Upload Validation, Magic-Byte Sniffing & Parser DoS Protection (`P3-05`).

Framework-independent upload security guard used by `pqc_agent/workspace_server.py` and `tools/calibration_engine.py`:
- Streaming chunked reads enforcing per-file (`PQC_MAX_UPLOAD_FILE_BYTES`) and per-turn (`PQC_MAX_UPLOAD_TOTAL_BYTES`)
  limits before buffering oversized payloads into RAM.
- Strict filename sanitization stripping directory traversal (`../`, `\\`), NUL/control characters, dotfiles, and
  overlong names (`<= 128` chars) before persistence to GCS or session metadata.
- Explicit extension allowlist, declared MIME compatibility verification, and magic-byte header validation.
- Explicit rejection of private keys and keystores (`.key`, `.p12`, `.pfx`, `.jks`, PEM/DER private key blocks).
- Pre-parse `.docx` OOXML ZIP-bomb, zip-slip, encrypted-member, and XML `<!DOCTYPE`/`<!ENTITY` (XXE) protection.
- Bounded `.pdf` page-count and text extraction with zero `latin-1` binary fallback on corrupt or spoofed payloads.
- Image header dimension bounds (PNG `IHDR`, JPEG `SOF*`) to prevent decompression bombs.
"""

from __future__ import annotations

import io
import json
import os
import re
import struct
import unicodedata
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, FrozenSet, List, Optional, Tuple


DEFAULT_MAX_UPLOAD_FILES_PER_TURN = 5
DEFAULT_MAX_UPLOAD_FILE_BYTES = 10 * 1024 * 1024  # 10 MiB
DEFAULT_MAX_UPLOAD_TOTAL_BYTES = 25 * 1024 * 1024  # 25 MiB
DEFAULT_READ_CHUNK_BYTES = 64 * 1024  # 64 KiB
DEFAULT_MAX_FILENAME_LENGTH = 128

DEFAULT_MAX_PDF_PAGES = 200
DEFAULT_MAX_EXTRACTED_TEXT_CHARS = 262_144  # 256 KiB chars
DEFAULT_MAX_DOCX_ENTRIES = 500
DEFAULT_MAX_DOCX_UNCOMPRESSED_BYTES = 32 * 1024 * 1024  # 32 MiB
DEFAULT_MAX_DOCX_COMPRESSION_RATIO = 100.0
DEFAULT_MAX_IMAGE_DIMENSION = 16_384
DEFAULT_MAX_IMAGE_PIXELS = 40_000_000


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        val = int(raw)
        return max(minimum, val)
    except ValueError:
        return default


def _env_float(name: str, default: float, *, minimum: float = 1.0) -> float:
    raw = (os.getenv(name) or "").strip()
    if not raw:
        return default
    try:
        val = float(raw)
        return max(minimum, val)
    except ValueError:
        return default


def max_upload_files_per_turn() -> int:
    return _env_int("PQC_MAX_UPLOAD_FILES_PER_TURN", DEFAULT_MAX_UPLOAD_FILES_PER_TURN)


def max_upload_file_bytes() -> int:
    return _env_int("PQC_MAX_UPLOAD_FILE_BYTES", DEFAULT_MAX_UPLOAD_FILE_BYTES)


def max_upload_total_bytes() -> int:
    return _env_int("PQC_MAX_UPLOAD_TOTAL_BYTES", DEFAULT_MAX_UPLOAD_TOTAL_BYTES)


def max_pdf_pages() -> int:
    return _env_int("PQC_MAX_PDF_PAGES", DEFAULT_MAX_PDF_PAGES)


def max_extracted_text_chars() -> int:
    return _env_int("PQC_MAX_EXTRACTED_TEXT_CHARS", DEFAULT_MAX_EXTRACTED_TEXT_CHARS)


def max_docx_entries() -> int:
    return _env_int("PQC_MAX_DOCX_ENTRIES", DEFAULT_MAX_DOCX_ENTRIES)


def max_docx_uncompressed_bytes() -> int:
    return _env_int("PQC_MAX_DOCX_UNCOMPRESSED_BYTES", DEFAULT_MAX_DOCX_UNCOMPRESSED_BYTES)


def max_docx_compression_ratio() -> float:
    return _env_float("PQC_MAX_DOCX_COMPRESSION_RATIO", DEFAULT_MAX_DOCX_COMPRESSION_RATIO)


def max_image_pixels() -> int:
    return _env_int("PQC_MAX_IMAGE_PIXELS", DEFAULT_MAX_IMAGE_PIXELS)


# ---------------------------------------------------------------------------
# Typed Validation Exceptions (HTTP status mapped cleanly by workspace_server)
# ---------------------------------------------------------------------------


class UploadValidationError(ValueError):
    """Base error raised when an uploaded file fails security validation."""

    def __init__(self, message: str, *, http_status: int = 400, error_code: str = "UPLOAD_VALIDATION_ERROR") -> None:
        super().__init__(message)
        self.http_status = http_status
        self.error_code = error_code


class UploadTooLargeError(UploadValidationError):
    """Raised when an upload exceeds per-file or per-turn byte quotas (HTTP 413)."""

    def __init__(self, message: str, *, error_code: str = "UPLOAD_SIZE_LIMIT_EXCEEDED") -> None:
        super().__init__(message, http_status=413, error_code=error_code)


class UploadFileCountError(UploadValidationError):
    """Raised when a turn includes too many uploaded files (HTTP 400)."""

    def __init__(self, message: str) -> None:
        super().__init__(message, http_status=400, error_code="UPLOAD_FILE_COUNT_EXCEEDED")


class UploadUnsupportedMediaError(UploadValidationError):
    """Raised when extension, declared MIME type, or magic bytes are unsupported or mismatched (HTTP 415)."""

    def __init__(self, message: str, *, error_code: str = "UPLOAD_UNSUPPORTED_MEDIA_TYPE") -> None:
        super().__init__(message, http_status=415, error_code=error_code)


class UploadRejectedContentError(UploadValidationError):
    """Raised on empty files, private keys, ZIP bombs, XXE payloads, or corrupt documents (HTTP 400)."""

    def __init__(self, message: str, *, error_code: str = "UPLOAD_REJECTED_CONTENT") -> None:
        super().__init__(message, http_status=400, error_code=error_code)


# ---------------------------------------------------------------------------
# Policy Tables
# ---------------------------------------------------------------------------


PROHIBITED_KEY_EXTENSIONS: FrozenSet[str] = frozenset(
    {
        ".key",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".kdbx",
        ".ppk",
        ".pkcs8",
        ".pkcs12",
    }
)

ALLOWED_UPLOAD_EXTENSIONS: FrozenSet[str] = frozenset(
    {
        ".pdf",
        ".docx",
        ".png",
        ".jpg",
        ".jpeg",
        ".pem",
        ".crt",
        ".cer",
        ".txt",
        ".md",
        ".markdown",
        ".csv",
        ".json",
        ".yaml",
        ".yml",
    }
)

# Canonical Gemini MIME type and binary-part flag per allowlisted extension
_EXT_TO_GEMINI: Dict[str, Tuple[str, bool]] = {
    ".pdf": ("application/pdf", True),
    ".docx": ("text/plain", False),
    ".png": ("image/png", True),
    ".jpg": ("image/jpeg", True),
    ".jpeg": ("image/jpeg", True),
    ".pem": ("text/plain", False),
    ".crt": ("text/plain", False),
    ".cer": ("text/plain", False),
    ".txt": ("text/plain", False),
    ".md": ("text/markdown", False),
    ".markdown": ("text/markdown", False),
    ".csv": ("text/csv", False),
    ".json": ("text/plain", False),
    ".yaml": ("text/plain", False),
    ".yml": ("text/plain", False),
}

# Permitted declared Content-Type values per extension (empty / application/octet-stream allowed only when magic bytes match)
_GENERIC_DECLARED_MIMES: FrozenSet[str] = frozenset({"", "application/octet-stream", "binary/octet-stream"})

_ALLOWED_DECLARED_MIMES: Dict[str, FrozenSet[str]] = {
    ".pdf": frozenset({"application/pdf", "application/x-pdf"}),
    ".docx": frozenset(
        {
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/zip",
            "application/x-zip-compressed",
        }
    ),
    ".png": frozenset({"image/png"}),
    ".jpg": frozenset({"image/jpeg", "image/jpg", "image/pjpeg"}),
    ".jpeg": frozenset({"image/jpeg", "image/jpg", "image/pjpeg"}),
    ".pem": frozenset(
        {
            "application/x-pem-file",
            "application/x-x509-ca-cert",
            "application/pkix-cert",
            "text/plain",
        }
    ),
    ".crt": frozenset(
        {
            "application/x-x509-ca-cert",
            "application/pkix-cert",
            "application/x-pem-file",
            "text/plain",
        }
    ),
    ".cer": frozenset(
        {
            "application/x-x509-ca-cert",
            "application/pkix-cert",
            "application/x-pem-file",
            "text/plain",
        }
    ),
    ".txt": frozenset({"text/plain"}),
    ".md": frozenset({"text/markdown", "text/x-markdown", "text/plain"}),
    ".markdown": frozenset({"text/markdown", "text/x-markdown", "text/plain"}),
    ".csv": frozenset({"text/csv", "application/csv", "application/vnd.ms-excel", "text/plain"}),
    ".json": frozenset({"application/json", "text/json", "text/plain"}),
    ".yaml": frozenset({"application/x-yaml", "application/yaml", "text/yaml", "text/x-yaml", "text/plain"}),
    ".yml": frozenset({"application/x-yaml", "application/yaml", "text/yaml", "text/x-yaml", "text/plain"}),
}

_PRIVATE_KEY_MARKERS: Tuple[bytes, ...] = (
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    b"-----BEGIN EC PARAMETERS-----",
)

# Binary magic headers that must never be accepted inside plain-text extensions
_DISALLOWED_BINARY_PREFIXES: Tuple[Tuple[bytes, str], ...] = (
    (b"MZ", "Windows PE/MZ executable"),
    (b"\x7fELF", "Linux ELF executable"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"PK\x05\x06", "ZIP archive"),
    (b"%PDF-", "PDF document"),
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"\x1f\x8b", "GZIP archive"),
    (b"BZh", "BZIP2 archive"),
    (b"\xfd7zXZ\x00", "XZ archive"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"Rar!\x1a\x07", "RAR archive"),
    (b"\xca\xfe\xba\xbe", "Mach-O/Java binary"),
    (b"\xcf\xfa\xed\xfe", "Mach-O binary"),
    (b"\xce\xfa\xed\xfe", "Mach-O binary"),
    (b"\xfe\xed\xfa\xcf", "Mach-O binary"),
    (b"\xfe\xed\xfa\xce", "Mach-O binary"),
    (b"\x00asm", "WebAssembly binary"),
)

_XML_FORBIDDEN_ENTITY_RE = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_SAFE_FILENAME_CHAR_RE = re.compile(r"[^A-Za-z0-9._-]+")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class ValidatedUpload:
    """Result of validating and safely extracting an uploaded multimodal artifact."""

    original_filename: str
    sanitized_filename: str
    extension: str
    declared_mime: str
    canonical_mime: str
    gemini_mime: str
    is_binary_part: bool
    raw_bytes: bytes
    extracted_text: str
    size_bytes: int


# ---------------------------------------------------------------------------
# Filename Sanitization & Streaming Bounded Reads
# ---------------------------------------------------------------------------


def sanitize_upload_filename(
    raw_filename: Optional[str],
    *,
    require_allowed_extension: bool = True,
    max_length: int = DEFAULT_MAX_FILENAME_LENGTH,
) -> str:
    """Strips path traversal, control chars, and unsafe symbols while preserving a safe extension."""
    raw = str(raw_filename or "")
    raw = unicodedata.normalize("NFKC", raw)
    raw = _CONTROL_CHAR_RE.sub("", raw).strip()

    # Extract final path component across both POSIX `/` and Windows `\` separators
    base = re.split(r"[/\\]+", raw)[-1] if raw else ""
    base = base.strip()

    # Remove unsafe characters and collapse repeated dots so `..` never survives
    cleaned = _SAFE_FILENAME_CHAR_RE.sub("_", base)
    cleaned = re.sub(r"\.{2,}", "_", cleaned)
    cleaned = cleaned.lstrip("._-").rstrip(". ")

    if not cleaned:
        if require_allowed_extension:
            raise UploadUnsupportedMediaError("Uploaded file must have a valid filename and supported extension.")
        return "uploaded_artifact.txt"

    stem, ext = os.path.splitext(cleaned)
    ext = ext.lower()
    stem = stem.strip("._-") or "artifact"

    if ext in PROHIBITED_KEY_EXTENSIONS:
        raise UploadRejectedContentError(
            f"Private key or keystore uploads ('{ext}') are prohibited; upload public certificates (.pem/.crt/.cer) or inventory exports only.",
            error_code="UPLOAD_PRIVATE_KEY_REJECTED",
        )

    if require_allowed_extension and ext not in ALLOWED_UPLOAD_EXTENSIONS:
        raise UploadUnsupportedMediaError(
            f"Unsupported file extension '{ext or '(none)'}'. Supported formats: {', '.join(sorted(ALLOWED_UPLOAD_EXTENSIONS))}."
        )

    max_stem = max(1, max_length - len(ext))
    if len(stem) > max_stem:
        stem = stem[:max_stem].rstrip("._-") or "artifact"

    return f"{stem}{ext}"


async def read_bounded_upload(
    upload_file: Any,
    *,
    max_file_bytes: Optional[int] = None,
    remaining_total_bytes: Optional[int] = None,
    chunk_size: int = DEFAULT_READ_CHUNK_BYTES,
) -> bytes:
    """Reads an async UploadFile in bounded chunks, aborting immediately before buffering oversized payloads."""
    file_cap = max_file_bytes if max_file_bytes is not None else max_upload_file_bytes()
    total_cap = remaining_total_bytes if remaining_total_bytes is not None else max_upload_total_bytes()
    effective_cap = min(file_cap, total_cap)

    buf = bytearray()
    total_read = 0
    while True:
        # Read at most chunk_size bytes; never call unbounded read()
        chunk = await upload_file.read(chunk_size)
        if not chunk:
            break
        total_read += len(chunk)
        if total_read > file_cap:
            raise UploadTooLargeError(
                f"Uploaded file exceeds maximum allowed size of {file_cap} bytes ({file_cap // (1024 * 1024)} MiB).",
                error_code="UPLOAD_SIZE_LIMIT_EXCEEDED",
            )
        if total_read > total_cap:
            raise UploadTooLargeError(
                f"Total uploaded payload exceeds maximum per-turn limit of {max_upload_total_bytes()} bytes.",
                error_code="UPLOAD_TOTAL_SIZE_EXCEEDED",
            )
        if total_read > effective_cap:
            raise UploadTooLargeError("Uploaded file exceeds size limit.")
        buf.extend(chunk)

    if total_read == 0:
        raise UploadRejectedContentError("Uploaded file is empty (0 bytes).", error_code="UPLOAD_EMPTY_FILE")

    return bytes(buf)


# ---------------------------------------------------------------------------
# Format-Specific Magic-Byte & Structural Validators
# ---------------------------------------------------------------------------


def _normalize_mime(declared_mime: Optional[str]) -> str:
    raw = str(declared_mime or "").strip().lower()
    if ";" in raw:
        raw = raw.split(";", 1)[0].strip()
    return raw


def _check_declared_mime_compatibility(ext: str, norm_mime: str) -> None:
    if norm_mime in _GENERIC_DECLARED_MIMES:
        return
    allowed = _ALLOWED_DECLARED_MIMES.get(ext, frozenset())
    if norm_mime not in allowed:
        raise UploadUnsupportedMediaError(
            f"Declared Content-Type '{norm_mime}' is incompatible with file extension '{ext}'.",
            error_code="UPLOAD_MIME_MISMATCH",
        )


def _reject_if_private_key_pem(raw_bytes: bytes) -> None:
    upper = raw_bytes.upper()
    for marker in _PRIVATE_KEY_MARKERS:
        if marker in upper:
            raise UploadRejectedContentError(
                "Private key material detected in upload. Uploading private keys is strictly prohibited; "
                "provide public X.509 certificates or inventory metadata only.",
                error_code="UPLOAD_PRIVATE_KEY_REJECTED",
            )


def _validate_and_extract_pdf(raw_bytes: bytes) -> str:
    if not raw_bytes.startswith(b"%PDF-"):
        raise UploadUnsupportedMediaError(
            "Invalid PDF header: file content does not begin with '%PDF-' magic signature.",
            error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
        )

    from pypdf import PdfReader

    try:
        reader = PdfReader(io.BytesIO(raw_bytes), strict=False)
        page_count = len(reader.pages)
    except Exception as exc:
        raise UploadRejectedContentError(
            f"Malformed or unreadable PDF document: {type(exc).__name__}.",
            error_code="UPLOAD_CORRUPT_DOCUMENT",
        ) from exc

    page_limit = max_pdf_pages()
    if page_count > page_limit:
        raise UploadRejectedContentError(
            f"PDF exceeds maximum allowed page count ({page_count} > {page_limit} pages).",
            error_code="UPLOAD_PDF_PAGE_LIMIT_EXCEEDED",
        )

    char_limit = max_extracted_text_chars()
    chunks: List[str] = []
    acc_chars = 0
    try:
        for page in reader.pages:
            page_txt = (page.extract_text() or "").strip()
            if not page_txt:
                continue
            remaining = char_limit - acc_chars
            if remaining <= 0:
                break
            if len(page_txt) > remaining:
                chunks.append(page_txt[:remaining])
                acc_chars += remaining
                break
            chunks.append(page_txt)
            acc_chars += len(page_txt) + 1
    except Exception as exc:
        raise UploadRejectedContentError(
            f"Failed to safely extract text from PDF document: {type(exc).__name__}.",
            error_code="UPLOAD_CORRUPT_DOCUMENT",
        ) from exc

    extracted = "\n".join(chunks).strip()
    if extracted:
        _reject_if_private_key_pem(extracted.encode("utf-8", errors="ignore"))
    return extracted


def _validate_docx_archive_safety(raw_bytes: bytes) -> None:
    """Inspects `.docx` ZIP structure, bounds uncompressed bytes & ratio, and blocks zip-slip/XXE before python-docx."""
    if not raw_bytes.startswith(b"PK\x03\x04"):
        raise UploadUnsupportedMediaError(
            "Invalid DOCX header: file content does not begin with ZIP/OOXML magic signature.",
            error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
        )

    entry_limit = max_docx_entries()
    uncompressed_limit = max_docx_uncompressed_bytes()
    ratio_limit = max_docx_compression_ratio()

    try:
        zf = zipfile.ZipFile(io.BytesIO(raw_bytes), mode="r")
    except zipfile.BadZipFile as exc:
        raise UploadUnsupportedMediaError(
            "Invalid DOCX archive: corrupted or non-ZIP payload.",
            error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
        ) from exc

    with zf:
        infos = zf.infolist()
        if len(infos) == 0:
            raise UploadUnsupportedMediaError(
                "Invalid DOCX archive: empty ZIP container.",
                error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
            )
        if len(infos) > entry_limit:
            raise UploadRejectedContentError(
                f"DOCX archive exceeds maximum entry count ({len(infos)} > {entry_limit}).",
                error_code="UPLOAD_ZIP_BOMB_DETECTED",
            )

        member_names: set[str] = set()
        declared_uncompressed_total = 0
        declared_compressed_total = 0

        for info in infos:
            member = info.filename
            if member.startswith(("/", "\\")) or ".." in re.split(r"[/\\]+", member) or re.match(r"^[A-Za-z]:", member):
                raise UploadRejectedContentError(
                    f"Unsafe path traversal entry detected in DOCX archive: '{member[:64]}'.",
                    error_code="UPLOAD_ZIP_SLIP_DETECTED",
                )
            if info.flag_bits & 0x1:
                raise UploadRejectedContentError(
                    "Encrypted DOCX archives are not supported.",
                    error_code="UPLOAD_CORRUPT_DOCUMENT",
                )

            declared_uncompressed_total += max(0, int(info.file_size))
            declared_compressed_total += max(0, int(info.compress_size))
            if declared_uncompressed_total > uncompressed_limit:
                raise UploadRejectedContentError(
                    f"DOCX uncompressed payload exceeds maximum allowed limit ({uncompressed_limit} bytes).",
                    error_code="UPLOAD_ZIP_BOMB_DETECTED",
                )
            if info.file_size >= 1024 * 1024:
                ratio = float(info.file_size) / float(max(info.compress_size, 1))
                if ratio > ratio_limit:
                    raise UploadRejectedContentError(
                        f"DOCX compression ratio ({ratio:.1f}:1) exceeds safety threshold ({ratio_limit:.1f}:1).",
                        error_code="UPLOAD_ZIP_BOMB_DETECTED",
                    )
            member_names.add(member)

        if declared_uncompressed_total >= 1024 * 1024:
            agg_ratio = float(declared_uncompressed_total) / float(max(declared_compressed_total, len(raw_bytes), 1))
            if agg_ratio > ratio_limit:
                raise UploadRejectedContentError(
                    f"DOCX aggregate compression ratio ({agg_ratio:.1f}:1) exceeds safety threshold.",
                    error_code="UPLOAD_ZIP_BOMB_DETECTED",
                )

        if "[Content_Types].xml" not in member_names or "word/document.xml" not in member_names:
            raise UploadUnsupportedMediaError(
                "ZIP archive is not a valid Word (.docx) document (missing OOXML [Content_Types].xml or word/document.xml).",
                error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
            )

        # Stream-read XML/RELS members with real decompressed byte tracking to defeat forged ZipInfo headers & XXE
        actual_uncompressed_total = 0
        for info in infos:
            low_name = info.filename.lower()
            if not (low_name.endswith(".xml") or low_name.endswith(".rels")):
                continue
            member_buf = bytearray()
            with zf.open(info, "r") as stream:
                while True:
                    chunk = stream.read(DEFAULT_READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    actual_uncompressed_total += len(chunk)
                    if actual_uncompressed_total > uncompressed_limit:
                        raise UploadRejectedContentError(
                            "DOCX decompressed XML content exceeds safety size limit (potential ZIP bomb).",
                            error_code="UPLOAD_ZIP_BOMB_DETECTED",
                        )
                    member_buf.extend(chunk)
            if _XML_FORBIDDEN_ENTITY_RE.search(member_buf):
                raise UploadRejectedContentError(
                    f"Unsafe XML DTD/ENTITY declaration rejected in DOCX member '{info.filename}'.",
                    error_code="UPLOAD_XXE_DETECTED",
                )


def _validate_and_extract_docx(raw_bytes: bytes) -> str:
    _validate_docx_archive_safety(raw_bytes)
    import docx

    try:
        document = docx.Document(io.BytesIO(raw_bytes))
        char_limit = max_extracted_text_chars()
        parts: List[str] = []
        acc_chars = 0

        def _append(line: str) -> bool:
            nonlocal acc_chars
            if not line:
                return True
            remaining = char_limit - acc_chars
            if remaining <= 0:
                return False
            if len(line) > remaining:
                parts.append(line[:remaining])
                acc_chars += remaining
                return False
            parts.append(line)
            acc_chars += len(line) + 1
            return True

        for para in document.paragraphs:
            if para.text.strip() and not _append(para.text.strip()):
                break
        if acc_chars < char_limit:
            for table in document.tables:
                for row in table.rows:
                    cells = [c.text.strip() for c in row.cells if c.text.strip()]
                    if cells and not _append(" | ".join(cells)):
                        break
                if acc_chars >= char_limit:
                    break
    except UploadValidationError:
        raise
    except Exception as exc:
        raise UploadRejectedContentError(
            f"Malformed or unreadable DOCX document: {type(exc).__name__}.",
            error_code="UPLOAD_CORRUPT_DOCUMENT",
        ) from exc

    extracted = "\n".join(parts).strip()
    if extracted:
        _reject_if_private_key_pem(extracted.encode("utf-8", errors="ignore"))
    return extracted


def _validate_png(raw_bytes: bytes) -> None:
    if len(raw_bytes) < 24 or not raw_bytes.startswith(b"\x89PNG\r\n\x1a\n") or raw_bytes[12:16] != b"IHDR":
        raise UploadUnsupportedMediaError(
            "Invalid PNG header: file content does not match PNG/IHDR magic signature.",
            error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
        )
    width, height = struct.unpack(">II", raw_bytes[16:24])
    if width == 0 or height == 0 or width > DEFAULT_MAX_IMAGE_DIMENSION or height > DEFAULT_MAX_IMAGE_DIMENSION:
        raise UploadRejectedContentError(
            f"PNG dimensions ({width}x{height}) exceed allowed safety bounds.",
            error_code="UPLOAD_CORRUPT_DOCUMENT",
        )
    if width * height > max_image_pixels():
        raise UploadRejectedContentError(
            f"PNG pixel count ({width * height}) exceeds decompression safety limit.",
            error_code="UPLOAD_CORRUPT_DOCUMENT",
        )


def _validate_jpeg(raw_bytes: bytes) -> None:
    if len(raw_bytes) < 4 or not raw_bytes.startswith(b"\xff\xd8\xff"):
        raise UploadUnsupportedMediaError(
            "Invalid JPEG header: file content does not begin with JPEG SOI signature.",
            error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
        )
    # Inspect SOF markers if present to reject JPEG dimension bombs
    idx = 2
    n = len(raw_bytes)
    while idx + 4 <= n:
        if raw_bytes[idx] != 0xFF:
            break
        while idx < n and raw_bytes[idx] == 0xFF:
            idx += 1
        if idx >= n:
            break
        marker = raw_bytes[idx]
        idx += 1
        if marker in (0xD8, 0xD9, 0x01) or (0xD0 <= marker <= 0xD7):
            continue
        if idx + 2 > n:
            break
        seg_len = struct.unpack(">H", raw_bytes[idx : idx + 2])[0]
        if seg_len < 2 or idx + seg_len > n:
            break
        # Baseline / progressive SOF markers carry height (bytes +3..+5) and width (bytes +5..+7)
        if marker in (0xC0, 0xC1, 0xC2, 0xC3) and seg_len >= 7:
            height, width = struct.unpack(">HH", raw_bytes[idx + 3 : idx + 7])
            if (
                width == 0
                or height == 0
                or width > DEFAULT_MAX_IMAGE_DIMENSION
                or height > DEFAULT_MAX_IMAGE_DIMENSION
                or width * height > max_image_pixels()
            ):
                raise UploadRejectedContentError(
                    f"JPEG dimensions ({width}x{height}) exceed allowed safety bounds.",
                    error_code="UPLOAD_CORRUPT_DOCUMENT",
                )
            break
        if marker == 0xDA:  # Start of Scan
            break
        idx += seg_len


def _validate_and_extract_certificate(raw_bytes: bytes) -> str:
    _reject_if_private_key_pem(raw_bytes)

    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, rsa

    # Reject DER-encoded PKCS#8 / PKCS#1 private keys disguised as .crt / .cer
    if not raw_bytes.lstrip().startswith(b"-----BEGIN "):
        try:
            serialization.load_der_private_key(raw_bytes, password=None)
            raise UploadRejectedContentError(
                "DER-encoded private key detected in upload. Uploading private keys is strictly prohibited.",
                error_code="UPLOAD_PRIVATE_KEY_REJECTED",
            )
        except UploadRejectedContentError:
            raise
        except Exception:
            pass

    cert = None
    if b"-----BEGIN CERTIFICATE-----" in raw_bytes:
        try:
            cert = x509.load_pem_x509_certificate(raw_bytes)
        except Exception as exc:
            raise UploadRejectedContentError(
                f"Malformed PEM X.509 certificate: {type(exc).__name__}.",
                error_code="UPLOAD_CORRUPT_DOCUMENT",
            ) from exc
    elif raw_bytes[:1] == b"\x30":
        try:
            cert = x509.load_der_x509_certificate(raw_bytes)
        except Exception as exc:
            raise UploadUnsupportedMediaError(
                f"File is not a valid PEM or DER X.509 public certificate: {type(exc).__name__}.",
                error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
            ) from exc
    else:
        raise UploadUnsupportedMediaError(
            "Invalid certificate payload: expected a public X.509 PEM ('-----BEGIN CERTIFICATE-----') or DER certificate.",
            error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
        )

    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        algo_desc = f"RSA_{pub.key_size}"
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        algo_desc = f"ECDSA_{pub.curve.name.upper()}"
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        algo_desc = "ED25519"
    elif isinstance(pub, dsa.DSAPublicKey):
        algo_desc = f"DSA_{pub.key_size}"
    else:
        algo_desc = type(pub).__name__

    return (
        "X509_CERTIFICATE_METADATA:\n"
        f"subject={cert.subject.rfc4514_string()}\n"
        f"issuer={cert.issuer.rfc4514_string()}\n"
        f"public_key_algorithm={algo_desc}\n"
        f"signature_algorithm={cert.signature_algorithm_oid._name}\n"
        f"not_valid_before={cert.not_valid_before_utc.isoformat()}\n"
        f"not_valid_after={cert.not_valid_after_utc.isoformat()}\n"
    )


def _validate_and_extract_text(ext: str, raw_bytes: bytes) -> str:
    _reject_if_private_key_pem(raw_bytes)

    if b"\x00" in raw_bytes:
        raise UploadUnsupportedMediaError(
            f"Binary NUL bytes detected in text upload ('{ext}'); binary smuggling is prohibited.",
            error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
        )

    for magic, label in _DISALLOWED_BINARY_PREFIXES:
        if raw_bytes.startswith(magic):
            raise UploadUnsupportedMediaError(
                f"Detected {label} magic bytes inside '{ext}' file; mismatched binary payloads are rejected.",
                error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
            )

    try:
        text = raw_bytes.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise UploadUnsupportedMediaError(
            f"File '{ext}' is not valid UTF-8 text (raw binary / latin-1 fallback is disabled).",
            error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
        ) from exc

    # Reject non-whitespace binary control characters
    bad_ctrl = sum(1 for ch in text[:8192] if ord(ch) < 32 and ch not in ("\n", "\r", "\t", "\f"))
    if bad_ctrl > 0:
        raise UploadUnsupportedMediaError(
            f"Disallowed binary control characters detected in '{ext}' text upload.",
            error_code="UPLOAD_MAGIC_BYTE_MISMATCH",
        )

    if ext == ".json":
        try:
            json.loads(text)
        except json.JSONDecodeError as exc:
            raise UploadRejectedContentError(
                f"Malformed JSON upload: {exc.msg} (line {exc.lineno}).",
                error_code="UPLOAD_CORRUPT_DOCUMENT",
            ) from exc

    return text[: max_extracted_text_chars()]


# ---------------------------------------------------------------------------
# Primary Public Entrypoints
# ---------------------------------------------------------------------------


def validate_and_extract_upload(
    filename: Optional[str],
    raw_bytes: bytes,
    declared_mime: Optional[str] = None,
    *,
    enforce_size_limit: bool = True,
) -> ValidatedUpload:
    """Validates filename, size, declared MIME, magic bytes, and structural integrity, returning safe extracted text."""
    if not isinstance(raw_bytes, (bytes, bytearray)):
        raise UploadRejectedContentError("Uploaded payload must be bytes.", error_code="UPLOAD_CORRUPT_DOCUMENT")
    raw_bytes = bytes(raw_bytes)

    if len(raw_bytes) == 0:
        raise UploadRejectedContentError("Uploaded file is empty (0 bytes).", error_code="UPLOAD_EMPTY_FILE")

    if enforce_size_limit and len(raw_bytes) > max_upload_file_bytes():
        cap = max_upload_file_bytes()
        raise UploadTooLargeError(
            f"Uploaded file exceeds maximum allowed size of {cap} bytes ({cap // (1024 * 1024)} MiB).",
            error_code="UPLOAD_SIZE_LIMIT_EXCEEDED",
        )

    sanitized_name = sanitize_upload_filename(filename, require_allowed_extension=True)
    ext = os.path.splitext(sanitized_name)[1].lower()
    norm_mime = _normalize_mime(declared_mime)
    _check_declared_mime_compatibility(ext, norm_mime)

    gemini_mime, is_binary_part = _EXT_TO_GEMINI[ext]

    if ext == ".pdf":
        extracted = _validate_and_extract_pdf(raw_bytes)
        canonical_mime = "application/pdf"
    elif ext == ".docx":
        extracted = _validate_and_extract_docx(raw_bytes)
        canonical_mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    elif ext == ".png":
        _validate_png(raw_bytes)
        extracted = f"[Validated PNG image attachment: {sanitized_name} ({len(raw_bytes)} bytes)]"
        canonical_mime = "image/png"
    elif ext in (".jpg", ".jpeg"):
        _validate_jpeg(raw_bytes)
        extracted = f"[Validated JPEG image attachment: {sanitized_name} ({len(raw_bytes)} bytes)]"
        canonical_mime = "image/jpeg"
    elif ext in (".pem", ".crt", ".cer"):
        extracted = _validate_and_extract_certificate(raw_bytes)
        canonical_mime = "application/x-x509-ca-cert"
    else:
        extracted = _validate_and_extract_text(ext, raw_bytes)
        canonical_mime = gemini_mime if ext != ".json" else "application/json"

    return ValidatedUpload(
        original_filename=str(filename or sanitized_name),
        sanitized_filename=sanitized_name,
        extension=ext,
        declared_mime=norm_mime or "application/octet-stream",
        canonical_mime=canonical_mime,
        gemini_mime=gemini_mime,
        is_binary_part=is_binary_part,
        raw_bytes=raw_bytes,
        extracted_text=extracted,
        size_bytes=len(raw_bytes),
    )


async def validate_upload_batch(upload_files: List[Any]) -> List[ValidatedUpload]:
    """Atomically reads and validates all uploads in a chat turn before any storage or LLM processing."""
    if not upload_files:
        return []

    file_limit = max_upload_files_per_turn()
    if len(upload_files) > file_limit:
        raise UploadFileCountError(
            f"Too many uploaded files ({len(upload_files)}). Maximum allowed per turn is {file_limit}."
        )

    per_file_cap = max_upload_file_bytes()
    total_cap = max_upload_total_bytes()
    remaining_total = total_cap
    validated: List[ValidatedUpload] = []

    for up_file in upload_files:
        raw_name = getattr(up_file, "filename", None)
        declared_mime = getattr(up_file, "content_type", None) or "application/octet-stream"
        # Pre-check filename & extension BEFORE reading large stream bytes from disk/network
        sanitize_upload_filename(raw_name, require_allowed_extension=True)
        raw_bytes = await read_bounded_upload(
            up_file,
            max_file_bytes=per_file_cap,
            remaining_total_bytes=remaining_total,
        )
        remaining_total -= len(raw_bytes)
        validated.append(
            validate_and_extract_upload(
                raw_name,
                raw_bytes,
                declared_mime=declared_mime,
                enforce_size_limit=True,
            )
        )

    return validated
