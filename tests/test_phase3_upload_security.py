"""Phase 3.2 (`P3-05`) Security Test Suite — Multimodal Upload Size, MIME, Magic-Byte, Parser DoS & Tenant Isolation.

Covers all unit, integration, adversarial, and regression controls from `PHASE_03_0_AUDIT.md` & `PHASE_03_0_TEST_PLAN.md`:
- Streaming chunked size limits (per-file & per-turn) and file-count limits
- Filename sanitization (path traversal, Windows separators, NUL/control chars, length cap)
- Allowlist, declared MIME compatibility, and magic-byte verification (zero `latin-1` binary fallback)
- Private key & keystore rejection (`.key`/`.p12`/`.pfx`, PEM private keys, DER private keys)
- `.docx` ZIP-bomb, entry-count, zip-slip, and XML DTD/XXE guards prior to `python-docx`
- `.pdf` page-count & corrupt-document guards + PNG/JPEG dimension-bomb guards
- Tenant-partitioned bounded LRU + byte-budget + TTL `_UPLOADED_ARTIFACT_CACHE`
"""

from __future__ import annotations

import asyncio
import datetime
import io
import json
import struct
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import docx
from fastapi.testclient import TestClient
from pypdf import PdfWriter
import pytest

from pqc_agent import auth_store, upload_validator, workspace_server as ws
from pqc_agent.model_registry import ModelRegistry
from tools import calibration_engine, gcloud_bridge


@pytest.fixture(autouse=True)
def _clean_upload_cache_and_env(monkeypatch: pytest.MonkeyPatch):
    calibration_engine.clear_uploaded_artifact_cache()
    for var in (
        "PQC_MAX_UPLOAD_FILES_PER_TURN",
        "PQC_MAX_UPLOAD_FILE_BYTES",
        "PQC_MAX_UPLOAD_TOTAL_BYTES",
        "PQC_MAX_PDF_PAGES",
        "PQC_MAX_EXTRACTED_TEXT_CHARS",
        "PQC_MAX_DOCX_ENTRIES",
        "PQC_MAX_DOCX_UNCOMPRESSED_BYTES",
        "PQC_MAX_DOCX_COMPRESSION_RATIO",
        "PQC_UPLOAD_CACHE_MAX_ENTRIES",
        "PQC_UPLOAD_CACHE_MAX_BYTES",
        "PQC_UPLOAD_CACHE_TTL_SECONDS",
    ):
        monkeypatch.delenv(var, raising=False)
    prev_uid = gcloud_bridge.get_current_tenant_user()
    gcloud_bridge.set_current_tenant_user("sec-architect")
    yield
    calibration_engine.clear_uploaded_artifact_cache()
    gcloud_bridge.set_current_tenant_user(prev_uid)


def _make_fake_registry() -> ModelRegistry:
    def _probe(model: str, _level: Any) -> Tuple[bool, Dict[str, Any]]:
        if model == "fake-ok-model":
            return True, {"model_version": "fake-ok-model-001"}
        return False, {"error_code": 404, "error": "Not found"}

    return ModelRegistry(
        candidates=[{"model": "fake-ok-model", "label": "Fake OK", "thinking_levels": [None]}],
        probe=_probe,
        default_model="fake-ok-model",
        default_thinking_level="",
    )


def _create_upload_test_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "p3_05_uploads.db"
    monkeypatch.setenv("SESSION_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("PQC_EXPORT_DIR", str(tmp_path / "exports"))
    monkeypatch.setenv("PQC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PQC_AUTH_SECRET", "p3-05-upload-hmac-secret-material-at-least-32-bytes!!")
    auth_store.clear_fallback_auth_stores()
    return ws.create_workspace_app(
        session_db_url=f"sqlite:///{db_path}",
        model_registry=_make_fake_registry(),
        verify_models_on_startup=False,
    )


def _login_user(client: TestClient, email: str) -> Dict[str, str]:
    resp = client.post("/api/auth/google", json={"google_access_token": f"valid:{email}"})
    assert resp.status_code == 200, resp.text
    csrf = resp.json()["csrf_token"]
    return {"X-PQC-CSRF-Token": csrf, "Origin": "http://testserver"}


# ---------------------------------------------------------------------------
# Deterministic Valid & Malicious Artifact Builders
# ---------------------------------------------------------------------------


def _build_valid_pdf_bytes(num_pages: int = 1) -> bytes:
    writer = PdfWriter()
    for _ in range(num_pages):
        writer.add_blank_page(width=200, height=200)
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


def _build_valid_docx_bytes(paragraph_text: str = "Mosca confidentiality horizon X=15 years") -> bytes:
    doc = docx.Document()
    doc.add_paragraph(paragraph_text)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _build_valid_png_bytes(width: int = 16, height: int = 16) -> bytes:
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"


def _build_valid_jpeg_bytes(width: int = 64, height: int = 64) -> bytes:
    # SOI + APP0 + SOF0 (with exact height & width) + EOI
    sof0_payload = struct.pack(">BHHB", 8, height, width, 3) + b"\x01\x11\x00\x02\x11\x00\x03\x11\x00"
    sof0 = b"\xff\xc0" + struct.pack(">H", len(sof0_payload) + 2) + sof0_payload
    return b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" + sof0 + b"\xff\xd9"


def _build_test_x509_pair() -> Tuple[bytes, bytes, bytes, bytes]:
    """Returns `(pem_cert, der_cert, pem_private_key, der_private_key)`."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pqc-test.example.com")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    pem_cert = cert.public_bytes(serialization.Encoding.PEM)
    der_cert = cert.public_bytes(serialization.Encoding.DER)
    pem_key = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    der_key = key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return pem_cert, der_cert, pem_key, der_key


def _build_custom_zip(entries: List[Tuple[str, bytes]], compress_type: int = zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=compress_type) as zf:
        for name, data in entries:
            zf.writestr(name, data)
    return buf.getvalue()


# =============================================================================
# 5.1 UNIT TESTS
# =============================================================================


def test_p3_05_unit_filename_sanitizer() -> None:
    assert upload_validator.sanitize_upload_filename("../../etc/passwd.md") == "passwd.md"
    assert upload_validator.sanitize_upload_filename("..\\..\\windows\\system32\\audit.csv") == "audit.csv"
    assert upload_validator.sanitize_upload_filename("folder/sub/report\x00name\n.pdf") == "reportname.pdf"
    assert upload_validator.sanitize_upload_filename("...leading..dots..notes.txt") == "leading_dots_notes.txt"

    overlong = ("a" * 200) + ".json"
    sanitized_long = upload_validator.sanitize_upload_filename(overlong)
    assert len(sanitized_long) <= 128
    assert sanitized_long.endswith(".json")

    # Prohibited private-key / keystore extensions -> HTTP 400 UPLOAD_PRIVATE_KEY_REJECTED
    for key_ext in ("server.key", "bundle.p12", "prod.pfx", "trust.jks", "vault.keystore"):
        with pytest.raises(upload_validator.UploadRejectedContentError) as exc_info:
            upload_validator.sanitize_upload_filename(key_ext)
        assert exc_info.value.http_status == 400
        assert exc_info.value.error_code == "UPLOAD_PRIVATE_KEY_REJECTED"

    # Unsupported executable/archive extensions -> HTTP 415
    for bad_ext in ("payload.exe", "script.sh", "module.py", "lib.dll", "archive.zip", "backup.tar.gz", "noext"):
        with pytest.raises(upload_validator.UploadUnsupportedMediaError) as exc_info:
            upload_validator.sanitize_upload_filename(bad_ext)
        assert exc_info.value.http_status == 415


def test_p3_05_unit_magic_byte_and_mime_sniffer_valid_formats() -> None:
    pem_cert, der_cert, _, _ = _build_test_x509_pair()
    valid_cases = [
        ("architecture.pdf", _build_valid_pdf_bytes(2), "application/pdf", "application/pdf", True),
        ("policy.docx", _build_valid_docx_bytes("Quantum roadmap 2027"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", "text/plain", False),
        ("diagram.png", _build_valid_png_bytes(32, 32), "image/png", "image/png", True),
        ("photo.jpg", _build_valid_jpeg_bytes(64, 48), "image/jpeg", "image/jpeg", True),
        ("public.pem", pem_cert, "application/x-pem-file", "text/plain", False),
        ("public.cer", der_cert, "application/x-x509-ca-cert", "text/plain", False),
        ("notes.md", b"\xef\xbb\xbf# Discovery\r\n- X = 15 years\r\n", "text/markdown", "text/markdown", False),
        ("inventory.csv", b"key,algo\r\nk1,RSA_2048\r\n", "text/csv", "text/csv", False),
        ("cbom.json", b'{"bomFormat":"CycloneDX","components":[]}', "application/json", "text/plain", False),
        ("config.yaml", b"mosca:\n  x: 15\n", "application/x-yaml", "text/plain", False),
        ("readme.txt", b"Plain UTF-8 notes\n", "text/plain", "text/plain", False),
    ]
    for fname, data, mime, exp_gemini_mime, exp_binary in valid_cases:
        res = upload_validator.validate_and_extract_upload(fname, data, declared_mime=mime)
        assert res.sanitized_filename == fname
        assert res.gemini_mime == exp_gemini_mime
        assert res.is_binary_part is exp_binary
        assert res.size_bytes == len(data)
        if fname == "policy.docx":
            assert "Quantum roadmap 2027" in res.extracted_text
        if fname in ("public.pem", "public.cer"):
            assert "X509_CERTIFICATE_METADATA:" in res.extracted_text
            assert "RSA_2048" in res.extracted_text


def test_p3_05_unit_streaming_chunked_reader_aborts_before_buffering_oversized_stream() -> None:
    """Verifies read_bounded_upload reads in bounded chunks and aborts immediately without buffering 100 MiB."""

    class _FakeInfiniteStream:
        def __init__(self) -> None:
            self.total_bytes_emitted = 0
            self.chunk_sizes_requested: List[int] = []

        async def read(self, size: int = -1) -> bytes:
            assert size > 0, "Unbounded UploadFile.read() must NEVER be called!"
            self.chunk_sizes_requested.append(size)
            chunk = b"A" * size
            self.total_bytes_emitted += len(chunk)
            return chunk

    stream = _FakeInfiniteStream()
    with pytest.raises(upload_validator.UploadTooLargeError) as exc_info:
        asyncio.run(
            upload_validator.read_bounded_upload(
                stream,
                max_file_bytes=200_000,
                remaining_total_bytes=500_000,
                chunk_size=65_536,
            )
        )
    assert exc_info.value.http_status == 413
    # Aborted on chunk #4 (262,144 bytes) rather than pulling gigabytes
    assert stream.total_bytes_emitted <= 200_000 + 65_536
    assert all(sz == 65_536 for sz in stream.chunk_sizes_requested)


def test_p3_05_unit_bounded_lru_upload_cache_is_tenant_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PQC_UPLOAD_CACHE_MAX_ENTRIES", "3")
    monkeypatch.setenv("PQC_UPLOAD_CACHE_MAX_BYTES", "2048")

    # 1. Cross-tenant isolation with IDENTICAL session_id and filename
    calibration_engine.register_uploaded_artifact_for_analysis(
        filename="secret.md",
        raw_bytes=b"ALICE_CONFIDENTIAL_DATA",
        mime_type="text/markdown",
        session_id="custom-session-1",
        user_id="alice@google.com",
    )
    calibration_engine.register_uploaded_artifact_for_analysis(
        filename="secret.md",
        raw_bytes=b"BOB_CONFIDENTIAL_DATA",
        mime_type="text/markdown",
        session_id="custom-session-1",
        user_id="bob@google.com",
    )

    class _MockSession:
        def __init__(self, sid: str, uid: str) -> None:
            self.id = sid
            self.user_id = uid

    class _MockCtx:
        def __init__(self, sid: str, uid: str) -> None:
            self.session = _MockSession(sid, uid)
            self.user_id = uid

        async def list_artifacts(self):
            raise RuntimeError("fallback to cache")

        async def load_artifact(self, _name):
            raise RuntimeError("fallback to cache")

    alice_read = json.loads(
        asyncio.run(calibration_engine.read_uploaded_artifact("secret.md", tool_context=_MockCtx("custom-session-1", "alice@google.com")))
    )
    bob_read = json.loads(
        asyncio.run(calibration_engine.read_uploaded_artifact("secret.md", tool_context=_MockCtx("custom-session-1", "bob@google.com")))
    )
    assert alice_read["status"] == "OK" and "ALICE_CONFIDENTIAL_DATA" in alice_read["extracted_text"]
    assert "BOB_CONFIDENTIAL_DATA" not in alice_read["extracted_text"]
    assert bob_read["status"] == "OK" and "BOB_CONFIDENTIAL_DATA" in bob_read["extracted_text"]
    assert "ALICE_CONFIDENTIAL_DATA" not in bob_read["extracted_text"]

    # 2. LRU max_entries eviction (limit=3): adding 2 more entries evicts oldest entry
    calibration_engine.register_uploaded_artifact_for_analysis(
        filename="doc3.md", raw_bytes=b"DOC3", mime_type="text/markdown", session_id="s3", user_id="carol@google.com"
    )
    calibration_engine.register_uploaded_artifact_for_analysis(
        filename="doc4.md", raw_bytes=b"DOC4", mime_type="text/markdown", session_id="s4", user_id="carol@google.com"
    )
    assert len(calibration_engine._UPLOADED_ARTIFACT_CACHE) <= 3

    # 3. TTL expiry evicts stale entries
    monkeypatch.setenv("PQC_UPLOAD_CACHE_TTL_SECONDS", "1.0")
    for rec in calibration_engine._UPLOADED_ARTIFACT_CACHE.values():
        rec["_stored_at_monotonic"] = time.monotonic() - 10.0
    expired_read = json.loads(
        asyncio.run(calibration_engine.read_uploaded_artifact("doc4.md", tool_context=_MockCtx("s4", "carol@google.com")))
    )
    assert expired_read["status"] == "NO_ARTIFACT_FOUND"


# =============================================================================
# 5.2 INTEGRATION TESTS
# =============================================================================


def test_p3_05_integration_valid_multimodal_uploads_through_chat_api(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    pem_cert, der_cert, _, _ = _build_test_x509_pair()
    app = _create_upload_test_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        headers = _login_user(client, "alice@google.com")
        resp = client.post(
            "/api/chat",
            headers=headers,
            data={"message": "Inspect these PQC artifacts", "model_id": "fake-ok-model"},
            files=[
                ("files", ("bom_notes.md", b"\xef\xbb\xbf# Notes\r\nData life 12y\r\n", "text/markdown")),
                ("files", ("scan.pdf", _build_valid_pdf_bytes(1), "application/pdf")),
                ("files", ("roadmap.docx", _build_valid_docx_bytes("PQC target 2028"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")),
                ("files", ("topology.png", _build_valid_png_bytes(16, 16), "image/png")),
                ("files", ("public_cert.pem", pem_cert, "application/x-pem-file")),
            ],
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "OK"
        uploaded_names = [a["filename"] for a in body["uploaded_artifacts"]]
        assert uploaded_names == ["bom_notes.md", "scan.pdf", "roadmap.docx", "topology.png", "public_cert.pem"]

        # Also test DER .cer upload in a second turn
        resp_der = client.post(
            "/api/chat",
            headers=headers,
            data={"message": "Inspect DER cert", "session_id": body["session_id"], "model_id": "fake-ok-model"},
            files=[("files", ("leaf.cer", der_cert, "application/x-x509-ca-cert"))],
        )
        assert resp_der.status_code == 200, resp_der.text
        assert resp_der.json()["uploaded_artifacts"][0]["filename"] == "leaf.cer"
    app.state.auth_store.close()


# =============================================================================
# 5.3 ADVERSARIAL TESTS
# =============================================================================


def test_p3_05_adversarial_size_and_count_limits_enforced_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    monkeypatch.setenv("PQC_MAX_UPLOAD_FILES_PER_TURN", "2")
    monkeypatch.setenv("PQC_MAX_UPLOAD_FILE_BYTES", "1024")
    monkeypatch.setenv("PQC_MAX_UPLOAD_TOTAL_BYTES", "1500")

    app = _create_upload_test_app(tmp_path, monkeypatch)
    save_calls: List[str] = []
    orig_save = app.state.artifact_service.save_artifact

    async def _spy_save(*args: Any, **kwargs: Any):
        save_calls.append(kwargs.get("filename", ""))
        return await orig_save(*args, **kwargs)

    monkeypatch.setattr(app.state.artifact_service, "save_artifact", _spy_save)

    with TestClient(app) as client:
        headers = _login_user(client, "alice@google.com")

        # 1. Single file > 1024 bytes -> HTTP 413, zero GCS/cache writes
        r_big = client.post(
            "/api/chat",
            headers=headers,
            data={"message": "Read big file", "model_id": "fake-ok-model"},
            files=[("files", ("big.txt", b"X" * 2048, "text/plain"))],
        )
        assert r_big.status_code == 413
        assert "UPLOAD_SIZE_LIMIT_EXCEEDED" in r_big.json()["detail"]

        # 2. Multi-file aggregate > 1500 bytes (two valid 900-byte files) -> HTTP 413, ATOMIC (file 1 NOT persisted!)
        r_agg = client.post(
            "/api/chat",
            headers=headers,
            data={"message": "Read batch", "model_id": "fake-ok-model"},
            files=[
                ("files", ("part1.txt", b"A" * 900, "text/plain")),
                ("files", ("part2.txt", b"B" * 900, "text/plain")),
            ],
        )
        assert r_agg.status_code == 413
        assert "UPLOAD_TOTAL_SIZE_EXCEEDED" in r_agg.json()["detail"]

        # 3. File count > 2 -> HTTP 400
        r_cnt = client.post(
            "/api/chat",
            headers=headers,
            data={"message": "Too many", "model_id": "fake-ok-model"},
            files=[
                ("files", ("f1.txt", b"one", "text/plain")),
                ("files", ("f2.txt", b"two", "text/plain")),
                ("files", ("f3.txt", b"three", "text/plain")),
            ],
        )
        assert r_cnt.status_code == 400
        assert "UPLOAD_FILE_COUNT_EXCEEDED" in r_cnt.json()["detail"]

        # 4. 0-byte empty upload -> HTTP 400
        r_empty = client.post(
            "/api/chat",
            headers=headers,
            data={"message": "Empty", "model_id": "fake-ok-model"},
            files=[("files", ("empty.txt", b"", "text/plain"))],
        )
        assert r_empty.status_code == 400
        assert "UPLOAD_EMPTY_FILE" in r_empty.json()["detail"]

        assert len(save_calls) == 0
        assert len(calibration_engine._UPLOADED_ARTIFACT_CACHE) == 0
    app.state.auth_store.close()


@pytest.mark.parametrize(
    "filename,payload,declared_mime,expected_status",
    [
        # PE executable renamed to .pdf
        ("inventory.pdf", b"MZ\x90\x00\x03\x00\x00\x00\x04\x00", "application/pdf", 415),
        # ELF binary renamed to .txt (proves latin-1 fallback eliminated)
        ("notes.txt", b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00", "text/plain", 415),
        # Arbitrary non-UTF-8 raw binary bytes renamed to .md
        ("binary_smuggle.md", b"\xff\xfe\x80\x81\x82\x90\xa0\xb0", "text/markdown", 415),
        # Valid PNG bytes renamed to .pdf
        ("scan.pdf", _build_valid_png_bytes(8, 8), "application/pdf", 415),
        # Valid PNG bytes with spoofed application/pdf Content-Type
        ("pic.png", _build_valid_png_bytes(8, 8), "application/pdf", 415),
        # Plain ZIP archive (without word/document.xml) renamed to .docx
        (
            "fake.docx",
            _build_custom_zip([("hello.txt", b"not a word document")]),
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            415,
        ),
        # Corrupt PDF payload (must NOT fall back to latin-1!)
        ("corrupt.pdf", b"%PDF-1.7\nthis-is-corrupted-xref-garbage", "application/pdf", 400),
        # Malformed JSON upload
        ("broken.json", b"{not: valid json", "application/json", 400),
        # PNG dimension decompression bomb (60000 x 60000)
        ("bomb.png", _build_valid_png_bytes(60000, 60000), "image/png", 400),
        # JPEG dimension decompression bomb (40000 x 40000)
        ("bomb.jpg", _build_valid_jpeg_bytes(40000, 40000), "image/jpeg", 400),
        # Unsupported executable extension
        ("malware.exe", b"MZ\x90\x00payload", "application/octet-stream", 415),
    ],
)
def test_p3_05_adversarial_magic_byte_spoofing_and_binary_smuggling_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    google_verifier: Any,
    filename: str,
    payload: bytes,
    declared_mime: str,
    expected_status: int,
) -> None:
    app = _create_upload_test_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        headers = _login_user(client, "alice@google.com")
        res = client.post(
            "/api/chat",
            headers=headers,
            data={"message": "Analyze attachment", "model_id": "fake-ok-model"},
            files=[("files", (filename, payload, declared_mime))],
        )
        assert res.status_code == expected_status, f"{filename}: got {res.status_code} {res.text}"
        assert len(calibration_engine._UPLOADED_ARTIFACT_CACHE) == 0
    app.state.auth_store.close()


def test_p3_05_adversarial_pdf_page_limit_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    monkeypatch.setenv("PQC_MAX_PDF_PAGES", "3")
    app = _create_upload_test_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        headers = _login_user(client, "alice@google.com")
        res = client.post(
            "/api/chat",
            headers=headers,
            data={"message": "Read huge PDF", "model_id": "fake-ok-model"},
            files=[("files", ("many_pages.pdf", _build_valid_pdf_bytes(5), "application/pdf"))],
        )
        assert res.status_code == 400
        assert "UPLOAD_PDF_PAGE_LIMIT_EXCEEDED" in res.json()["detail"]
    app.state.auth_store.close()


def test_p3_05_adversarial_docx_zip_bomb_zip_slip_and_xxe_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    minimal_content_types = b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>'
    minimal_doc_xml = b'<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>'
    docx_mime = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"

    # 1. ZIP bomb: highly compressible 4 MiB member compressed to ~4 KiB (> 100:1 ratio)
    zip_bomb_bytes = _build_custom_zip(
        [
            ("[Content_Types].xml", minimal_content_types),
            ("word/document.xml", minimal_doc_xml),
            ("word/bomb.xml", b"0" * (4 * 1024 * 1024)),
        ]
    )
    # 2. XXE payload inside word/document.xml
    xxe_doc = _build_custom_zip(
        [
            ("[Content_Types].xml", minimal_content_types),
            (
                "word/document.xml",
                b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><w:document>&xxe;</w:document>',
            ),
        ]
    )
    # 3. Zip-slip entry path traversal
    zip_slip_doc = _build_custom_zip(
        [
            ("[Content_Types].xml", minimal_content_types),
            ("word/document.xml", minimal_doc_xml),
            ("../../evil.xml", b"<evil/>"),
        ]
    )
    # 4. Entry count explosion (> PQC_MAX_DOCX_ENTRIES)
    monkeypatch.setenv("PQC_MAX_DOCX_ENTRIES", "5")
    too_many_entries_doc = _build_custom_zip(
        [("[Content_Types].xml", minimal_content_types), ("word/document.xml", minimal_doc_xml)]
        + [(f"word/extra_{i}.xml", b"<x/>") for i in range(6)]
    )

    app = _create_upload_test_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        headers = _login_user(client, "alice@google.com")

        for fname, data, expected_code in (
            ("bomb.docx", zip_bomb_bytes, "UPLOAD_ZIP_BOMB_DETECTED"),
            ("xxe.docx", xxe_doc, "UPLOAD_XXE_DETECTED"),
            ("slip.docx", zip_slip_doc, "UPLOAD_ZIP_SLIP_DETECTED"),
            ("entries.docx", too_many_entries_doc, "UPLOAD_ZIP_BOMB_DETECTED"),
        ):
            res = client.post(
                "/api/chat",
                headers=headers,
                data={"message": "Inspect DOCX", "model_id": "fake-ok-model"},
                files=[("files", (fname, data, docx_mime))],
            )
            assert res.status_code == 400, f"{fname}: {res.status_code} {res.text}"
            assert expected_code in res.json()["detail"], f"{fname}: {res.text}"
        assert len(calibration_engine._UPLOADED_ARTIFACT_CACHE) == 0
    app.state.auth_store.close()


def test_p3_05_adversarial_private_key_uploads_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    _, _, pem_key, der_key = _build_test_x509_pair()
    app = _create_upload_test_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        headers = _login_user(client, "alice@google.com")

        for fname, payload, mime in (
            ("prod_tls.key", pem_key, "text/plain"),
            ("keystore.p12", b"\x30\x82\x01\x00dummy", "application/x-pkcs12"),
            ("disguised_cert.pem", pem_key, "application/x-pem-file"),
            ("leaked_in_notes.md", b"# Server notes\n" + pem_key, "text/markdown"),
            ("der_privkey.cer", der_key, "application/x-x509-ca-cert"),
        ):
            res = client.post(
                "/api/chat",
                headers=headers,
                data={"message": "Check cert", "model_id": "fake-ok-model"},
                files=[("files", (fname, payload, mime))],
            )
            assert res.status_code == 400, f"{fname}: {res.status_code} {res.text}"
            assert "UPLOAD_PRIVATE_KEY_REJECTED" in res.json()["detail"]

        assert len(calibration_engine._UPLOADED_ARTIFACT_CACHE) == 0
        assert len(app.state.artifact_service._local_fallback_store) == 0
    app.state.auth_store.close()


def test_p3_05_adversarial_path_traversal_filename_sanitized_before_gcs_and_cache(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    app = _create_upload_test_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        headers = _login_user(client, "alice@google.com")
        res = client.post(
            "/api/chat",
            headers=headers,
            data={"message": "Check sanitized names", "model_id": "fake-ok-model"},
            files=[
                ("files", ("../../etc/passwd.md", b"# Discovery doc\n", "text/markdown")),
                ("files", ("dir/sub/report.csv", b"col1,col2\n1,2\n", "text/csv")),
            ],
        )
        assert res.status_code == 200, res.text
        meta = res.json()["uploaded_artifacts"]
        assert [m["filename"] for m in meta] == ["passwd.md", "report.csv"]

        # Verify zero traversal segments in stored artifact service keys or cache keys
        for store_key in app.state.artifact_service._local_fallback_store:
            assert ".." not in store_key
            assert store_key.endswith("/passwd.md") or store_key.endswith("/report.csv")
        for cache_key in calibration_engine._UPLOADED_ARTIFACT_CACHE:
            assert ".." not in cache_key
            assert cache_key.startswith("alice@google.com:")
    app.state.auth_store.close()


def test_p3_05_adversarial_cross_tenant_same_session_id_upload_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, google_verifier: Any
) -> None:
    app = _create_upload_test_app(tmp_path, monkeypatch)
    with TestClient(app) as client:
        # Alice uploads secret document under custom session_id="shared-audit-id"
        alice_hdrs = _login_user(client, "alice@google.com")
        assert (
            client.post(
                "/api/sessions",
                headers=alice_hdrs,
                json={"session_id": "shared-audit-id", "title": "Alice Audit"},
            ).status_code
            == 200
        )
        r_alice = client.post(
            "/api/chat",
            headers=alice_hdrs,
            data={"message": "Upload Alice doc", "session_id": "shared-audit-id", "model_id": "fake-ok-model"},
            files=[("files", ("audit.md", b"ALICE_ONLY_SECRET_PAYLOAD_9911", "text/markdown"))],
        )
        assert r_alice.status_code == 200

        # Bob signs in: attempting to hijack Alice's session_id on /api/sessions is rejected (403),
        # AND even if Bob uploads his own audit.md or registers in cache with identical session_id="shared-audit-id",
        # Alice's and Bob's artifacts remain strictly isolated by (user_id, session_id, filename).
        bob_hdrs = _login_user(client, "bob@google.com")
        hijack_sess = client.post(
            "/api/sessions",
            headers=bob_hdrs,
            json={"session_id": "shared-audit-id", "title": "Bob Audit"},
        )
        assert hijack_sess.status_code == 403

        r_bob_chat = client.post(
            "/api/chat",
            headers=bob_hdrs,
            data={"message": "Upload Bob doc", "session_id": "shared-audit-id", "model_id": "fake-ok-model"},
            files=[("files", ("audit.md", b"BOB_ONLY_SECRET_PAYLOAD_2288", "text/markdown"))],
        )
        assert r_bob_chat.status_code == 403
        # Also test direct identical session_id collision in calibration_engine cache
        calibration_engine.register_uploaded_artifact_for_analysis(
            filename="audit.md",
            raw_bytes=b"BOB_SAME_SESSION_ID_PAYLOAD_3344",
            mime_type="text/markdown",
            session_id="shared-audit-id",
            user_id="bob@google.com",
        )

        class _Sess:
            def __init__(self, sid: str, uid: str) -> None:
                self.id = sid
                self.user_id = uid

        class _InvCtx:
            def __init__(self, uid: str) -> None:
                self.user_id = uid

        class _ToolCtx:
            def __init__(self, sid: str, uid: str) -> None:
                self.session = _Sess(sid, uid)
                self._invocation_context = _InvCtx(uid)

            async def list_artifacts(self):
                raise RuntimeError("exercise cache lookup")

            async def load_artifact(self, _name):
                raise RuntimeError("exercise cache lookup")

        alice_out = json.loads(
            asyncio.run(calibration_engine.read_uploaded_artifact("audit.md", tool_context=_ToolCtx("shared-audit-id", "alice@google.com")))
        )
        bob_out = json.loads(
            asyncio.run(calibration_engine.read_uploaded_artifact("audit.md", tool_context=_ToolCtx("shared-audit-id", "bob@google.com")))
        )
        assert alice_out["status"] == "OK"
        assert "ALICE_ONLY_SECRET_PAYLOAD_9911" in alice_out["extracted_text"]
        assert "BOB_ONLY_SECRET_PAYLOAD_2288" not in alice_out["extracted_text"]
        assert "BOB_SAME_SESSION_ID_PAYLOAD_3344" not in alice_out["extracted_text"]

        assert bob_out["status"] == "OK"
        assert "BOB_SAME_SESSION_ID_PAYLOAD_3344" in bob_out["extracted_text"]
        assert "ALICE_ONLY_SECRET_PAYLOAD_9911" not in bob_out["extracted_text"]
    app.state.auth_store.close()
