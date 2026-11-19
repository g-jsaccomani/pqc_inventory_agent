"""Phase 3.1 (`P3-01`) — Outbound SSRF, Egress Guard, Gcloud Grammar & Confused-Deputy Security Suite.

Deterministic unit, integration, regression, and adversarial tests covering:
- Stage 1: `pqc_agent/egress_guard.py` (`safe_urlopen`) and integrations in `workspace_server.py`,
  `credential_service.py`, and `auth_guard.py` (`_CertCachingRequest`).
- Stage 2: Strict structured `gcloud` command/flag grammar and subprocess environment sanitization in
  `tools/gcloud_bridge.py`.
- Stage 3: Complete elimination of confused-deputy `access_token` -> server ADC fallback.

All network, DNS, TLS socket, and subprocess interactions use deterministic local fakes/mocks;
zero external or attacker-controlled endpoints are ever contacted.
"""

from __future__ import annotations

from email.message import Message as HttpHeadersMessage
import http.client
import io
import json
import logging
from pathlib import Path
import socket
import ssl
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.parse
import urllib.request

from fastapi.testclient import TestClient
from google.auth import exceptions as google_auth_exceptions
import pytest

from pqc_agent import auth_guard, auth_store, credential_service, egress_guard
from pqc_agent import workspace_server as ws
from tools import gcloud_bridge


# =============================================================================
# Helpers & Deterministic Transport Doubles
# =============================================================================
def _public_google_dns(
    host: str, port: int, family: int = 0, socktype: int = socket.SOCK_STREAM
) -> List[Tuple[Any, ...]]:
    return [
        (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("142.250.80.10", port)),
        (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("2607:f8b0:4004:800::200a", port, 0, 0)),
    ]


class _MockRawResponse:
    """Deterministic HTTP response stream supporting chunked `read(amt)` and header inspection."""

    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        headers: Optional[List[Tuple[str, str]]] = None,
        chunk_cap: Optional[int] = None,
    ) -> None:
        self._buf = io.BytesIO(body)
        self.status = status
        self._chunk_cap = chunk_cap
        self.closed = False
        msg = HttpHeadersMessage()
        for k, v in headers or []:
            msg.add_header(k, v)
        self.headers = msg

    def getcode(self) -> int:
        return self.status

    def info(self) -> HttpHeadersMessage:
        return self.headers

    def read(self, amt: Optional[int] = None) -> bytes:
        if amt is None or amt < 0:
            return self._buf.read()
        limit = min(amt, self._chunk_cap) if self._chunk_cap else amt
        return self._buf.read(limit)

    def close(self) -> None:
        self.closed = True
        self._buf.close()


class _SingleHopOpener(urllib.request.OpenerDirector):
    """Deterministic `OpenerDirector` test double recording exact outbound hops."""

    def __init__(self, handler_fn):
        super().__init__()
        self._handler_fn = handler_fn
        self.requests: List[Tuple[str, float]] = []

    def open(self, fullurl, data=None, timeout=None):  # type: ignore[override]
        url = fullurl.full_url if hasattr(fullurl, "full_url") else str(fullurl)
        self.requests.append((url, float(timeout)))
        return self._handler_fn(fullurl, timeout)


def _create_portal_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "p3_01_portal.db"
    monkeypatch.setenv("SESSION_DB_URL", f"sqlite:///{db_path}")
    monkeypatch.setenv("PQC_EXPORT_DIR", str(tmp_path / "exports"))
    monkeypatch.setenv("PQC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PQC_AUTH_SECRET", "p3-01-test-hmac-secret-material-at-least-32-bytes!!")
    return ws.create_workspace_app()


# =============================================================================
# 4.1 Safe HTTP Unit Tests
# =============================================================================
def test_p3_01_safe_urlopen_accepts_allowlisted_https_google_hosts() -> None:
    expected_hosts = (
        "oauth2.googleapis.com",
        "www.googleapis.com",
        "openidconnect.googleapis.com",
        "accounts.google.com",
    )
    assert egress_guard.GOOGLE_OAUTH_ALLOWED_HOSTS == frozenset(expected_hosts)

    for host in expected_hosts:
        opener = _SingleHopOpener(
            lambda _req, _t: _MockRawResponse(
                b'{"ok":true}',
                status=200,
                headers=[("Content-Type", "application/json"), ("Content-Length", "11")],
            )
        )
        url = f"https://{host}/endpoint"
        with egress_guard.safe_urlopen(
            url,
            timeout=5.0,
            dns_resolver=_public_google_dns,
            opener=opener,
        ) as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode("utf-8")) == {"ok": True}
        assert len(opener.requests) == 1


@pytest.mark.parametrize(
    "bad_url,expected_exc",
    [
        # Plaintext HTTP & non-HTTPS schemes rejected
        ("http://oauth2.googleapis.com/token", egress_guard.EgressPolicyError),
        ("http://www.googleapis.com/oauth2/v3/userinfo", egress_guard.EgressPolicyError),
        ("file:///etc/passwd", egress_guard.EgressPolicyError),
        ("ftp://oauth2.googleapis.com/resource", egress_guard.EgressPolicyError),
        ("data:text/plain;base64,SGVsbG8=", egress_guard.EgressPolicyError),
        # Unknown hostnames & subdomain/suffix spoofing rejected
        ("https://attacker.example/token", egress_guard.EgressPolicyError),
        ("https://oauth2.googleapis.com.attacker.example/token", egress_guard.EgressPolicyError),
        ("https://sub.oauth2.googleapis.com/token", egress_guard.EgressPolicyError),
        ("https://evil-oauth2.googleapis.com/token", egress_guard.EgressPolicyError),
        ("https://googleapis.com/token", egress_guard.EgressPolicyError),
        # Malformed hostnames & URL tricks rejected
        ("https://oauth2.googleapis.com./token", egress_guard.EgressPolicyError),
        ("https://.oauth2.googleapis.com/token", egress_guard.EgressPolicyError),
        ("https://oauth2..googleapis.com/token", egress_guard.EgressPolicyError),
        ("https://oauth2.googleapis.com\\@attacker.example/token", egress_guard.EgressPolicyError),
        (" https://oauth2.googleapis.com/token", egress_guard.EgressPolicyError),
        ("https://oauth2.googleapis.com/token\r\nX-Injected: 1", egress_guard.EgressPolicyError),
        # Userinfo rejected
        ("https://user:pass@oauth2.googleapis.com/token", egress_guard.EgressPolicyError),
        ("https://oauth2.googleapis.com@attacker.example/token", egress_guard.EgressPolicyError),
        # Unexpected ports rejected
        ("https://oauth2.googleapis.com:8443/token", egress_guard.EgressPolicyError),
        ("https://oauth2.googleapis.com:80/token", egress_guard.EgressPolicyError),
        ("https://oauth2.googleapis.com:/token", egress_guard.EgressPolicyError),
        # IP-literal URLs rejected (public, loopback, private, link-local, metadata, integer/hex, IPv6)
        ("https://142.250.80.10/token", egress_guard.EgressDestinationError),
        ("https://127.0.0.1/token", egress_guard.EgressDestinationError),
        ("https://10.0.0.1/token", egress_guard.EgressDestinationError),
        ("https://172.16.0.1/token", egress_guard.EgressDestinationError),
        ("https://192.168.1.1/token", egress_guard.EgressDestinationError),
        ("https://169.254.169.254/computeMetadata/v1/", egress_guard.EgressDestinationError),
        ("https://0.0.0.0/token", egress_guard.EgressDestinationError),
        ("https://2130706433/token", egress_guard.EgressDestinationError),
        ("https://0x7f000001/token", egress_guard.EgressDestinationError),
        ("https://[::1]/token", egress_guard.EgressDestinationError),
        ("https://[fe80::1]/token", egress_guard.EgressDestinationError),
        ("https://[fd00:ec2::254]/latest/meta-data/", egress_guard.EgressDestinationError),
    ],
)
def test_p3_01_safe_urlopen_rejects_disallowed_urls_before_network(
    bad_url: str, expected_exc: type[Exception]
) -> None:
    dns_called = False

    def _ForbiddenDns(*_args: Any, **_kwargs: Any) -> List[Tuple[Any, ...]]:
        nonlocal dns_called
        dns_called = True
        raise AssertionError("DNS should never be queried when URL policy fails")

    opener = _SingleHopOpener(lambda *_a: pytest.fail("Network opener must never be invoked"))
    with pytest.raises(expected_exc):
        egress_guard.safe_urlopen(bad_url, timeout=5.0, dns_resolver=_ForbiddenDns, opener=opener)

    assert dns_called is False
    assert opener.requests == []


def test_p3_01_safe_urlopen_rejects_host_header_smuggling() -> None:
    req = urllib.request.Request(
        "https://oauth2.googleapis.com/token",
        headers={"Host": "attacker.example"},
    )
    opener = _SingleHopOpener(lambda *_a: pytest.fail("Opener must not be called"))
    with pytest.raises(egress_guard.EgressPolicyError, match="Host header"):
        egress_guard.safe_urlopen(req, timeout=5.0, dns_resolver=_public_google_dns, opener=opener)
    assert opener.requests == []


@pytest.mark.parametrize("redirect_code", [301, 302, 303, 307, 308])
def test_p3_01_safe_urlopen_blocks_redirects_to_metadata_without_second_hop(redirect_code: int) -> None:
    """Specific adversarial redirect test targeting `http://169.254.169.254/computeMetadata/v1/`."""
    metadata_target = "http://169.254.169.254/computeMetadata/v1/"
    contacted_targets: List[Tuple[str, int]] = []

    class _FakeTlsSocket:
        def __init__(self, raw_http_bytes: bytes) -> None:
            self._rbuf = io.BytesIO(raw_http_bytes)
            self.sent_bytes = bytearray()

        def sendall(self, data: bytes) -> None:
            self.sent_bytes.extend(data)

        def makefile(self, mode: str = "rb", buffering: int = -1) -> io.BytesIO:
            return self._rbuf

        def close(self) -> None:
            pass

    class _FakeRawSocket:
        def __init__(self, family: int, socktype: int) -> None:
            self.family = family
            self.socktype = socktype
            self.timeout: Optional[float] = None

        def settimeout(self, val: Optional[float]) -> None:
            self.timeout = val

        def connect(self, addr: Tuple[Any, ...]) -> None:
            contacted_targets.append((str(addr[0]), int(addr[1])))
            if str(addr[0]) == "169.254.169.254":
                pytest.fail("CRITICAL: Redirect second hop contacted metadata IP 169.254.169.254!")

        def close(self) -> None:
            pass

    raw_redirect_http = (
        f"HTTP/1.1 {redirect_code} Redirect\r\n"
        f"Location: {metadata_target}\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii")

    ssl_ctx = ssl.create_default_context()
    # Patch wrap_socket on this dedicated test SSLContext while keeping verify_mode=CERT_REQUIRED & check_hostname=True.
    ssl_ctx.wrap_socket = lambda sock, server_hostname=None: _FakeTlsSocket(raw_redirect_http)  # type: ignore[method-assign]

    with pytest.raises(egress_guard.EgressRedirectError) as exc_info:
        egress_guard.safe_urlopen(
            "https://oauth2.googleapis.com/tokeninfo?access_token=ya29.top-secret-token",
            timeout=5.0,
            ssl_context=ssl_ctx,
            dns_resolver=_public_google_dns,
            socket_factory=_FakeRawSocket,  # type: ignore[arg-type]
        )

    # Assert first hop connected ONLY to pinned Google public IP, NEVER to 169.254.169.254, and token was redacted!
    assert contacted_targets == [("142.250.80.10", 443)]
    assert all(ip != "169.254.169.254" for ip, _ in contacted_targets)
    assert "ya29.top-secret-token" not in str(exc_info.value)


def test_p3_01_safe_urlopen_enforces_response_size_limits_and_never_returns_partial_data() -> None:
    # 1. Oversized Content-Length rejected immediately before reading body
    read_attempted = False

    class _TrapBodyResponse(_MockRawResponse):
        def read(self, amt: Optional[int] = None) -> bytes:
            nonlocal read_attempted
            read_attempted = True
            return b"x" * 70000

    opener_cl = _SingleHopOpener(
        lambda _req, _t: _TrapBodyResponse(
            b"",
            status=200,
            headers=[("Content-Length", str(egress_guard.DEFAULT_MAX_RESPONSE_BYTES + 1))],
        )
    )
    with pytest.raises(egress_guard.EgressResponseTooLargeError, match="Content-Length"):
        egress_guard.safe_urlopen(
            "https://oauth2.googleapis.com/token",
            timeout=5.0,
            dns_resolver=_public_google_dns,
            opener=opener_cl,
        )
    assert read_attempted is False

    # 2. Lying small Content-Length with oversized streamed body rejected without returning partial data
    oversized_stream = b"A" * (egress_guard.DEFAULT_MAX_RESPONSE_BYTES + 50)
    raw_lying = _MockRawResponse(
        oversized_stream,
        status=200,
        headers=[("Content-Length", "32")],
        chunk_cap=8192,
    )
    opener_lying = _SingleHopOpener(lambda _req, _t: raw_lying)
    with pytest.raises(egress_guard.EgressResponseTooLargeError):
        egress_guard.safe_urlopen(
            "https://oauth2.googleapis.com/token",
            timeout=5.0,
            dns_resolver=_public_google_dns,
            opener=opener_lying,
        )
    assert raw_lying.closed is True

    # 3. Missing Content-Length still enforces exact 64 KiB cap (65537 fails, 65536 succeeds)
    raw_missing_over = _MockRawResponse(
        b"B" * (egress_guard.DEFAULT_MAX_RESPONSE_BYTES + 1),
        status=200,
        headers=[("Transfer-Encoding", "chunked")],
        chunk_cap=4096,
    )
    opener_missing_over = _SingleHopOpener(lambda _req, _t: raw_missing_over)
    with pytest.raises(egress_guard.EgressResponseTooLargeError):
        egress_guard.safe_urlopen(
            "https://www.googleapis.com/oauth2/v3/userinfo",
            timeout=5.0,
            dns_resolver=_public_google_dns,
            opener=opener_missing_over,
        )

    exact_limit_payload = b"C" * egress_guard.DEFAULT_MAX_RESPONSE_BYTES
    opener_exact = _SingleHopOpener(
        lambda _req, _t: _MockRawResponse(exact_limit_payload, status=200, headers=[], chunk_cap=4096)
    )
    with egress_guard.safe_urlopen(
        "https://www.googleapis.com/oauth2/v3/userinfo",
        timeout=5.0,
        dns_resolver=_public_google_dns,
        opener=opener_exact,
    ) as ok_resp:
        assert len(ok_resp.read()) == egress_guard.DEFAULT_MAX_RESPONSE_BYTES


@pytest.mark.parametrize("bad_timeout", [None, 0, -1.5, float("inf"), float("-inf"), float("nan"), True, False, 120.0])
def test_p3_01_safe_urlopen_requires_explicit_finite_timeout(bad_timeout: Any) -> None:
    opener = _SingleHopOpener(lambda *_a: pytest.fail("Opener must not run without finite timeout"))
    with pytest.raises(egress_guard.EgressPolicyError):
        egress_guard.safe_urlopen(
            "https://oauth2.googleapis.com/token",
            timeout=bad_timeout,
            dns_resolver=_public_google_dns,
            opener=opener,
        )
    assert opener.requests == []


def test_p3_01_safe_urlopen_enforces_tls_certificate_and_hostname_verification() -> None:
    # Default SSL context keeps CERT_REQUIRED and check_hostname=True
    default_ctx = egress_guard._validate_or_create_ssl_context(None)
    assert default_ctx.verify_mode == ssl.CERT_REQUIRED
    assert default_ctx.check_hostname is True
    assert default_ctx.minimum_version >= ssl.TLSVersion.TLSv1_2

    # Unverified SSL context fails closed
    unverified_ctx = ssl._create_unverified_context()
    with pytest.raises(egress_guard.EgressPolicyError, match="TLS"):
        egress_guard.safe_urlopen(
            "https://oauth2.googleapis.com/token",
            timeout=5.0,
            ssl_context=unverified_ctx,
            dns_resolver=_public_google_dns,
        )

    # Context with check_hostname=False fails closed
    no_host_ctx = ssl.create_default_context()
    no_host_ctx.check_hostname = False
    with pytest.raises(egress_guard.EgressPolicyError, match="TLS"):
        egress_guard.safe_urlopen(
            "https://oauth2.googleapis.com/token",
            timeout=5.0,
            ssl_context=no_host_ctx,
            dns_resolver=_public_google_dns,
        )


def test_p3_01_sensitive_headers_and_tokens_never_appear_in_logs_or_errors(
    caplog: pytest.LogCaptureFixture,
) -> None:
    secret_access = "ya29.SENSITIVE_ACCESS_TOKEN_DO_NOT_LOG_998877"
    secret_refresh = "1//SENSITIVE_REFRESH_TOKEN_DO_NOT_LOG_665544"
    secret_client = "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11"

    def _failing_opener(req: urllib.request.Request, _timeout: float) -> Any:
        raise OSError(
            f"Upstream failure for {req.full_url} with Authorization: Bearer {secret_access} "
            f"refresh_token={secret_refresh} client_secret={secret_client}"
        )

    opener = _SingleHopOpener(_failing_opener)
    req = urllib.request.Request(
        f"https://oauth2.googleapis.com/tokeninfo?access_token={secret_access}",
        headers={"Authorization": f"Bearer {secret_access}"},
    )

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(urllib.error.URLError) as exc_info:
            egress_guard.safe_urlopen(req, timeout=5.0, dns_resolver=_public_google_dns, opener=opener)

    err_str = str(exc_info.value)
    for secret in (secret_access, secret_refresh, secret_client):
        assert secret not in err_str
        assert secret not in caplog.text


def test_p3_01_auth_guard_jwks_and_credential_refresh_enforce_egress_guard() -> None:
    # 1. Credential refresh rejects tampered token_uri pointing outside Google allowlist or using HTTP
    for bad_token_uri in (
        "https://attacker.example/token",
        "http://oauth2.googleapis.com/token",
        "https://169.254.169.254/token",
    ):
        with pytest.raises(egress_guard.EgressError):
            credential_service._default_oauth_refresh_exchange(
                refresh_token="1//synthetic-refresh",
                client_id="client-123.apps.googleusercontent.com",
                client_secret="GOCSPX-synthetic",
                token_uri=bad_token_uri,
            )

    # 2. _CertCachingRequest enforces HTTPS, GOOGLE_JWKS_ALLOWED_HOSTS, redirect ban, and 64 KiB cap
    assert auth_guard._CertCachingRequest is not None
    jwks_opener = _SingleHopOpener(
        lambda _req, _t: _MockRawResponse(b'{"kid1":"-----BEGIN CERTIFICATE-----"}', status=200)
    )
    cert_req = auth_guard._CertCachingRequest(dns_resolver=_public_google_dns, opener=jwks_opener)
    ok_resp = cert_req("https://www.gstatic.com/iap/verify/public_key", method="GET", timeout=5.0)
    assert ok_resp.status == 200
    # Second call hits cache without a second outbound hop
    ok_cached = cert_req("https://www.gstatic.com/iap/verify/public_key", method="GET", timeout=5.0)
    assert ok_cached.status == 200
    assert len(jwks_opener.requests) == 1

    # Untrusted host, HTTP, POST, redirect, and oversized JWKS fail closed with google.auth TransportError
    for blocked_jwks_url in (
        "http://www.gstatic.com/iap/verify/public_key",
        "https://attacker.example/jwks.json",
        "https://169.254.169.254/computeMetadata/v1/",
    ):
        with pytest.raises(google_auth_exceptions.TransportError):
            cert_req(blocked_jwks_url, method="GET", timeout=5.0)

    with pytest.raises(google_auth_exceptions.TransportError):
        cert_req("https://www.gstatic.com/iap/verify/public_key", method="POST", body=b"{}", timeout=5.0)

    redir_opener = _SingleHopOpener(
        lambda _req, _t: _MockRawResponse(
            b"", status=302, headers=[("Location", "http://169.254.169.254/computeMetadata/v1/")]
        )
    )
    redir_cert_req = auth_guard._CertCachingRequest(dns_resolver=_public_google_dns, opener=redir_opener)
    with pytest.raises(google_auth_exceptions.TransportError, match="redirect"):
        redir_cert_req("https://www.googleapis.com/oauth2/v1/certs", method="GET", timeout=5.0)
    assert len(redir_opener.requests) == 1


# =============================================================================
# 4.2 DNS and Destination Validation & Pinning Tests
# =============================================================================
@pytest.mark.parametrize(
    "bad_ip",
    [
        # Loopback
        "127.0.0.1",
        "127.0.0.53",
        "::1",
        # Private RFC 1918 & ULA
        "10.0.0.1",
        "10.128.0.15",
        "172.16.0.1",
        "172.31.255.254",
        "192.168.1.1",
        "fc00::1",
        "fd12:3456:789a::1",
        # Link-local & Cloud Metadata
        "169.254.169.254",
        "169.254.0.10",
        "fe80::1",
        "fe80::1%eth0",
        "fd00:ec2::254",
        # CGNAT / Alibaba metadata / Reserved / Multicast / Unspecified / Documentation
        "100.64.0.1",
        "100.100.100.200",
        "0.0.0.0",
        "::",
        "224.0.0.1",
        "ff02::1",
        "240.0.0.1",
        "255.255.255.255",
        "192.0.2.1",
        "2001:db8::1",
        # IPv6 transition/encapsulation edge cases
        "::ffff:169.254.169.254",
        "::ffff:127.0.0.1",
        "::ffff:142.250.80.10",
        "2002:7f00:0001::1",
        "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
        "64:ff9b::a9fe:a9fe",
        "::142.250.80.10",
    ],
)
def test_p3_01_dns_rejects_prohibited_ipv4_and_ipv6_resolutions(bad_ip: str) -> None:
    with pytest.raises(egress_guard.EgressDestinationError):
        egress_guard.validate_destination_ip(bad_ip)

    family = socket.AF_INET6 if ":" in bad_ip else socket.AF_INET
    sockaddr = (bad_ip, 443, 0, 0) if family == socket.AF_INET6 else (bad_ip, 443)

    def _poisoned_dns(host: str, port: int, *_rest: Any) -> List[Tuple[Any, ...]]:
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr)]

    with pytest.raises(egress_guard.EgressDestinationError):
        egress_guard.resolve_and_validate_host("oauth2.googleapis.com", 443, dns_resolver=_poisoned_dns)


def test_p3_01_dns_multiple_answers_with_single_prohibited_ip_fails_closed() -> None:
    """Mixed public + private/metadata DNS response must fail closed completely."""

    def _mixed_dns(host: str, port: int, *_rest: Any) -> List[Tuple[Any, ...]]:
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("142.250.80.10", port)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", port)),
        ]

    with pytest.raises(egress_guard.EgressDestinationError, match="metadata"):
        egress_guard.resolve_and_validate_host("oauth2.googleapis.com", 443, dns_resolver=_mixed_dns)


def test_p3_01_dns_errors_and_empty_answers_fail_closed() -> None:
    def _error_dns(*_args: Any) -> List[Tuple[Any, ...]]:
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    with pytest.raises(egress_guard.EgressDestinationError, match="DNS resolution failed"):
        egress_guard.resolve_and_validate_host("oauth2.googleapis.com", 443, dns_resolver=_error_dns)

    with pytest.raises(egress_guard.EgressDestinationError, match="no addresses"):
        egress_guard.resolve_and_validate_host("oauth2.googleapis.com", 443, dns_resolver=lambda *_a: [])


def test_p3_01_dns_pinning_prevents_rebinding_and_preserves_tls_sni() -> None:
    """Proves DNS is resolved once and TCP connects directly to the validated numeric IP with TLS SNI."""
    dns_invocations: List[str] = []
    tcp_connected_endpoints: List[Tuple[Any, ...]] = []
    tls_wrapped_hostnames: List[Optional[str]] = []

    def _rebinding_dns_if_called_twice(host: str, port: int, *_rest: Any) -> List[Tuple[Any, ...]]:
        dns_invocations.append(host)
        if len(dns_invocations) > 1:
            # A second DNS resolution would rebind to metadata IP!
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", port))]
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("142.250.80.42", port))]

    raw_http_200 = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Length: 17\r\n"
        b"Connection: close\r\n\r\n"
        b'{"pinned":"true"}'
    )

    class _PinnedTlsStream:
        def __init__(self) -> None:
            self._buf = io.BytesIO(raw_http_200)

        def sendall(self, _data: bytes) -> None:
            pass

        def makefile(self, mode: str = "rb", buffering: int = -1) -> io.BytesIO:
            return self._buf

        def close(self) -> None:
            pass

    class _PinnedRawSocket:
        def __init__(self, family: int, socktype: int) -> None:
            self.family = family
            self.socktype = socktype

        def settimeout(self, _timeout: Optional[float]) -> None:
            pass

        def connect(self, addr: Tuple[Any, ...]) -> None:
            tcp_connected_endpoints.append(addr)

        def close(self) -> None:
            pass

    ssl_ctx = ssl.create_default_context()

    def _wrap_socket(sock: Any, server_hostname: Optional[str] = None) -> _PinnedTlsStream:
        tls_wrapped_hostnames.append(server_hostname)
        return _PinnedTlsStream()

    ssl_ctx.wrap_socket = _wrap_socket  # type: ignore[method-assign]

    with egress_guard.safe_urlopen(
        "https://oauth2.googleapis.com/token",
        timeout=6.0,
        ssl_context=ssl_ctx,
        dns_resolver=_rebinding_dns_if_called_twice,
        socket_factory=_PinnedRawSocket,  # type: ignore[arg-type]
    ) as resp:
        assert resp.status == 200
        assert json.loads(resp.read().decode("utf-8")) == {"pinned": "true"}

    assert dns_invocations == ["oauth2.googleapis.com"]  # Single DNS lookup only!
    assert tcp_connected_endpoints == [("142.250.80.42", 443)]  # Exact numeric IP, never hostname!
    assert tls_wrapped_hostnames == ["oauth2.googleapis.com"]  # Exact SNI / cert hostname preserved!


# =============================================================================
# 4.3 Gcloud Adversarial Tests
# =============================================================================
@pytest.mark.parametrize(
    "malicious_cmd",
    [
        # Required adversarial commands from PHASE03 specification
        "gcloud kms keys list --location=global --api-endpoint-overrides=cloudkms=https://attacker.example/",
        "gcloud kms keys list --location=global --property=api_endpoint_overrides/cloudkms=https://attacker.example/",
        "gcloud kms keys list --flags-file=/etc/passwd",
        "gcloud kms keys list --credential-file-override=/tmp/credentials.json",
        "gcloud kms keys list --access-token-file=/tmp/token",
        "gcloud kms keys list --impersonate-service-account=attacker@example.iam.gserviceaccount.com",
        "gcloud kms keys list --log-http",
        # Space-separated forms
        "gcloud kms keys list --location global --api-endpoint-overrides cloudkms=https://attacker.example/",
        "gcloud kms keys list --location global --property api_endpoint_overrides/cloudkms=http://169.254.169.254/",
        "gcloud kms keys list --flags-file /etc/passwd",
        "gcloud kms keys list --credential-file-override /tmp/credentials.json",
        "gcloud kms keys list --access-token-file /tmp/token",
        "gcloud kms keys list --impersonate-service-account attacker@example.iam.gserviceaccount.com",
        "gcloud kms keys list --account attacker@example.com",
        "gcloud kms keys list --configuration attacker-config",
        # Underscore, case, prefix abbreviation, and negation bypass attempts
        "gcloud kms keys list --location=global --api_endpoint_overrides=cloudkms=https://attacker.example/",
        "gcloud kms keys list --location=global --API-ENDPOINT-OVERRIDES=cloudkms=https://attacker.example/",
        "gcloud kms keys list --location=global --api-endpoint=cloudkms=https://attacker.example/",
        "gcloud kms keys list --location=global --propert=core/account=attacker@example.com",
        "gcloud kms keys list --location=global --impersonate=attacker@example.iam.gserviceaccount.com",
        "gcloud kms keys list --location=global --cred=/tmp/cred.json",
        "gcloud kms keys list --location=global --no-log-http",
        "gcloud kms keys list --location=global --authorization-token-file=/tmp/tok",
        "gcloud kms keys versions get-public-key 1 --key=k1 --keyring=kr1 --location=global --output-file=/tmp/pwn",
        # Repeated flags
        "gcloud kms keys list --location=global --location=us-central1",
        "gcloud kms keys list --project=proj-alpha-01 --project=proj-beta-02 --location=global",
        "gcloud kms keys list --location=global -q --quiet",
        # Unknown flags & wrong-command flags
        "gcloud kms keys list --location=global --unknown-flag=123",
        "gcloud kms keys list --location=global --verbosity=debug",
        "gcloud kms keys list --scope=organizations/31564119954",
        "gcloud version --keyring=kr1",
        # URL & metadata injection in flag values and positional arguments
        "gcloud kms keys list --location=global --project=https://attacker.example/proj",
        "gcloud kms keys list --location=global --filter=name:https://attacker.example/",
        "gcloud asset search-all-resources --scope=http://169.254.169.254/computeMetadata/v1/",
        "gcloud asset search-all-resources --query=endpoint:169.254.169.254",
        "gcloud kms keys describe https://attacker.example/key --location=global --keyring=kr1",
        "gcloud kms keys describe ../etc/passwd --location=global --keyring=kr1",
        "gcloud kms keys list --location=@/etc/passwd",
        # Malformed syntax, non-gcloud binaries, option terminators, missing flag values
        "/usr/bin/gcloud kms keys list --location=global",
        "curl https://attacker.example/",
        "kms keys list --location=global",
        "gcloud kms keys list -- --api-endpoint-overrides=cloudkms=https://attacker.example/",
        "gcloud kms keys list --location --quiet",
        "gcloud kms keys list --location=",
        "gcloud kms keys list extra-positional --location=global",
        "gcloud kms keys describe --location=global --keyring=kr1",
        "gcloud compute ssl-policies list --global --region=us-central1",
        "gcloud alpha kms keys list --location=global",
        "gcloud beta kms keys list --location=global",
        # Attempts to read/mutate gcloud configuration, auth, or secrets
        "gcloud config set api_endpoint_overrides/cloudkms https://attacker.example/",
        "gcloud config configurations activate default",
        "gcloud config list",
        "gcloud config get-value account",
        "gcloud auth list",
        "gcloud auth print-access-token",
        "gcloud auth activate-service-account --key-file=/tmp/key.json",
        "gcloud secrets versions access latest --secret=prod-db-password",
        "gcloud compute ssh prod-vm --zone=us-central1-a",
    ],
)
def test_p3_01_gcloud_adversarial_commands_rejected_with_zero_subprocess_calls(
    malicious_cmd: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    subproc_calls: List[Any] = []
    monkeypatch.setattr(
        gcloud_bridge.subprocess,
        "run",
        lambda *a, **kw: subproc_calls.append((a, kw)),
    )

    is_valid, _tokens, msg = gcloud_bridge.validate_gcloud_command(malicious_cmd)
    assert is_valid is False, f"Expected malicious command to be blocked: {malicious_cmd}"
    assert msg

    exec_res = json.loads(gcloud_bridge.execute_gcloud_command(malicious_cmd))
    assert exec_res["status"] == "BLOCKED_DESTRUCTIVE_OR_INVALID_COMMAND"
    assert exec_res["exit_code"] == 126
    assert len(subproc_calls) == 0


def test_p3_01_gcloud_environment_sanitization_strips_endpoint_overrides_and_proxies(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adc_file = tmp_path / "adc.json"
    adc_file.write_text("{}", encoding="utf-8")

    monkeypatch.setenv("CLOUDSDK_API_ENDPOINT_OVERRIDES_CLOUDKMS", "https://attacker.example/")
    monkeypatch.setenv("CLOUDSDK_API_ENDPOINT_OVERRIDES_CLOUDASSET", "http://169.254.169.254/")
    monkeypatch.setenv("CLOUDSDK_PROXY_ADDRESS", "proxy.attacker.example")
    monkeypatch.setenv("CLOUDSDK_PROXY_PORT", "8080")
    monkeypatch.setenv("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "/tmp/evil_creds.json")
    monkeypatch.setenv("CLOUDSDK_ACTIVE_CONFIG_NAME", "evil-config")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.attacker.example:8080")
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.attacker.example:8443")
    monkeypatch.setenv("http_proxy", "http://proxy.attacker.example:8080")
    monkeypatch.setenv("https_proxy", "http://proxy.attacker.example:8443")
    monkeypatch.setenv("ALL_PROXY", "socks5://proxy.attacker.example:1080")
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("GCE_METADATA_HOST", "169.254.169.254.attacker.example")
    monkeypatch.setenv("PYTHONHTTPSVERIFY", "0")
    monkeypatch.setenv("SSL_CERT_FILE", "/tmp/rogue_ca.pem")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", "/tmp/rogue_ca.pem")
    monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
    monkeypatch.setenv("PQC_ADMIN_EMAILS", "env-test@google.com")
    gcloud_bridge.set_current_tenant_user("env-test@google.com")
    gcloud_bridge.set_gcp_connection_config(
        mode="adc",
        project_id="pqc-inventory-agent-cd06",
        user_id="env-test@google.com",
    )
    # Ensure singleton test store is bound in active context before simulating Cloud Run K_SERVICE env var
    tok_store = auth_store.set_active_auth_store(auth_store.get_active_auth_store())

    monkeypatch.setenv("K_SERVICE", "pqc-inventory-portal")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "pqc-inventory-agent-cd06")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(adc_file))

    captured_envs: List[Dict[str, str]] = []

    def _fake_run(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert kwargs.get("shell") is False
        captured_envs.append(dict(kwargs["env"]))
        return subprocess.CompletedProcess(cmd, 0, stdout="[]", stderr="")

    monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/usr/bin/gcloud")
    monkeypatch.setattr(gcloud_bridge.subprocess, "run", _fake_run)

    try:
        res = json.loads(gcloud_bridge.execute_gcloud_command("gcloud kms keys list --location=global --format=json"))
    finally:
        auth_store.reset_active_auth_store(tok_store)
    assert res["status"] == "SUCCESS"
    assert len(captured_envs) == 1
    clean_env = captured_envs[0]

    for forbidden_key in (
        "CLOUDSDK_API_ENDPOINT_OVERRIDES_CLOUDKMS",
        "CLOUDSDK_API_ENDPOINT_OVERRIDES_CLOUDASSET",
        "CLOUDSDK_PROXY_ADDRESS",
        "CLOUDSDK_PROXY_PORT",
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
        "CLOUDSDK_ACTIVE_CONFIG_NAME",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "NO_PROXY",
        "GCE_METADATA_HOST",
        "PYTHONHTTPSVERIFY",
        "SSL_CERT_FILE",
        "REQUESTS_CA_BUNDLE",
        "LD_PRELOAD",
    ):
        assert forbidden_key not in clean_env

    # Cloud Run ADC essentials remain intact in explicit ADC mode
    assert clean_env["K_SERVICE"] == "pqc-inventory-portal"
    assert clean_env["GOOGLE_CLOUD_PROJECT"] == "pqc-inventory-agent-cd06"
    assert clean_env["GOOGLE_APPLICATION_CREDENTIALS"] == str(adc_file)
    assert clean_env["CLOUDSDK_CORE_DISABLE_PROMPTS"] == "1"


# =============================================================================
# 4.4 Legitimate Read-Only Command Regression Tests
# =============================================================================
@pytest.mark.parametrize(
    "legit_cmd",
    [
        # Cloud KMS
        "gcloud kms keyrings list --location=global --project=pqc-inventory-agent-cd06 --format=json",
        "gcloud kms keyrings describe prod-keyring --location us-central1 --project pqc-inventory-agent-cd06",
        "gcloud kms keys list --location=global --keyring=prod-keyring --project=pqc-inventory-agent-cd06 --format=json",
        "gcloud kms keys describe payment-signing-key --location=global --keyring=prod-keyring --format=json",
        "gcloud kms keys get-iam-policy payment-signing-key --location=global --keyring=prod-keyring --format=json",
        "gcloud kms keys versions list --location=global --keyring=prod-keyring --key=payment-signing-key --filter=state=ENABLED",
        "gcloud kms keys versions describe 1 --location=global --keyring=prod-keyring --key=payment-signing-key",
        "gcloud kms keys versions get-public-key 1 --location=global --keyring=prod-keyring --key=payment-signing-key",
        "gcloud kms import-jobs list --location=us-central1 --keyring=byok-ring --format=json",
        "gcloud kms import-jobs describe job-01 --location=us-central1 --keyring=byok-ring",
        # Cloud Asset Inventory
        "gcloud asset search-all-resources --scope=organizations/31564119954 --asset-types=cloudkms.googleapis.com/CryptoKey --page-size=500 --format=json",
        "gcloud asset search-all-iam-policies --scope folders/534285347409 --query policy:cloudkms --limit 100 --format json",
        "gcloud asset list --organization=31564119954 --asset-types=compute.googleapis.com/SslPolicy --format=json",
        # Compute SSL Policies & Proxies
        "gcloud compute ssl-policies list --project=pqc-inventory-agent-cd06 --global --format=json",
        "gcloud compute ssl-policies describe modern-tls13-policy --project=pqc-inventory-agent-cd06 --global --format=json",
        "gcloud compute ssl-policies describe regional-policy --project=pqc-inventory-agent-cd06 --region=us-central1",
        "gcloud compute ssl-policies list-available-features --project=pqc-inventory-agent-cd06 --region=us-central1",
        "gcloud compute target-https-proxies list --project=pqc-inventory-agent-cd06 --global --format=json",
        "gcloud compute target-https-proxies describe edge-https-proxy --project=pqc-inventory-agent-cd06 --global",
        # Private CA (Certificate Authority Service)
        "gcloud privateca pools list --location=us-central1 --project=pqc-inventory-agent-cd06 --format=json",
        "gcloud privateca pools describe enterprise-ca-pool --location=us-central1 --project=pqc-inventory-agent-cd06",
        "gcloud privateca roots list --location=us-central1 --pool=enterprise-ca-pool --project=pqc-inventory-agent-cd06",
        "gcloud privateca subordinates list --location=us-central1 --pool=enterprise-ca-pool --format=json",
        "gcloud privateca certificates list --issuer-pool=enterprise-ca-pool --location=us-central1 --limit=50",
        # Resource hierarchy & workload correlation
        "gcloud projects get-iam-policy pqc-inventory-agent-cd06 --format=json",
        "gcloud folders list --organization=31564119954 --format=json",
        "gcloud run services describe checkout-api --region=us-central1 --project=pqc-inventory-agent-cd06 --format=json",
        "gcloud container clusters describe prod-gke --location=us-central1 --project=pqc-inventory-agent-cd06 --format=json",
        "gcloud storage buckets list --project=pqc-inventory-agent-cd06 --format=json",
        "gcloud iam service-accounts describe workload-sa@pqc-inventory-agent-cd06.iam.gserviceaccount.com --project=pqc-inventory-agent-cd06",
        "gcloud version",
        "gcloud --version --quiet",
    ],
)
def test_p3_01_legitimate_pqc_read_only_commands_pass_validation(legit_cmd: str) -> None:
    is_valid, canonical_tokens, msg = gcloud_bridge.validate_gcloud_command(legit_cmd)
    assert is_valid is True, f"Legitimate command unexpectedly blocked ({msg}): {legit_cmd}"
    assert len(canonical_tokens) >= 1


# =============================================================================
# 4.5 Confused-Deputy & Tenant Credential Boundary Tests
# =============================================================================
def test_p3_01_confused_deputy_delegated_token_never_falls_back_to_adc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = _create_portal_app(tmp_path, monkeypatch)
    monkeypatch.setattr(gcloud_bridge, "_resolve_gcloud_binary", lambda: "/usr/bin/gcloud")

    invocations: List[Tuple[List[str], Dict[str, str]]] = []
    next_returncode = 0
    next_stderr = ""
    next_stdout = '[{"name":"key-1"}]'

    def _mock_subprocess_run(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        invocations.append((list(cmd), dict(kwargs["env"])))
        return subprocess.CompletedProcess(cmd, next_returncode, stdout=next_stdout, stderr=next_stderr)

    monkeypatch.setattr(gcloud_bridge.subprocess, "run", _mock_subprocess_run)

    with TestClient(app) as client:
        # Sign in tenant user Alice
        monkeypatch.setattr(
            ws,
            "_verify_google_oauth_or_id_token",
            lambda id_token_jwt=None, google_access_token=None, expected_nonce=None: (
                {
                    "email": "alice@google.com",
                    "email_verified": True,
                    "name": "Alice Security",
                    "picture": "",
                    "hd": "google.com",
                    "auth_method": "google_access_token",
                    "expires_in": 3600,
                },
                None,
            ),
        )
        login_res = client.post("/api/auth/google", json={"google_access_token": "valid:alice@google.com"})
        assert login_res.status_code == 200
        csrf = login_res.json()["csrf_token"]
        headers = {"X-PQC-CSRF-Token": csrf, "Origin": "http://testserver"}

        user_delegated_token = "ya29.alice-delegated-3lo-token-secret-xyz987"
        conn_update = client.post(
            "/api/connection",
            headers=headers,
            json={
                "mode": "access_token",
                "organization_id": "31564119954",
                "project_id": "pqc-inventory-agent-cd06",
                "access_token": user_delegated_token,
            },
        )
        assert conn_update.status_code == 200
        assert conn_update.json()["mode"] == "access_token"

        # Case 1: User token succeeds -> exact invocation count 1, uses CLOUDSDK_AUTH_ACCESS_TOKEN, no ADC
        invocations.clear()
        next_returncode = 0
        next_stderr = ""
        ok_resp = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud kms keys list --location=global --format=json"},
        )
        assert ok_resp.status_code == 200
        ok_body = ok_resp.json()
        assert ok_body["status"] == "SUCCESS"
        assert ok_body["connection_mode"] == "access_token"
        assert len(invocations) == 1
        assert invocations[0][1].get("CLOUDSDK_AUTH_ACCESS_TOKEN") == user_delegated_token
        assert "GOOGLE_APPLICATION_CREDENTIALS" not in invocations[0][1]

        # Case 2: User token returns PERMISSION_DENIED (even on org 31564119954!) -> exact invocation count 1, ZERO ADC retry!
        invocations.clear()
        next_returncode = 1
        next_stdout = ""
        next_stderr = (
            "ERROR: (gcloud.asset.search-all-resources) PERMISSION_DENIED: "
            "Caller does not have required permission on organizations/31564119954."
        )
        denied_resp = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud asset search-all-resources --scope=organizations/31564119954 --format=json"},
        )
        assert denied_resp.status_code == 200
        denied_body = denied_resp.json()
        assert denied_body["status"] == "COMMAND_ERROR"
        assert denied_body["connection_mode"] == "access_token"
        assert denied_body["exit_code"] == 1
        assert "PERMISSION_DENIED" in denied_body["stderr"]
        assert user_delegated_token not in json.dumps(denied_body)
        assert len(invocations) == 1  # Strictly 1 invocation; ZERO server ADC fallback retries!
        assert invocations[0][1].get("CLOUDSDK_AUTH_ACCESS_TOKEN") == user_delegated_token

        # Case 3: User token expires in EncryptedDatabaseCredentialService -> exact invocation count 0, ZERO ADC fallback!
        app.state.credential_service.store_delegated_token(
            user_id="alice@google.com",
            access_token="ya29.short-lived-expiring-token-112233",
            expires_in=1.0,
            caller_user_id="alice@google.com",
        )
        # Advance stored credential expiry into the past deterministically
        cred_id = credential_service.build_credential_id(
            credential_service.DEFAULT_APP_NAME,
            "google.com",
            "alice@google.com",
            credential_service.DEFAULT_GCP_CREDENTIAL_KEY,
        )
        with app.state.auth_store._session_factory() as db:
            row = db.get(auth_store.DelegatedCredentialRecord, cred_id)
            assert row is not None
            row.expires_at = time.time() - 30.0
            db.commit()

        invocations.clear()
        expired_resp = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud kms keys list --location=global"},
        )
        assert expired_resp.status_code == 200
        expired_body = expired_resp.json()
        assert expired_body["status"] == "COMMAND_ERROR"
        assert expired_body["error_code"] == "ACCESS_TOKEN_REQUIRED"
        assert expired_body["connection_mode"] == "access_token"
        assert len(invocations) == 0  # ZERO subprocess calls when delegated token has expired!

        # Also verify get_active_gcp_credentials fails closed when mode == 'access_token' and token expired
        gcloud_bridge.set_current_tenant_user("alice@google.com")
        with pytest.raises(PermissionError, match="ACCESS_TOKEN_REQUIRED"):
            gcloud_bridge.get_active_gcp_credentials(user_id="alice@google.com")

        # Case 4: Untrusted caller cannot override credential mode via /api/gcloud payload or CLI flags
        invocations.clear()
        override_payload_resp = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud version", "mode": "adc"},
        )
        assert override_payload_resp.status_code == 422
        assert len(invocations) == 0

        flag_override_resp = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud kms keys list --location=global --account=server-sa@proj.iam.gserviceaccount.com"},
        )
        assert flag_override_resp.json()["status"] == "BLOCKED_DESTRUCTIVE_OR_INVALID_COMMAND"
        assert len(invocations) == 0

        # Invalid mode in /api/connection raises 400 instead of silently resetting to 'adc'
        bad_mode_resp = client.post(
            "/api/connection",
            headers=headers,
            json={"mode": "unexpected_untrusted_mode"},
        )
        assert bad_mode_resp.status_code == 400
        assert client.get("/api/connection").json()["mode"] == "access_token"

        # Unapproved service account impersonation remains blocked by allowlist
        monkeypatch.setenv(
            "PQC_ALLOWED_IMPERSONATION_SERVICE_ACCOUNTS",
            "approved-reader@pqc-inventory-agent-cd06.iam.gserviceaccount.com",
        )
        unapproved_imp = client.post(
            "/api/connection",
            headers=headers,
            json={
                "mode": "impersonation",
                "impersonated_service_account": "attacker@evil-proj.iam.gserviceaccount.com",
            },
        )
        assert unapproved_imp.status_code == 403

        # Case 5: Non-admin ADC selection is denied (403); explicit trusted admin ADC selection works within scope
        unauth_adc_switch = client.post("/api/connection", headers=headers, json={"mode": "adc"})
        assert unauth_adc_switch.status_code == 403
        monkeypatch.setenv("PQC_ADMIN_EMAILS", "alice@google.com")
        adc_switch = client.post("/api/connection", headers=headers, json={"mode": "adc"})
        assert adc_switch.status_code == 200
        assert adc_switch.json()["mode"] == "adc"

        invocations.clear()
        next_returncode = 0
        next_stdout = '[{"name":"adc-key"}]'
        next_stderr = ""
        adc_exec = client.post(
            "/api/gcloud",
            headers=headers,
            json={"command": "gcloud kms keys list --location=global --format=json"},
        )
        assert adc_exec.status_code == 200
        adc_body = adc_exec.json()
        assert adc_body["status"] == "SUCCESS"
        assert adc_body["connection_mode"] == "adc"
        assert len(invocations) == 1
        assert "CLOUDSDK_AUTH_ACCESS_TOKEN" not in invocations[0][1]

    app.state.auth_store.close()


def test_p3_01_integration_oauth_exchange_google_signin_and_refresh_via_safe_urlopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercises `/api/auth/google`, `/api/auth/oauth/callback` (PKCE + nonce), and refresh rotation via `safe_urlopen`."""
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_ID", "p3-01-client.apps.googleusercontent.com")
    monkeypatch.setenv("PQC_GOOGLE_OAUTH_CLIENT_SECRET", "GOCSPX-p3-01-secret")
    app = _create_portal_app(tmp_path, monkeypatch)

    observed_safe_calls: List[Tuple[str, float, int]] = []
    expected_nonce_box: Dict[str, str] = {"nonce": ""}

    real_safe_urlopen = egress_guard.safe_urlopen

    def _routed_safe_urlopen(request_or_url: Any, *, timeout: Optional[float] = None, **kwargs: Any) -> Any:
        url = request_or_url.full_url if hasattr(request_or_url, "full_url") else str(request_or_url)
        observed_safe_calls.append((egress_guard.redact_url_for_log(url), float(timeout or 0), int(kwargs.get("max_bytes", 0))))

        def _dispatch(req: urllib.request.Request, _t: float) -> _MockRawResponse:
            full = req.full_url
            if full == "https://oauth2.googleapis.com/token":
                body_qs = urllib.parse.parse_qs((req.data or b"").decode("utf-8"))
                grant = (body_qs.get("grant_type") or [""])[0]
                if grant == "refresh_token":
                    payload = {"access_token": "ya29.rotated-via-safe-urlopen", "expires_in": 3600}
                else:
                    payload = {
                        "access_token": "ya29.exchanged-via-safe-urlopen",
                        "refresh_token": "1//refresh-via-safe-urlopen",
                        "id_token": "synthetic-id-token-segment",
                        "expires_in": 3600,
                    }
                raw = json.dumps(payload).encode("utf-8")
                return _MockRawResponse(raw, status=200, headers=[("Content-Length", str(len(raw)))])
            if full.startswith("https://oauth2.googleapis.com/tokeninfo?id_token="):
                raw = json.dumps(
                    {
                        "iss": "https://accounts.google.com",
                        "aud": "p3-01-client.apps.googleusercontent.com",
                        "email": "bob@google.com",
                        "email_verified": "true",
                        "exp": str(int(time.time()) + 600),
                        "nonce": expected_nonce_box["nonce"],
                    }
                ).encode("utf-8")
                return _MockRawResponse(raw, status=200, headers=[("Content-Length", str(len(raw)))])
            if full.startswith("https://oauth2.googleapis.com/tokeninfo?access_token="):
                raw = json.dumps(
                    {"email": "bob@google.com", "email_verified": "true", "expires_in": "3600"}
                ).encode("utf-8")
                return _MockRawResponse(raw, status=200, headers=[("Content-Length", str(len(raw)))])
            if full == "https://www.googleapis.com/oauth2/v3/userinfo":
                raw = json.dumps(
                    {"email": "bob@google.com", "name": "Bob PQC", "picture": "https://lh3.googleusercontent.com/a/bob"}
                ).encode("utf-8")
                return _MockRawResponse(raw, status=200, headers=[("Content-Length", str(len(raw)))])
            raise AssertionError(f"Unexpected URL in safe_urlopen integration test: {full}")

        return real_safe_urlopen(
            request_or_url,
            timeout=timeout,
            dns_resolver=_public_google_dns,
            opener=_SingleHopOpener(_dispatch),
            **kwargs,
        )

    monkeypatch.setattr(egress_guard, "safe_urlopen", _routed_safe_urlopen)

    with TestClient(app) as client:
        # 1. Google access token sign-in + userinfo enrichment
        signin_res = client.post("/api/auth/google", json={"google_access_token": "ya29.bob-login"})
        assert signin_res.status_code == 200
        assert signin_res.json()["user"]["name"] == "Bob PQC"

        # 2. OAuth Authorization Code + PKCE + OIDC nonce flow
        start = client.get("/api/auth/oauth/signin", follow_redirects=False)
        assert start.status_code == 302
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(start.headers["location"]).query)
        expected_nonce_box["nonce"] = qs["nonce"][0]
        cb = client.get("/api/auth/oauth/callback", params={"code": "pkce-code-123", "state": qs["state"][0]})
        assert cb.status_code == 200

        # 3. Refresh-token rotation through credential_service._default_oauth_refresh_exchange -> safe_urlopen
        svc = app.state.credential_service
        svc.store_delegated_token(
            user_id="bob@google.com",
            access_token="ya29.initial-short",
            refresh_token="1//bob-refresh-token",
            expires_in=10.0,
            client_id="p3-01-client.apps.googleusercontent.com",
            client_secret="GOCSPX-p3-01-secret",
            caller_user_id="bob@google.com",
        )
        rotated = svc.load_delegated_token(
            user_id="bob@google.com",
            caller_user_id="bob@google.com",
            now_override=time.time() + 120.0,
        )
        assert rotated is not None
        assert rotated.access_token == "ya29.rotated-via-safe-urlopen"

    called_urls = [u for u, _t, _b in observed_safe_calls]
    assert "https://oauth2.googleapis.com/tokeninfo" in called_urls
    assert "https://www.googleapis.com/oauth2/v3/userinfo" in called_urls
    assert "https://oauth2.googleapis.com/token" in called_urls
    assert all(t > 0 and b == egress_guard.DEFAULT_MAX_RESPONSE_BYTES for _u, t, b in observed_safe_calls)
    app.state.auth_store.close()
