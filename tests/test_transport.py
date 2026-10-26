import http.server
import ipaddress
import socket
import threading
import time
from unittest.mock import patch

import httpx
import pytest

from scanner.transport import (
    PeerCheckedTransport,
    ScannerResourceError,
    TargetScopeError,
    TransportLimits,
    _is_allowed,
    _normalized_ip,
)


class _Handler(http.server.BaseHTTPRequestHandler):
    body = b"ok"
    delay = 0.0

    def do_GET(self):
        if self.delay:
            time.sleep(self.delay)
        self.send_response(200)
        self.send_header("Content-Length", str(len(self.body)))
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, *_args):
        pass


@pytest.fixture
def local_http_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


def test_explicit_narrow_loopback_cidr_allows_local_demo(monkeypatch, local_http_server):
    monkeypatch.setenv("API_SCANNER_ALLOWED_CIDRS", "127.0.0.1/32")
    with httpx.Client(transport=PeerCheckedTransport()) as client:
        response = client.get(local_http_server)
    assert response.text == "ok"


@pytest.mark.parametrize(
    "address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "224.0.0.1", "0.0.0.0", "::1", "::ffff:127.0.0.1"]
)
def test_non_global_destinations_are_blocked_without_explicit_scope(address):
    ip = _normalized_ip(address)
    assert not _is_allowed(ip, [])


def test_wide_private_cidr_configuration_is_rejected(monkeypatch):
    monkeypatch.setenv("API_SCANNER_ALLOWED_CIDRS", "10.0.0.0/8")
    with pytest.raises(TargetScopeError, match="too broad"):
        from scanner.transport import _allowed_networks

        _allowed_networks()


def test_mixed_public_and_private_dns_answers_fail_closed(monkeypatch):
    monkeypatch.delenv("API_SCANNER_ALLOWED_CIDRS", raising=False)
    rows = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80)),
    ]
    with patch("scanner.transport.socket.getaddrinfo", return_value=rows):
        with httpx.Client(transport=PeerCheckedTransport()) as client:
            with pytest.raises(TargetScopeError, match="blocked"):
                client.get("http://mixed.example/")


def test_alternate_integer_ip_that_resolves_to_loopback_is_blocked(monkeypatch):
    monkeypatch.delenv("API_SCANNER_ALLOWED_CIDRS", raising=False)
    rows = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))]
    with patch("scanner.transport.socket.getaddrinfo", return_value=rows):
        with httpx.Client(transport=PeerCheckedTransport()) as client:
            with pytest.raises(TargetScopeError):
                client.get("http://2130706433/")


def test_oversized_response_is_stopped_at_stream_limit(monkeypatch, local_http_server):
    monkeypatch.setenv("API_SCANNER_ALLOWED_CIDRS", "127.0.0.1/32")
    _Handler.body = b"0123456789abcdef"
    limits = TransportLimits(response_bytes=8, total_seconds=2, read_seconds=1, connect_seconds=1)
    with httpx.Client(transport=PeerCheckedTransport(limits)) as client:
        with pytest.raises(ScannerResourceError, match="byte limit"):
            client.get(local_http_server)
    _Handler.body = b"ok"


def test_slow_response_obeys_read_and_total_timeout(monkeypatch, local_http_server):
    monkeypatch.setenv("API_SCANNER_ALLOWED_CIDRS", "127.0.0.1/32")
    _Handler.delay = 0.2
    limits = TransportLimits(connect_seconds=0.5, read_seconds=0.05, total_seconds=0.1)
    try:
        with httpx.Client(transport=PeerCheckedTransport(limits)) as client:
            with pytest.raises(httpx.RequestError):
                client.get(local_http_server)
    finally:
        _Handler.delay = 0


def test_connected_peer_must_match_validated_dns_snapshot(monkeypatch):
    monkeypatch.delenv("API_SCANNER_ALLOWED_CIDRS", raising=False)
    records = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))]

    class FakeSocket:
        def __init__(self, *_args):
            pass

        def settimeout(self, _timeout):
            pass

        def connect(self, _sockaddr):
            pass

        def getpeername(self):
            return ("1.1.1.1", 80)

        def close(self):
            pass

    with (
        patch("scanner.transport.socket.getaddrinfo", return_value=records),
        patch("scanner.transport.socket.socket", FakeSocket),
    ):
        with httpx.Client(transport=PeerCheckedTransport()) as client:
            with pytest.raises(TargetScopeError, match="peer differs"):
                client.get("http://public.example/")


def test_new_request_revalidates_changed_dns_answer(monkeypatch, local_http_server):
    monkeypatch.setenv("API_SCANNER_ALLOWED_CIDRS", "127.0.0.1/32")
    port = int(local_http_server.rsplit(":", 1)[1])
    loopback = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
    private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.9", port))]
    with (
        patch("scanner.transport.socket.getaddrinfo", side_effect=[loopback, private]) as resolve,
        httpx.Client(transport=PeerCheckedTransport()) as client,
    ):
        assert client.get(local_http_server).status_code == 200
        with pytest.raises(TargetScopeError, match="blocked"):
            client.get(local_http_server)
    assert resolve.call_count == 2


def test_scanner_client_attaches_the_transport_instance_used_for_accounting():
    from scanner.transport import create_scanner_client

    client = create_scanner_client()
    assert client._transport is client._scanner_transport
    client.close()


def test_expired_total_scan_deadline_blocks_even_the_first_request():
    transport = PeerCheckedTransport(scan_deadline=time.monotonic() - 1)
    request = httpx.Request("GET", "https://example.com/")
    with pytest.raises(ScannerResourceError, match="scan time limit"):
        transport.handle_request(request)


def test_request_count_limit_is_enforced_per_scanner_client(monkeypatch, local_http_server):
    from scanner.transport import create_scanner_client

    monkeypatch.setenv("API_SCANNER_ALLOWED_CIDRS", "127.0.0.1/32")
    client = create_scanner_client()
    client._scanner_transport.max_requests = 1
    with client:
        assert client.get(local_http_server).status_code == 200
        with pytest.raises(ScannerResourceError, match="request-count limit"):
            client.get(local_http_server)
    assert "ScannerResourceError" in client._scanner_transport.failures
