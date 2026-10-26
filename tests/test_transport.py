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
    client_ports = []

    def do_GET(self):
        self.client_ports.append(self.client_address[1])
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


@pytest.mark.parametrize("address", ["fc00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::7f00:1"])
def test_ipv6_private_link_local_and_mapped_private_addresses_are_blocked(address):
    assert not _is_allowed(_normalized_ip(address), [])


def test_global_ipv6_destination_is_allowed():
    assert _is_allowed(_normalized_ip("2606:4700:4700::1111"), [])
    assert _is_allowed(_normalized_ip("::ffff:8.8.8.8"), [])


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


def test_malformed_resolver_records_fail_as_structured_scope_error(monkeypatch):
    with (
        patch("scanner.transport.socket.getaddrinfo", return_value=[("malformed",)]),
        httpx.Client(transport=PeerCheckedTransport()) as client,
    ):
        with pytest.raises(TargetScopeError, match="malformed"):
            client.get("http://malformed.example/")


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


def test_each_request_uses_a_new_connection(monkeypatch, local_http_server):
    monkeypatch.setenv("API_SCANNER_ALLOWED_CIDRS", "127.0.0.1/32")
    _Handler.client_ports.clear()
    from scanner.transport import create_scanner_client

    with create_scanner_client() as client:
        assert client.get(local_http_server).status_code == 200
        assert client.get(local_http_server).status_code == 200
    assert len(_Handler.client_ports) == 2
    assert _Handler.client_ports[0] != _Handler.client_ports[1]


def test_redirect_is_returned_without_following_private_location(monkeypatch):
    monkeypatch.setenv("API_SCANNER_ALLOWED_CIDRS", "127.0.0.1/32")
    requests_seen = []

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests_seen.append(self.path)
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/private")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    from scanner.transport import create_scanner_client

    try:
        with create_scanner_client() as client:
            response = client.get(f"http://127.0.0.1:{server.server_port}/redirect")
        assert response.status_code == 302
        assert requests_seen == ["/redirect"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


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


def test_hanging_resolver_has_deadline_and_keeps_capacity_bounded(monkeypatch):
    import threading
    from scanner.transport import _DNS_CAPACITY, _resolve

    release = threading.Event()
    monkeypatch.setattr("scanner.transport.socket.getaddrinfo", lambda *_args: (release.wait(2), [])[1])
    limits = TransportLimits(dns_seconds=0.03, total_seconds=0.1)
    request = httpx.Request("GET", "https://stalled.example/")
    start = time.monotonic()
    with pytest.raises(ScannerResourceError, match="DNS resolution"):
        _resolve("stalled.example", 443, start + 0.1, limits, request)
    # Work remains occupied until the OS call returns; timeout cannot free slots
    # and permit unbounded abandoned requests.
    assert _DNS_CAPACITY._value <= 7
    release.set()


def test_resolver_capacity_exhaustion_fails_without_submission(monkeypatch):
    from scanner.transport import _resolve

    class NoCapacity:
        def acquire(self, timeout=None):
            return False

    monkeypatch.setattr("scanner.transport._DNS_CAPACITY", NoCapacity())
    with pytest.raises(ScannerResourceError, match="capacity"):
        _resolve(
            "stalled.example",
            443,
            time.monotonic() + 1,
            TransportLimits(dns_seconds=0.01),
            httpx.Request("GET", "https://stalled.example/"),
        )


def test_repeated_resolver_timeouts_remain_bounded_and_release_on_completion(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from scanner.transport import _resolve

    pool = ThreadPoolExecutor(max_workers=1)
    capacity = threading.BoundedSemaphore(2)
    release = threading.Event()
    started = threading.Event()

    def hanging_resolver(*_args):
        started.set()
        release.wait(1)
        return []

    monkeypatch.setattr("scanner.transport._DNS_POOL", pool)
    monkeypatch.setattr("scanner.transport._DNS_CAPACITY", capacity)
    monkeypatch.setattr("scanner.transport.socket.getaddrinfo", hanging_resolver)
    limits = TransportLimits(dns_seconds=0.01, total_seconds=0.05)
    try:
        for _ in range(2):
            with pytest.raises(ScannerResourceError):
                _resolve(
                    "stalled.example",
                    443,
                    time.monotonic() + 0.05,
                    limits,
                    httpx.Request("GET", "https://stalled.example/"),
                )
        assert started.is_set()
        assert capacity._value == 0
        with pytest.raises(ScannerResourceError, match="capacity"):
            _resolve(
                "stalled.example",
                443,
                time.monotonic() + 0.05,
                limits,
                httpx.Request("GET", "https://stalled.example/"),
            )
        release.set()
        deadline = time.monotonic() + 1
        while capacity._value != 2 and time.monotonic() < deadline:
            time.sleep(0.005)
        assert capacity._value == 2
    finally:
        release.set()
        pool.shutdown(wait=True)


def test_expired_worker_deadline_cannot_start_dns_resolution():
    transport = PeerCheckedTransport()
    request = httpx.Request("GET", "https://changed.example/")
    with patch("scanner.transport._resolve") as resolve:
        with pytest.raises(ScannerResourceError, match="request time limit"):
            transport._perform_request(request, time.monotonic() - 1)
    resolve.assert_not_called()
