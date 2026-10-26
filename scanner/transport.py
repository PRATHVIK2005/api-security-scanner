"""Peer-checked, bounded HTTPX transport for scanner requests.

Each request resolves its hostname, validates every result, and opens a socket to
one of those exact sockaddr values. Proxies and redirects are disabled by the
client factory, so DNS changes between validation and connect cannot retarget a
request. A fresh socket is used for every request; there is no connection pool.
"""

from __future__ import annotations

import concurrent.futures
import http.client
import ipaddress
import os
import socket
import ssl
import time
import threading
from dataclasses import dataclass

import httpx

from scanner.validation import InvalidURLError, validate_target_url

_DNS_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="scanner-dns")
_DNS_CAPACITY = threading.BoundedSemaphore(8)  # four running calls and at most four queued calls
_IO_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="scanner-http")
_IO_CAPACITY = threading.BoundedSemaphore(8)  # bounded callers, active requests, and queue
_ALWAYS_BLOCKED = {
    ipaddress.ip_address("169.254.169.254"),  # common cloud metadata IPv4
    ipaddress.ip_address("100.100.100.200"),  # Alibaba metadata IPv4
    ipaddress.ip_address("fd00:ec2::254"),  # AWS IPv6 metadata
}
_MAX_DNS_ANSWERS = 64


class TargetScopeError(httpx.RequestError):
    """The requested URL or its resolved/connected address is outside scope."""


class ScannerResourceError(httpx.RequestError):
    """A scanner request exceeded a configured time or byte limit."""


@dataclass(frozen=True)
class TransportLimits:
    connect_seconds: float = 3.0
    read_seconds: float = 5.0
    total_seconds: float = 12.0
    dns_seconds: float = 2.0
    response_bytes: int = 1_000_000
    request_bytes: int = 64_000

    @classmethod
    def from_environment(cls) -> "TransportLimits":
        def number(name: str, default: float, maximum: float) -> float:
            try:
                value = float(os.getenv(name, str(default)))
            except ValueError as exc:
                raise ValueError(f"{name} must be numeric") from exc
            if value <= 0 or value > maximum:
                raise ValueError(f"{name} must be between 0 and {maximum}")
            return value

        def integer(name: str, default: int, maximum: int) -> int:
            try:
                value = int(os.getenv(name, str(default)))
            except ValueError as exc:
                raise ValueError(f"{name} must be an integer") from exc
            if value <= 0 or value > maximum:
                raise ValueError(f"{name} must be between 1 and {maximum}")
            return value

        return cls(
            connect_seconds=number("API_SCANNER_CONNECT_TIMEOUT", 3.0, 20.0),
            read_seconds=number("API_SCANNER_READ_TIMEOUT", 5.0, 30.0),
            total_seconds=number("API_SCANNER_TOTAL_REQUEST_TIMEOUT", 12.0, 60.0),
            dns_seconds=number("API_SCANNER_DNS_TIMEOUT", 2.0, 10.0),
            response_bytes=integer("API_SCANNER_MAX_RESPONSE_BYTES", 1_000_000, 10_000_000),
            request_bytes=integer("API_SCANNER_MAX_REQUEST_BYTES", 64_000, 1_000_000),
        )


def _normalized_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    address = ipaddress.ip_address(value.split("%", 1)[0])
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


def _allowed_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    raw = os.getenv("API_SCANNER_ALLOWED_CIDRS", "")
    networks = []
    for entry in filter(None, (item.strip() for item in raw.split(","))):
        try:
            network = ipaddress.ip_network(entry, strict=True)
        except ValueError as exc:
            raise TargetScopeError(f"Invalid API_SCANNER_ALLOWED_CIDRS entry: {entry}", request=None) from exc
        minimum_prefix = 24 if network.version == 4 else 120
        if network.prefixlen < minimum_prefix:
            raise TargetScopeError(
                f"Allowed CIDR {entry} is too broad; use /{minimum_prefix} or a narrower network.", request=None
            )
        networks.append(network)
    return networks


def _is_allowed(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    if address in _ALWAYS_BLOCKED or address.is_multicast or address.is_unspecified or address.is_reserved:
        return False
    if address.is_global:
        return True
    return any(address.version == network.version and address in network for network in networks)


def _resolve(host: str, port: int, deadline: float, limits: TransportLimits, request: httpx.Request):
    remaining = min(limits.dns_seconds, deadline - time.monotonic())
    if remaining <= 0:
        raise ScannerResourceError("DNS resolution exceeded its time limit", request=request)
    if not _DNS_CAPACITY.acquire(timeout=remaining):
        raise ScannerResourceError("DNS resolver capacity is exhausted", request=request)
    if time.monotonic() >= deadline:
        _DNS_CAPACITY.release()
        raise ScannerResourceError("DNS resolution exceeded its time limit", request=request)
    try:
        future = _DNS_POOL.submit(socket.getaddrinfo, host, port, 0, socket.SOCK_STREAM)
    except RuntimeError as exc:
        _DNS_CAPACITY.release()
        raise ScannerResourceError("DNS resolver is unavailable", request=request) from exc
    # A timed-out OS resolver cannot always be cancelled. Retain its bounded slot
    # until the worker actually finishes, preventing abandoned-work accumulation.
    future.add_done_callback(lambda _future: _DNS_CAPACITY.release())
    try:
        records = future.result(timeout=min(limits.dns_seconds, max(0.001, deadline - time.monotonic())))
    except concurrent.futures.TimeoutError as exc:
        raise ScannerResourceError("DNS resolution exceeded its time limit", request=request) from exc
    except OSError as exc:
        raise TargetScopeError("DNS resolution failed", request=request) from exc
    try:
        record_count = len(records)
    except TypeError as exc:
        raise TargetScopeError("DNS returned malformed address records", request=request) from exc
    if record_count > _MAX_DNS_ANSWERS:
        raise ScannerResourceError("DNS returned more addresses than the configured safety limit", request=request)
    networks = _allowed_networks()
    answers = []
    unique = set()
    for record in records:
        try:
            family, socktype, proto, _canonname, sockaddr = record
        except (TypeError, ValueError) as exc:
            raise TargetScopeError("DNS returned malformed address records", request=request) from exc
        try:
            address = _normalized_ip(sockaddr[0])
        except ValueError as exc:
            raise TargetScopeError("DNS returned an invalid address", request=request) from exc
        if not _is_allowed(address, networks):
            raise TargetScopeError("Target resolves to a blocked or non-allowlisted address", request=request)
        key = (family, address, sockaddr)
        if key not in unique:
            unique.add(key)
            answers.append((family, socktype, proto, sockaddr, address))
    if not answers:
        raise TargetScopeError("DNS returned no usable addresses", request=request)
    return answers


class PeerCheckedTransport(httpx.BaseTransport):
    """HTTP transport which pins each socket to the validated DNS snapshot."""

    def __init__(self, limits: TransportLimits | None = None, scan_deadline: float | None = None):
        self.limits = limits or TransportLimits.from_environment()
        self.scan_deadline = scan_deadline
        try:
            self.max_requests = int(os.getenv("API_SCANNER_MAX_REQUESTS_PER_SCAN", "5000"))
        except ValueError as exc:
            raise ValueError("API_SCANNER_MAX_REQUESTS_PER_SCAN must be an integer") from exc
        if not 1 <= self.max_requests <= 10_000:
            raise ValueError("API_SCANNER_MAX_REQUESTS_PER_SCAN must be between 1 and 10000")
        self.request_count = 0
        self.failures: list[str] = []
        self._request_lock = threading.Lock()
        self._active_sockets: dict[int, socket.socket] = {}

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        remaining_scan = self.scan_deadline - time.monotonic() if self.scan_deadline is not None else None
        if remaining_scan is not None and remaining_scan <= 0:
            with self._request_lock:
                self.failures.append(ScannerResourceError.__name__)
            raise ScannerResourceError("Total scan time limit reached", request=request)
        with self._request_lock:
            if self.request_count >= self.max_requests:
                self.failures.append(ScannerResourceError.__name__)
                raise ScannerResourceError("Scan request-count limit reached", request=request)
            self.request_count += 1
        request_timeout = (
            min(self.limits.total_seconds, remaining_scan) if remaining_scan is not None else self.limits.total_seconds
        )
        request_deadline = time.monotonic() + request_timeout
        if not _IO_CAPACITY.acquire(timeout=max(0, request_deadline - time.monotonic())):
            error = ScannerResourceError("HTTP worker capacity is exhausted", request=request)
            with self._request_lock:
                self.failures.append(type(error).__name__)
            raise error
        if time.monotonic() >= request_deadline:
            _IO_CAPACITY.release()
            raise ScannerResourceError("Total request time limit reached", request=request)
        try:
            future = _IO_POOL.submit(self._perform_request, request, request_deadline)
        except RuntimeError as exc:
            _IO_CAPACITY.release()
            raise ScannerResourceError("HTTP worker pool is unavailable", request=request) from exc
        future.add_done_callback(lambda _future: _IO_CAPACITY.release())
        try:
            return future.result(timeout=max(0, request_deadline - time.monotonic()))
        except concurrent.futures.TimeoutError as exc:
            with self._request_lock:
                active_socket = self._active_sockets.pop(id(request), None)
            if active_socket is not None:
                try:
                    active_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                active_socket.close()
            future.cancel()
            error = ScannerResourceError("Total request time limit reached", request=request)
            with self._request_lock:
                self.failures.append(type(error).__name__)
            raise error from exc
        except httpx.RequestError as exc:
            with self._request_lock:
                self.failures.append(type(exc).__name__)
            raise
        finally:
            with self._request_lock:
                self._active_sockets.pop(id(request), None)

    def _perform_request(self, request: httpx.Request, deadline: float) -> httpx.Response:
        if time.monotonic() >= deadline:
            raise ScannerResourceError("Total request time limit reached", request=request)
        url = str(request.url)
        try:
            validate_target_url(url)
        except InvalidURLError as exc:
            raise TargetScopeError("Invalid target URL", request=request) from exc
        host = request.url.host
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        if self.scan_deadline is not None:
            deadline = min(deadline, self.scan_deadline)
        answers = _resolve(host, port, deadline, self.limits, request)
        connection = None
        connected_socket = None
        response = None
        last_error = None
        for family, socktype, proto, sockaddr, approved_ip in answers:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ScannerResourceError("Connection exceeded total request time", request=request)
            sock = socket.socket(family, socktype, proto)
            with self._request_lock:
                self._active_sockets[id(request)] = sock
            try:
                sock.settimeout(min(self.limits.connect_seconds, remaining))
                sock.connect(sockaddr)
                if time.monotonic() >= deadline:
                    raise ScannerResourceError("Connection exceeded total request time", request=request)
                peer_ip = _normalized_ip(sock.getpeername()[0])
                if peer_ip != approved_ip or not _is_allowed(peer_ip, _allowed_networks()):
                    raise TargetScopeError("Connected peer differs from the validated target address", request=request)
                if request.url.scheme == "https":
                    tls_context = ssl.create_default_context()
                    sock = tls_context.wrap_socket(sock, server_hostname=host)
                    with self._request_lock:
                        self._active_sockets[id(request)] = sock
                    if time.monotonic() >= deadline:
                        raise ScannerResourceError("TLS connection exceeded total request time", request=request)
                    peer_ip = _normalized_ip(sock.getpeername()[0])
                    if peer_ip != approved_ip:
                        raise TargetScopeError("TLS peer differs from the validated target address", request=request)
                connection = http.client.HTTPConnection(host, port, timeout=min(self.limits.connect_seconds, remaining))
                connection.sock = sock
                connected_socket = sock
                with self._request_lock:
                    self._active_sockets[id(request)] = sock
                break
            except (TargetScopeError, ScannerResourceError):
                sock.close()
                raise
            except OSError as exc:
                sock.close()
                last_error = exc
        if connection is None:
            raise httpx.ConnectError(
                "Unable to connect to any validated target address", request=request
            ) from last_error

        try:
            body = bytearray()
            for chunk in request.stream:
                body.extend(chunk)
                if len(body) > self.limits.request_bytes:
                    raise ScannerResourceError("Request body exceeded configured size limit", request=request)
            target = request.url.raw_path.decode("ascii")
            connection.putrequest(request.method, target, skip_accept_encoding=True)
            connection.putheader("Connection", "close")
            connection.putheader("Accept-Encoding", "identity")
            skip = {"host", "connection", "content-length", "transfer-encoding", "accept-encoding"}
            for name, value in request.headers.multi_items():
                if name.lower() not in skip:
                    connection.putheader(name, value)
            if body:
                connection.putheader("Content-Length", str(len(body)))
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ScannerResourceError("Request exceeded total request time", request=request)
            connected_socket.settimeout(min(self.limits.read_seconds, remaining))
            connection.endheaders(bytes(body) if body else None)
            connected_socket.settimeout(min(self.limits.read_seconds, max(0.001, deadline - time.monotonic())))
            response = connection.getresponse()
            headers = httpx.Headers(response.getheaders())
            encoding = headers.get("content-encoding", "identity").lower()
            if encoding not in {"", "identity"}:
                raise ScannerResourceError("Compressed response bodies are not accepted", request=request)
            length = headers.get("content-length")
            if length and length.isdigit() and int(length) > self.limits.response_bytes:
                raise ScannerResourceError("Response body exceeded configured byte limit", request=request)
            content = bytearray()
            while True:
                if len(content) >= self.limits.response_bytes:
                    extra = response.read1(1)
                    if extra:
                        raise ScannerResourceError("Response body exceeded configured byte limit", request=request)
                    break
                chunk = response.read1(min(64 * 1024, self.limits.response_bytes - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
            return httpx.Response(
                status_code=response.status,
                headers=headers,
                content=bytes(content),
                request=request,
                extensions={"http_version": b"HTTP/1.1"},
            )
        except ScannerResourceError:
            raise
        except (OSError, http.client.HTTPException) as exc:
            raise httpx.RequestError("Target request failed or timed out", request=request) from exc
        finally:
            if response is not None:
                response.close()
            connection.close()
            if connected_socket is not None:
                connected_socket.close()

    def close(self) -> None:
        return None


def create_scanner_client(
    headers: dict[str, str] | None = None,
    scan_deadline: float | None = None,
) -> httpx.Client:
    limits = TransportLimits.from_environment()
    transport = PeerCheckedTransport(limits, scan_deadline=scan_deadline)
    client = httpx.Client(
        transport=transport,
        timeout=httpx.Timeout(limits.total_seconds),
        follow_redirects=False,
        trust_env=False,
        headers=headers,
    )
    client._scanner_transport = transport
    return client
