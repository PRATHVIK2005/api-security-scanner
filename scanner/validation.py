"""URL and input validation utilities for API Security Scanner."""

import ipaddress
import re
from urllib.parse import urlparse


class InvalidURLError(ValueError):
    """Raised when a target URL fails format or scheme validation."""

    pass


def validate_target_url(url: str | None) -> str:
    """
    Validate that the target URL has http or https scheme and a valid hostname.

    Accepts:
        - http://example.com
        - https://example.com
        - http://127.0.0.1:8000
        - http://localhost:8000
        - https://api.example.com/v1

    Rejects:
        - None / empty string
        - Invalid schemes (ftp://, file://, etc.)
        - Non-URLs (hello, not-a-url)
        - Missing hostnames (http://)
    """
    if not url or not isinstance(url, str) or not url.strip():
        raise InvalidURLError("Target URL cannot be empty.")

    cleaned_url = url.strip()

    if any(ord(char) < 32 for char in cleaned_url) or any(char.isspace() for char in cleaned_url):
        raise InvalidURLError("Target URL cannot contain whitespace or control characters.")

    try:
        parsed = urlparse(cleaned_url)
        hostname = parsed.hostname
        port = parsed.port  # Access validates numeric/range constraints.
    except Exception as exc:
        raise InvalidURLError("Invalid URL structure or port.") from exc

    if parsed.scheme.lower() not in ("http", "https"):
        raise InvalidURLError("Invalid URL. Only http:// and https:// targets are supported.")

    if not parsed.netloc or not hostname:
        raise InvalidURLError(
            f"Invalid URL '{cleaned_url}'. Target must contain a valid host (e.g., http://127.0.0.1:8000 or https://api.example.com)."
        )
    if parsed.netloc.endswith(":"):
        raise InvalidURLError("Target URL contains an invalid port.")

    if parsed.username is not None or parsed.password is not None:
        raise InvalidURLError("Target URLs must not contain embedded credentials.")

    # Reject host syntax that DNS clients interpret inconsistently.
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        if (
            ":" in hostname
            or len(hostname) > 253
            or any(
                not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in hostname.split(".")
            )
        ):
            raise InvalidURLError("Target URL contains an invalid hostname.")
    if hostname.startswith(".") or hostname.endswith(".") or ".." in hostname:
        raise InvalidURLError("Target URL contains an invalid hostname.")
    if port is not None and not 1 <= port <= 65535:
        raise InvalidURLError("Target URL port must be between 1 and 65535.")

    return cleaned_url.rstrip("/")
