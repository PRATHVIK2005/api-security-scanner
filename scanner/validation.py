"""URL and input validation utilities for API Security Scanner."""

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

    try:
        parsed = urlparse(cleaned_url)
    except Exception as exc:
        raise InvalidURLError(f"Invalid URL structure: {exc}")

    if parsed.scheme.lower() not in ("http", "https"):
        raise InvalidURLError(
            "Invalid URL. Only http:// and https:// targets are supported."
        )

    if not parsed.netloc and not parsed.hostname:
        raise InvalidURLError(
            f"Invalid URL '{cleaned_url}'. Target must contain a valid host (e.g., http://127.0.0.1:8000 or https://api.example.com)."
        )

    return cleaned_url
