"""Small, conservative redaction helpers for secrets in scanner evidence and URLs."""

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SENSITIVE_NAME = re.compile(
    r"(?:authorization|cookie|session|token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key)", re.I
)
BEARER = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/-]+=*")
NAMED_SECRET = re.compile(
    r"(?i)(\b(?:authorization|cookie|session[\w-]*|access[_-]?token|refresh[_-]?token|token|secret|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key)\b\s*[:=]\s*)(['\"]?)[^\s,;\"']+\2"
)
PEM = re.compile(r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----", re.S)
COOKIE_HEADER = re.compile(r"(?i)\b(cookie|set-cookie)\s*:\s*[^\r\n]+")


def redact_text(value: str | None) -> str | None:
    if value is None:
        return None
    safe = PEM.sub("[REDACTED PRIVATE KEY]", value)
    safe = COOKIE_HEADER.sub(r"\1: [REDACTED]", safe)
    safe = BEARER.sub(r"\1[REDACTED]", safe)
    return NAMED_SECRET.sub(r"\1[REDACTED]", safe)


def redact_url(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parts = urlsplit(value)
        query = [
            (key, "[REDACTED]" if SENSITIVE_NAME.search(key) else val)
            for key, val in parse_qsl(parts.query, keep_blank_values=True)
        ]
        safe_netloc = parts.netloc.rsplit("@", 1)[-1]
        return urlunsplit((parts.scheme, safe_netloc, parts.path, urlencode(query), ""))
    except ValueError:
        return redact_text(value)
