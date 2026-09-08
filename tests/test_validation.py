import pytest
from scanner.validation import validate_target_url, InvalidURLError


def test_valid_urls():
    valid_targets = [
        "http://example.com",
        "https://example.com",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "https://api.domain.io/v1",
        "http://192.168.1.100:5000/api",
    ]
    for target in valid_targets:
        validated = validate_target_url(target)
        assert validated == target


def test_invalid_urls():
    invalid_targets = [
        "hello",
        "not-a-url",
        "ftp://example.com",
        "file:///path/to/file",
        "ws://example.com",
        "",
        "   ",
        None,
        "http://",
        "https://",
    ]
    for target in invalid_targets:
        with pytest.raises(InvalidURLError):
            validate_target_url(target)
