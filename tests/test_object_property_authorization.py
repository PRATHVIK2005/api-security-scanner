from unittest.mock import MagicMock
from scanner.checks.object_property_authorization import check_object_property_authorization
from scanner.models import Endpoint


def test_detects_writable_privileged_property_in_request_schema():
    endpoint = Endpoint(
        url="https://api.example.com/users",
        method="POST",
        path="/users",
        request_body_schema={
            "type": "object",
            "properties": {
                "username": {"type": "string"},
                "role": {"type": "string"},
                "is_admin": {"type": "boolean"},
            },
        },
    )
    findings = check_object_property_authorization(endpoint)
    assert len(findings) == 1
    assert findings[0].title == "Potential Writable Privileged Property"
    assert "role" in findings[0].description
    assert "is_admin" in findings[0].description


def test_detects_sensitive_property_in_response_schema():
    endpoint = Endpoint(
        url="https://api.example.com/users/profile",
        method="GET",
        path="/users/profile",
        response_schemas={
            "200": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "username": {"type": "string"},
                    "password_hash": {"type": "string"},
                },
            }
        },
    )
    findings = check_object_property_authorization(endpoint)
    assert len(findings) == 1
    assert findings[0].title == "Potential Sensitive Object Property Exposure"
    assert "password_hash" in findings[0].description


def test_detects_sensitive_property_in_live_response():
    mock_resp = MagicMock()
    mock_resp.json.return_value = {
        "user_id": 101,
        "name": "Alice",
        "secret": "top-secret-val",
    }
    findings = check_object_property_authorization("https://api.example.com/user", response=mock_resp)
    assert len(findings) == 1
    assert findings[0].title == "Potential Sensitive Object Property Exposure"


def test_clean_schema_has_no_findings():
    endpoint = Endpoint(
        url="https://api.example.com/items",
        method="POST",
        path="/items",
        request_body_schema={
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "quantity": {"type": "integer"},
            },
        },
        response_schemas={
            "200": {
                "type": "object",
                "properties": {
                    "id": {"type": "integer"},
                    "name": {"type": "string"},
                    "quantity": {"type": "integer"},
                },
            }
        },
    )
    findings = check_object_property_authorization(endpoint)
    assert findings == []
