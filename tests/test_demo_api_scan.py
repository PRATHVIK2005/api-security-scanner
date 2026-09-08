from fastapi.testclient import TestClient

from demo_api.main import app as demo_app
from scanner.discovery import parse_openapi
from scanner.checks.exposed_endpoints import check_exposed_endpoint
from scanner.checks.token_security import check_token_security
from scanner.checks.cors import check_cors


def test_demo_api_discovery_and_openapi_parsing():
    """Verify endpoint discovery parses all endpoints from demo API."""
    with TestClient(demo_app) as client:
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        data = resp.json()
        endpoints = parse_openapi(data, "http://testserver")
        
        paths = {e.path for e in endpoints}
        assert "/admin" in paths
        assert "/token-test" in paths
        assert "/users" in paths
        assert "/debug" in paths
        assert "/legacy/users" in paths


def test_demo_api_vulnerability_detections():
    """Verify security checks correctly flag issues on demo API endpoints."""
    with TestClient(demo_app) as client:
        # 1. Exposed admin endpoint detection
        admin_resp = client.get("/admin")
        assert admin_resp.status_code == 200
        admin_findings = check_exposed_endpoint("http://testserver/admin", admin_resp.status_code)
        assert len(admin_findings) == 1
        assert "Exposed Admin" in admin_findings[0].title

        # 2. Token / API Key exposure detection
        token_resp = client.get("/token-test")
        assert token_resp.status_code == 200
        token_findings = check_token_security("http://testserver/token-test", token_resp)
        assert len(token_findings) >= 2
        titles = [f.title for f in token_findings]
        assert "JWT Token Exposed in Response" in titles
        assert "Potential API Key Exposed in Response" in titles
