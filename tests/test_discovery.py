from scanner.discovery import parse_openapi
from scanner.discovery import _resolve_local_references


def test_openapi_authentication_detection():

    openapi_data = {
        "security": [{"BearerAuth": []}],
        "paths": {"/users": {"get": {}}, "/public": {"get": {"security": []}}},
    }

    endpoints = parse_openapi(
        openapi_data,
        "https://api.example.com",
    )

    users_endpoint = endpoints[0]
    public_endpoint = endpoints[1]

    assert users_endpoint.requires_auth is True
    assert public_endpoint.requires_auth is False


def test_local_schema_parameter_and_nested_refs_resolve_without_losing_operations():
    spec = {
        "paths": {
            "/items": {
                "parameters": [{"$ref": "#/components/parameters/Limit"}],
                "get": {
                    "parameters": [{"$ref": "#/components/parameters/ItemId"}],
                    "responses": {
                        "200": {"content": {"application/json": {"schema": {"$ref": "#/components/schemas/Item"}}}}
                    },
                },
            }
        },
        "components": {
            "parameters": {
                "Limit": {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                "ItemId": {"name": "id", "in": "path", "schema": {"$ref": "#/components/schemas/Id"}},
            },
            "schemas": {
                "Id": {"type": "string"},
                "Item": {"type": "object", "properties": {"id": {"$ref": "#/components/schemas/Id"}}},
            },
        },
    }
    resolved, unresolved, external = _resolve_local_references(spec)
    endpoints = parse_openapi(resolved, "https://api.example.test")
    assert len(endpoints) == 1
    assert {p["name"] for p in endpoints[0].parameters} == {"limit", "id"}
    assert endpoints[0].response_schemas["200"]["properties"]["id"]["type"] == "string"
    assert unresolved == external == 0


def test_cycles_missing_malformed_and_external_refs_are_reported_and_preserved():
    spec = {
        "paths": {"/x": {"get": {"responses": {"200": {"$ref": "#/missing"}}}}},
        "components": {
            "schemas": {
                "A": {"$ref": "#/components/schemas/B"},
                "B": {"$ref": "#/components/schemas/A"},
                "Bad": {"$ref": "#/components/schemas/~2bad"},
                "Remote": {"$ref": "https://other.test/schema.json#/X"},
            }
        },
    }
    resolved, unresolved, external = _resolve_local_references(spec)
    assert unresolved >= 4
    assert external == 1
    assert len(parse_openapi(resolved, "https://api.example.test")) == 1


def test_reference_depth_limit_marks_incomplete(monkeypatch):
    monkeypatch.setenv("API_SCANNER_MAX_OPENAPI_REF_DEPTH", "1")
    spec = {
        "components": {
            "schemas": {
                "A": {"$ref": "#/components/schemas/B"},
                "B": {"$ref": "#/components/schemas/C"},
                "C": {"type": "object"},
            }
        }
    }
    _, unresolved, _ = _resolve_local_references(spec)
    assert unresolved == 1


def test_oversized_document_rejected():
    from scanner.discovery import _load_document

    import pytest

    with pytest.raises(ValueError, match="2 MB"):
        _load_document(b" " * (2_000_001))


def test_same_origin_external_refs_are_not_fetched_and_reported_as_limited():
    import json

    import httpx

    from scanner.discovery import discover_endpoints

    calls = []
    document = {
        "openapi": "3.0.0",
        "paths": {
            "/items": {
                "get": {
                    "responses": {"200": {"$ref": "https://api.example.test/openapi.json#/components/responses/Item"}}
                }
            }
        },
        "components": {"responses": {"Item": {"description": "ok"}}},
    }

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, content=json.dumps(document).encode(), headers={"content-type": "application/json"})

    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    result = discover_endpoints(
        "https://api.example.test", specification_url="https://api.example.test/openapi.json", client=client
    )
    assert len(result.endpoints) == 1
    assert any("external reference" in item for item in result.limitations)
    assert calls == ["https://api.example.test/openapi.json"]
