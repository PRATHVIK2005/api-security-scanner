from scanner.discovery import parse_openapi


def test_openapi_authentication_detection():

    openapi_data = {
        "security": [
            {
                "BearerAuth": []
            }
        ],
        "paths": {
            "/users": {
                "get": {}
            },
            "/public": {
                "get": {
                    "security": []
                }
            }
        }
    }

    endpoints = parse_openapi(
        openapi_data,
        "https://api.example.com",
    )

    users_endpoint = endpoints[0]
    public_endpoint = endpoints[1]

    assert users_endpoint.requires_auth is True
    assert public_endpoint.requires_auth is False