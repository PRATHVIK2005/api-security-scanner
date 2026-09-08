import httpx

from scanner.models import (
    DiscoveryResult,
    Endpoint,
)


OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
]


VALID_METHODS = {
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "HEAD",
    "OPTIONS",
}


def discover_endpoints(
    base_url: str,
    headers: dict[str, str] | None = None,
) -> DiscoveryResult:
    """Discover API endpoints from common OpenAPI specification paths."""

    base_url = base_url.rstrip("/")

    for path in OPENAPI_PATHS:
        spec_url = f"{base_url}{path}"

        try:
            response = httpx.get(
                spec_url,
                headers=headers,
                timeout=5,
                follow_redirects=True,
            )

            if response.status_code != 200:
                continue

            try:
                data = response.json()
            except ValueError:
                continue

            endpoints = parse_openapi(
                data,
                base_url,
            )

            if endpoints:
                return DiscoveryResult(
                    endpoints=endpoints,
                    source="OpenAPI",
                    specification_url=spec_url,
                )

        except httpx.RequestError:
            continue

    return DiscoveryResult(
        endpoints=[
            Endpoint(
                url=base_url,
                method="GET",
                path="/",
                requires_auth=False,
            )
        ],
        source="Fallback",
        specification_url=None,
    )


def parse_openapi(
    data: dict,
    base_url: str,
) -> list[Endpoint]:
    """Extract endpoints and authentication information from OpenAPI."""

    endpoints = []

    paths = data.get("paths", {})

    if not isinstance(paths, dict):
        return endpoints

    global_security = data.get("security")

    for path, operations in paths.items():

        if not isinstance(operations, dict):
            continue

        path_parameters = operations.get("parameters", [])
        if not isinstance(path_parameters, list):
            path_parameters = []

        for method, operation in operations.items():

            method_upper = method.upper()

            if method_upper not in VALID_METHODS:
                continue

            if not isinstance(operation, dict):
                operation = {}

            # Combine path-level and operation-level parameters
            op_parameters = operation.get("parameters", [])
            if not isinstance(op_parameters, list):
                op_parameters = []
            all_parameters = list(path_parameters) + list(op_parameters)

            # Extract request body schema (OpenAPI 3 or Swagger 2)
            request_body_schema = None
            req_body = operation.get("requestBody")
            if isinstance(req_body, dict):
                content = req_body.get("content", {})
                if isinstance(content, dict):
                    json_media = content.get("application/json", {})
                    if isinstance(json_media, dict):
                        request_body_schema = json_media.get("schema")
            
            if not request_body_schema:
                # Swagger 2 body parameter check
                for p in all_parameters:
                    if isinstance(p, dict) and p.get("in") == "body" and "schema" in p:
                        request_body_schema = p.get("schema")
                        break

            # Extract response schemas
            response_schemas = {}
            responses = operation.get("responses", {})
            if isinstance(responses, dict):
                for status_key, resp_obj in responses.items():
                    if isinstance(resp_obj, dict):
                        # OpenAPI 3
                        content = resp_obj.get("content", {})
                        if isinstance(content, dict) and "application/json" in content:
                            json_resp = content.get("application/json", {})
                            if isinstance(json_resp, dict) and "schema" in json_resp:
                                response_schemas[str(status_key)] = json_resp.get("schema")
                        # Swagger 2
                        elif "schema" in resp_obj:
                            response_schemas[str(status_key)] = resp_obj.get("schema")

            # Endpoint explicitly declares security
            if "security" in operation:
                requires_auth = bool(operation["security"])
                sec_metadata = operation.get("security")
            # Otherwise inherit global security
            else:
                requires_auth = bool(global_security)
                sec_metadata = global_security

            endpoints.append(
                Endpoint(
                    url=f"{base_url}{path}",
                    method=method_upper,
                    path=path,
                    requires_auth=requires_auth,
                    parameters=all_parameters,
                    request_body_schema=request_body_schema if isinstance(request_body_schema, dict) else None,
                    response_schemas=response_schemas if response_schemas else None,
                    operation_id=operation.get("operationId"),
                    summary=operation.get("summary"),
                    description=operation.get("description"),
                    tags=operation.get("tags", []) if isinstance(operation.get("tags"), list) else [],
                    deprecated=bool(operation.get("deprecated", False)),
                    security=sec_metadata if isinstance(sec_metadata, list) else None,
                )
            )

    return endpoints