"""Bounded endpoint discovery from OpenAPI documents or explicit endpoint lists."""

import json
import copy
import os
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from scanner.models import DiscoveryResult, Endpoint
from scanner.transport import create_scanner_client
from scanner.validation import InvalidURLError, validate_target_url

OPENAPI_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api-docs",
    "/v3/api-docs",
    "/api/openapi.json",
    "/swagger/v1/swagger.json",
)
VALID_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
MAX_SPEC_BYTES = 2_000_000
MAX_ENDPOINTS = 500
MAX_REF_COUNT = 2_000
MAX_REF_DEPTH = 32


def _same_origin(left: str, right: str) -> bool:
    a, b = urlparse(left), urlparse(right)
    try:
        return (a.scheme.lower(), a.hostname.lower(), a.port or (443 if a.scheme == "https" else 80)) == (
            b.scheme.lower(),
            b.hostname.lower(),
            b.port or (443 if b.scheme == "https" else 80),
        )
    except (AttributeError, ValueError):
        return False


def _load_document(raw: bytes, suffix: str = "", allow_list: bool = False) -> dict | list:
    text = raw.decode("utf-8-sig")
    if len(raw) > MAX_SPEC_BYTES:
        raise ValueError("Document exceeds the 2 MB size limit.")

    def check_json_depth(source: str) -> None:
        depth = 0
        nodes = 0
        quoted = escaped = False
        for char in source:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
                continue
            if char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                nodes += 1
                if depth > 100:
                    raise ValueError("JSON nesting exceeds the depth limit.")
            elif char in "]}":
                depth -= 1
                if depth < 0:
                    raise ValueError("Malformed JSON structure.")
            elif char in ",:":
                nodes += 1
            if nodes > 100_000:
                raise ValueError("JSON document exceeds the structural node limit.")

    def parse_json(source: str):
        check_json_depth(source)
        try:
            return json.loads(source)
        except RecursionError as exc:
            raise ValueError("Malformed or excessively nested JSON document.") from exc

    def parse_yaml() -> object:
        try:
            import yaml
        except ImportError as exc:
            raise ValueError("YAML input requires PyYAML; install the project dependencies.") from exc

        class BoundedSafeLoader(yaml.SafeLoader):
            depth = 0
            nodes = 0

            def compose_node(self, parent, index):
                if self.check_event(yaml.AliasEvent):
                    raise ValueError("YAML aliases are not supported in scanner input.")
                self.depth += 1
                self.nodes += 1
                try:
                    if self.depth > 100 or self.nodes > 100_000:
                        raise ValueError("YAML document exceeds its depth or node limit.")
                    return super().compose_node(parent, index)
                finally:
                    self.depth -= 1

        try:
            return yaml.load(text, Loader=BoundedSafeLoader)
        except yaml.YAMLError as exc:
            raise ValueError("Malformed YAML document.") from exc

    if suffix.lower() in {".yaml", ".yml"}:
        data = parse_yaml()
    else:
        try:
            data = parse_json(text)
        except json.JSONDecodeError:
            data = parse_yaml()
    if allow_list and isinstance(data, list):
        return data
    if not isinstance(data, dict):
        raise ValueError("Specification must contain a mapping/object at its root.")
    return data


def load_endpoint_list(path: str | Path, base_url: str) -> list[Endpoint]:
    """Load JSON/YAML [{method, path, ...}] or {endpoints: [...]} safely."""
    source = Path(path)
    if source.stat().st_size > MAX_SPEC_BYTES:
        raise ValueError("Endpoint list exceeds the 2 MB size limit.")
    with source.open("rb") as stream:
        raw = stream.read(MAX_SPEC_BYTES + 1)
    if len(raw) > MAX_SPEC_BYTES:
        raise ValueError("Endpoint list exceeds the 2 MB size limit.")
    document = _load_document(raw, source.suffix, allow_list=True)
    rows = document.get("endpoints", document) if isinstance(document, dict) else document
    if not isinstance(rows, list):
        raise ValueError("Endpoint list must be an array or an object with an 'endpoints' array.")
    endpoints: list[Endpoint] = []
    seen: set[tuple[str, str]] = set()
    for index, row in enumerate(rows):
        if index >= MAX_ENDPOINTS:
            raise ValueError(f"Endpoint list exceeds the {MAX_ENDPOINTS} endpoint limit.")
        if not isinstance(row, dict):
            raise ValueError(f"Endpoint entry {index + 1} must be an object.")
        method = str(row.get("method", "GET")).upper()
        if method not in VALID_METHODS:
            raise ValueError(f"Endpoint entry {index + 1} has unsupported method {method!r}.")
        path_value = row.get("path")
        if not isinstance(path_value, str) or not path_value.strip():
            raise ValueError(f"Endpoint entry {index + 1} requires a non-empty path.")
        normalized = path_value.strip()
        parsed_path = urlparse(normalized)
        candidate = (
            normalized
            if parsed_path.scheme or parsed_path.netloc
            else urljoin(base_url.rstrip("/") + "/", normalized.lstrip("/"))
        )
        validate_target_url(candidate)
        if not _same_origin(base_url, candidate):
            raise ValueError(f"Endpoint entry {index + 1} is outside the target origin.")
        route = urlparse(candidate).path or "/"
        key = (method, candidate)
        if key in seen:
            continue
        seen.add(key)
        endpoints.append(
            Endpoint(
                url=candidate,
                method=method,
                path=route,
                requires_auth=bool(row.get("requires_auth", False)),
                operation_id=row.get("operation_id"),
                summary=row.get("summary"),
                description=row.get("description"),
                tags=row.get("tags", []) if isinstance(row.get("tags", []), list) else [],
                deprecated=bool(row.get("deprecated", False)),
            )
        )
    if not endpoints:
        raise ValueError("Endpoint list is valid but contains no usable endpoints.")
    return endpoints


def _reference_inventory(document: dict) -> tuple[int, int]:
    """Count $ref fields iteratively; never fetch or recursively resolve them."""
    total = external = 0
    stack = [document]
    visited = set()
    while stack:
        item = stack.pop()
        identity = id(item)
        if identity in visited:
            continue
        visited.add(identity)
        if isinstance(item, dict):
            ref = item.get("$ref")
            if isinstance(ref, str):
                total += 1
                parsed = urlparse(ref)
                if parsed.scheme or parsed.netloc or not ref.startswith("#/"):
                    external += 1
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return total, external


def _resolve_local_references(document: dict) -> tuple[dict, int, int]:
    """Resolve bounded local JSON Pointers. External and invalid refs remain visible."""
    max_refs = int(os.getenv("API_SCANNER_MAX_OPENAPI_REFS", str(MAX_REF_COUNT)))
    max_depth = int(os.getenv("API_SCANNER_MAX_OPENAPI_REF_DEPTH", str(MAX_REF_DEPTH)))
    if not 1 <= max_refs <= 10_000 or not 1 <= max_depth <= 64:
        raise ValueError("OpenAPI reference limits are outside their allowed range")
    root = copy.deepcopy(document)
    count = 0
    unresolved = 0
    external = 0

    def pointer(ref: str):
        if not ref.startswith("#/") or "#" in ref[1:]:
            return None
        current = root
        for raw in ref[2:].split("/"):
            token = raw.replace("~1", "/").replace("~0", "~")
            # Reject malformed JSON Pointer escapes instead of guessing.
            import re

            if re.search(r"~(?![01])", raw):
                return None
            if isinstance(current, list):
                if not token.isdigit() or int(token) >= len(current):
                    return None
                current = current[int(token)]
            elif isinstance(current, dict) and token in current:
                current = current[token]
            else:
                return None
        return current

    def walk(value, stack: tuple[str, ...], depth: int):
        nonlocal count, unresolved, external
        if isinstance(value, list):
            return [walk(item, stack, depth) for item in value]
        if not isinstance(value, dict):
            return value
        ref = value.get("$ref")
        if isinstance(ref, str):
            count += 1
            if count > max_refs or depth >= max_depth or ref in stack:
                unresolved += 1
                return {key: walk(item, stack, depth + 1) for key, item in value.items() if key != "$ref"} | {
                    "$ref": ref
                }
            if not ref.startswith("#/"):
                external += 1
                unresolved += 1
                return {key: walk(item, stack, depth + 1) for key, item in value.items()}
            target = pointer(ref)
            if target is None:
                unresolved += 1
                return {key: walk(item, stack, depth + 1) for key, item in value.items()}
            resolved = walk(target, stack + (ref,), depth + 1)
            # OpenAPI Reference Object siblings do not override the referenced object;
            # retain them additively for useful metadata where vendor extensions exist.
            if isinstance(resolved, dict):
                resolved = {**resolved, **{k: walk(v, stack, depth + 1) for k, v in value.items() if k != "$ref"}}
            return resolved
        return {key: walk(item, stack, depth) for key, item in value.items()}

    return walk(root, (), 0), unresolved, external


def discover_endpoints(
    base_url: str,
    headers: dict[str, str] | None = None,
    specification_url: str | None = None,
    endpoint_list: str | Path | None = None,
    client: httpx.Client | None = None,
) -> DiscoveryResult:
    """Discover operations and retain probe outcomes for transparent fallback."""
    base_url = validate_target_url(base_url).rstrip("/")
    if endpoint_list is not None:
        return DiscoveryResult(endpoints=load_endpoint_list(endpoint_list, base_url), source="Endpoint list")
    if client is None:
        with create_scanner_client(headers=headers) as safe_client:
            return discover_endpoints(
                base_url,
                headers=headers,
                specification_url=specification_url,
                client=safe_client,
            )
    probes = (
        [specification_url] if specification_url else [urljoin(base_url + "/", p.lstrip("/")) for p in OPENAPI_PATHS]
    )
    attempts: list[str] = []
    for spec_url in probes:
        try:
            validate_target_url(spec_url)
            if not _same_origin(base_url, spec_url):
                attempts.append(f"{spec_url}: rejected (outside target origin)")
                continue
            response = client.get(spec_url)
            if response.is_redirect:
                attempts.append(f"{spec_url}: redirect not followed")
                continue
            if response.status_code != 200:
                attempts.append(f"{spec_url}: HTTP {response.status_code}")
                continue
            if len(response.content) > MAX_SPEC_BYTES:
                attempts.append(f"{spec_url}: document exceeds 2 MB limit")
                continue
            data = _load_document(response.content, Path(urlparse(spec_url).path).suffix)
            version = data.get("openapi")
            swagger_version = data.get("swagger")
            if version is not None and (not isinstance(version, str) or not version.startswith("3.")):
                attempts.append(f"{spec_url}: unsupported OpenAPI version")
                continue
            if swagger_version is not None and swagger_version != "2.0":
                attempts.append(f"{spec_url}: unsupported Swagger version")
                continue
            resolved_data, unresolved_count, external_ref_count = _resolve_local_references(data)
            endpoints = parse_openapi(resolved_data, base_url)
            if endpoints:
                limits = (
                    [f"Reached the {MAX_ENDPOINTS}-operation limit; discovery may be incomplete."]
                    if len(endpoints) >= MAX_ENDPOINTS
                    else []
                )
                if unresolved_count:
                    limits.append(
                        f"{unresolved_count} reference(s) were unresolved or exceeded local resolution limits."
                    )
                if external_ref_count:
                    limits.append(f"{external_ref_count} external reference(s) were not fetched.")
                return DiscoveryResult(
                    endpoints=endpoints,
                    source="OpenAPI",
                    specification_url=spec_url,
                    attempts=attempts,
                    limitations=limits,
                )
            attempts.append(f"{spec_url}: valid document contains no usable operations")
        except httpx.RequestError as exc:
            attempts.append(f"{spec_url}: request failed ({type(exc).__name__})")
        except (InvalidURLError, ValueError, TypeError, RecursionError):
            attempts.append(f"{spec_url}: malformed JSON/YAML document or invalid specification URL")
        if specification_url:
            break
    return DiscoveryResult(
        endpoints=[Endpoint(url=base_url, method="GET", path="/", requires_auth=False)],
        source="Fallback",
        specification_url=specification_url,
        attempts=attempts,
        limitations=[
            "No usable OpenAPI document found; only the base URL was scanned, so endpoint coverage is incomplete."
        ],
    )


def parse_openapi(data: dict, base_url: str) -> list[Endpoint]:
    """Parse OpenAPI/Swagger operation metadata without merging HTTP methods."""
    if not isinstance(data, dict) or not isinstance(data.get("paths"), dict):
        return []
    endpoints: list[Endpoint] = []
    seen: set[tuple[str, str]] = set()
    for path, operations in data["paths"].items():
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(operations, dict):
            continue
        path_parameters = operations.get("parameters", [])
        path_parameters = path_parameters if isinstance(path_parameters, list) else []
        for method, operation in operations.items():
            method = str(method).upper()
            if method not in VALID_METHODS or not isinstance(operation, dict):
                continue
            try:
                full_url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
                validate_target_url(full_url)
                if not _same_origin(base_url, full_url):
                    continue
            except InvalidURLError:
                continue
            op_parameters = operation.get("parameters", [])
            op_parameters = op_parameters if isinstance(op_parameters, list) else []
            parameter_map = {
                (p.get("name"), p.get("in")): p for p in path_parameters + op_parameters if isinstance(p, dict)
            }
            parameters = list(parameter_map.values())
            request_schema = None
            body = operation.get("requestBody", {})
            content = body.get("content", {}) if isinstance(body, dict) else {}
            if isinstance(content, dict):
                for media, media_obj in content.items():
                    if "json" in media and isinstance(media_obj, dict) and isinstance(media_obj.get("schema"), dict):
                        request_schema = media_obj["schema"]
                        break
            if request_schema is None:
                request_schema = next(
                    (
                        p.get("schema")
                        for p in parameters
                        if p.get("in") == "body" and isinstance(p.get("schema"), dict)
                    ),
                    None,
                )
            response_schemas = {}
            responses = operation.get("responses", {})
            if isinstance(responses, dict):
                for status, response in responses.items():
                    if not isinstance(response, dict):
                        continue
                    response_content = response.get("content", {})
                    schema = (
                        next(
                            (
                                v.get("schema")
                                for media, v in response_content.items()
                                if "json" in media and isinstance(v, dict) and isinstance(v.get("schema"), dict)
                            ),
                            None,
                        )
                        if isinstance(response_content, dict)
                        else None
                    )
                    schema = schema or (response.get("schema") if isinstance(response.get("schema"), dict) else None)
                    if schema is not None:
                        response_schemas[str(status)] = schema
            security = operation.get("security", data.get("security"))
            key = (method, full_url)
            if key in seen:
                continue
            seen.add(key)
            endpoints.append(
                Endpoint(
                    url=full_url,
                    method=method,
                    path=path,
                    requires_auth=bool(security),
                    parameters=parameters,
                    request_body_schema=request_schema,
                    response_schemas=response_schemas or None,
                    operation_id=operation.get("operationId"),
                    summary=operation.get("summary"),
                    description=operation.get("description"),
                    tags=operation.get("tags", []) if isinstance(operation.get("tags", []), list) else [],
                    deprecated=bool(operation.get("deprecated", False)),
                    security=security if isinstance(security, list) else None,
                )
            )
            if len(endpoints) >= MAX_ENDPOINTS:
                return endpoints
    return endpoints
