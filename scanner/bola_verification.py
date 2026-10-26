"""Opt-in, read-only BOLA verification for explicitly owned test objects."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from scanner.models import Finding, Severity
from scanner.validation import InvalidURLError, validate_target_url

MAX_CONFIG_BYTES = 16_384


@dataclass(frozen=True)
class BOLAConfig:
    authorized_token: str
    unauthorized_token: str
    object_url: str
    owner_json_path: str
    expected_owner: str


def load_bola_config(path: str | Path) -> BOLAConfig:
    """Load a small local JSON config; callers must keep it out of version control."""
    with Path(path).open("rb") as config_file:
        raw = config_file.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("BOLA configuration exceeds the 16 KiB limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("BOLA configuration must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("BOLA configuration must be a JSON object")
    fields = ("authorized_token", "unauthorized_token", "object_url", "owner_json_path", "expected_owner")
    if any(not isinstance(value.get(key), str) or not value[key].strip() for key in fields):
        raise ValueError("BOLA configuration requires non-empty string values for all documented fields")
    if value["authorized_token"] == value["unauthorized_token"]:
        raise ValueError("BOLA identities must use distinct tokens")
    try:
        object_url = validate_target_url(value["object_url"])
    except InvalidURLError as exc:
        raise ValueError("BOLA object_url must be an absolute HTTP(S) URL") from exc
    if not value["owner_json_path"].split(".") or any(not part for part in value["owner_json_path"].split(".")):
        raise ValueError("owner_json_path must use a non-empty dotted JSON path")
    return BOLAConfig(
        authorized_token=value["authorized_token"],
        unauthorized_token=value["unauthorized_token"],
        object_url=object_url,
        owner_json_path=value["owner_json_path"],
        expected_owner=value["expected_owner"],
    )


def _same_origin(left: str, right: str) -> bool:
    a, b = urlparse(left), urlparse(right)
    return (a.scheme.lower(), a.hostname, a.port or (443 if a.scheme == "https" else 80)) == (
        b.scheme.lower(),
        b.hostname,
        b.port or (443 if b.scheme == "https" else 80),
    )


def _json_path(value: object, path: str) -> object | None:
    current = value
    for key in path.split("."):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def verify_bola(client: httpx.Client, target: str, config: BOLAConfig) -> Finding:
    """Compare two explicitly authorized GET identities against one known test object."""
    if not _same_origin(target, config.object_url):
        return _inconclusive(config.object_url, "Configured object URL is outside the target origin.")
    observations = []
    try:
        for token in (config.authorized_token, config.unauthorized_token):
            response = client.get(config.object_url, headers={"Authorization": f"Bearer {token}"})
            owner = None
            try:
                owner = _json_path(response.json(), config.owner_json_path)
            except (ValueError, UnicodeDecodeError):
                pass
            observations.append((response.status_code, owner))
    except httpx.RequestError as exc:
        return _inconclusive(config.object_url, f"Identity comparison could not complete ({type(exc).__name__}).")

    authorized, other = observations
    if authorized[1] is not None and 200 <= authorized[0] < 300 and str(authorized[1]) == config.expected_owner:
        if other[1] is not None and 200 <= other[0] < 300 and str(other[1]) == config.expected_owner:
            return Finding(
                severity=Severity.HIGH,
                title="Verified Cross-Identity Object Access (BOLA)",
                endpoint=config.object_url,
                method="GET",
                confidence="high",
                verification_status="confirmed",
                check_id="bola.two_identity_read_only.v1",
                evidence=(
                    "The authorized test identity received the configured owner marker, and a distinct test identity "
                    "received the same object owner marker in a successful GET response. Response bodies and tokens "
                    "were not retained."
                ),
                response_status=other[0],
                recommendation="Enforce object ownership or policy checks before returning this object.",
            )
        semantically_denied = other[0] in {401, 403, 404}
        if semantically_denied:
            return Finding(
                severity=Severity.INFO,
                title="BOLA Test Object Access-Controlled",
                endpoint=config.object_url,
                method="GET",
                confidence="high",
                verification_status="verified_negative",
                check_id="bola.two_identity_read_only.v1",
                evidence="The authorized identity matched the configured owner marker; the second identity did not receive that marker.",
                response_status=other[0],
            )
        if 200 <= other[0] < 300:
            return _inconclusive(
                config.object_url,
                "The second identity returned a successful response without the same configured owner marker.",
                status=other[0],
            )
    return _inconclusive(
        config.object_url,
        "The authorized identity did not return the configured ownership marker; the comparison is inconclusive.",
        status=authorized[0],
    )


def _inconclusive(url: str, evidence: str, status: int | None = None) -> Finding:
    return Finding(
        severity=Severity.INFO,
        title="BOLA Verification Inconclusive",
        endpoint=url,
        method="GET",
        confidence="low",
        verification_status="inconclusive",
        check_id="bola.two_identity_read_only.v1",
        evidence=evidence,
        response_status=status,
        recommendation="Verify object ownership with two authorized test identities and a known ownership marker.",
    )
