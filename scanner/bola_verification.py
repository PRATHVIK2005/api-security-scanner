"""Opt-in, read-only BOLA verification for explicitly owned test objects."""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from scanner.models import Finding, Severity
from scanner.validation import InvalidURLError, validate_target_url

MAX_CONFIG_BYTES = 65_536


@dataclass(frozen=True)
class BOLAIdentity:
    identity_id: str
    role: str
    token: str
    identity_url: str
    identity_json_path: str
    expected_identity: str


@dataclass(frozen=True)
class BOLAObjectCase:
    case_id: str
    object_type: str
    object_url: str
    owner_json_path: str
    expected_owner: str
    access_rules: dict[str, str]


@dataclass(frozen=True)
class BOLAConfig:
    authorized_token: str
    unauthorized_token: str
    object_url: str
    owner_json_path: str
    expected_owner: str
    access_policy: str = "private"
    identity_url: str | None = None
    identity_json_path: str | None = None
    authorized_identity: str | None = None
    unauthorized_identity: str | None = None
    identities: tuple[BOLAIdentity, ...] = ()
    object_cases: tuple[BOLAObjectCase, ...] = ()


def load_bola_config(path: str | Path) -> BOLAConfig:
    """Load a small local JSON config; callers must keep it out of version control."""
    with Path(path).open("rb") as config_file:
        raw = config_file.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("BOLA configuration exceeds the 64 KiB limit")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("BOLA configuration must be valid UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("BOLA configuration must be a JSON object")
    if "identities" in value or "objects" in value:
        return _load_matrix_config(value)
    fields = (
        "authorized_token",
        "unauthorized_token",
        "object_url",
        "owner_json_path",
        "expected_owner",
        "identity_url",
        "identity_json_path",
        "authorized_identity",
        "unauthorized_identity",
    )
    if any(not isinstance(value.get(key), str) or not value[key].strip() for key in fields):
        raise ValueError("BOLA configuration requires non-empty string values for all documented fields")
    if value["authorized_token"] == value["unauthorized_token"]:
        raise ValueError("BOLA identities must use distinct tokens")
    try:
        object_url = validate_target_url(value["object_url"])
        identity_url = validate_target_url(value["identity_url"])
    except InvalidURLError as exc:
        raise ValueError("BOLA object_url must be an absolute HTTP(S) URL") from exc
    if not value["owner_json_path"].split(".") or any(not part for part in value["owner_json_path"].split(".")):
        raise ValueError("owner_json_path must use a non-empty dotted JSON path")
    access_policy = value.get("access_policy", "private")
    if access_policy not in {"private", "public"}:
        raise ValueError("access_policy must be 'private' or 'public'")
    if not _same_origin(object_url, identity_url):
        raise ValueError("identity_url must match the configured object origin")
    identity_path = value["identity_json_path"]
    if any(not part for part in identity_path.split(".")):
        raise ValueError("identity_json_path must use a non-empty dotted JSON path")
    if value["authorized_identity"] == value["unauthorized_identity"]:
        raise ValueError("test identities must be distinct")
    return BOLAConfig(
        authorized_token=value["authorized_token"],
        unauthorized_token=value["unauthorized_token"],
        object_url=object_url,
        owner_json_path=value["owner_json_path"],
        expected_owner=value["expected_owner"],
        access_policy=access_policy,
        identity_url=identity_url,
        identity_json_path=identity_path,
        authorized_identity=value["authorized_identity"],
        unauthorized_identity=value["unauthorized_identity"],
        identities=(
            BOLAIdentity(
                "authorized",
                "owner",
                value["authorized_token"],
                identity_url,
                identity_path,
                value["authorized_identity"],
            ),
            BOLAIdentity(
                "unauthorized",
                "other",
                value["unauthorized_token"],
                identity_url,
                identity_path,
                value["unauthorized_identity"],
            ),
        ),
        object_cases=(
            BOLAObjectCase(
                "object",
                "object",
                object_url,
                value["owner_json_path"],
                value["expected_owner"],
                {"owner": "allow", "other": "allow" if access_policy == "public" else "deny"},
            ),
        ),
    )


def _load_matrix_config(value: dict) -> BOLAConfig:
    identities_raw, objects_raw = value.get("identities"), value.get("objects")
    if not isinstance(identities_raw, list) or not isinstance(objects_raw, list) or not 1 <= len(identities_raw) <= 20:
        raise ValueError("BOLA configuration requires 2–20 identities and a non-empty objects list")
    if not 1 <= len(objects_raw) <= 50:
        raise ValueError("BOLA configuration supports 1–50 explicitly listed objects")
    identities = []
    ids, tokens = set(), set()
    for item in identities_raw:
        keys = ("id", "role", "token", "identity_url", "identity_json_path", "expected_identity")
        if not isinstance(item, dict) or any(not isinstance(item.get(k), str) or not item[k].strip() for k in keys):
            raise ValueError(
                "Each BOLA identity requires id, role, token, identity_url, identity_json_path, and expected_identity"
            )
        identity_url = validate_target_url(item["identity_url"])
        if item["id"] in ids or item["token"] in tokens:
            raise ValueError("BOLA identity IDs and credentials must be distinct")
        if any(not segment for segment in item["identity_json_path"].split(".")):
            raise ValueError("identity_json_path must use a non-empty dotted JSON path")
        ids.add(item["id"])
        tokens.add(item["token"])
        identities.append(
            BOLAIdentity(
                item["id"],
                item["role"],
                item["token"],
                identity_url,
                item["identity_json_path"],
                item["expected_identity"],
            )
        )
    if len(identities) < 2:
        raise ValueError("At least two distinct explicitly configured identities are required")

    identity_by_role = {identity.role for identity in identities}
    cases = []
    case_ids = set()
    for item in objects_raw:
        keys = ("case_id", "object_type", "object_url", "owner_json_path", "expected_owner", "access_rules")
        if not isinstance(item, dict) or any(k not in item for k in keys):
            raise ValueError(
                "Each object case requires case_id, object_type, object_url, owner_json_path, expected_owner, and access_rules"
            )
        if any(not isinstance(item[k], str) or not item[k].strip() for k in keys[:-1]):
            raise ValueError("BOLA object case text fields must be non-empty strings")
        object_url = validate_target_url(item["object_url"])
        if item["case_id"] in case_ids:
            raise ValueError("BOLA case_id values must be unique")
        if not _same_origin(object_url, identities[0].identity_url) or any(
            not _same_origin(object_url, identity.identity_url) for identity in identities
        ):
            raise ValueError("All identity and object URLs must match the same origin")
        if any(not segment for segment in item["owner_json_path"].split(".")):
            raise ValueError("owner_json_path must use a non-empty dotted JSON path")
        rules = item["access_rules"]
        if not isinstance(rules, dict) or set(rules) != identity_by_role:
            raise ValueError("Each object access_rules map must cover every configured role")
        if any(not isinstance(rule, str) or rule not in {"allow", "deny"} for rule in rules.values()):
            raise ValueError("Access rules must be 'allow' or 'deny'")
        if not {"allow", "deny"}.issubset(set(rules.values())):
            raise ValueError("Each object access_rules map must define positive and negative controls")
        if not any(
            identity.expected_identity == item["expected_owner"] and rules[identity.role] == "allow"
            for identity in identities
        ):
            raise ValueError("Each object case requires a configured owner identity with expected allow access")
        case_ids.add(item["case_id"])
        cases.append(
            BOLAObjectCase(
                item["case_id"],
                item["object_type"],
                object_url,
                item["owner_json_path"],
                item["expected_owner"],
                dict(rules),
            )
        )
    first_identity, first_case = identities[0], cases[0]
    return BOLAConfig(
        authorized_token=first_identity.token,
        unauthorized_token=identities[1].token,
        object_url=first_case.object_url,
        owner_json_path=first_case.owner_json_path,
        expected_owner=first_case.expected_owner,
        identity_url=first_identity.identity_url,
        identity_json_path=first_identity.identity_json_path,
        authorized_identity=first_identity.expected_identity,
        unauthorized_identity=identities[1].expected_identity,
        identities=tuple(identities),
        object_cases=tuple(cases),
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


def _configured_identities(config: BOLAConfig) -> tuple[BOLAIdentity, ...]:
    if config.identities:
        return config.identities
    if not all(
        (config.identity_url, config.identity_json_path, config.authorized_identity, config.unauthorized_identity)
    ):
        return ()
    return (
        BOLAIdentity(
            "authorized",
            "owner",
            config.authorized_token,
            config.identity_url,
            config.identity_json_path,
            config.authorized_identity,
        ),
        BOLAIdentity(
            "unauthorized",
            "other",
            config.unauthorized_token,
            config.identity_url,
            config.identity_json_path,
            config.unauthorized_identity,
        ),
    )


def _configured_cases(config: BOLAConfig) -> tuple[BOLAObjectCase, ...]:
    if config.object_cases:
        return config.object_cases
    if not all((config.object_url, config.owner_json_path, config.expected_owner)):
        return ()
    other_rule = "allow" if config.access_policy == "public" else "deny"
    return (
        BOLAObjectCase(
            "object",
            "object",
            config.object_url,
            config.owner_json_path,
            config.expected_owner,
            {"owner": "allow", "other": other_rule},
        ),
    )


def verify_bola_cases(client: httpx.Client, target: str, config: BOLAConfig) -> list[Finding]:
    """Run only the explicitly listed identity and object GET controls."""
    identities = _configured_identities(config)
    cases = _configured_cases(config)
    if not cases:
        return [
            _inconclusive(
                config.object_url or target, "Explicit identity, ownership, or access-rule ground truth is missing."
            )
        ]
    if not identities:
        return [
            _inconclusive(
                case.object_url,
                "Configured object URL is outside the target origin."
                if not _same_origin(target, case.object_url)
                else "Explicit identity ground truth is missing.",
            )
            for case in cases
        ]
    auth_state: dict[str, bool] = {}
    try:
        for identity in identities:
            if not _same_origin(target, identity.identity_url):
                auth_state[identity.identity_id] = False
                continue
            response = client.get(identity.identity_url, headers={"Authorization": f"Bearer {identity.token}"})
            try:
                actual_identity = _json_path(response.json(), identity.identity_json_path)
            except (ValueError, UnicodeDecodeError):
                actual_identity = None
            auth_state[identity.identity_id] = (
                200 <= response.status_code < 300
                and actual_identity is not None
                and str(actual_identity) == identity.expected_identity
            )
    except httpx.RequestError as exc:
        return [
            _inconclusive(c.object_url, f"Identity verification could not complete ({type(exc).__name__}).")
            for c in cases
        ]

    findings = []
    for case in cases:
        if not _same_origin(target, case.object_url):
            findings.append(_inconclusive(case.object_url, "Configured object URL is outside the target origin."))
            continue
        case_identities = [identity for identity in identities if identity.role in case.access_rules]
        if not case_identities or any(not auth_state.get(identity.identity_id, False) for identity in case_identities):
            findings.append(
                _case_finding(
                    case,
                    "inconclusive",
                    None,
                    "One or more required test identities failed independent authentication.",
                )
            )
            continue
        observations = []
        failed = False
        for identity in case_identities:
            try:
                response = client.get(case.object_url, headers={"Authorization": f"Bearer {identity.token}"})
                try:
                    owner = _json_path(response.json(), case.owner_json_path)
                except (ValueError, UnicodeDecodeError):
                    owner = None
                observations.append((identity, response.status_code, owner))
            except httpx.RequestError:
                failed = True
                break
        if failed:
            findings.append(
                _case_finding(case, "inconclusive", None, "An explicitly configured object GET failed or timed out.")
            )
            continue

        unexpected_access = any(
            case.access_rules[identity.role] == "deny" and owner is not None and str(owner) == case.expected_owner
            for identity, status, owner in observations
        )
        if unexpected_access:
            denied_identity = next(
                identity
                for identity, status, owner in observations
                if case.access_rules[identity.role] == "deny"
                and owner is not None
                and str(owner) == case.expected_owner
            )
            findings.append(
                _case_finding(
                    case,
                    "confirmed",
                    next(status for identity, status, owner in observations if identity == denied_identity),
                    "A separately authenticated identity whose configured role must be denied received the known object-owner marker. No response body or credential was retained.",
                )
            )
            continue

        controls_passed = True
        status_for_result = None
        for identity, status, owner in observations:
            expected = case.access_rules[identity.role]
            status_for_result = status
            if expected == "allow":
                controls_passed &= 200 <= status < 300 and owner is not None and str(owner) == case.expected_owner
            else:
                controls_passed &= status in {403, 404}
        if controls_passed:
            classification = "verified_public" if set(case.access_rules.values()) == {"allow"} else "verified_negative"
            findings.append(
                _case_finding(
                    case,
                    classification,
                    status_for_result,
                    "Configured allow controls matched the known owner marker and configured deny controls were independently authenticated and denied.",
                )
            )
        else:
            findings.append(
                _case_finding(
                    case,
                    "inconclusive",
                    status_for_result,
                    "Observed responses did not establish every configured access rule and ownership marker.",
                )
            )
    return findings


def verify_bola(client: httpx.Client, target: str, config: BOLAConfig) -> Finding:
    """Backward-compatible one-case wrapper; multi-case callers use verify_bola_cases."""
    return verify_bola_cases(client, target, config)[0]


def _case_finding(case: BOLAObjectCase, classification: str, status: int | None, evidence: str) -> Finding:
    fingerprint = hashlib.sha256(f"{case.case_id}|{case.object_type}|{case.object_url}".encode()).hexdigest()[:16]
    title = {
        "confirmed": "Verified Cross-Role Object Access (BOLA)",
        "verified_negative": "Configured BOLA Access Controls Verified",
        "verified_public": "Configured Public Object Access Verified",
        "inconclusive": "BOLA Verification Inconclusive",
    }[classification]
    return Finding(
        severity=Severity.HIGH if classification == "confirmed" else Severity.INFO,
        title=title,
        endpoint=case.object_url,
        method="GET",
        confidence="high" if classification != "inconclusive" else "low",
        verification_status=classification,
        check_id=f"bola.explicit.v1.{fingerprint}",
        evidence=evidence,
        response_status=status,
        recommendation="Enforce object-level authorization against the authenticated identity and configured policy."
        if classification == "confirmed"
        else None,
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
