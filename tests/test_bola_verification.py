import json

import httpx

from scanner.bola_verification import load_bola_config, verify_bola, verify_bola_cases


def _config(**overrides):
    from scanner.bola_verification import BOLAConfig

    values = dict(
        authorized_token="owner",
        unauthorized_token="other",
        object_url="http://127.0.0.1/object/1",
        owner_json_path="owner.id",
        expected_owner="known-owner",
        identity_url="http://127.0.0.1/me",
        identity_json_path="id",
        authorized_identity="user-1",
        unauthorized_identity="user-2",
    )
    values.update(overrides)
    return BOLAConfig(**values)


def _identity_response(request):
    identity = "user-1" if request.headers["authorization"] in {"Bearer owner", "Bearer owner-test-token"} else "user-2"
    return httpx.Response(200, json={"id": identity})


def test_two_identity_test_confirms_matching_known_owner(tmp_path):
    config_path = tmp_path / "bola.json"
    config_path.write_text(
        json.dumps(
            {
                "authorized_token": "owner-test-token",
                "unauthorized_token": "other-test-token",
                "object_url": "http://127.0.0.1:8001/items/test-object",
                "owner_json_path": "owner.id",
                "expected_owner": "test-user-1",
                "identity_url": "http://127.0.0.1:8001/me",
                "identity_json_path": "id",
                "authorized_identity": "test-user-1",
                "unauthorized_identity": "test-user-2",
            }
        ),
        encoding="utf-8",
    )
    config = load_bola_config(config_path)
    seen = []

    def handler(request):
        seen.append(request.headers["authorization"])
        if request.url.path == "/me":
            identity = "test-user-1" if "owner-test-token" in request.headers["authorization"] else "test-user-2"
            return httpx.Response(200, json={"id": identity})
        return httpx.Response(200, json={"owner": {"id": "test-user-1"}})

    finding = verify_bola(
        httpx.Client(transport=httpx.MockTransport(handler)),
        "http://127.0.0.1:8001",
        config,
    )
    assert finding.verification_status == "confirmed"
    assert finding.confidence == "high"
    assert finding.response_status == 200
    assert len(seen) == 4 and seen[0] != seen[1] and seen[2] != seen[3]
    assert "test-token" not in finding.model_dump_json()


def test_two_identity_test_is_inconclusive_when_owner_marker_differs():
    tokens = iter(("Bearer owner", "Bearer other"))

    def handler(request):
        if request.url.path == "/me":
            return _identity_response(request)
        token = next(tokens)
        if token == "Bearer other":
            return httpx.Response(200, json={"owner": {"id": "somebody-else"}})
        return httpx.Response(200, json={"owner": {"id": "known-owner"}})

    from scanner.bola_verification import BOLAConfig

    result = verify_bola(
        httpx.Client(transport=httpx.MockTransport(handler)),
        "http://127.0.0.1:8001",
        _config(object_url="http://127.0.0.1:8001/object/1", identity_url="http://127.0.0.1:8001/me"),
    )
    assert result.verification_status == "inconclusive"


def test_two_identity_test_is_inconclusive_without_authorized_owner_ground_truth():
    from scanner.bola_verification import BOLAConfig

    def handler(request):
        return _identity_response(request) if request.url.path == "/me" else httpx.Response(200, json={"id": "1"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    finding = verify_bola(
        client,
        "http://127.0.0.1:8001",
        _config(object_url="http://127.0.0.1:8001/object/1", identity_url="http://127.0.0.1:8001/me"),
    )
    assert finding.verification_status == "inconclusive"


def test_second_identity_success_without_owner_semantics_is_inconclusive():
    from scanner.bola_verification import BOLAConfig

    responses = iter(
        (
            httpx.Response(200, json={"id": "user-1"}),
            httpx.Response(200, json={"id": "user-2"}),
            httpx.Response(200, json={"owner": {"id": "known-owner"}}),
            httpx.Response(200, json={"message": "ok"}),
        )
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda request: next(responses)))
    finding = verify_bola(
        client,
        "http://127.0.0.1:8001",
        _config(object_url="http://127.0.0.1:8001/object/1", identity_url="http://127.0.0.1:8001/me"),
    )
    assert finding.verification_status == "inconclusive"


def test_two_identity_test_rejects_cross_origin_object():
    from scanner.bola_verification import BOLAConfig

    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    finding = verify_bola(
        client,
        "http://127.0.0.1:8001",
        BOLAConfig("owner", "other", "http://127.0.0.1:8002/object/1", "owner.id", "known-owner"),
    )
    assert finding.verification_status == "inconclusive"
    assert "outside" in finding.evidence


def test_bola_config_size_and_distinct_identity_validation(tmp_path):
    config_path = tmp_path / "bola.json"
    config_path.write_text(
        json.dumps(
            {
                "authorized_token": "same",
                "unauthorized_token": "same",
                "object_url": "http://127.0.0.1/object/1",
                "owner_json_path": "owner.id",
                "expected_owner": "owner-1",
                "identity_url": "http://127.0.0.1/me",
                "identity_json_path": "id",
                "authorized_identity": "user-1",
                "unauthorized_identity": "user-2",
            }
        )
    )
    import pytest

    with pytest.raises(ValueError, match="distinct"):
        load_bola_config(config_path)


def test_cross_account_denial_is_negative_but_authentication_failure_is_inconclusive():
    from scanner.bola_verification import BOLAConfig

    config = _config()
    for denied_status, expected in (
        (403, "verified_negative"),
        (401, "inconclusive"),
        (429, "inconclusive"),
        (500, "inconclusive"),
    ):
        responses = iter(
            (
                httpx.Response(200, json={"id": "user-1"}),
                httpx.Response(200, json={"id": "user-2"}),
                httpx.Response(200, json={"owner": {"id": "known-owner"}}),
                httpx.Response(denied_status),
            )
        )
        finding = verify_bola(
            httpx.Client(transport=httpx.MockTransport(lambda _req: next(responses))), "http://127.0.0.1", config
        )
        assert finding.verification_status == expected


def test_configured_public_policy_reports_expected_access_without_bola():
    from scanner.bola_verification import BOLAConfig

    config = _config(expected_owner="public-object", access_policy="public")

    def handler(request):
        if request.url.path == "/me":
            return _identity_response(request)
        return httpx.Response(200, json={"owner": {"id": "public-object"}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    finding = verify_bola(client, "http://127.0.0.1", config)
    assert finding.verification_status == "verified_public"
    assert finding.severity.value == "INFO"


def test_invalid_or_expired_identity_token_stops_before_object_requests():
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.headers["authorization"] == "Bearer other":
            return httpx.Response(401)
        return _identity_response(request)

    finding = verify_bola(
        httpx.Client(transport=httpx.MockTransport(handler)),
        "http://127.0.0.1",
        _config(),
    )
    assert finding.verification_status == "inconclusive"
    assert calls == ["/me", "/me"]


def test_matrix_verifies_multiple_configured_object_types_and_roles_without_enumeration(tmp_path):
    config_data = {
        "identities": [
            {
                "id": "owner-a",
                "role": "owner",
                "token": "test-owner-secret",
                "identity_url": "http://127.0.0.1:8001/me",
                "identity_json_path": "id",
                "expected_identity": "owner-a",
            },
            {
                "id": "viewer-b",
                "role": "viewer",
                "token": "test-viewer-secret",
                "identity_url": "http://127.0.0.1:8001/me",
                "identity_json_path": "id",
                "expected_identity": "viewer-b",
            },
        ],
        "objects": [
            {
                "case_id": "invoice-one",
                "object_type": "invoice",
                "object_url": "http://127.0.0.1:8001/invoices/known-one",
                "owner_json_path": "owner.id",
                "expected_owner": "owner-a",
                "access_rules": {"owner": "allow", "viewer": "deny"},
            },
            {
                "case_id": "document-one",
                "object_type": "document",
                "object_url": "http://127.0.0.1:8001/documents/known-one",
                "owner_json_path": "owner.id",
                "expected_owner": "owner-a",
                "access_rules": {"owner": "allow", "viewer": "deny"},
            },
        ],
    }
    path = tmp_path / "matrix.json"
    path.write_text(json.dumps(config_data), encoding="utf-8")
    config = load_bola_config(path)
    calls = []

    def handler(request):
        calls.append((request.method, request.url.path, request.headers["authorization"]))
        token = request.headers["authorization"]
        if request.url.path == "/me":
            identity_id = "owner-a" if "owner" in token else "viewer-b"
            return httpx.Response(200, json={"id": identity_id})
        if "viewer" in token:
            return httpx.Response(403, json={"message": "denied"})
        return httpx.Response(200, json={"owner": {"id": "owner-a"}})

    findings = verify_bola_cases(httpx.Client(transport=httpx.MockTransport(handler)), "http://127.0.0.1:8001", config)
    assert [finding.verification_status for finding in findings] == ["verified_negative", "verified_negative"]
    assert len({finding.check_id for finding in findings}) == 2
    assert len(calls) == 6
    assert all(method == "GET" for method, _, _ in calls)
    assert {url for _, url, _ in calls} == {"/me", "/invoices/known-one", "/documents/known-one"}
    assert "test-owner-secret" not in "".join(finding.model_dump_json() for finding in findings)


def test_matrix_rejects_missing_access_control_ground_truth(tmp_path):
    path = tmp_path / "incomplete.json"
    path.write_text(json.dumps({"identities": [], "objects": []}), encoding="utf-8")
    import pytest

    with pytest.raises(ValueError, match="identities"):
        load_bola_config(path)


def test_owner_marker_overrides_misleading_denial_or_error_status_for_verified_leak():
    for status in (200, 403, 500):
        responses = iter(
            (
                httpx.Response(200, json={"id": "user-1"}),
                httpx.Response(200, json={"id": "user-2"}),
                httpx.Response(200, json={"owner": {"id": "known-owner"}}),
                httpx.Response(status, json={"owner": {"id": "known-owner"}}),
            )
        )
        finding = verify_bola(
            httpx.Client(transport=httpx.MockTransport(lambda _request: next(responses))),
            "http://127.0.0.1",
            _config(),
        )
        assert finding.verification_status == "confirmed"


def test_owner_allow_control_with_denial_status_is_not_marked_clean():
    responses = iter(
        (
            httpx.Response(200, json={"id": "user-1"}),
            httpx.Response(200, json={"id": "user-2"}),
            httpx.Response(404, json={"owner": {"id": "known-owner"}}),
            httpx.Response(403),
        )
    )
    finding = verify_bola(
        httpx.Client(transport=httpx.MockTransport(lambda _request: next(responses))),
        "http://127.0.0.1",
        _config(),
    )
    assert finding.verification_status == "inconclusive"
