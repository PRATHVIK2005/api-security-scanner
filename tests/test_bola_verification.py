import json

import httpx

from scanner.bola_verification import load_bola_config, verify_bola


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
            }
        ),
        encoding="utf-8",
    )
    config = load_bola_config(config_path)
    seen = []

    def handler(request):
        seen.append(request.headers["authorization"])
        return httpx.Response(200, json={"owner": {"id": "test-user-1"}})

    finding = verify_bola(
        httpx.Client(transport=httpx.MockTransport(handler)),
        "http://127.0.0.1:8001",
        config,
    )
    assert finding.verification_status == "confirmed"
    assert finding.confidence == "high"
    assert finding.response_status == 200
    assert len(seen) == 2 and seen[0] != seen[1]
    assert "test-token" not in finding.model_dump_json()


def test_two_identity_test_is_inconclusive_when_owner_marker_differs():
    tokens = iter(("Bearer owner", "Bearer other"))

    def handler(request):
        token = next(tokens)
        if token == "Bearer other":
            return httpx.Response(200, json={"owner": {"id": "somebody-else"}})
        return httpx.Response(200, json={"owner": {"id": "known-owner"}})

    from scanner.bola_verification import BOLAConfig

    result = verify_bola(
        httpx.Client(transport=httpx.MockTransport(handler)),
        "http://127.0.0.1:8001",
        BOLAConfig("owner", "other", "http://127.0.0.1:8001/object/1", "owner.id", "known-owner"),
    )
    assert result.verification_status == "inconclusive"


def test_two_identity_test_is_inconclusive_without_authorized_owner_ground_truth():
    from scanner.bola_verification import BOLAConfig

    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"id": "1"})))
    finding = verify_bola(
        client,
        "http://127.0.0.1:8001",
        BOLAConfig("owner", "other", "http://127.0.0.1:8001/object/1", "owner.id", "known-owner"),
    )
    assert finding.verification_status == "inconclusive"


def test_second_identity_success_without_owner_semantics_is_inconclusive():
    from scanner.bola_verification import BOLAConfig

    responses = iter(
        (
            httpx.Response(200, json={"owner": {"id": "known-owner"}}),
            httpx.Response(200, json={"message": "ok"}),
        )
    )
    client = httpx.Client(transport=httpx.MockTransport(lambda request: next(responses)))
    finding = verify_bola(
        client,
        "http://127.0.0.1:8001",
        BOLAConfig("owner", "other", "http://127.0.0.1:8001/object/1", "owner.id", "known-owner"),
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
            }
        )
    )
    import pytest

    with pytest.raises(ValueError, match="distinct"):
        load_bola_config(config_path)
