"""Ingest tests: what the hub accepts, what it refuses, and what it counts.

The zero-trust claim is only as good as these paths, and each gap they close
was silent while open:

1. Replay. The signature covered the body alone, so a captured request was
   accepted every time it was sent, and a sidecar retry after a lost response
   stored the event twice.
2. `/ingest/batch` accepted unsigned events from anyone by default, and what
   it stored was indistinguishable from live attacker sessions.
3. HMAC_SECRET=dev switched verification off without a word.
4. A malformed event answered 500, which the sidecar retries forever.

Redis and the stores are faked (`hubfakes`), so these run without services.

Run with:  pytest intelligence_hub/tests/ -v
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from analytics.retention import build_visits, is_live
from config import Settings, settings
from hubfakes import DROP, event_body, signed, stores  # noqa: F401  (stores is a fixture)
from ingest.signing import Rejected, authenticate, content_event_id, sign

SECRET = settings.hmac_secret
SKEW = settings.ingest_clock_skew_seconds
NOW = 1_800_000_000.0

# The same vector is asserted by honeypot-ecosystem/tests/test_shipper.py
# against the sidecar's sign(). Both passing is what says they agree.
VECTOR_SECRET = "test-vector-secret"
VECTOR_TIMESTAMP = "1700000000"
VECTOR_EVENT_ID = "0123456789abcdef0123456789abcdef"
VECTOR_BODY = b'{"eventid":"cowrie.session.connect","session":"a1b2c3d4e5f6"}'
VECTOR_SIGNATURE = "1a92635e611899a732801a51e65eddf1038cf14b6a532f8cd0140bfbdd1cc4db"
VECTOR_CONTENT_ID = "50269379b856988113c218b0c20e9f5e"


def check(headers, body=None, **kwargs):
    body = event_body() if body is None else body
    return authenticate(headers, body, secret=SECRET, clock_skew=SKEW, now=NOW, **kwargs)


def client_for(stores) -> TestClient:
    # A 500 should come back as a response, as it does for the sidecar.
    return TestClient(stores.app, raise_server_exceptions=False)


def ingest_keys(stores) -> list[str]:
    return [key for key in stores.redis.values if key.startswith("ingest:event:")]


# --------------------------------------------------------------------------
# the signing scheme
# --------------------------------------------------------------------------


def test_signature_matches_the_vector_shared_with_the_sidecar():
    assert sign(VECTOR_SECRET, VECTOR_TIMESTAMP, VECTOR_EVENT_ID, VECTOR_BODY) == VECTOR_SIGNATURE
    assert content_event_id(VECTOR_BODY) == VECTOR_CONTENT_ID


def test_a_signed_current_request_is_accepted():
    body = event_body()
    assert check(signed(body, ts=NOW), body) == content_event_id(body)


@pytest.mark.parametrize("tamper", ["body", "timestamp", "event_id"])
def test_the_signature_covers_body_timestamp_and_event_id(tamper):
    body = event_body()
    headers = signed(body, ts=NOW)
    if tamper == "body":
        body = event_body(input="rm -rf /")
    elif tamper == "timestamp":
        headers["X-Timestamp"] = str(int(NOW) - 1)
    else:
        headers["X-Event-Id"] = "f" * 32
    with pytest.raises(Rejected) as caught:
        check(headers, body)
    assert caught.value.status == 401


@pytest.mark.parametrize("offset", [SKEW + 1, -(SKEW + 1), 3600, -3600])
def test_a_timestamp_outside_the_window_is_refused(offset):
    body = event_body()
    with pytest.raises(Rejected) as caught:
        check(signed(body, ts=NOW + offset), body)
    assert caught.value.status == 401
    assert "window" in caught.value.detail


@pytest.mark.parametrize("offset", [SKEW, -SKEW, 0])
def test_a_timestamp_inside_the_window_is_accepted(offset):
    body = event_body()
    assert check(signed(body, ts=NOW + offset), body)


@pytest.mark.parametrize("missing", [["X-Signature"], ["X-Timestamp"], ["X-Event-Id"]])
def test_missing_headers_are_refused(missing):
    body = event_body()
    headers = {k: v for k, v in signed(body, ts=NOW).items() if k not in missing}
    with pytest.raises(Rejected) as caught:
        check(headers, body)
    assert caught.value.status == 401


def test_a_legacy_body_only_signature_is_refused_by_default():
    import hashlib
    import hmac

    body = event_body()
    legacy = {"X-Signature": hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()}
    with pytest.raises(Rejected) as caught:
        check(legacy, body)
    assert caught.value.status == 401
    # Opted into for a rolling upgrade: deduplicated on the sidecar's own id
    # derivation, so a later retry under the new scheme is the same event.
    assert check(legacy, body, allow_legacy=True) == content_event_id(body)


@pytest.mark.parametrize("header,value", [
    ("X-Timestamp", "soon"),
    ("X-Timestamp", "-5"),
    ("X-Timestamp", "1.5"),
    ("X-Event-Id", "short"),
    # "." is the separator in what is signed: allowing it in the id would let
    # bytes move between the id and the body under the same signature.
    ("X-Event-Id", "0123456789abcdef.0123456789abcdef"),
])
def test_malformed_signing_headers_are_a_bad_request(header, value):
    body = event_body()
    headers = signed(body, ts=NOW)
    headers[header] = value
    with pytest.raises(Rejected) as caught:
        check(headers, body)
    assert caught.value.status == 400


@pytest.mark.parametrize("junk", ["zz" * 32, "é" * 64, "abc", ""])
def test_a_junk_signature_is_a_401_not_a_crash(junk):
    body = event_body()
    headers = signed(body, ts=NOW)
    headers["X-Signature"] = junk
    with pytest.raises(Rejected) as caught:
        check(headers, body)
    assert caught.value.status == 401


# --------------------------------------------------------------------------
# POST /ingest/: each event once
# --------------------------------------------------------------------------


def test_a_signed_event_is_ingested_and_tagged_as_a_sensor_event(stores):
    body = event_body()
    response = client_for(stores).post("/ingest/", content=body, headers=signed(body))

    assert response.status_code == 200, response.text
    assert len(stores.indexed) == 1
    assert stores.indexed[0]["source"] == "sensor"
    assert stores.db.sessions["a1b2c3d4e5f6"].source == "sensor"
    key = f"ingest:event:{content_event_id(body)}"
    assert stores.redis.values[key] == "done"
    assert stores.redis.ttls[key] == settings.dedup_ttl_seconds


def test_replaying_a_captured_request_is_refused(stores):
    client = client_for(stores)
    body = event_body()
    headers = signed(body)

    assert client.post("/ingest/", content=body, headers=headers).status_code == 200
    replay = client.post("/ingest/", content=body, headers=headers)

    assert replay.status_code == 409
    assert len(stores.indexed) == 1


def test_a_sidecar_retry_after_a_lost_response_is_not_stored_twice(stores):
    """Re-signed later with a fresh timestamp, as the sidecar's spool does."""
    client = client_for(stores)
    body = event_body()

    assert client.post("/ingest/", content=body, headers=signed(body)).status_code == 200
    retry = client.post("/ingest/", content=body, headers=signed(body, ts=time.time() + 30))

    assert retry.status_code == 409  # the sidecar counts this as delivered
    assert len(stores.indexed) == 1


def test_a_captured_request_goes_stale(stores):
    body = event_body()
    old = signed(body, ts=time.time() - SKEW - 60)
    response = client_for(stores).post("/ingest/", content=body, headers=old)

    assert response.status_code == 401
    assert stores.indexed == []
    assert ingest_keys(stores) == []


def test_the_seen_record_always_outlives_the_clock_window(monkeypatch):
    # A replay can carry an acceptable timestamp for up to two windows after
    # the original was accepted, so a shorter memory would let it through.
    monkeypatch.setattr(settings, "ingest_dedup_ttl_seconds", 10)
    assert settings.dedup_ttl_seconds == 2 * SKEW


def test_a_wrong_secret_is_refused(stores):
    body = event_body()
    response = client_for(stores).post("/ingest/", content=body, headers=signed(body, secret="not-the-secret"))
    assert response.status_code == 401
    assert stores.indexed == []


def test_a_failed_ingest_releases_its_claim_so_the_retry_lands(stores):
    client = client_for(stores)
    body = event_body()
    stores.fail_next_index = True

    first = client.post("/ingest/", content=body, headers=signed(body))
    assert first.status_code == 500  # retryable: the sidecar keeps the event
    assert ingest_keys(stores) == []

    second = client.post("/ingest/", content=body, headers=signed(body))
    assert second.status_code == 200
    assert len(stores.indexed) == 1


def test_without_redis_the_hub_fails_closed(stores):
    stores.redis.down = True
    body = event_body()
    response = client_for(stores).post("/ingest/", content=body, headers=signed(body))

    assert response.status_code == 503  # retried by the sidecar, never stored blind
    assert stores.indexed == []


def test_a_copy_arriving_mid_ingest_is_told_to_retry(stores):
    body = event_body()
    stores.redis.values[f"ingest:event:{content_event_id(body)}"] = "processing"
    response = client_for(stores).post("/ingest/", content=body, headers=signed(body))

    # Not 409: the first copy may still fail, and then this one is needed.
    assert response.status_code == 503
    assert response.headers["retry-after"]
    assert stores.indexed == []


def test_a_failed_live_feed_publish_does_not_fail_a_stored_event(stores, monkeypatch):
    async def broken_publish(channel, message):
        raise ConnectionError("pub/sub gone")

    monkeypatch.setattr(stores.redis, "publish", broken_publish)
    body = event_body()
    response = client_for(stores).post("/ingest/", content=body, headers=signed(body))

    # A 500 here would make the sidecar resend an event that is already stored.
    assert response.status_code == 200
    assert len(stores.indexed) == 1


# --------------------------------------------------------------------------
# malformed events are the sender's problem: 4xx, never 500
# --------------------------------------------------------------------------


@pytest.mark.parametrize("body,expected", [
    (event_body(timestamp=DROP), 422),            # normalize() used to raise -> 500
    (event_body(timestamp="last tuesday"), 422),
    (event_body(src_port="ssh"), 422),
    (event_body(duration="forever"), 422),
    (event_body(src_ip="not-an-ip"), 422),        # Elasticsearch would refuse it -> 500
    (event_body(src_ip=DROP), 422),
    (event_body(dst_ip="example.com"), 422),
    (b"[1, 2, 3]", 422),
    (b'"just a string"', 422),
    (b"{not json", 400),
    (b"\xff\xfe\x00garbage", 400),
])
def test_a_malformed_event_is_a_4xx_and_stores_nothing(stores, body, expected):
    response = client_for(stores).post("/ingest/", content=body, headers=signed(body))

    assert response.status_code == expected, response.text
    assert stores.indexed == []
    assert stores.db.sessions == {}
    # The claim is withdrawn, so nothing about this id lingers in Redis.
    assert ingest_keys(stores) == []


# --------------------------------------------------------------------------
# HMAC_SECRET=dev
# --------------------------------------------------------------------------


def make_settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)


@pytest.mark.parametrize("secret", ["dev", "change-me", "", "  dev  "])
def test_the_hub_refuses_to_start_with_a_published_secret(secret):
    with pytest.raises(ValidationError) as caught:
        make_settings(hmac_secret=secret)
    assert "INSECURE_DEV_MODE" in str(caught.value)


def test_insecure_dev_mode_is_explicit_and_only_dev_disables_checks():
    dev = make_settings(hmac_secret="dev", insecure_dev_mode=True)
    assert dev.signatures_disabled

    placeholder = make_settings(hmac_secret="change-me", insecure_dev_mode=True)
    assert not placeholder.signatures_disabled  # weak, but still verified

    real = make_settings(hmac_secret="a-real-secret", insecure_dev_mode=True)
    assert not real.signatures_disabled


def test_in_insecure_dev_mode_unsigned_events_are_accepted(stores, monkeypatch):
    monkeypatch.setattr(settings, "hmac_secret", "dev")
    monkeypatch.setattr(settings, "insecure_dev_mode", True)
    body = event_body()

    response = client_for(stores).post("/ingest/", content=body)
    assert response.status_code == 200


def test_a_real_secret_is_verified_even_with_the_flag_set(stores, monkeypatch):
    monkeypatch.setattr(settings, "insecure_dev_mode", True)
    body = event_body()

    response = client_for(stores).post("/ingest/", content=body)
    assert response.status_code == 401


# --------------------------------------------------------------------------
# POST /ingest/batch: the operator path
# --------------------------------------------------------------------------

TOKEN = "operator-token-for-tests-0123456789"


@pytest.fixture
def operator(monkeypatch):
    monkeypatch.setattr(settings, "operator_token", TOKEN)
    return {"Authorization": f"Bearer {TOKEN}"}


def upload(stores, *bodies, headers=None):
    return client_for(stores).post("/ingest/batch", content=b"\n".join(bodies), headers=headers or {})


def test_unsigned_uploads_are_off_by_default():
    defaults = make_settings(hmac_secret="a-real-secret")
    assert defaults.allow_unsigned_batch is False
    assert defaults.operator_token == ""


def test_with_no_operator_token_configured_uploads_are_disabled(stores):
    response = upload(stores, event_body())
    assert response.status_code == 403
    assert "OPERATOR_TOKEN" in response.json()["detail"]
    assert stores.indexed == []


@pytest.mark.parametrize("headers", [
    {},
    {"Authorization": "Bearer wrong-token-wrong-token"},
    {"Authorization": f"Basic {TOKEN}"},
    {"Authorization": f"Bearer {TOKEN}x"},
])
def test_uploads_need_the_operator_token(stores, operator, headers):
    response = upload(stores, event_body(), headers=headers)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert stores.indexed == []


def test_an_upload_is_tagged_and_kept_apart_from_live_sessions(stores, operator):
    response = upload(stores, event_body(), event_body(input="id"), headers=operator)

    assert response.status_code == 200, response.text
    data = response.json()
    assert data["processed"] == 2
    assert data["source"] == "operator_upload"
    assert {r["session"] for r in data["results"]} == {"upload-a1b2c3d4e5f6"}
    assert all(e["source"] == "operator_upload" for e in stores.indexed)
    assert stores.db.sessions["upload-a1b2c3d4e5f6"].source == "operator_upload"
    assert "a1b2c3d4e5f6" not in stores.db.sessions


def test_an_upload_cannot_rewrite_a_live_session(stores, operator):
    """Uploading the honeypot's own log must not touch the sessions it recorded."""
    client = client_for(stores)
    live = event_body()
    assert client.post("/ingest/", content=live, headers=signed(live)).status_code == 200
    before = stores.db.sessions["a1b2c3d4e5f6"]
    count_before = before.event_count

    upload(stores, live, event_body(attacker="198.51.100.9"), headers=operator)

    assert stores.db.sessions["a1b2c3d4e5f6"] is before
    assert before.event_count == count_before
    assert before.attacker_id == "203.0.113.7"


def test_uploaded_sessions_never_reach_the_retention_figures(stores, operator):
    client = client_for(stores)
    live = event_body()
    assert client.post("/ingest/", content=live, headers=signed(live)).status_code == 200
    upload(stores, event_body(session="ffffffffffff", src_ip="198.51.100.9", attacker=DROP), headers=operator)

    # Shaped exactly as api/retention.py's query returns them.
    rows = [
        {
            "attacker": s.attacker_id or s.src_ip,
            "adaptive": True if s.adaptive is None else s.adaptive,
            "sensor_id": s.sensor_id,
            "started_at": s.started_at,
            "ended_at": s.ended_at or s.started_at,
            "event_count": s.event_count or 0,
            "threat_score": s.threat_score or 0,
            "source": s.source or "sensor",
        }
        for s in stores.db.sessions.values()
    ]
    assert len(rows) == 2
    visits = build_visits(rows)
    assert [v["attacker"] for v in visits] == ["203.0.113.7"]


def test_is_live_only_admits_sensor_sessions():
    assert is_live({"source": "sensor"})
    assert is_live({})  # the query always supplies one; older fixtures have none
    assert not is_live({"source": "operator_upload"})
    assert not is_live({"source": "anything-else"})


def test_a_bad_line_in_an_upload_is_reported_not_fatal(stores, operator):
    response = upload(stores, event_body(), event_body(timestamp=DROP), b"{nope", headers=operator)

    assert response.status_code == 200
    results = response.json()["results"]
    assert [("error" in r) for r in results] == [False, True, True]
    assert len(stores.indexed) == 1


def test_the_deprecated_flag_still_allows_tokenless_uploads_and_still_tags(stores, monkeypatch):
    monkeypatch.setattr(settings, "allow_unsigned_batch", True)
    response = upload(stores, event_body())

    assert response.status_code == 200
    assert stores.indexed[0]["source"] == "operator_upload"


def test_a_short_operator_token_is_refused():
    with pytest.raises(ValidationError):
        make_settings(hmac_secret="a-real-secret", operator_token="hunter2")
