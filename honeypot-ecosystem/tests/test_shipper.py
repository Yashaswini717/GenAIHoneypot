"""Signing and delivery tests for the shipper.

The sidecar is the only holder of the signing key, so what it signs and how
it reads the hub's answers decide whether the zero-trust claim holds:

* Every attempt is signed over a timestamp, an event id and the body, the
  scheme the hub verifies (`intelligence_hub/backend/ingest/signing.py`). The
  shared vector below is asserted on the hub side too.
* The event id is derived from the event's bytes, so a retry after a lost
  response is recognised by the hub (409) and dropped as delivered, instead of
  being ingested twice.
* A 4xx about the event dead-letters it. It used to be retried forever, and
  because the spool drain stops at the first failure, one malformed event
  held back every event spooled behind it.
* A 401 is retried, not dead-lettered: with a fresh signature per attempt it
  can only mean a wrong secret or clock, which applies to every event alike.

The hub is faked with httpx.MockTransport, verifying the scheme independently.

Run with:  pytest honeypot-ecosystem/tests/ -v
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sys
import time
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared" / "sidecar"))

import shipper  # noqa: E402
from shipper import Outcome, ShipperConfig, classify, event_id_for, sign, signed_headers  # noqa: E402

SECRET = "sidecar-test-secret"

# Asserted against the hub's sign() in intelligence_hub/tests/test_ingest.py.
VECTOR_SECRET = "test-vector-secret"
VECTOR_TIMESTAMP = "1700000000"
VECTOR_EVENT_ID = "0123456789abcdef0123456789abcdef"
VECTOR_BODY = b'{"eventid":"cowrie.session.connect","session":"a1b2c3d4e5f6"}'
VECTOR_SIGNATURE = "1a92635e611899a732801a51e65eddf1038cf14b6a532f8cd0140bfbdd1cc4db"
VECTOR_CONTENT_ID = "50269379b856988113c218b0c20e9f5e"


def event(**changes) -> bytes:
    base = {
        "eventid": "cowrie.command.input",
        "session": "a1b2c3d4e5f6",
        "src_ip": "203.0.113.7",
        "sensor": "node-01-jump",
        "timestamp": "2026-11-01T10:00:00.000000Z",
        "input": "uname -a",
    }
    return json.dumps({**base, **changes}).encode()


@pytest.fixture
def configured(monkeypatch, tmp_path):
    cfg = ShipperConfig(
        hub_url="http://hub",
        hmac_secret=SECRET,
        event_path=tmp_path / "events.ndjson",
        state_path=tmp_path / "state" / "offset.json",
        spool_dir=tmp_path / "pending",
        dead_letter_dir=tmp_path / "dead-letter",
        brain_enabled=False,
    )
    monkeypatch.setattr(shipper, "config", cfg)
    return cfg


def lines_of(*bodies: bytes) -> list[shipper.Line]:
    """Bodies as read_new_lines() returns them, at made-up offsets."""
    lines, end = [], 0
    for body in bodies:
        end += len(body) + 1
        lines.append(shipper.Line(body, end))
    return lines


class Crash(BaseException):
    """The sidecar dying mid-send. Nothing in the shipper catches it, just as
    nothing catches a SIGKILL."""


class FakeHub:
    """Verifies the scheme the way the hub does, and remembers event ids.

    `script` lets a test decide the answer for particular events; anything
    else is verified, deduplicated and stored.
    """

    def __init__(self, skew: int = 300) -> None:
        self.skew = skew
        self.seen: set[str] = set()
        self.stored: list[bytes] = []
        self.attempts: list[dict[str, str]] = []
        self.script: dict[bytes, int] = {}
        self.lose_next_response = False
        self.crash_on: bytes | None = None     # the sidecar dies sending this
        self.crash_after: bytes | None = None  # ...or right after the hub stored it

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = request.content
        headers = {k: request.headers[k] for k in ("x-timestamp", "x-event-id", "x-signature")}
        self.attempts.append(headers)
        if body == self.crash_on:
            raise Crash("the sidecar died before the hub had this")
        if body in self.script:
            return httpx.Response(self.script[body], json={"detail": "scripted"})

        ts, event_id = headers["x-timestamp"], headers["x-event-id"]
        message = f"{ts}.{event_id}.".encode() + body
        expected = hmac.new(SECRET.encode(), message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, headers["x-signature"]):
            return httpx.Response(401, json={"detail": "Invalid HMAC signature"})
        if abs(time.time() - int(ts)) > self.skew:
            return httpx.Response(401, json={"detail": "outside the window"})
        if event_id in self.seen:
            return httpx.Response(409, json={"detail": "already ingested"})

        self.seen.add(event_id)
        self.stored.append(body)
        if body == self.crash_after:
            raise Crash("the sidecar died before hearing the hub had this")
        if self.lose_next_response:
            self.lose_next_response = False
            raise httpx.ReadTimeout("response lost after the hub stored the event")
        return httpx.Response(200, json={"status": "ok"})


def run_with(hub: FakeHub, scenario):
    """Run `scenario(shipper)` against `hub`, closing everything afterwards."""

    async def main():
        s = shipper.Shipper()
        s.client = httpx.AsyncClient(transport=httpx.MockTransport(hub.handler))
        try:
            await scenario(s)
            return s
        finally:
            await s.close()

    return asyncio.run(main())


# --------------------------------------------------------------------------
# signing
# --------------------------------------------------------------------------


def test_signature_matches_the_vector_shared_with_the_hub(monkeypatch):
    monkeypatch.setattr(shipper, "config", ShipperConfig(hmac_secret=VECTOR_SECRET))
    assert sign(VECTOR_BODY, VECTOR_TIMESTAMP, VECTOR_EVENT_ID) == VECTOR_SIGNATURE
    assert event_id_for(VECTOR_BODY) == VECTOR_CONTENT_ID


def test_each_attempt_is_signed_afresh_under_the_same_event_id(configured):
    body = event()
    first = signed_headers(body, now=1_800_000_000)
    later = signed_headers(body, now=1_800_003_600)

    assert first["X-Event-Id"] == later["X-Event-Id"] == event_id_for(body)
    assert first["X-Timestamp"] == "1800000000"
    assert later["X-Timestamp"] == "1800003600"
    assert first["X-Signature"] != later["X-Signature"]
    assert first["X-Signature"] == sign(body, "1800000000", event_id_for(body))


def test_distinct_events_get_distinct_ids():
    assert event_id_for(event()) != event_id_for(event(input="id"))
    assert event_id_for(event()) != event_id_for(event(timestamp="2026-11-01T10:00:00.000001Z"))


# --------------------------------------------------------------------------
# reading the hub's answer
# --------------------------------------------------------------------------


@pytest.mark.parametrize("status", [200, 201, 202, 204, 409])
def test_accepted_or_already_held_is_delivered(status):
    assert classify(status) is Outcome.DELIVERED


@pytest.mark.parametrize("status", [400, 410, 413, 415, 422])
def test_a_complaint_about_the_event_is_rejected(status):
    assert classify(status) is Outcome.REJECTED


@pytest.mark.parametrize("status", [301, 303, 307, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504])
def test_a_problem_with_the_connection_is_retried(status):
    assert classify(status) is Outcome.RETRY


# --------------------------------------------------------------------------
# delivery
# --------------------------------------------------------------------------


def test_a_signed_event_is_accepted_by_a_verifying_hub(configured):
    hub = FakeHub()

    async def scenario(s):
        result = await s.deliver(event())
        assert result.outcome is Outcome.DELIVERED

    s = run_with(hub, scenario)
    assert hub.stored == [event()]
    assert s.delivered == 1


def test_a_retry_after_a_lost_response_is_not_ingested_twice(configured):
    hub = FakeHub()
    hub.lose_next_response = True

    async def scenario(s):
        await s.ship(lines_of(event()))  # stored, but the answer never came
        assert s.spool.depth == 1
        await s.drain_spool()            # resent: 409, dropped as delivered

    s = run_with(hub, scenario)
    assert hub.stored == [event()]
    assert s.spool.depth == 0
    assert s.duplicates == 1
    ids = {a["x-event-id"] for a in hub.attempts}
    assert ids == {event_id_for(event())}


def test_a_rejected_event_is_dead_lettered_and_does_not_block_the_spool(configured):
    hub = FakeHub()
    bad, good = event(input="bad"), event(input="good")
    hub.script[bad] = 422

    async def scenario(s):
        s.spool.add(bad)
        time.sleep(0.002)  # spool names sort by millisecond
        s.spool.add(good)
        await s.drain_spool()

    s = run_with(hub, scenario)
    assert hub.stored == [good]
    assert s.spool.pending() == []
    [dead] = s.dead.pending()
    assert dead.read_bytes() == bad
    reason = json.loads(dead.with_name(dead.stem + ".reason.json").read_text(encoding="utf-8"))
    assert reason["reason"].startswith("422")
    assert s.dead_lettered == 1


def test_a_rejected_live_event_is_dead_lettered_not_spooled(configured):
    hub = FakeHub()
    bad = event(input="bad")
    hub.script[bad] = 400

    s = run_with(hub, lambda s: s.ship(lines_of(bad, event())))
    assert s.spool.depth == 0
    assert len(s.dead.pending()) == 1
    assert hub.stored == [event()]


def test_while_the_hub_is_down_the_drain_stops_in_order(configured):
    hub = FakeHub()
    first, second = event(input="first"), event(input="second")
    hub.script[first] = 503

    async def scenario(s):
        s.spool.add(first)
        time.sleep(0.002)
        s.spool.add(second)
        await s.drain_spool()

    s = run_with(hub, scenario)
    assert len(hub.attempts) == 1  # stopped at the first, so order holds
    assert s.spool.depth == 2
    assert s.dead.pending() == []


def test_a_wrong_secret_holds_events_rather_than_dead_lettering_them(configured, monkeypatch):
    hub = FakeHub()
    monkeypatch.setattr(shipper, "config", ShipperConfig(**{**configured.__dict__, "hmac_secret": "rotated"}))

    s = run_with(hub, lambda s: s.ship(lines_of(event(), event(input="id"))))
    # Fixing the secret drains these by themselves; dead letters would need a person.
    assert s.spool.depth == 2
    assert s.dead.pending() == []
    assert hub.stored == []


def test_a_spooled_event_is_resigned_when_it_is_retried(configured, monkeypatch):
    hub = FakeHub(skew=10**9)  # accept any timestamp; this test reads them
    hub.script[event()] = 503
    # Only the signing clock: the spool and httpx read time.time() too.
    clock = iter([1_800_000_000.0, 1_800_000_090.0])
    real = shipper.signed_headers
    monkeypatch.setattr(shipper, "signed_headers", lambda body: real(body, now=next(clock)))

    async def scenario(s):
        await s.ship(lines_of(event()))
        del hub.script[event()]
        await s.drain_spool()

    run_with(hub, scenario)
    first, retry = hub.attempts
    assert first["x-event-id"] == retry["x-event-id"]
    assert first["x-timestamp"] == "1800000000"
    assert retry["x-timestamp"] == "1800000090"


# --------------------------------------------------------------------------
# the read offset
# --------------------------------------------------------------------------
#
# It used to be saved as soon as a batch was read, before any of it was sent,
# so a crash in between lost the batch: past the offset, in no spool. It now
# moves past an event only once that event is delivered, spooled or
# dead-lettered.


def write_events(cfg, *bodies: bytes) -> None:
    cfg.event_path.write_bytes(b"".join(body + b"\n" for body in bodies))


def saved_offset(cfg) -> int:
    return json.loads(cfg.state_path.read_text(encoding="utf-8"))["offset"]


def test_a_crash_mid_batch_loses_nothing(configured):
    hub = FakeHub()
    events = [event(input=cmd) for cmd in ("whoami", "id", "uname -a")]
    write_events(configured, *events)
    hub.crash_on = events[1]

    async def first_life(s):
        with pytest.raises(Crash):
            await s.ship(await s.read_new_lines())

    run_with(hub, first_life)
    assert hub.stored == events[:1]
    hub.crash_on = None

    async def second_life(s):
        lines = await s.read_new_lines()
        # The old code saved the offset past all three on read: this was [].
        assert [line.body for line in lines] == events[1:]
        await s.ship(lines)

    s = run_with(hub, second_life)
    assert hub.stored == events
    assert s.duplicates == 0
    assert saved_offset(configured) == configured.event_path.stat().st_size


def test_an_event_that_landed_just_before_a_crash_is_not_stored_twice(configured):
    hub = FakeHub()
    events = [event(input="whoami"), event(input="id")]
    write_events(configured, *events)
    hub.crash_after = events[0]  # stored by the hub; the sidecar never heard

    async def first_life(s):
        with pytest.raises(Crash):
            await s.ship(await s.read_new_lines())

    run_with(hub, first_life)
    hub.crash_after = None

    async def second_life(s):
        await s.ship(await s.read_new_lines())

    s = run_with(hub, second_life)
    assert hub.stored == events  # each exactly once
    assert s.duplicates == 1     # events[0], read again and answered 409
    assert s.delivered == 1


def test_an_error_mid_batch_does_not_skip_the_rest(configured, monkeypatch):
    """Not only crashes: the run loop survives an exception and reads again."""
    hub = FakeHub()
    events = [event(input="whoami"), event(input="id")]
    write_events(configured, *events)
    hub.script[events[0]] = 503

    async def scenario(s):
        def disk_full(body):
            raise OSError("No space left on device")

        monkeypatch.setattr(s.spool, "add", disk_full)
        with pytest.raises(OSError):
            await s.ship(await s.read_new_lines())
        again = await s.read_new_lines()
        assert [line.body for line in again] == events

    run_with(hub, scenario)


def test_blank_lines_are_stepped_over_and_a_partial_line_waits(configured):
    hub = FakeHub()
    events = [event(input="whoami"), event(input="id")]
    partial = b'{"eventid": "cowrie.comm'
    configured.event_path.write_bytes(b"\n" + events[0] + b"\n\n\n" + events[1] + b"\n\n" + partial)

    async def scenario(s):
        lines = await s.read_new_lines()
        assert [line.body for line in lines] == events
        await s.ship(lines)
        # Everything up to the partial line, which the proxy is still writing.
        assert saved_offset(configured) == configured.event_path.stat().st_size - len(partial)
        assert await s.read_new_lines() == []

    run_with(hub, scenario)
    assert hub.stored == events


def test_a_run_of_blank_lines_is_not_read_forever(configured):
    configured.event_path.write_bytes(b"\n\n  \n")

    async def scenario(s):
        assert await s.read_new_lines() == []
        assert saved_offset(configured) == 5
        assert await s.read_new_lines() == []

    run_with(FakeHub(), scenario)
