"""How the hub knows a sensor event came from one of our sidecars, and once.

The contract, shared with `honeypot-ecosystem/shared/sidecar/shipper.py`:

    X-Timestamp   when the request was signed, in whole Unix seconds
    X-Event-Id    the event's id: unique per event, the same on every retry
    X-Signature   hex HMAC-SHA256 over  b"<timestamp>.<event id>." + body

Signing only the body proved who sent an event but not when, or how many
times. A request captured anywhere between the sidecar and the hub could be
sent again and was accepted every time, and the sidecar's own at-least-once
retries ingested the same event twice whenever a response was lost.

Each field closes part of that:

* The timestamp bounds how long a captured request is worth anything. One
  signed further than `ingest_clock_skew_seconds` from the hub's clock is
  refused.
* The event id closes the window the timestamp leaves open. The receiver
  records every accepted id in Redis for longer than that window, so a replay
  inside it is refused as already seen -- and so is a retry of an event that
  did land, which is what makes at-least-once delivery ingest each event once.
* Both are inside the signature, so neither can be changed to dodge the
  checks. Neither may contain ".", the separator: if they could, bytes could
  be moved between the id and the body without changing what was signed.

This module is pure -- no FastAPI, no Redis -- so the scheme can be tested on
fixed input. The receiver turns `Rejected` into an HTTP response.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import time
from collections.abc import Mapping

TIMESTAMP_HEADER = "X-Timestamp"
EVENT_ID_HEADER = "X-Event-Id"
SIGNATURE_HEADER = "X-Signature"

_TIMESTAMP = re.compile(r"[0-9]{1,12}")
_EVENT_ID = re.compile(r"[A-Za-z0-9_-]{16,128}")
_SIGNATURE = re.compile(r"[0-9a-fA-F]{64}")


class Rejected(Exception):
    """A request the hub will not accept, and the status that says why.

    401 means "not proven to be from a sidecar, now"; 400 means the request
    is malformed. Neither is retried successfully by sending the same bytes.
    """

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


def signing_input(timestamp: str, event_id: str, body: bytes) -> bytes:
    """The exact bytes the signature covers."""
    return f"{timestamp}.{event_id}.".encode() + body


def sign(secret: str, timestamp: str, event_id: str, body: bytes) -> str:
    return hmac.new(
        secret.encode(), signing_input(timestamp, event_id, body), hashlib.sha256
    ).hexdigest()


def content_event_id(body: bytes) -> str:
    """The id the sidecar gives an event: the start of its body's SHA-256.

    Used here only for legacy body-only requests, which carry no id. Deriving
    it the same way means a legacy delivery and a later retry of the same
    event under the new scheme are recognised as one event.
    """
    return hashlib.sha256(body).hexdigest()[:32]


def _signature_matches(expected: str, supplied: str) -> bool:
    # Checked for shape first: compare_digest raises on non-ASCII strings,
    # and a header full of junk should be a 401, not a 500.
    return bool(_SIGNATURE.fullmatch(supplied)) and hmac.compare_digest(
        expected, supplied.lower()
    )


def authenticate(
    headers: Mapping[str, str],
    body: bytes,
    *,
    secret: str,
    clock_skew: int,
    allow_legacy: bool = False,
    now: float | None = None,
) -> str:
    """Check one sensor request and return the event id to deduplicate on.

    Raises `Rejected` for anything that is not a correctly signed, current
    request. Whether the id has been seen before is the caller's question:
    answering it needs Redis.
    """
    signature = headers.get(SIGNATURE_HEADER) or ""
    timestamp = headers.get(TIMESTAMP_HEADER)
    event_id = headers.get(EVENT_ID_HEADER)

    if not signature:
        raise Rejected(401, f"Missing {SIGNATURE_HEADER}")

    if timestamp is None and event_id is None:
        # A sidecar from before the timestamped scheme. Accepted only while
        # an operator has explicitly opted in for a rolling upgrade: with no
        # timestamp, nothing stops a captured request being replayed once
        # its id has expired from Redis.
        if not allow_legacy:
            raise Rejected(
                401,
                f"{TIMESTAMP_HEADER} and {EVENT_ID_HEADER} are required. Body-only "
                "signatures are no longer accepted; update the sidecar.",
            )
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        if not _signature_matches(expected, signature):
            raise Rejected(401, "Invalid HMAC signature")
        return content_event_id(body)

    if timestamp is None or event_id is None:
        raise Rejected(401, f"{TIMESTAMP_HEADER} and {EVENT_ID_HEADER} must be sent together")
    if not _TIMESTAMP.fullmatch(timestamp):
        raise Rejected(400, f"{TIMESTAMP_HEADER} must be whole Unix seconds")
    if not _EVENT_ID.fullmatch(event_id):
        raise Rejected(400, f"{EVENT_ID_HEADER} must be 16-128 characters of A-Z a-z 0-9 _ -")

    if not _signature_matches(sign(secret, timestamp, event_id, body), signature):
        raise Rejected(401, "Invalid HMAC signature")

    # After the signature, so the timestamp being judged is known to be the
    # one the sidecar signed, and the advice about clocks is accurate.
    skew = abs((time.time() if now is None else now) - int(timestamp))
    if skew > clock_skew:
        raise Rejected(
            401,
            f"{TIMESTAMP_HEADER} is {int(skew)}s from the hub's clock, outside the "
            f"{clock_skew}s window. Either a clock is wrong or this is a replay.",
        )
    return event_id
