"""Signs telemetry and ships it to the intelligence hub.

This process is the reason the zero-trust claim is real rather than
decorative. It runs in the control plane, on the other side of the trust
boundary from every node, and it is the only thing in the ecosystem that
holds the HMAC signing key. Nothing an attacker can reach can produce a valid
signature, and nothing they can reach can tamper with an event, or replay
one, without the hub refusing it.

It tails the NDJSON the SSH proxy writes and streams events to the hub one at
a time, POSTing each to `/ingest/` with three headers -- matching
`intelligence_hub/backend/ingest/signing.py`:

    X-Timestamp   when this attempt was signed, in whole Unix seconds
    X-Event-Id    derived from the event's bytes, so the same on every retry
    X-Signature   hex HMAC-SHA256 over  b"<timestamp>.<event id>." + body

Signing the body alone proved who sent an event but not when, or how often:
a captured request could be sent again and was accepted every time. The hub
now refuses a timestamp outside a small window, and an event id it has
already ingested.

Why one event per request rather than batches
---------------------------------------------
`/ingest/batch` is the operator's upload path for the dashboard. It takes an
operator token instead of a signature, and everything sent through it is
tagged as an upload and kept out of the retention figures. Batching sensor
events through it would forfeit both the signature and their standing as
live evidence. Streaming single signed events keeps every event that reaches
the hub cryptographically verified as ours.

It also matches the requirement more honestly. "Every activity logged and sent
in real time" is not a batch every second, it is an event the moment it
happens, and it puts each event on the live WebSocket feed immediately.

Ordering is preserved by sending sequentially. That matters: the hub upserts a
session row on first sight, so `session.connect` has to arrive before the
commands belonging to it. Throughput is not a concern at honeypot volumes —
even heavy distributed brute force is a few tens of events per second.

Delivery is at-least-once and durable, and the hub makes it exactly-once in
effect. An event that cannot be delivered is written to a spool directory and
retried with backoff, so a hub restart costs latency rather than evidence.
Every retry carries the same event id, so when a response was lost after the
hub had stored the event, the retry is answered 409 and dropped as delivered.
An event the hub rejects as malformed goes to a dead-letter directory instead
of being retried, because retrying it can never succeed and would hold back
everything spooled behind it. The read offset is saved as each event is
handled, not when it is read, so a crash re-reads the event that was in
flight -- which the hub then recognises by its id -- instead of losing it.
"""

from __future__ import annotations

import asyncio
import enum
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import httpx

from brain_courier import BrainCourier
from watcher import EventWatcher

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("sidecar")


@dataclass(frozen=True)
class ShipperConfig:
    hub_url: str = os.environ.get("HUB_URL", "http://intelligence-hub:8000")
    hmac_secret: str = os.environ.get("HMAC_SECRET", "dev")
    event_path: Path = Path(os.environ.get("EVENT_PATH", "/var/spool/honeypot/events.ndjson"))
    state_path: Path = Path(os.environ.get("STATE_PATH", "/var/lib/sidecar/offset.json"))
    spool_dir: Path = Path(os.environ.get("SPOOL_DIR", "/var/lib/sidecar/pending"))
    #: Events the hub refused as malformed. They wait here for a person; move
    #: a file back into the spool directory to send it again.
    dead_letter_dir: Path = Path(os.environ.get("DEAD_LETTER_DIR", "/var/lib/sidecar/dead-letter"))

    #: Upper bound on how long we sit idle before re-checking. With inotify
    #: this is not the event latency -- events wake us immediately -- it only
    #: bounds how long a spooled batch waits before the next retry.
    flush_interval: float = float(os.environ.get("FLUSH_INTERVAL", "5.0"))
    request_timeout: float = float(os.environ.get("REQUEST_TIMEOUT", "15"))
    max_backoff: float = float(os.environ.get("MAX_BACKOFF", "60"))

    # -- the second branch of the fan-out ---------------------------------
    #
    # The same signed event that goes to the hub for analysis also goes to the
    # brain for adaptation, so the decoys change while the attacker is still
    # connected. The brain branch is queued and never blocks the hub branch.
    brain_url: str = os.environ.get("BRAIN_URL", "http://ai-brain:8000")
    broker_url: str = os.environ.get("BROKER_URL", "http://session-broker:8080")
    brain_enabled: bool = os.environ.get("BRAIN_ENABLED", "true").lower() != "false"


config = ShipperConfig()


# --------------------------------------------------------------------------
# signing
# --------------------------------------------------------------------------


def _describe(body: bytes) -> str:
    """A short label for one event, for the delivery log."""
    try:
        event = json.loads(body)
        eid = event.get("eventid", "?")
        session = event.get("session", "?")
        return f"{eid} [{session}]"
    except Exception:
        return f"{len(body)} bytes"


def event_id_for(body: bytes) -> str:
    """The id the hub deduplicates on: the start of the body's SHA-256.

    Derived rather than random, so it survives everything that can make us
    send an event twice -- a retry after a lost response, a spooled copy, a
    sidecar that lost its read offset and starts the file again -- and the
    hub ingests the event once each time. Distinct events cannot share bytes:
    each carries its session and a microsecond timestamp.
    """
    return hashlib.sha256(body).hexdigest()[:32]


def sign(body: bytes, timestamp: str, event_id: str) -> str:
    """HMAC-SHA256 over the timestamp, the event id and the exact body bytes.

    Signing the serialised body rather than the parsed event is what makes
    the signature meaningful: it covers precisely what crosses the wire, so
    any modification in transit invalidates it. The timestamp and id are
    inside it so that neither can be changed to slip a replay past the hub.
    """
    message = f"{timestamp}.{event_id}.".encode() + body
    return hmac.new(config.hmac_secret.encode(), message, hashlib.sha256).hexdigest()


def signed_headers(body: bytes, now: float | None = None) -> dict[str, str]:
    """Headers for one delivery attempt, signed at the moment of sending.

    The timestamp is when we send, not when the event happened: a spooled
    event retried an hour later is signed afresh, so the hub's clock window
    never rejects evidence for having waited out an outage.
    """
    timestamp = str(int(time.time() if now is None else now))
    event_id = event_id_for(body)
    return {
        "Content-Type": "application/json",
        "X-Timestamp": timestamp,
        "X-Event-Id": event_id,
        "X-Signature": sign(body, timestamp, event_id),
    }


# --------------------------------------------------------------------------
# what a response means
# --------------------------------------------------------------------------


class Outcome(enum.Enum):
    DELIVERED = "delivered"  # the hub has it, from this attempt or an earlier one
    RETRY = "retry"          # keep it, send it again later
    REJECTED = "rejected"    # the hub says the event is wrong; resending cannot help


#: 4xx answers that describe the connection rather than the event. They apply
#: to every event alike, so dead-lettering on them would empty the whole
#: stream into the dead-letter directory; they are retried instead.
#:
#:   401, 403  the secret or a clock is wrong. Each attempt is signed afresh,
#:             so nothing in one event's bytes can cause this -- and once the
#:             configuration is fixed, everything spooled meanwhile drains by
#:             itself. (bootstrap.py --force rotating the secret is the
#:             common cause; see the README.)
#:   404, 405  HUB_URL points at something that is not the hub's /ingest/.
#:   408, 429  a timeout and a rate limit: later, by definition.
RETRYABLE_4XX = frozenset({401, 403, 404, 405, 408, 429})


def classify(status: int) -> Outcome:
    # 409 is the hub saying it already has this event id: an earlier attempt
    # landed and only its response was lost.
    if 200 <= status < 300 or status == 409:
        return Outcome.DELIVERED
    if 400 <= status < 500 and status not in RETRYABLE_4XX:
        return Outcome.REJECTED
    return Outcome.RETRY


@dataclass(frozen=True)
class Delivery:
    outcome: Outcome
    reason: str = ""


# --------------------------------------------------------------------------
# durable read position
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Line:
    """One event as read from the event file."""

    body: bytes
    #: Offset just past this line, and any blank lines after it: where the
    #: read position moves once the event has been handled.
    end: int


class ReadPosition:
    """Where we got to, surviving restarts.

    Tracks the inode alongside the offset. Without that, a rotated or
    recreated event file looks like a truncation and we would either replay
    everything or skip to a stale offset in a brand new file.
    """

    def __init__(self, state_path: Path) -> None:
        self._path = state_path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self.offset = 0
        self.inode = 0
        self._load()

    def _load(self) -> None:
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            self.offset = int(data.get("offset", 0))
            self.inode = int(data.get("inode", 0))
        except Exception:
            log.warning("unreadable offset state, starting from the beginning", exc_info=True)

    def save(self) -> None:
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"offset": self.offset, "inode": self.inode}), encoding="utf-8")
        tmp.replace(self._path)  # atomic, so a crash mid-write cannot corrupt it

    def advance_to(self, offset: int) -> None:
        """Everything before `offset` is handled; remember that across restarts."""
        self.offset = offset
        self.save()

    def reset_for(self, inode: int) -> None:
        log.info("event file changed (inode %s -> %s), reading from the start", self.inode, inode)
        self.inode = inode
        self.offset = 0


# --------------------------------------------------------------------------
# spool
# --------------------------------------------------------------------------


def _spool_name() -> str:
    return f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}.ndjson"


class Spool:
    """Batches that could not be delivered yet.

    Evidence is the product here, so an unreachable hub must cost latency and
    nothing else.
    """

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._dir.mkdir(parents=True, exist_ok=True)

    def add(self, body: bytes) -> None:
        (self._dir / _spool_name()).write_bytes(body)

    def pending(self) -> list[Path]:
        return sorted(self._dir.glob("*.ndjson"))

    @property
    def depth(self) -> int:
        return len(self.pending())


class DeadLetters:
    """Events the hub refused as malformed, kept for a person to look at.

    Before this, one such event at the head of the spool was retried forever:
    the drain stopped at it every time, everything spooled behind it stayed
    undelivered, and the live stream slowed to the backoff interval. Each
    event is kept next to a `.reason.json` saying what the hub answered.
    Moving the `.ndjson` back into the spool directory sends it again.
    """

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._dir.mkdir(parents=True, exist_ok=True)

    def add(self, body: bytes, reason: str, name: str | None = None) -> Path:
        path = self._dir / (name or _spool_name())
        path.write_bytes(body)
        path.with_name(path.stem + ".reason.json").write_text(
            json.dumps({
                "reason": reason,
                "dead_lettered_at": datetime.now(timezone.utc).isoformat(),
            }),
            encoding="utf-8",
        )
        return path

    def pending(self) -> list[Path]:
        return sorted(self._dir.glob("*.ndjson"))


# --------------------------------------------------------------------------
# shipping
# --------------------------------------------------------------------------


class Shipper:
    def __init__(self) -> None:
        self.position = ReadPosition(config.state_path)
        self.spool = Spool(config.spool_dir)
        self.dead = DeadLetters(config.dead_letter_dir)
        self.client = httpx.AsyncClient(timeout=config.request_timeout)
        self.watcher = EventWatcher(config.event_path)
        self.courier = BrainCourier(
            brain_url=config.brain_url,
            broker_url=config.broker_url,
            enabled=config.brain_enabled,
        )
        self.delivered = 0
        self.duplicates = 0
        self.failed = 0
        self.dead_lettered = 0

    async def close(self) -> None:
        await self.client.aclose()
        await self.courier.close()
        self.watcher.close()

    async def deliver(self, body: bytes) -> Delivery:
        """POST one signed event to the zero-trust ingest path."""
        try:
            response = await self.client.post(
                f"{config.hub_url}/ingest/",
                content=body,
                headers=signed_headers(body),
            )
        except Exception as exc:
            log.warning("hub unreachable: %s", exc)
            return Delivery(Outcome.RETRY, f"unreachable: {exc}")

        # Only 2xx (and 409, "already have it") counts as accepted. Treating
        # "anything under 400" as success is how 28 events were silently fed
        # into an unrelated Splunk instance that happened to hold the host's
        # port 8000 and answered 303 — the sidecar logged every one of them as
        # delivered. A redirect is not an acceptance, and telemetry that goes
        # to the wrong service is worse than telemetry that fails loudly.
        status = response.status_code
        outcome = classify(status)
        if outcome is Outcome.DELIVERED:
            if status == 409:
                self.duplicates += 1
                log.info("hub already had %s; an earlier attempt landed", _describe(body))
            else:
                self.delivered += 1
                log.info("delivered %s (total %d)", _describe(body), self.delivered)
            return Delivery(outcome)

        reason = f"{status} {response.text[:200]}"
        if status in (301, 302, 303, 307, 308):
            log.error(
                "HUB_URL points at something that redirects (%s -> %s). That is not "
                "the intelligence hub; check what else holds that port.",
                status,
                response.headers.get("location", "?"),
            )
        elif status in (401, 403):
            log.error(
                "hub refused the signature (%s). HMAC_SECRET must match the hub's and "
                "the clocks must agree; events are held until they do.",
                reason,
            )
        elif outcome is Outcome.REJECTED:
            log.error("hub rejected %s as malformed: %s", _describe(body), reason)
        else:
            log.warning("hub could not take an event: %s", reason)
        return Delivery(outcome, reason)

    def _dead_letter(self, body: bytes, reason: str, name: str | None = None) -> None:
        path = self.dead.add(body, reason, name)
        self.dead_lettered += 1
        log.error("dead-lettered %s to %s", _describe(body), path)

    async def drain_spool(self) -> None:
        """Retry anything held back, oldest first.

        Stops at the first event worth retrying, to keep order while the hub
        is unavailable. An event the hub rejects does not stop it: that event
        is dead-lettered and the drain moves on to the next.
        """
        for path in self.spool.pending():
            try:
                body = path.read_bytes()
            except OSError:
                continue
            result = await self.deliver(body)
            if result.outcome is Outcome.RETRY:
                return  # hub still unavailable; preserve ordering
            if result.outcome is Outcome.REJECTED:
                self._dead_letter(body, result.reason, path.name)
            path.unlink(missing_ok=True)

    async def read_new_lines(self) -> list[Line]:
        """Read whatever has been appended since the last checkpoint.

        Does not move the checkpoint: `ship()` does, one event at a time, as
        each is handled. Moving it here, before anything was sent, meant that
        a crash between reading and sending lost the whole batch: past the
        saved offset, and in no spool.
        """
        path = config.event_path
        if not path.exists():
            return []

        stat = path.stat()
        if stat.st_ino != self.position.inode:
            self.position.reset_for(stat.st_ino)
        elif stat.st_size < self.position.offset:
            log.info("event file truncated, rewinding")
            self.position.offset = 0

        if stat.st_size == self.position.offset:
            return []

        start = self.position.offset
        with path.open("rb") as handle:
            handle.seek(start)
            chunk = handle.read(stat.st_size - start)

        # A partial trailing line means the proxy is mid-write; leave it for
        # the next pass rather than shipping half an event.
        last_newline = chunk.rfind(b"\n")
        if last_newline == -1:
            return []

        lines: list[Line] = []
        end = start
        for raw in chunk[: last_newline + 1].split(b"\n")[:-1]:
            end += len(raw) + 1
            if raw.strip():
                lines.append(Line(raw, end))
            elif lines:
                # A blank line goes with the event before it, so handling
                # that event steps past the blank line too.
                lines[-1] = Line(lines[-1].body, end)

        if not lines:
            # Only blank lines: nothing to lose by stepping past them now.
            self.position.advance_to(end)
        return lines

    async def ship(self, lines: list[Line]) -> None:
        """Send freshly read events: spool what can be retried, dead-letter the rest.

        The read offset moves past an event only once it is handled --
        delivered, spooled or dead-lettered -- so a crash, or an error in this
        loop, re-reads what was not handled instead of skipping it. Re-reading
        one that did land costs nothing: its id comes from its bytes, so the
        hub answers 409 and it counts as delivered.
        """
        for line in lines:
            self.courier.offer(_parse(line.body))
            result = await self.deliver(line.body)
            if result.outcome is Outcome.RETRY:
                self.spool.add(line.body)
                self.failed += 1
            elif result.outcome is Outcome.REJECTED:
                self._dead_letter(line.body, result.reason)
            self.position.advance_to(line.end)

    async def run(self) -> None:
        log.info(
            "sidecar up: %s -> %s/ingest/ | %s | brain=%s | signing %s",
            config.event_path,
            config.hub_url,
            "inotify, immediate" if self.watcher.immediate else "polling fallback",
            config.brain_url if config.brain_enabled else "disabled",
            "enabled" if config.hmac_secret != "dev" else "with the dev secret",
        )
        if config.hmac_secret == "dev":
            log.warning(
                "HMAC_SECRET is 'dev'. The hub refuses to start with it unless "
                "INSECURE_DEV_MODE is set; set a real secret before public exposure."
            )
        waiting = len(self.dead.pending())
        if waiting:
            log.warning(
                "%d dead-lettered event(s) in %s. Move them back to %s to resend.",
                waiting, config.dead_letter_dir, config.spool_dir,
            )

        backoff = 1.0
        while True:
            try:
                await self.drain_spool()
                lines = await self.read_new_lines()

                if not lines:
                    # Blocks until the proxy appends, not until a timer fires.
                    await self.watcher.wait(config.flush_interval)
                    continue

                # The fan-out. Both branches start from the same signed event.
                #
                # Hub branch: sequential and one at a time. Sequential because
                # the hub upserts a session row on first sight, so
                # session.connect has to land before its commands; one at a
                # time because only /ingest/ takes signed sensor events.
                #
                # Brain branch: queued and non-blocking. Intent is a property
                # of a command sequence rather than of one event, and a slow
                # or absent brain must never delay, reorder or drop what
                # reaches the hub.
                await self.ship(lines)

                if self.spool.depth:
                    backoff = min(backoff * 2, config.max_backoff)
                    log.info("%d event(s) spooled; backing off %.0fs", self.spool.depth, backoff)
                    await asyncio.sleep(backoff)
                else:
                    backoff = 1.0
            except asyncio.CancelledError:
                raise
            except Exception:
                log.error("shipper loop error", exc_info=True)
                await asyncio.sleep(5)


def _parse(body: bytes) -> dict:
    try:
        return json.loads(body)
    except Exception:
        return {}


async def main() -> None:
    shipper = Shipper()
    courier_task = asyncio.create_task(shipper.courier.run())
    try:
        await shipper.run()
    finally:
        courier_task.cancel()
        await asyncio.gather(courier_task, return_exceptions=True)
        await shipper.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
