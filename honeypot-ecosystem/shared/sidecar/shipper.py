"""Signs telemetry and ships it to the intelligence hub.

This process is the reason the zero-trust claim is real rather than
decorative. It runs in the control plane, on the other side of the trust
boundary from every node, and it is the only thing in the ecosystem that
holds the HMAC signing key. Nothing an attacker can reach can produce a valid
signature, and nothing they can reach can tamper with a batch without
invalidating one.

It tails the NDJSON the SSH proxy writes and streams events to the hub one at
a time, signing each event's exact bytes with HMAC-SHA256 and POSTing to
`/ingest/` with the digest in X-Signature — matching `verify_hmac` in the
hub's receiver.

Why one event per request rather than batches
---------------------------------------------
The hub verifies signatures on `/ingest/` but not on `/ingest/batch`, which
parses lines straight from the body. Shipping in batches therefore meant every
event travelled the one path where the zero-trust check does not run — the
guarantee existed on paper and nowhere else. Streaming single signed events
closes that: every event that reaches the hub has been cryptographically
verified as ours.

It also matches the requirement more honestly. "Every activity logged and sent
in real time" is not a batch every second, it is an event the moment it
happens, and it puts each event on the live WebSocket feed immediately.

Ordering is preserved by sending sequentially. That matters: the hub upserts a
session row on first sight, so `session.connect` has to arrive before the
commands belonging to it. Throughput is not a concern at honeypot volumes —
even heavy distributed brute force is a few tens of events per second.

Delivery is at-least-once and durable. An event that cannot be delivered is
written to a spool directory and retried with backoff, so a hub restart costs
latency rather than evidence. Read offsets are persisted, so a sidecar restart
does not replay or skip.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import httpx

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

    #: How often to check the spool file for new events. Events are sent
    #: individually the moment they are seen, so this is poll latency, not a
    #: batching window.
    flush_interval: float = float(os.environ.get("FLUSH_INTERVAL", "1.0"))
    request_timeout: float = float(os.environ.get("REQUEST_TIMEOUT", "15"))
    max_backoff: float = float(os.environ.get("MAX_BACKOFF", "60"))


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


def sign(body: bytes) -> str:
    """HMAC-SHA256 over the exact bytes being sent.

    Signing the serialised body rather than the parsed events is what makes
    the signature meaningful: it covers precisely what crosses the wire, so
    any modification in transit invalidates it.
    """
    return hmac.new(config.hmac_secret.encode(), body, hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------
# durable read position
# --------------------------------------------------------------------------


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

    def reset_for(self, inode: int) -> None:
        log.info("event file changed (inode %s -> %s), reading from the start", self.inode, inode)
        self.inode = inode
        self.offset = 0


# --------------------------------------------------------------------------
# spool
# --------------------------------------------------------------------------


class Spool:
    """Batches that could not be delivered yet.

    Evidence is the product here, so an unreachable hub must cost latency and
    nothing else.
    """

    def __init__(self, directory: Path) -> None:
        self._dir = directory
        self._dir.mkdir(parents=True, exist_ok=True)

    def add(self, body: bytes) -> None:
        name = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}.ndjson"
        (self._dir / name).write_bytes(body)

    def pending(self) -> list[Path]:
        return sorted(self._dir.glob("*.ndjson"))

    @property
    def depth(self) -> int:
        return len(self.pending())


# --------------------------------------------------------------------------
# shipping
# --------------------------------------------------------------------------


class Shipper:
    def __init__(self) -> None:
        self.position = ReadPosition(config.state_path)
        self.spool = Spool(config.spool_dir)
        self.client = httpx.AsyncClient(timeout=config.request_timeout)
        self.delivered = 0
        self.failed = 0

    async def close(self) -> None:
        await self.client.aclose()

    async def deliver(self, body: bytes) -> bool:
        """POST one signed event to the zero-trust ingest path.

        `/ingest/` is the endpoint that actually verifies the signature.
        `/ingest/batch` exists for the operator's manual log-upload UI and
        does not verify, so no sensor traffic goes through it.
        """
        try:
            response = await self.client.post(
                f"{config.hub_url}/ingest/",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Signature": sign(body),
                },
            )
        except Exception as exc:
            log.warning("hub unreachable: %s", exc)
            return False

        # Only 2xx counts as accepted. Treating "anything under 400" as success
        # is how 28 events were silently fed into an unrelated Splunk instance
        # that happened to hold the host's port 8000 and answered 303 — the
        # sidecar logged every one of them as delivered. A redirect is not an
        # acceptance, and telemetry that goes to the wrong service is worse
        # than telemetry that fails loudly.
        if not 200 <= response.status_code < 300:
            if response.status_code in (301, 302, 303, 307, 308):
                log.error(
                    "HUB_URL points at something that redirects (%s -> %s). That is not "
                    "the intelligence hub; check what else holds that port.",
                    response.status_code,
                    response.headers.get("location", "?"),
                )
            else:
                # 401 here almost always means the secret does not match the hub's.
                log.warning("hub rejected a batch: %s %s", response.status_code, response.text[:200])
            return False

        self.delivered += 1
        log.info(
            "delivered %s (total %d)",
            _describe(body),
            self.delivered,
        )
        return True

    async def drain_spool(self) -> None:
        """Retry anything held back, oldest first, stopping on the first failure."""
        for path in self.spool.pending():
            try:
                body = path.read_bytes()
            except OSError:
                continue
            if await self.deliver(body):
                path.unlink(missing_ok=True)
            else:
                return  # hub still down; preserve ordering

    async def read_new_lines(self) -> list[bytes]:
        """Read whatever has been appended since the last checkpoint."""
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

        with path.open("rb") as handle:
            handle.seek(self.position.offset)
            chunk = handle.read(stat.st_size - self.position.offset)

        # A partial trailing line means the proxy is mid-write; leave it for
        # the next pass rather than shipping half an event.
        last_newline = chunk.rfind(b"\n")
        if last_newline == -1:
            return []
        consumed = chunk[: last_newline + 1]
        self.position.offset += len(consumed)
        self.position.save()

        return [line for line in consumed.split(b"\n") if line.strip()]

    async def run(self) -> None:
        log.info(
            "sidecar up: %s -> %s/ingest/ | streaming single signed events, "
            "polling every %.1fs | signing %s",
            config.event_path,
            config.hub_url,
            config.flush_interval,
            "enabled" if config.hmac_secret != "dev" else "with the dev secret",
        )
        if config.hmac_secret == "dev":
            log.warning(
                "HMAC_SECRET is 'dev' — the hub skips verification for this value. "
                "Set a real secret before public exposure."
            )

        backoff = 1.0
        while True:
            try:
                await self.drain_spool()
                lines = await self.read_new_lines()

                if not lines:
                    await asyncio.sleep(config.flush_interval)
                    continue

                # Sequential and one at a time. Sequential because the hub
                # upserts a session row on first sight, so session.connect has
                # to land before the commands that belong to it; one at a time
                # because only /ingest/ verifies the signature.
                for event in lines:
                    if not await self.deliver(event):
                        self.spool.add(event)
                        self.failed += 1

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


async def main() -> None:
    shipper = Shipper()
    try:
        await shipper.run()
    finally:
        await shipper.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
