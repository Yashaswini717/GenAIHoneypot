"""The write end of the telemetry pipeline.

Events are appended as NDJSON to a file on a volume shared with exactly one
other process, the sidecar, which tails it, signs each batch with HMAC-SHA256
and ships it to the intelligence hub.

Two properties matter, and both come from *where* this runs rather than from
anything clever in the code:

  * The attacker cannot see it. This process lives in the proxy container.
    The attacker's shell lives in a separate backend container. Under this
    architecture the node emits no telemetry at all, so there is no event
    file, no log shipper and no agent inside the attacker's reach to find.

  * The attacker cannot modify it. Same reason. There is no path from the
    backend container to this volume.

Every write is flushed immediately. Batching would be cheaper, but "every
activity logged and sent in real time" is a requirement, and a session that
ends in a container kill must not lose its last events.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class EventEmitter:
    """Appends Cowrie-schema events to the NDJSON spool.

    One instance is shared by every session, so writes are serialised through
    a lock to keep lines from interleaving.
    """

    def __init__(self, event_path: Path) -> None:
        self._path = event_path
        self._lock = asyncio.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)

    async def emit(self, event: dict[str, Any]) -> None:
        """Append one event. Never raises into the session."""
        line = json.dumps(event, separators=(",", ":"), default=str)
        try:
            async with self._lock:
                await asyncio.to_thread(self._append, line)
        except Exception:
            # Losing telemetry is bad; killing an attacker's session because
            # we could not write telemetry is worse, and far more suspicious.
            log.error("failed to emit event %s", event.get("eventid"), exc_info=True)

    def _append(self, line: str) -> None:
        with self._path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()

    async def emit_all(self, events: list[dict[str, Any]]) -> None:
        for event in events:
            await self.emit(event)
