"""Ready-made model-written decoys, each set served to one attacker only.

Why it exists: on the cloud honeypot (2026-11) the logged-in bots stayed 6 to 67
seconds, and one model-written decoy profile takes 1 to 4.5 minutes against a
free model, so content generated on demand reached nobody. The model-written
files do not depend on the attacker -- the brain is only ever told the action and
whose home the files go in -- so they can be made ahead of time and kept here
until a session needs them.

What keeps every attacker's decoys unique, which is the point of generating them
at all rather than shipping fixed files:

  * Single use. Taking a set removes it with a rename, which is atomic even
    across the brain's worker processes, so no set is ever served twice.
  * No repeated file. The SHA-256 of every file served, from stock or generated
    on the spot, is recorded, and a stocked file whose content was served before
    is dropped when its set is taken. A model asked the same thing twice can say
    the same thing twice; this makes sure no two attackers see it.
  * Credentials are not stocked. They are made per request and registered to
    that attacker's environment, so a tripwire still says who used them.
  * Paths stay relative and are placed in the attacker's home at request time.

When a key's stock is empty the caller generates on the spot, as before -- slow,
but still unique. Stock is never reused to fill a gap.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable, Optional

from config.logging_config import get_logger

logger = get_logger(__name__)

#: Temporary and claimed files older than this are left over from a crash.
_STALE_SECONDS = 600


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


class DecoyStock:
    """Single-use sets of model-written files, kept on disk by content key."""

    def __init__(self, directory: Path | str, per_key: int = 2) -> None:
        self.directory = Path(directory)
        self.per_key = per_key
        self.directory.mkdir(parents=True, exist_ok=True)
        self._clear_stale()

    # -- reading -----------------------------------------------------------

    def count(self, key: str) -> int:
        return sum(1 for _ in self._key_dir(key).glob("*.json"))

    def most_needed(self, keys: Iterable[str]) -> Optional[str]:
        """The key furthest below `per_key`, or None when every key is full."""
        short = [(self.count(key), key) for key in keys]
        short = [(count, key) for count, key in short if count < self.per_key]
        return min(short)[1] if short else None

    def take(self, key: str) -> Optional[dict[str, Any]]:
        """Claim one set for one attacker. It is never handed out again.

        Returns {"files", "failures", "made"}, or None when there is nothing
        unused to give.
        """
        directory = self._key_dir(key)
        for item in sorted(directory.glob("*.json"), key=_mtime):
            claimed = directory / f".{item.stem}.claimed"
            try:
                os.replace(item, claimed)  # whoever renames it first owns it
            except FileNotFoundError:
                continue
            try:
                payload = json.loads(claimed.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                payload = None
            finally:
                claimed.unlink(missing_ok=True)
            if not payload:
                continue

            served = self._served()
            fresh = [f for f in payload.get("files", []) if f.get("content") and _digest(f["content"]) not in served]
            dropped = len(payload.get("files", [])) - len(fresh)
            if dropped:
                logger.info("decoy_stock_dropped_repeats", key=key, dropped=dropped)
            if not fresh:
                continue
            self.record_served(fresh)
            return {"files": fresh, "failures": payload.get("failures", []), "made": payload.get("made")}
        return None

    # -- writing -----------------------------------------------------------

    def put(self, key: str, files: list[dict[str, Any]], failures: Iterable[str] = ()) -> Optional[Path]:
        """Add one freshly generated set. Empty files are not kept."""
        files = [f for f in files if f.get("content")]
        if not files:
            return None
        directory = self._key_dir(key)
        payload = {"key": key, "made": time.time(), "files": files, "failures": list(failures)}
        temporary = directory / f".{uuid.uuid4().hex}.tmp"
        temporary.write_text(json.dumps(payload), encoding="utf-8")
        final = directory / f"{uuid.uuid4().hex}.json"
        os.replace(temporary, final)
        return final

    def record_served(self, files: Iterable[dict[str, Any]]) -> None:
        """Remember these files' content, so it is never served again."""
        lines = "".join(_digest(f["content"]) + "\n" for f in files if f.get("content"))
        if lines:
            with open(self.directory / "served.sha256", "a", encoding="utf-8") as handle:
                handle.write(lines)

    # -- live generation goes first ----------------------------------------
    #
    # A free model's rate limit is per account, not per caller. Filling stock
    # while an attacker's decoys are being generated live made both fail with
    # "Rate limit exceeded" (seen locally against Mistral, 2026-11-17), so the
    # filler waits between steps while any live generation is running, in any
    # of the brain's worker processes. Markers older than _STALE_SECONDS are
    # ignored, so a crashed request cannot stop the filler for good.

    def live_started(self) -> Path:
        marker = self._live_dir() / uuid.uuid4().hex
        marker.touch()
        return marker

    def live_finished(self, marker: Path) -> None:
        marker.unlink(missing_ok=True)

    def live_busy(self) -> bool:
        cutoff = time.time() - _STALE_SECONDS
        busy = False
        for marker in self._live_dir().iterdir():
            if _mtime(marker) > cutoff:
                busy = True
            else:
                marker.unlink(missing_ok=True)  # left by a request that never finished
        return busy

    async def wait_while_live(self, poll_seconds: float = 2.0) -> None:
        while self.live_busy():
            await asyncio.sleep(poll_seconds)

    def _live_dir(self) -> Path:
        directory = self.directory / ".live"
        directory.mkdir(exist_ok=True)
        return directory

    # -- housekeeping ------------------------------------------------------

    def _key_dir(self, key: str) -> Path:
        if not key or "/" in key or "\\" in key or key.startswith("."):
            raise ValueError(f"bad stock key {key!r}")
        directory = self.directory / key
        directory.mkdir(exist_ok=True)
        return directory

    def _served(self) -> set[str]:
        try:
            return set((self.directory / "served.sha256").read_text(encoding="utf-8").split())
        except FileNotFoundError:
            return set()

    def _clear_stale(self) -> None:
        cutoff = time.time() - _STALE_SECONDS
        for pattern in ("*/.*.tmp", "*/.*.claimed"):
            for path in self.directory.glob(pattern):
                try:
                    if path.stat().st_mtime < cutoff:
                        path.unlink()
                except OSError:
                    pass


def _mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


class StepPacer:
    """Spaces the filler's model calls out, and stands aside for live generation.

    The filler is never in a hurry, and a free model's rate limit is per
    account. Filling at full speed against Mistral's free tier (2026-11-17)
    lost one step in three to "Rate limit exceeded" even with nothing else
    running. Used as PopulationStrategy.step_gate, one instance per filler.
    """

    def __init__(self, stock: DecoyStock, min_interval: float) -> None:
        self.stock = stock
        self.min_interval = min_interval
        self._last = 0.0

    async def __call__(self) -> None:
        await self.stock.wait_while_live()
        wait = self._last + self.min_interval - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        self._last = time.monotonic()


#: Makes one set's model-written files for a stock context: (files, failures).
MakeContent = Callable[[dict[str, str]], Awaitable[tuple[list[dict[str, Any]], list[str]]]]


class StockFiller:
    """Keeps every content key stocked, one set at a time, in the background.

    One filler runs across all of the brain's worker processes: each worker
    starts one, and only the one holding the lock file works. A set that comes
    back empty means the model is failing (no quota, a dead provider), so the
    filler backs off rather than spending requests in a loop.
    """

    def __init__(
        self,
        stock: DecoyStock,
        contexts: dict[str, dict[str, str]],
        make_content: MakeContent,
        *,
        poll_seconds: float = 15.0,
        backoff_max_seconds: float = 1800.0,
    ) -> None:
        self.stock = stock
        self.contexts = contexts
        self.make_content = make_content
        self.poll_seconds = poll_seconds
        self.backoff_max_seconds = backoff_max_seconds
        self._lock_handle: Any = None

    async def run(self) -> None:
        while not self._acquire_lock():
            await asyncio.sleep(self.poll_seconds * 4)
        logger.info("decoy_stock_filler_started", per_key=self.stock.per_key, keys=len(self.contexts))
        backoff = self.poll_seconds
        while True:
            if not await self.fill_once():
                await asyncio.sleep(self.poll_seconds)
                continue
            if self._last_ok:
                backoff = self.poll_seconds
            else:
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, self.backoff_max_seconds)

    async def fill_once(self) -> bool:
        """Make one set for the most-needed key. False when nothing was needed."""
        self._last_ok = True
        key = self.stock.most_needed(self.contexts)
        if key is None:
            return False
        started = time.monotonic()
        try:
            files, failures = await self.make_content(dict(self.contexts[key]))
        except Exception as exc:  # the model or the network; never fatal here
            files, failures = [], [f"{type(exc).__name__}: {exc}"]
        if self.stock.put(key, files, failures) is None:
            self._last_ok = False
            logger.warning("decoy_stock_fill_failed", key=key, failed_steps=len(failures))
        else:
            logger.info(
                "decoy_stock_filled", key=key, files=len(files), failed_steps=len(failures),
                seconds=round(time.monotonic() - started, 1), now=self.stock.count(key),
            )
        return True

    def _acquire_lock(self) -> bool:
        if self._lock_handle is not None:
            return True
        try:
            import fcntl
        except ImportError:  # not Linux: one process, nothing to coordinate
            self._lock_handle = True
            return True
        handle = open(self.stock.directory / "filler.lock", "a+")
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return False
        self._lock_handle = handle
        return True
