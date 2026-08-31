"""Wake the moment the proxy appends, instead of polling for it.

The sidecar used to sleep a fixed interval and then check whether the event
file had grown. That put an average half-interval of latency on every event
and a full interval on the worst case — a second of delay between an attacker
typing a command and the hub and brain seeing it. For a pipeline whose whole
purpose is learning attack patterns *while the attacker is still connected*,
that is the difference between reacting and reporting.

inotify removes it. The kernel tells us the instant the file is written, so
the wait is bounded by scheduling rather than by a timer, and an idle sidecar
costs nothing at all rather than waking twenty times a second.

The proxy and sidecar are separate containers sharing one volume, which is
fine: inotify watches the filesystem, not the process.

Falls back to short-interval polling if inotify is unavailable, so the sidecar
still works if the dependency is missing or the platform lacks it.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

log = logging.getLogger("sidecar.watcher")

#: Used only by the fallback path, and deliberately short. If we are polling
#: at all something is wrong, and latency matters more than the wasted stats.
_FALLBACK_POLL_SECONDS = 0.05


class EventWatcher:
    """Blocks until the event file changes, or until a timeout elapses."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._inotify = None
        self._flags = None
        self._watch_dir: Path | None = None
        self._setup()

    def _setup(self) -> None:
        try:
            from inotify_simple import INotify, flags  # type: ignore
        except Exception:
            log.warning(
                "inotify unavailable, falling back to %.0fms polling; "
                "events will be delayed by up to that long",
                _FALLBACK_POLL_SECONDS * 1000,
            )
            return

        try:
            # Watch the directory rather than the file. A watch on the inode
            # dies with the file, so a rotation or a recreate would silently
            # leave us watching something that no longer exists — and the
            # sidecar would go quiet without ever erroring.
            self._path.parent.mkdir(parents=True, exist_ok=True)
            inotify = INotify()
            self._flags = flags
            inotify.add_watch(
                str(self._path.parent),
                flags.MODIFY | flags.CREATE | flags.MOVED_TO | flags.CLOSE_WRITE,
            )
            self._inotify = inotify
            self._watch_dir = self._path.parent
            log.info("watching %s with inotify", self._path.parent)
        except Exception:
            log.warning("could not set up inotify, falling back to polling", exc_info=True)
            self._inotify = None

    @property
    def immediate(self) -> bool:
        """True when the watcher is event-driven rather than polling."""
        return self._inotify is not None

    async def wait(self, timeout: float) -> None:
        """Return as soon as something changed, or after `timeout` seconds.

        The timeout still matters even with inotify: it bounds how long we go
        without retrying a spooled batch when the hub has been unreachable.
        """
        if self._inotify is None:
            await asyncio.sleep(_FALLBACK_POLL_SECONDS)
            return

        def _read() -> None:
            # read() blocks in a worker thread, so the event loop stays free.
            self._inotify.read(timeout=int(timeout * 1000))

        try:
            await asyncio.to_thread(_read)
        except Exception:
            log.debug("inotify read failed; sleeping briefly instead", exc_info=True)
            await asyncio.sleep(_FALLBACK_POLL_SECONDS)

    def close(self) -> None:
        if self._inotify is not None:
            try:
                self._inotify.close()
            except Exception:
                pass
