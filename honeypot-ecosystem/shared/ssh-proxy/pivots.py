"""Which attacker sessions have a pivot open inside them.

An attacker who runs `ssh deploy@erp-web` on node-01 goes on typing through
their node-01 session: every keystroke meant for erp-web crosses it. Both
recorders see those lines -- node-01's as part of the outer session, the peer
gateway's as the pivot's own -- so each command was recorded twice and counted
twice: two tripwires, two classifications, two alerts for one database query.

The outer session's copy is marked nested rather than dropped. The keystrokes
are real and the transcript keeps them; they just must not be counted again as
something done on node-01.

A pivot is tied to the outer session that typed the ssh command for it, not to
every session the attacker has open. A second terminal on node-01 keeps working
normally while the first is inside erp-web: a command wrongly marked nested is
a command nothing scores, and a missed detection is worse than a double count.
A pivot no session typed (a script, a one-shot command) marks nothing, which
was the behaviour before.
"""

from __future__ import annotations

import re
import time
from typing import Any, Callable

#: How long after typing ssh the pivot may arrive and still be tied to that
#: session. Spawning a peer the first time takes a few seconds.
LAUNCH_WINDOW = 60.0

# `ssh` as a command word: not .ssh/, ssh-keygen or sshd, but sshpass's ssh too.
_SSH = re.compile(r"(?<![\w.-])ssh\s")


class PivotTracker:
    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        #: owner -> (session id, time) of the last ssh typed in an outer session
        self._launched: dict[str, tuple[str, float]] = {}
        #: open pivot -> (owner, session id of the outer session it was typed in)
        self._open: dict[object, tuple[str, str]] = {}

    def typed(self, owner: str, session_id: str, command: str) -> None:
        """Note a command typed in a session; an ssh may be about to pivot."""
        if _SSH.search(command):
            self._launched[owner] = (session_id, self._clock())

    def opened(self, pivot: object, owner: str) -> None:
        """A pivot for `owner` has been resolved; tie it to the session that typed ssh."""
        launch = self._launched.pop(owner, None)
        if launch is not None and self._clock() - launch[1] <= LAUNCH_WINDOW:
            self._open[pivot] = (owner, launch[0])

    def closed(self, pivot: object) -> None:
        self._open.pop(pivot, None)

    def nested(self, owner: str, session_id: str) -> bool:
        """Whether a pivot is open inside this session."""
        return (owner, session_id) in self._open.values()


#: One per proxy process, which runs both the perimeter and the peer gateway.
TRACKER = PivotTracker()


def mark(events: Any, command: str) -> dict[str, Any]:
    """`events.command(command)`, marked nested if a pivot is open inside the session."""
    event = events.command(command)
    owner = events.attacker or events.src_ip
    if TRACKER.nested(owner, events.session_id):
        event["nested"] = True
    else:
        TRACKER.typed(owner, events.session_id, command)
    return event
