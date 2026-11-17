"""Ending an inner session without waiting on the node.

When the attacker's side of a session ended, the proxy closed its inner session
politely: it sent a channel close and waited for the node's sshd to answer. sshd
does not answer while the shell it started is still running, and a shell whose
output nobody reads any more, or that never got its EOF, keeps running.

On the cloud honeypot (2026-11-06) that wait lasted exactly 15 minutes, until the
node's own keepalive limit dropped the connection. The session's last command,
which the reconstructor only gives up at teardown, reached the hub 15 minutes
after the bot had left -- too late for the classifier to plant anything while it
was there -- and the connection to the sandbox stayed open all that time.

Now the inner connection itself is closed, with a short bound on the wait, and
aborted if even that does not finish. Closing the connection rather than only
the channel is the point: it goes down with a disconnect and a FIN whatever
sshd is still waiting for.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

log = logging.getLogger(__name__)

#: How long to wait for the inner connection to finish closing.
CLOSE_TIMEOUT = 5.0


async def close_inner(conn: Any, shell: Any = None, timeout: float = CLOSE_TIMEOUT) -> None:
    """Close the proxy's connection to a node, never waiting longer than `timeout`."""
    if shell is not None:
        try:
            shell.close()
        except Exception:
            pass
    try:
        conn.close()
        await asyncio.wait_for(conn.wait_closed(), timeout)
    except asyncio.CancelledError:
        conn.abort()
        raise
    except Exception:
        log.info("inner connection did not close within %.0fs; aborting it", timeout)
        conn.abort()
