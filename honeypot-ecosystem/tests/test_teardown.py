"""The inner session is closed without waiting on the node.

On the cloud honeypot (2026-11-06) the proxy waited 15 minutes for a node's sshd
to confirm a channel close after the attacker had already left. The session's
last command, rebuilt only at teardown, reached the hub 15 minutes late. These
tests pin the bounded close that replaced the wait.

Run with:  pytest honeypot-ecosystem/tests/ -v
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

import pytest

PROXY = Path(__file__).resolve().parents[1] / "shared" / "ssh-proxy"
sys.path.insert(0, str(PROXY))

from teardown import close_inner  # noqa: E402


class FakeShell:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    """A connection whose close is confirmed at once, or never."""

    def __init__(self, confirms: bool) -> None:
        self.confirms = confirms
        self.closed = False
        self.aborted = False

    def close(self) -> None:
        self.closed = True

    def abort(self) -> None:
        self.aborted = True

    async def wait_closed(self) -> None:
        if not self.confirms:
            await asyncio.Event().wait()  # what the node's sshd did for 15 minutes


def test_a_node_that_never_confirms_is_aborted_within_the_bound():
    conn, shell = FakeConnection(confirms=False), FakeShell()

    started = time.monotonic()
    asyncio.run(close_inner(conn, shell, timeout=0.2))

    assert time.monotonic() - started < 2
    assert shell.closed and conn.closed and conn.aborted


def test_a_node_that_confirms_is_closed_cleanly():
    conn = FakeConnection(confirms=True)

    asyncio.run(close_inner(conn))

    assert conn.closed and not conn.aborted


def test_neither_front_end_waits_on_the_channel_any_more():
    """`async with ... create_process(...)` is what waited for the node."""
    for name in ("proxy.py", "peer_gateway.py"):
        source = (PROXY / name).read_text(encoding="utf-8")
        assert "create_process(" in source
        assert "async with backend_conn.create_process" not in source
        assert "async with backend.create_process" not in source
        assert "await close_inner(" in source, f"{name} no longer closes through teardown.close_inner"


def test_closing_a_real_session_whose_shell_never_ends():
    """End to end with asyncssh on both sides: the node's shell runs forever,
    as `cat` blocked on its output did, and the close still finishes at once."""
    asyncssh = pytest.importorskip("asyncssh")

    lost = asyncio.Event()

    class Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def password_auth_supported(self):
            return True

        def validate_password(self, username, password):
            return True

        def connection_lost(self, exc):
            lost.set()

    async def endless_shell(process):
        process.stdout.write(b"$ ")
        await asyncio.sleep(3600)

    async def run() -> float:
        key = asyncssh.generate_private_key("ssh-ed25519")
        server = await asyncssh.create_server(
            Server, "127.0.0.1", 0, server_host_keys=[key],
            process_factory=endless_shell, encoding=None,
        )
        port = server.sockets[0].getsockname()[1]
        try:
            conn = await asyncssh.connect(
                "127.0.0.1", port, username="u", password="p",
                known_hosts=None, client_keys=None, agent_path=None,
            )
            shell = await conn.create_process(None, term_type="xterm", encoding=None)
            shell.stdin.write(b"echo 1 > /dev/null && cat /bin/echo\n")

            started = time.monotonic()
            await close_inner(conn, shell, timeout=2)
            elapsed = time.monotonic() - started
            await asyncio.wait_for(lost.wait(), 5)  # the node saw the connection go
            return elapsed
        finally:
            server.close()
            await server.wait_closed()

    assert asyncio.run(run()) < 3
