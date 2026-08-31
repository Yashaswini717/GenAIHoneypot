"""The pivot gateway: node-02 and node-03, bridged and recorded.

When an attacker on node-01 runs `ssh deploy@erp-web`, the address that
resolves is a secondary address on *this* container, not another host. So the
pivot lands here, and the same recorder that captures node-01 captures it.

Why go to that trouble
----------------------
The obvious arrangement — put node-02 beside node-01 and let them talk — is
simpler and completely unobserved. The proxy is not in the path, so the hub
would see the login and nothing else: no commands, no intent classification,
no adaptive decoys on two thirds of the estate. "Every activity logged" would
quietly mean "activity on one node logged".

The alternative of running a recorder inside nodes 02 and 03 fails for the
same reason it failed for node-01: a root attacker can find it, kill it, or
truncate its output. Recording belongs outside the box being recorded.

How a connection is routed
--------------------------
The destination address decides the node — `.21` is the web host, `.31` the
database — and the *source* address decides whose environment it belongs to.
The attacker controls neither, so a pivot can only ever reach their own peers.
The broker resolves both and spawns the target on first contact.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

import asyncssh
import httpx

from config import config
from cowrie_events import SessionEventFactory
from credentials import CredentialStore
from emitter import EventEmitter
from recorder import CommandReconstructor, TranscriptWriter

log = logging.getLogger("ssh-proxy.peer")


class PeerGateway:
    """Second SSH front end, facing the attacker's own subnet."""

    def __init__(self, emitter: EventEmitter) -> None:
        self.emitter = emitter
        self.credentials = CredentialStore.from_path(config.peer_credentials_path)
        self.authorized_keys = self._load_decoy_key()

    def _load_decoy_key(self) -> list[asyncssh.SSHKey]:
        """The public half of the key planted on node-01.

        Without this the chain is decorative: an attacker finds a key, uses
        it, and is rejected — which tells them the key was bait.
        """
        try:
            if config.decoy_pubkey_path.exists():
                keys = asyncssh.read_public_key_list(str(config.decoy_pubkey_path))
                log.info("decoy deploy key loaded; `ssh -i` on it will work")
                return list(keys)
        except Exception:
            log.warning("could not load the decoy public key", exc_info=True)
        log.warning(
            "no decoy public key: the planted key will be rejected, which tells "
            "an attacker it was bait. Run tools/bootstrap.py."
        )
        return []

    async def start(self) -> None:
        await asyncssh.create_server(
            lambda: PeerServer(self),
            "0.0.0.0",
            config.peer_listen_port,
            server_host_keys=self.host_keys,
            process_factory=self.handle,
            encoding=None,
            server_version=self.server_version,
            **self.algorithms,
        )
        log.info(
            "pivot gateway listening on :%d (answers erp-web and db-01 inside "
            "each attacker's subnet)",
            config.peer_listen_port,
        )

    # Populated by proxy.py at startup so both listeners present an identical
    # SSH policy. Two hosts in one estate negotiating differently would be a
    # tell in its own right.
    host_keys: list[str] = []
    server_version: str = ""
    algorithms: dict[str, Any] = {}

    # -- session handling --------------------------------------------------

    async def resolve(self, from_address: str, to_address: str) -> dict[str, Any] | None:
        """Ask the broker which node this was, spawning it if needed."""
        try:
            async with httpx.AsyncClient(timeout=config.broker_timeout) as client:
                response = await client.post(
                    f"{config.broker_url}/session/peer",
                    json={"from_address": from_address, "to_address": to_address},
                )
                if response.status_code == 404:
                    return None  # a hostname with nothing behind it
                response.raise_for_status()
                return response.json()
        except Exception:
            log.error("could not resolve peer %s -> %s", from_address, to_address, exc_info=True)
            return None

    async def handle(self, process: asyncssh.SSHServerProcess) -> None:
        conn = process.get_extra_info("connection")
        events: SessionEventFactory = conn._honeypot_events  # noqa: SLF001
        username = process.get_extra_info("username") or "deploy"

        pending = getattr(conn, "_honeypot_resolve", None)
        if pending is not None:
            with contextlib.suppress(Exception):
                await pending
        target = conn._honeypot_target  # noqa: SLF001

        if target is None:
            process.stderr.write(b"Connection closed by remote host\r\n")
            process.exit(255)
            return

        reconstructor = CommandReconstructor()
        transcript = TranscriptWriter(config.transcript_dir, events.session_id)

        term_type = process.get_terminal_type() or "xterm-256color"
        term_size = process.get_terminal_size() or (80, 24, 0, 0)

        # `ssh host 'command'` must run that command, not drop into a shell.
        # Ignoring it meant the most natural way to use a stolen key --
        # exactly what the deploy script on node-01 demonstrates -- silently
        # did the wrong thing and returned a login banner instead of output.
        requested = process.command
        interactive = requested is None

        log.info(
            "pivot session %s: %s -> %s (%s)",
            events.session_id,
            events.src_ip,
            target["hostname"],
            "spawned" if target.get("spawned") else "existing",
        )

        try:
            if requested:
                await self.emitter.emit(events.command(requested))

            backend = await _connect_when_ready(target["address"], username)
            async with backend:
                async with backend.create_process(
                    requested,
                    term_type=term_type if interactive else None,
                    term_size=term_size[:2] if interactive else None,
                    encoding=None,
                ) as shell:
                    await _pump(process, shell, reconstructor, transcript, events, self.emitter)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.error("pivot session to %s failed", target["hostname"], exc_info=True)
            process.stderr.write(b"Connection to host closed.\r\n")
        finally:
            for command in reconstructor.flush():
                await self.emitter.emit(events.command(command))
            transcript.close()
            with contextlib.suppress(Exception):
                process.exit(0)


class PeerServer(asyncssh.SSHServer):
    """One inbound pivot connection."""

    def __init__(self, gateway: PeerGateway) -> None:
        self.gateway = gateway
        self.events: SessionEventFactory | None = None
        self.conn: Any = None
        self.target: dict[str, Any] | None = None
        self.auth_failures = 0
        self._login_emitted = False

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn
        peer = conn.get_extra_info("peername") or ("unknown", 0)
        # The address they connected TO is what identifies the node they
        # believe they are reaching.
        local = conn.get_extra_info("sockname") or ("unknown", 0)

        sensor = _sensor_for(local[0])
        self.events = SessionEventFactory(
            src_ip=peer[0],
            src_port=peer[1],
            dst_ip=local[0],
            dst_port=22,
            sensor=sensor,
        )
        conn._honeypot_events = self.events  # noqa: SLF001
        conn._honeypot_target = None  # noqa: SLF001
        _schedule(self.gateway.emitter.emit(self.events.connect()))

        # Resolution starts now but is *awaited* by the session handler rather
        # than raced against it. Spawning a peer takes a moment, and auth
        # finishes fast: reading the target as a plain attribute meant the
        # session sometimes began before the answer arrived and the attacker
        # got "Connection closed by remote host" -- on a pivot that had, in
        # fact, worked.
        conn._honeypot_resolve = asyncio.ensure_future(  # noqa: SLF001
            self._resolve(peer[0], local[0])
        )

    async def _resolve(self, from_address: str, to_address: str) -> None:
        self.target = await self.gateway.resolve(from_address, to_address)
        if self.conn is not None:
            self.conn._honeypot_target = self.target  # noqa: SLF001
        if self.target and self.events is not None:
            self.events.sensor = self.target["node"]

    def connection_lost(self, exc: Exception | None) -> None:
        if self.events is not None:
            _schedule(self.gateway.emitter.emit(self.events.closed()))

    def begin_auth(self, username: str) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def kbdint_auth_supported(self) -> bool:
        return False

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        """Accept the key we planted, for the account it belongs to.

        This is the payoff for the whole decoy chain. Rejecting it would tell
        the attacker the key was bait.
        """
        accepted = username == "deploy" and any(
            key == authorized for authorized in self.gateway.authorized_keys
        )
        # AsyncSSH calls this more than once per connection (offer, then
        # signature), which produced four identical login.success events for a
        # single login and would have inflated every brute-force metric in the
        # hub.
        if accepted and self.events is not None and not self._login_emitted:
            self._login_emitted = True
            _schedule(
                self.gateway.emitter.emit(
                    self.events.login_success(username, "<publickey:decoy_deploy_key>")
                )
            )
        return accepted

    async def validate_password(self, username: str, password: str) -> bool:
        assert self.events is not None
        outcome = await self.gateway.credentials.authenticate(username, password)
        if outcome.accepted:
            if not self._login_emitted:
                self._login_emitted = True
                await self.gateway.emitter.emit(self.events.login_success(username, password))
            return True
        self.auth_failures += 1
        await self.gateway.emitter.emit(self.events.login_failed(username, password))
        return False


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _sensor_for(address: str) -> str:
    """Provisional sensor name from the destination's last octet.

    Refined once the broker answers; this only covers events emitted before
    that, such as the initial connect.
    """
    try:
        return {21: "node-02-erp", 31: "node-03-db"}[int(address.rsplit(".", 1)[1])]
    except (ValueError, IndexError, KeyError):
        return "node-unknown"


async def _connect_when_ready(address: str, username: str) -> Any:
    """Wait out a peer that was spawned moments ago.

    Lazily created nodes refuse connections until their sshd binds, and
    node-03 additionally initialises a database on first boot. To an attacker
    this reads as a busy host, which is why the wait is generous.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + float(config.backend_connect_timeout) * 3
    announced = False

    while True:
        try:
            return await asyncssh.connect(
                address,
                port=22,
                username=username,
                client_keys=[str(config.backend_key_path)],
                known_hosts=None,
                connect_timeout=config.backend_connect_timeout,
            )
        except (ConnectionRefusedError, OSError):
            if loop.time() >= deadline:
                raise
            if not announced:
                log.info("peer %s still booting, waiting for sshd", address)
                announced = True
            await asyncio.sleep(0.5)


async def _pump(
    process: asyncssh.SSHServerProcess,
    shell: asyncssh.SSHClientProcess,
    reconstructor: CommandReconstructor,
    transcript: TranscriptWriter,
    events: SessionEventFactory,
    emitter: EventEmitter,
) -> None:
    async def attacker_to_shell() -> None:
        while True:
            data = await process.stdin.read(4096)
            if not data:
                break
            transcript.write("i", data)
            reconstructor.feed_input(data)
            shell.stdin.write(data)
        with contextlib.suppress(Exception):
            shell.stdin.write_eof()

    async def shell_to_attacker() -> None:
        while True:
            data = await shell.stdout.read(4096)
            if not data:
                break
            transcript.write("o", data)
            for command in reconstructor.feed_output(data):
                await emitter.emit(events.command(command))
            process.stdout.write(data)

    async def shell_stderr() -> None:
        while True:
            data = await shell.stderr.read(4096)
            if not data:
                break
            transcript.write("o", data)
            process.stderr.write(data)

    tasks = [
        asyncio.create_task(attacker_to_shell()),
        asyncio.create_task(shell_to_attacker()),
        asyncio.create_task(shell_stderr()),
    ]
    try:
        await asyncio.wait_for(
            asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED),
            timeout=config.max_session_seconds,
        )
    except asyncio.TimeoutError:
        log.info("pivot session %s hit the wall-clock cap", events.session_id)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


def _schedule(coro: Any) -> None:
    try:
        asyncio.get_running_loop().create_task(coro)
    except RuntimeError:
        log.debug("no running loop; dropping a telemetry event")
