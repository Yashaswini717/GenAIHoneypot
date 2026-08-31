"""The honeypot's front door.

Every attacker SSH connection terminates here. The proxy authenticates them,
asks the session broker for their isolated backend container, opens its own
SSH session to that container, and then sits in the middle of the PTY stream
relaying bytes in both directions while recording everything.

Why the recording lives here and not in the node
------------------------------------------------
An in-node recorder runs inside the box the attacker owns. With root they can
find it in /proc, strace it, kill it, replace their login shell, or truncate
its output. Masking the process name hides it from a casual `ps`; it does not
hide it from a determined root. Any recorder inside the attacker's reach is a
recorder the attacker can defeat.

Here, the attacker's shell is in a separate container and the recording is on
the wire. They cannot see it, cannot kill it, and cannot corrupt it — and even
if they wipe every log inside their container, the transcript is already
elsewhere. As a side effect the node emits no telemetry at all, so there is no
agent, no log shipper and no spool file inside the container to discover.

Terminating SSH here is also what makes HASSH, pre-auth brute-force telemetry
and per-source-IP container routing possible at all.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import sys
from pathlib import Path
from typing import Any

import asyncssh
import httpx

# The shared event schema lives beside this file in the image (/app/common)
# but one level up in the repo (shared/common), so resolve whichever exists
# rather than assuming a depth.
_HERE = Path(__file__).resolve().parent
for _candidate in (_HERE / "common", _HERE.parent / "common"):
    if _candidate.is_dir():
        sys.path.insert(0, str(_candidate))
        break

import openssh_profile as profile  # noqa: E402
from config import config  # noqa: E402
from cowrie_events import SessionEventFactory  # noqa: E402
from credentials import CredentialStore  # noqa: E402
from emitter import EventEmitter  # noqa: E402
from hassh import HandshakeSniffer  # noqa: E402
from peer_gateway import PeerGateway  # noqa: E402
from recorder import CommandReconstructor, TranscriptWriter  # noqa: E402

log = logging.getLogger("ssh-proxy")

emitter = EventEmitter(config.event_path)
credentials = CredentialStore.from_env()


# --------------------------------------------------------------------------
# HASSH capture
# --------------------------------------------------------------------------


def install_hassh_hook() -> bool:
    """Tee raw peer bytes into a per-connection sniffer.

    We hook `data_received`, which is the asyncio Protocol contract rather
    than an AsyncSSH internal, so this survives library upgrades. KEXINIT
    travels in the clear before key exchange completes, so the sniffer can
    read it straight off the stream.

    Returns False if the hook could not be installed, in which case sessions
    simply carry no `hassh` field — the hub treats it as optional.
    """
    try:
        from asyncssh.connection import SSHConnection

        if getattr(SSHConnection, "_honeypot_hassh_patched", False):
            return True

        original = SSHConnection.data_received

        def data_received(self: Any, *args: Any, **kwargs: Any) -> Any:
            try:
                sniffer = getattr(self, "_honeypot_sniffer", None)
                if sniffer is None:
                    sniffer = HandshakeSniffer()
                    self._honeypot_sniffer = sniffer
                if not sniffer.done and args:
                    sniffer.feed(args[0])
            except Exception:  # never break the transport
                log.debug("hassh tee failed", exc_info=True)
            return original(self, *args, **kwargs)

        SSHConnection.data_received = data_received
        SSHConnection._honeypot_hassh_patched = True
        return True
    except Exception:
        log.warning("could not install the HASSH hook; sessions will omit hassh", exc_info=True)
        return False


# --------------------------------------------------------------------------
# server
# --------------------------------------------------------------------------


class HoneypotServer(asyncssh.SSHServer):
    """One instance per inbound connection."""

    def __init__(self) -> None:
        self.events: SessionEventFactory | None = None
        self.conn: Any = None
        self.auth_failures = 0
        self.authenticated_user: str | None = None
        self._kex_emitted = False

    # -- lifecycle ---------------------------------------------------------

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn
        peer = conn.get_extra_info("peername") or ("unknown", 0)
        local = conn.get_extra_info("sockname") or ("unknown", 0)

        self.events = SessionEventFactory(
            src_ip=peer[0],
            src_port=peer[1],
            dst_ip=local[0],
            # Report the port the attacker believes they reached, not our
            # internal bind port.
            dst_port=config.advertised_port,
            sensor=config.sensor_id,
        )
        conn._honeypot_events = self.events  # noqa: SLF001 - handed to the session
        _schedule(emitter.emit(self.events.connect()))

    def connection_lost(self, exc: Exception | None) -> None:
        if self.events is not None:
            _schedule(emitter.emit(self.events.closed()))
            _schedule(_release_backend(self.events.src_ip))

    def debug_msg_received(self, msg: str, lang: str, always_display: bool) -> None:
        log.debug("client debug message: %s", msg)

    # -- fingerprinting ----------------------------------------------------

    def _emit_client_fingerprint(self) -> None:
        """Emit the client ident and HASSH once the handshake is readable."""
        if self._kex_emitted or self.events is None or self.conn is None:
            return
        sniffer = getattr(self.conn, "_honeypot_sniffer", None)
        if sniffer is None or not sniffer.result.complete:
            return

        result = sniffer.result
        self._kex_emitted = True
        if result.version:
            _schedule(emitter.emit(self.events.client_ident(result.version)))
        if result.hassh:
            _schedule(
                emitter.emit(
                    self.events.client_kex(
                        hassh=result.hassh,
                        kex_algs=result.kex_algs,
                        encryption_algs=result.encryption_algs,
                        mac_algs=result.mac_algs,
                        compression_algs=result.compression_algs,
                        host_key_algs=result.host_key_algs,
                    )
                )
            )

    # -- authentication ----------------------------------------------------

    def begin_auth(self, username: str) -> bool:
        self._emit_client_fingerprint()
        return True  # always require a credential

    def public_key_auth_supported(self) -> bool:
        # A real sshd always offers publickey. Advertising password-only is a
        # shape no genuine host has, and every client sees it without needing
        # to enumerate anything.
        return profile.PUBKEY_AUTH

    def password_auth_supported(self) -> bool:
        return profile.PASSWORD_AUTH

    def kbdint_auth_supported(self) -> bool:
        return profile.KBDINT_AUTH

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        # No key is authorised, exactly as on a host whose authorized_keys
        # does not list the attacker. Rejection here is normal, not suspicious.
        return False

    async def validate_password(self, username: str, password: str) -> bool:
        self._emit_client_fingerprint()
        outcome = await credentials.authenticate(username, password)
        assert self.events is not None

        if outcome.accepted:
            self.authenticated_user = username
            await emitter.emit(self.events.login_success(username, password))
            return True

        self.auth_failures += 1
        await emitter.emit(self.events.login_failed(username, password))

        if self.auth_failures >= profile.MAX_AUTH_TRIES and self.conn is not None:
            # sshd drops the connection at MaxAuthTries. Letting an attacker
            # guess forever is as much a tell as accepting the wrong password.
            self.conn.disconnect(
                asyncssh.DISC_NO_MORE_AUTH_METHODS_AVAILABLE,
                "Too many authentication failures",
            )
        return False

    # -- port forwarding ---------------------------------------------------

    def connection_requested(
        self,
        dest_host: str,
        dest_port: int,
        orig_host: str,
        orig_port: int,
    ) -> bool:
        """direct-tcpip. The hub scores these as lateral movement."""
        if self.events is not None:
            _schedule(emitter.emit(self.events.direct_tcpip(dest_host, dest_port)))
        # Phase 1 has no other nodes to reach, so the forward fails the way a
        # forward to a down host fails. Phase 5 routes these into the
        # deception network instead.
        return False


# --------------------------------------------------------------------------
# session bridging
# --------------------------------------------------------------------------


async def _acquire_backend(src_ip: str, username: str | None) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=config.broker_timeout) as client:
        response = await client.post(
            f"{config.broker_url}/session",
            json={"src_ip": src_ip, "username": username},
        )
        response.raise_for_status()
        return response.json()


async def _release_backend(src_ip: str) -> None:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(f"{config.broker_url}/session/release", json={"src_ip": src_ip})
    except Exception:
        log.debug("backend release failed for %s", src_ip, exc_info=True)


async def _connect_backend_when_ready(backend: dict[str, Any], username: str) -> Any:
    """Open the inner SSH session, waiting for a freshly created node to boot.

    A container that was created milliseconds ago refuses connections until
    its sshd binds — so the first session for a new attacker would otherwise
    fail outright, which is both a bug and a tell. Refusal here means the node
    is reachable but not yet listening, so retry; anything else is a real
    failure and is raised immediately.

    Phase 2 should keep a small pool of pre-warmed containers so the first
    session for a new source IP does not pay this cost at all.
    """
    deadline = asyncio.get_running_loop().time() + config.backend_connect_timeout
    attempt = 0

    while True:
        attempt += 1
        try:
            return await asyncssh.connect(
                backend["host"],
                port=backend["port"],
                username=username,
                client_keys=[str(config.backend_key_path)],
                known_hosts=None,
                connect_timeout=config.backend_connect_timeout,
            )
        except ConnectionRefusedError:
            if asyncio.get_running_loop().time() >= deadline:
                raise
            if attempt == 1:
                log.info("node %s still booting, waiting for sshd", backend["container_name"])
            await asyncio.sleep(0.4)


async def handle_session(process: asyncssh.SSHServerProcess) -> None:
    """Bridge one interactive session to its backend container, recording it."""
    conn = process.get_extra_info("connection")
    events: SessionEventFactory = conn._honeypot_events  # noqa: SLF001
    username = process.get_extra_info("username") or config.backend_user

    reconstructor = CommandReconstructor()
    transcript = TranscriptWriter(config.transcript_dir, events.session_id)

    try:
        backend = await _acquire_backend(events.src_ip, username)
    except Exception:
        log.error("could not acquire a backend for %s", events.src_ip, exc_info=True)
        # A real host under load drops you with a system message rather than
        # something that reads like a honeypot failing.
        process.stderr.write(b"System is booting up. Please try again later.\r\n")
        process.exit(1)
        transcript.close()
        return

    log.info(
        "session %s: %s@%s -> %s (%s)",
        events.session_id,
        username,
        events.src_ip,
        backend["container_name"],
        "returning" if backend["reused"] else "new",
    )

    term_type = process.get_terminal_type() or "xterm-256color"
    term_size = process.get_terminal_size() or (80, 24, 0, 0)

    try:
        async with await _connect_backend_when_ready(backend, username) as backend_conn:
            async with backend_conn.create_process(
                term_type=term_type,
                term_size=term_size[:2],
                encoding=None,
            ) as shell:
                await _pump(process, shell, reconstructor, transcript, events)
    except asyncio.CancelledError:
        raise
    except Exception:
        log.error("backend session failed for %s", events.src_ip, exc_info=True)
        process.stderr.write(b"Connection to host closed.\r\n")
    finally:
        for command in reconstructor.flush():
            await emitter.emit(events.command(command))
        transcript.close()
        with contextlib.suppress(Exception):
            process.exit(0)


async def _pump(
    process: asyncssh.SSHServerProcess,
    shell: asyncssh.SSHClientProcess,
    reconstructor: CommandReconstructor,
    transcript: TranscriptWriter,
    events: SessionEventFactory,
) -> None:
    """Relay bytes both ways until either side closes."""

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

    async def shell_stderr_to_attacker() -> None:
        while True:
            data = await shell.stderr.read(4096)
            if not data:
                break
            transcript.write("o", data)
            process.stderr.write(data)

    tasks = [
        asyncio.create_task(attacker_to_shell()),
        asyncio.create_task(shell_to_attacker()),
        asyncio.create_task(shell_stderr_to_attacker()),
    ]
    try:
        await asyncio.wait_for(
            asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED),
            timeout=config.max_session_seconds,
        )
    except asyncio.TimeoutError:
        log.info("session %s hit the wall-clock cap", events.session_id)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


# --------------------------------------------------------------------------
# host keys
# --------------------------------------------------------------------------


def load_or_create_host_keys() -> list[str]:
    """Persistent host keys.

    Regenerating on every restart changes the fingerprint, which no real
    server does and which every returning attacker's known_hosts would flag
    with a large warning. Generated once, then reused from the volume.

    One ed25519 and one RSA key, which together produce exactly the host key
    algorithms in SERVER_HOST_KEY_ALGS.
    """
    config.host_key_dir.mkdir(parents=True, exist_ok=True)
    specs = [("ssh_host_ed25519_key", "ssh-ed25519", {}), ("ssh_host_rsa_key", "ssh-rsa", {"key_size": 3072})]

    paths: list[str] = []
    for filename, algorithm, kwargs in specs:
        path = config.host_key_dir / filename
        if not path.exists():
            key = asyncssh.generate_private_key(algorithm, **kwargs)
            path.write_bytes(key.export_private_key())
            path.chmod(0o600)
            log.info("generated host key %s", path.name)
        paths.append(str(path))
    return paths


# --------------------------------------------------------------------------
# entrypoint
# --------------------------------------------------------------------------


def _schedule(coro: Any) -> None:
    """Fire-and-forget a coroutine from a synchronous AsyncSSH callback."""
    try:
        asyncio.get_running_loop().create_task(coro)
    except RuntimeError:
        log.debug("no running loop; dropping a telemetry event")


async def main() -> None:
    logging.basicConfig(
        level=config.log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    config.ensure_dirs()

    # Fails loudly if the installed AsyncSSH cannot deliver the advertised
    # policy, rather than quietly going live with an algorithm list that
    # contradicts the node's own sshd_config.
    profile.verify_profile()

    hassh_ok = install_hassh_hook()
    host_keys = load_or_create_host_keys()

    algorithms = dict(
        kex_algs=list(profile.KEX_ALGS),
        encryption_algs=list(profile.ENCRYPTION_ALGS),
        mac_algs=list(profile.MAC_ALGS),
        compression_algs=list(profile.COMPRESSION_ALGS),
        signature_algs=list(profile.SIGNATURE_ALGS),
        login_timeout=profile.LOGIN_GRACE_TIME,
        public_key_auth=profile.PUBKEY_AUTH,
        password_auth=profile.PASSWORD_AUTH,
        kbdint_auth=profile.KBDINT_AUTH,
    )

    await asyncssh.create_server(
        HoneypotServer,
        config.listen_host,
        config.listen_port,
        server_host_keys=host_keys,
        process_factory=handle_session,
        encoding=None,
        server_version=profile.SERVER_VERSION.replace("SSH-2.0-", ""),
        **algorithms,
    )

    # Second front end, on the attacker-facing networks only. It answers the
    # addresses node-01 resolves for erp-web and db-01, so a pivot is bridged
    # and recorded by the same machinery instead of travelling host-to-host
    # where nothing is watching. Same host keys and the same algorithm policy
    # as the perimeter listener: two hosts in one estate that negotiate
    # differently would be a tell on their own.
    gateway = PeerGateway(emitter)
    gateway.host_keys = host_keys
    gateway.server_version = profile.SERVER_VERSION.replace("SSH-2.0-", "")
    gateway.algorithms = algorithms
    await gateway.start()

    log.info(
        "listening on %s:%d as %s | sensor=%s | hassh=%s",
        config.listen_host,
        config.listen_port,
        profile.SERVER_VERSION,
        config.sensor_id,
        "on" if hassh_ok else "off",
    )
    await asyncio.Event().wait()


if __name__ == "__main__":
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main())
