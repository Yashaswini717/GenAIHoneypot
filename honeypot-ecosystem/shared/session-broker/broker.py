"""Hands out one isolated backend container per attacker.

This service exists as a separate process for one reason: it owns the Docker
socket, and the process exposed to the internet must never be the process that
can create containers. The SSH proxy asks this service over an internal-only
HTTP API and receives an address to connect to; it has no way to create,
inspect, or escape into anything itself.

Isolation model
---------------
Sessions are keyed by source IP. Each key gets its own container, created from
the current node image, and Docker's storage driver gives us copy-on-write for
free — the image layers are shared, only the attacker's own changes occupy
space in their container's writable layer.

Keying by IP rather than by connection is deliberate. An attacker who plants a
cron job, disconnects, reconnects and finds it gone has learned the box is
fake; keeping their container means their persistence genuinely persists,
which is both more convincing and what makes the "persistence" intent class
meaningful. They still never see another attacker's changes.

Containers are reaped after an idle TTL, together with any pivot targets the
attacker reached. On reap we log the changed paths from `docker diff` (the
broker's own log, not the hub's event stream), so what an attacker modified is
recorded even though the container is not.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import docker
from docker.errors import DockerException, NotFound
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
log = logging.getLogger("session-broker")


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------

NODE_IMAGE = os.environ.get("NODE_IMAGE", "honeypot/node-01-jump:current")
NODE_NETWORK = os.environ.get("NODE_NETWORK", "deception-net")
NODE_HOSTNAME = os.environ.get("NODE_HOSTNAME", "jump-01")

#: The node the SSH proxy fronts. Used both as the label on entry containers
#: and as the filter when rebuilding state after a restart -- the two must
#: stay the same string, so they read it from here rather than repeating it.
ENTRY_NODE_NAME = os.environ.get("ENTRY_NODE_NAME", "node-01-jump")
NODE_DOMAIN = os.environ.get("NODE_DOMAIN", "cs.internal")
SSH_PORT = int(os.environ.get("NODE_SSH_PORT", "22"))

#: The SSH proxy's container name. The broker attaches it to each attacker's
#: private network so sessions can be bridged; without it the proxy would have
#: no route to any node.
PROXY_CONTAINER = os.environ.get("PROXY_CONTAINER", "gw-01")

#: Hostnames every attacker's environment resolves. Injected at creation time
#: rather than baked into the image, because each attacker's network gets its
#: own subnet and therefore its own addresses.
PEER_NODES = [h.strip() for h in os.environ.get(
    "PEER_NODES", "erp-web,db-01,backup-01").split(",") if h.strip()]

#: How long a container survives with no active session before reaping.
IDLE_TTL_SECONDS = int(os.environ.get("SESSION_IDLE_TTL", str(6 * 60 * 60)))

#: Ceiling on simultaneous containers. A distributed brute-force campaign can
#: otherwise turn per-IP isolation into a memory exhaustion bug on our own host.
MAX_CONTAINERS = int(os.environ.get("MAX_CONTAINERS", "40"))

#: Container runtime for attacker nodes; empty means Docker's default (runc).
#: "runsc" runs them under gVisor, so a kernel exploit by an attacker with root
#: in a node meets gVisor's user-space kernel instead of the host's -- worth it
#: on an internet-facing host. gVisor must be installed and registered with
#: Docker first (deploy/server-setup.sh does both).
NODE_RUNTIME = os.environ.get("NODE_RUNTIME", "").strip()

MEM_LIMIT = os.environ.get("NODE_MEM_LIMIT", "512m")
PIDS_LIMIT = int(os.environ.get("NODE_PIDS_LIMIT", "200"))
CPU_QUOTA = int(os.environ.get("NODE_CPU_QUOTA", "50000"))  # 0.5 CPU at the default 100ms period

#: Capabilities sshd genuinely needs to accept a login and drop to a user.
#:
#: Note what is absent: no NET_ADMIN, no SYS_ADMIN, no SYS_PTRACE, no
#: SYS_MODULE. And note what is *present* — enough for `sudo` to work, because
#: an attacker whose privilege escalation silently fails has been told the box
#: is not real. no-new-privileges is deliberately NOT set for the same reason.
NODE_CAPABILITIES = [
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "FSETID",
    "KILL",
    "SETGID",
    "SETUID",
    "SETPCAP",
    "SYS_CHROOT",
    "AUDIT_WRITE",
]


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------


@dataclass
class Backend:
    key: str
    container_id: str
    container_name: str
    address: str
    created_at: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    session_count: int = 0
    #: Decoy actions already planted into this container. Each lands once per
    #: environment: a return visit must find the decoys the way the attacker
    #: left them -- edited, deleted -- not freshly restored. In memory only, so
    #: a broker restart forgets it; the no-clobber rule in _write_files still
    #: protects every file that exists, leaving only deleted decoys to return.
    planted: set[str] = field(default_factory=set)

    def touch(self) -> None:
        self.last_seen = time.time()


class BrokerState:
    def __init__(self) -> None:
        self.backends: dict[str, Backend] = {}
        self.lock = asyncio.Lock()


state = BrokerState()
app = FastAPI(title="Honeypot Session Broker", version="1.0.0")

try:
    _docker = docker.from_env()
except DockerException:  # pragma: no cover - surfaced at startup in the log
    _docker = None
    log.error("could not reach the Docker socket", exc_info=True)


# --------------------------------------------------------------------------
# API
# --------------------------------------------------------------------------


class SessionRequest(BaseModel):
    src_ip: str = Field(description="Attacker's source address; the isolation key")
    username: str | None = Field(default=None, description="Account they authenticated as")


class SessionResponse(BaseModel):
    host: str
    port: int
    container_id: str
    container_name: str
    reused: bool = Field(description="True when the attacker is returning to their own container")
    session_count: int


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "ok" if _docker is not None else "degraded",
        "active_containers": len(state.backends),
        "image": NODE_IMAGE,
    }


@app.post("/session", response_model=SessionResponse)
async def acquire_session(request: SessionRequest) -> SessionResponse:
    """Return the backend for this source IP, creating it if needed."""
    if _docker is None:
        raise HTTPException(status_code=503, detail="docker unavailable")

    key = request.src_ip
    async with state.lock:
        existing = state.backends.get(key)
        if existing and await asyncio.to_thread(_container_alive, existing.container_id):
            existing.touch()
            existing.session_count += 1
            # Re-attach every time, not just on creation.
            #
            # Per-attacker network attachments live on the proxy *container*,
            # so recreating the proxy silently drops all of them while the
            # broker's own state still says everything is fine. The result was
            # a proxy with no interface on the attacker's network and every
            # session timing out with nothing explaining why. Both calls are
            # idempotent, so paying for them on the reuse path costs a
            # negligible exec and removes the whole failure mode.
            network = await asyncio.to_thread(_ensure_network, key)
            await asyncio.to_thread(_attach_proxy, network)
            await asyncio.to_thread(_claim_peer_addresses, key, network)
            log.info("reusing container %s for %s", existing.container_name, key)
            return SessionResponse(
                host=existing.address,
                port=SSH_PORT,
                container_id=existing.container_id,
                container_name=existing.container_name,
                reused=True,
                session_count=existing.session_count,
            )

        if existing:
            log.info("container for %s vanished, recreating", key)
            state.backends.pop(key, None)

        if len(state.backends) >= MAX_CONTAINERS:
            await _reap_oldest_locked()
            if len(state.backends) >= MAX_CONTAINERS:
                raise HTTPException(status_code=503, detail="capacity reached")

        backend = await asyncio.to_thread(_create_container, key)
        backend.session_count = 1
        state.backends[key] = backend
        log.info("created container %s for %s at %s", backend.container_name, key, backend.address)
        return SessionResponse(
            host=backend.address,
            port=SSH_PORT,
            container_id=backend.container_id,
            container_name=backend.container_name,
            reused=False,
            session_count=1,
        )


@app.post("/session/release")
async def release_session(request: SessionRequest) -> dict[str, Any]:
    """Mark a session as finished. The container stays up until the idle TTL.

    Keeping it alive is the point: a returning attacker must find their own
    changes still in place.
    """
    async with state.lock:
        backend = state.backends.get(request.src_ip)
        if backend:
            backend.touch()
    return {"status": "ok"}


class PeerRequest(BaseModel):
    from_address: str = Field(description="Address of the node the pivot came from")
    to_address: str = Field(description="Address the attacker connected to (.21 / .31)")


class PeerResponse(BaseModel):
    node: str
    hostname: str
    address: str
    port: int = 22
    spawned: bool
    #: Who this environment belongs to — the attacker's real source address.
    #: The gateway stamps it on the pivot session, because the peer address it
    #: sees is our own jump host and would otherwise split one attacker's
    #: journey into unrelated sessions.
    owner: str


@app.post("/session/peer", response_model=PeerResponse)
async def acquire_peer(request: PeerRequest) -> PeerResponse:
    """Resolve a pivot attempt into a real backend, spawning it if needed.

    The proxy holds the .21/.31 addresses inside each attacker's subnet, so a
    pivot from node-01 lands on the proxy rather than on another host. It asks
    here which node the attacker was reaching for, and gets back somewhere to
    bridge to.

    Whose environment it belongs to is decided by the *source* address, not by
    anything the attacker controls — so a pivot can only ever reach the
    attacker's own peers.
    """
    if _docker is None:
        raise HTTPException(status_code=503, detail="docker unavailable")

    try:
        octet = int(request.to_address.rsplit(".", 1)[1])
    except (ValueError, IndexError):
        raise HTTPException(status_code=400, detail="unroutable destination")

    spec = PEER_PLAN.get(octet)
    if spec is None:
        # A hostname that resolves but has nothing behind it, such as
        # backup-01. Refusing here makes it a host that is down.
        raise HTTPException(status_code=404, detail="no such host")

    async with state.lock:
        owner = next(
            (b.key for b in state.backends.values() if b.address == request.from_address),
            None,
        )
    if owner is None:
        log.warning("pivot from unknown address %s, refusing", request.from_address)
        raise HTTPException(status_code=403, detail="unknown origin")

    name = _peer_container_name(owner, spec["node"])
    existed = await asyncio.to_thread(_peer_exists, name)
    address = await asyncio.to_thread(_spawn_peer, owner, octet)

    return PeerResponse(
        node=spec["node"],
        hostname=spec["hostname"],
        address=address,
        spawned=not existed,
        owner=owner,
    )


def _peer_exists(name: str) -> bool:
    try:
        _docker.containers.get(name)
        return True
    except (NotFound, DockerException):
        return False


class DecoyFile(BaseModel):
    path: str = Field(description="Absolute path inside the attacker's container")
    content: str
    mode: int = Field(default=0o644)


class DecoyRequest(BaseModel):
    src_ip: str = Field(description="The session's source address")
    attacker: str | None = Field(
        default=None,
        description="Whose environment, as the proxy recorded it; on a pivot this is not src_ip",
    )
    node: str | None = Field(default=None, description="The node the session is on, e.g. node-02-erp")
    action: str = Field(description="The brain's chosen action label, for logging")
    intent: str = Field(default="unknown")
    files: list[DecoyFile]


@app.post("/session/decoys")
async def plant_decoys(request: DecoyRequest) -> dict[str, Any]:
    """Write brain-chosen decoys into one attacker's own container.

    This lives here rather than in the sidecar on purpose. Writing into a
    container requires the Docker socket, and the process holding the HMAC
    signing key must not also hold the ability to create and modify
    containers. The sidecar decides *what* to plant; only the broker can
    actually place it, and only into the environment belonging to that
    attacker — never into another attacker's.

    On a pivot it goes into the attacker's own copy of the node the session
    is on. Pivots used to be looked up by source address, which there is the
    attacker's jump host and owns no environment, so erp-web and db-01 never
    received a decoy ("no-active-session").
    """
    if _docker is None:
        raise HTTPException(status_code=503, detail="docker unavailable")

    owner = request.attacker or request.src_ip
    backend = state.backends.get(owner)
    if backend is None:
        # Their session ended before the brain answered. Normal, not an error.
        return {"status": "no-active-session", "planted": 0}

    target, label = backend.container_id, request.action
    target_name = backend.container_name
    if request.node in {spec["node"] for spec in PEER_PLAN.values()}:
        target_name = _peer_container_name(owner, request.node)
        if not await asyncio.to_thread(_peer_exists, target_name):
            return {"status": "no-active-session", "planted": 0}
        # By name: it is stable for the life of the environment, as an id is.
        target, label = target_name, f"{request.node}:{request.action}"

    # Once per environment, not once per session. The sidecar only remembers
    # what it planted within one session, so every return visit used to plant
    # the same action again: decoys the attacker had deleted came back, and
    # ones they had edited were silently reverted. Per node, so planting on
    # erp-web does not count as planting on node-01.
    if label in backend.planted:
        return {"status": "already-planted", "planted": 0, "skipped": len(request.files)}
    # Claimed before the write, so two sessions planting the same action at
    # once cannot both get past the check while the first is still writing.
    backend.planted.add(label)

    try:
        planted, skipped = await asyncio.to_thread(
            _write_files,
            target,
            [(f.path, f.content, f.mode) for f in request.files],
        )
    except Exception as exc:
        backend.planted.discard(label)
        log.error("could not plant decoys into %s", target_name, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    backend.touch()
    log.info(
        "planted %s (intent=%s) into %s: %d file(s), %d left alone because they already exist",
        request.action,
        request.intent,
        target_name,
        planted,
        skipped,
    )
    return {"status": "ok", "planted": planted, "skipped": skipped, "container": target_name}


#: Prints which of its arguments already exist, and creates the parent
#: directory of each one that does not. One exec per plant, in place of the
#: `mkdir -p` this used to run once per directory.
_PREPARE_SCRIPT = (
    'for p in "$@"; do '
    'if [ -e "$p" ] || [ -L "$p" ]; then printf \'%s\\n\' "$p"; '
    'else d="${p%/*}"; if [ -n "$d" ]; then mkdir -p "$d"; fi; fi; '
    "done"
)


def _prepare_paths(container: Any, paths: list[str]) -> set[str]:
    """Which of `paths` already exist in the container; parents made for the rest."""
    if not paths:
        return set()
    exit_code, output = container.exec_run(["sh", "-c", _PREPARE_SCRIPT, "sh", *paths], user="root")
    if exit_code != 0:
        raise RuntimeError(f"could not prepare decoy paths (exit {exit_code}): {output!r}")
    requested = set(paths)
    return {line for line in (output or b"").decode("utf-8", "replace").splitlines() if line in requested}


#: Prints, for each argument in order, "<mtime> <directory>": the nearest
#: directory above it that already exists. Run before anything is created,
#: because making a directory, or adding anything to one, moves its mtime to
#: the present.
_ANCESTOR_SCRIPT = (
    'for p in "$@"; do a="${p%/*}"; '
    'while [ -n "$a" ] && [ ! -d "$a" ]; do a="${a%/*}"; done; '
    'printf \'%s %s\\n\' "$(stat -c %Y "${a:-/}")" "${a:-/}"; '
    "done"
)


def _existing_ancestors(container: Any, paths: list[str]) -> dict[str, tuple[str, int]]:
    """Each path's nearest existing directory, with that directory's mtime now."""
    if not paths:
        return {}
    exit_code, output = container.exec_run(["sh", "-c", _ANCESTOR_SCRIPT, "sh", *paths], user="root")
    if exit_code != 0:
        return {}
    found = {}
    lines = (output or b"").decode("utf-8", "replace").splitlines()
    for path, line in zip(paths, lines):
        stamp, _, directory = line.partition(" ")
        if stamp.isdigit() and directory:
            found[path] = (directory, int(stamp))
    return found


def _write_files(container_id: str, files: list[tuple[str, str, int]]) -> tuple[int, int]:
    """Place files inside a running container via the archive API.

    Returns (written, skipped). A path that already exists is never
    overwritten: it is either something the attacker made or changed, a real
    file the node depends on, or a decoy planted earlier -- and replacing any
    of those is visible. Generated profiles used to overwrite `.bashrc`,
    `.bash_history`, `/etc/crontab` and the live `/var/log/auth.log`, so the
    attacker's own history vanished and rsyslog went on writing to an unlinked
    file while `tail` showed model-written lines.

    put_archive is used rather than `exec` because it leaves no process behind
    in the container's own process table. An attacker running `ps` while a
    decoy is being planted should see nothing at all — a stray `sh -c cat > ...`
    appearing mid-session would give away both the mechanism and the fact that
    something is watching them.
    """
    import io
    import tarfile

    container = _docker.containers.get(container_id)
    written = 0
    # Read once: every decoy in this container hangs off the same fixed point.
    anchor = _container_epoch(container)
    stamps: dict[str, int] = {}

    # Before anything is created; see _date_directories.
    ancestors = _existing_ancestors(container, [path for path, _, _ in files])

    # Also creates any missing directories (.aws, /srv/exports and so on).
    present = _prepare_paths(container, [path for path, _, _ in files])
    fresh = [(path, content, mode) for path, content, mode in files if path not in present]

    # Group by directory: put_archive extracts a tar relative to one path.
    by_dir: dict[str, list[tuple[str, str, int]]] = {}
    for path, content, mode in fresh:
        directory, _, name = path.rpartition("/")
        by_dir.setdefault(directory or "/", []).append((name, content, mode))

    for directory, entries in by_dir.items():
        # Ownership must match the directory the file lands in. put_archive
        # defaults to root:root, so decoys dropped into /home/devuser arrived
        # owned by root while every neighbouring file was devuser:devuser --
        # two root-owned files materialising mid-session is exactly the kind
        # of thing `ls -la ~` shows and nothing explains.
        owner = _owner_for(directory)
        mtimes = {name: _decoy_mtime(anchor, container_id, f"{directory}/{name}") for name, _, _ in entries}

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, content, mode in entries:
                payload = content.encode("utf-8")
                info = tarfile.TarInfo(name=name)
                info.size = len(payload)
                info.mode = mode
                info.uname = owner
                info.gname = owner
                info.mtime = mtimes[name]
                archive.addfile(info, io.BytesIO(payload))
        buffer.seek(0)

        if container.put_archive(directory, buffer.read()):
            written += len(entries)
            stamps.update({f"{directory.rstrip('/')}/{name}": mtime for name, mtime in mtimes.items()})
            # uname/gname in the tar only apply if those names resolve inside
            # the container, so chown explicitly rather than trusting it.
            if owner != "root":
                paths = " ".join(f"{directory}/{name}" for name, _, _ in entries)
                container.exec_run(
                    ["sh", "-c", f"chown {owner}:{owner} {paths}"], user="root"
                )
                # Every directory `mkdir -p` had to create, not just the leaf.
                #
                # A path like /home/devuser/.config/gh creates BOTH .config and
                # gh as root, and chowning only the leaf left `.config` sitting
                # root-owned in a user's home -- the first line of `ls -la ~`,
                # and exactly the anomaly the comment above is about. Flat
                # bundles never showed it because they had no intermediate
                # directories; generated profiles have several.
                #
                # Also `owner:owner` rather than a bare `owner`: chown without
                # a group leaves group root, which `ls -la` prints just as
                # plainly as a wrong owner does.
                owned = _owned_ancestors(directory, owner)
                if owned:
                    container.exec_run(
                        ["sh", "-c", f"chown {owner}:{owner} {' '.join(owned)}"],
                        user="root",
                    )

    _date_directories(container, stamps, ancestors)
    return written, len(files) - len(fresh)


#: Sets atime and mtime from "<epoch> <path>" argument pairs.
_BACKDATE_SCRIPT = 'while [ "$#" -gt 1 ]; do touch -c -d "@$1" "$2"; shift 2; done'


def _directory_times(stamps: dict[str, int], ancestors: dict[str, tuple[str, int]]) -> dict[str, int]:
    """The mtime each directory should end on once the files in `stamps` exist.

    `stamps` maps each file written to its backdated mtime; `ancestors` maps it
    to the nearest directory that existed before the write, with that
    directory's mtime then. Every directory in between was made for this write,
    so it takes the time of the newest file below it. The pre-existing one
    keeps its own time unless something newer was added to it.
    """
    times: dict[str, int] = {}
    for path, stamp in stamps.items():
        if path not in ancestors:
            continue
        top, before = ancestors[path]
        if not path.startswith(top.rstrip("/") + "/"):
            continue
        directory = path.rpartition("/")[0] or "/"
        while directory != top:
            times[directory] = max(times.get(directory, 0), stamp)
            directory = directory.rpartition("/")[0] or "/"
        times[top] = max(times.get(top, before), stamp)
    return times


def _date_directories(container: Any, stamps: dict[str, int], ancestors: dict[str, tuple[str, int]]) -> None:
    """Date the directories a write touched to match the files it wrote.

    Only the files used to be backdated. `mkdir -p` dated every directory it
    made to the present, and adding a file or directory moved its parent's
    mtime there too, so `ls -la ~/app` showed `.` and `..` from today above
    contents months old (seen 2026-11-04). Now the tree looks as it would had
    the decoys really been written on their dates.

    Never fails a plant: the files are in place either way, and a directory
    that keeps today's date is the old behaviour, not a new failure.
    """
    times = _directory_times(stamps, ancestors)
    if not times:
        return
    pairs = [str(value) for directory, mtime in sorted(times.items()) for value in (mtime, directory)]
    try:
        exit_code, output = container.exec_run(["sh", "-c", _BACKDATE_SCRIPT, "sh", *pairs], user="root")
    except Exception as exc:
        log.warning("could not date decoy directories: %s", exc)
        return
    if exit_code != 0:
        log.warning("could not date decoy directories (exit %s): %r", exit_code, output)


#: Decoys are dated between these two bounds, in days before now.
#:
#: Never newer than the lower bound, because a file whose mtime is the current
#: second, sitting in a home directory whose other files are months old, is the
#: thing `ls -lat` puts at the very top. Never older than the upper bound, so
#: decoys stay inside the window of history the node claims to have
#: (`identity.yaml` seeds 94 days, and the image's own files run back years).
_DECOY_AGE_MIN_DAYS = 3
_DECOY_AGE_MAX_DAYS = 180


def _decoy_mtime(anchor: int, container_id: str, path: str) -> int:
    """A plausible, stable modification time for one decoy.

    Two properties matter, and a fixed `now - 3 days` had neither.

    Spread: every file planted in a session used to share an mtime to the
    second. Half a dozen files stamped identically, among neighbours dated
    across months and years, is a cluster `ls -lat` surfaces immediately -- and
    it reads as exactly what it is, a batch written by one process.

    Stability: `anchor` is the container's creation time, not the current time.
    Anchoring to now would keep the *relative* age fixed while the absolute
    mtime crept forward, so an attacker returning two days later would find
    every decoy's timestamp had moved two days with them. A file whose mtime
    changes between two logins is a far louder tell than one that merely looks
    recent, and letting them come back to their own environment is the whole
    reason the container is kept.

    Keying on the container as well as the path means two attackers do not see
    identical timestamps on identical decoys, which is what separate machines
    would look like.
    """
    digest = hashlib.sha256(f"{container_id}:{path}".encode()).digest()
    span = (_DECOY_AGE_MAX_DAYS - _DECOY_AGE_MIN_DAYS) * 86400
    offset = _DECOY_AGE_MIN_DAYS * 86400 + int.from_bytes(digest[:6], "big") % span
    return anchor - offset


def _container_epoch(container: Any) -> int:
    """When this container was created, as a Unix timestamp.

    The stable reference decoy timestamps hang off. Docker reports nanosecond
    precision, which `fromisoformat` will not parse, so the fraction is
    truncated to microseconds.
    """
    try:
        created = container.attrs["Created"]
        head, _, frac = created.partition(".")
        if frac:
            created = f"{head}.{frac.rstrip('Z')[:6]}+00:00"
        else:
            created = f"{head.rstrip('Z')}+00:00"
        return int(datetime.fromisoformat(created).timestamp())
    except Exception:
        log.debug("could not read container creation time; anchoring to now", exc_info=True)
        return int(time.time())


def _owned_ancestors(directory: str, owner: str) -> list[str]:
    """Directories between the owner's home and `directory`, inclusive.

    `/home/devuser/.config/gh` yields `/home/devuser/.config` and
    `/home/devuser/.config/gh`. The home directory itself is left alone: it
    exists in the image, already has the right owner, and rewriting it would be
    one more mtime that moved for no reason a reader could explain.
    """
    parts = [p for p in directory.split("/") if p]
    if len(parts) < 3 or parts[0] != "home" or parts[1] != owner:
        return []
    home = f"/home/{owner}"
    out, current = [], home
    for segment in parts[2:]:
        current = f"{current}/{segment}"
        out.append(current)
    return out


def _owner_for(directory: str) -> str:
    """Who should own a decoy dropped here.

    Derived from the path so the courier does not have to know about accounts:
    anything under /home/<name> belongs to <name>, everything else to root,
    which matches how a real filesystem looks.
    """
    parts = [p for p in directory.split("/") if p]
    if len(parts) >= 2 and parts[0] == "home":
        return parts[1]
    return "root"


@app.get("/sessions")
async def list_sessions() -> dict[str, Any]:
    now = time.time()
    return {
        "count": len(state.backends),
        "sessions": [
            {
                "key": b.key,
                "container": b.container_name,
                "address": b.address,
                "age_seconds": round(now - b.created_at, 1),
                "idle_seconds": round(now - b.last_seen, 1),
                "session_count": b.session_count,
            }
            for b in state.backends.values()
        ],
    }


# --------------------------------------------------------------------------
# docker plumbing
# --------------------------------------------------------------------------


def _safe_name(src_ip: str) -> str:
    """A container name that does not advertise what this is.

    Docker answers reverse DNS with the container name, so anything an
    attacker can reach will eventually print it -- `netstat`, `w`, `last`,
    ssh's "Last login from". A name like "hp-node01-..." names the project in
    one line, so nodes are named after the role they claim instead.
    """
    digest = hashlib.sha256(f"{src_ip}:{NODE_HOSTNAME}".encode()).hexdigest()[:6]
    return f"{NODE_HOSTNAME}-{digest}"


def _container_alive(container_id: str) -> bool:
    try:
        container = _docker.containers.get(container_id)
        container.reload()
        return container.status == "running"
    except (NotFound, DockerException):
        return False


def _kvm_style_mac(key: str) -> str:
    """A MAC that looks like a virtual machine rather than a container.

    Docker hands out addresses in 02:42:xx, which `ip link` shows and which
    identifies the runtime immediately. 52:54:00 is QEMU/KVM's assigned OUI,
    so the node reads as an ordinary VM — which is what a university jump host
    on cloud infrastructure would actually be.

    Derived from the session key so a returning attacker sees the same address
    on the same container.
    """
    digest = hashlib.sha256(key.encode()).hexdigest()
    return "52:54:00:" + ":".join(digest[i : i + 2] for i in (0, 2, 4))


def _runtime_options() -> dict[str, str]:
    """`runtime=` for an attacker node, or nothing for Docker's default.

    Both kinds of node -- the entry host and the pivot peers -- take it, so
    an attacker cannot step from a sandboxed container into an unsandboxed one.
    """
    return {"runtime": NODE_RUNTIME} if NODE_RUNTIME else {}


#: The estate, and where each node sits relative to the attacker.
#
# node-01 is the only host on the front network. node-02 and node-03 live on a
# back network node-01 cannot reach at all -- the addresses node-01 resolves
# for them are secondary addresses on the PROXY, so every pivot is bridged and
# recorded rather than travelling host-to-host where nothing is watching.
#
# The last octet is the routing key: .21 is always the web node, .31 always the
# database. Keeping it stable means the proxy can map a destination address to
# a role without asking anyone.
PEER_PLAN: dict[int, dict[str, str]] = {
    21: {"node": "node-02-erp", "hostname": "erp-web", "image": "honeypot/node-02-erp:current"},
    31: {"node": "node-03-db", "hostname": "db-01", "image": "honeypot/node-03-db:current"},
}


def _back_network_name(key: str) -> str:
    digest = hashlib.sha256(f"net:{key}".encode()).hexdigest()[:6]
    return f"{NODE_DOMAIN}-{digest}-b"


def _ensure_back_network(key: str) -> Any:
    """Where the pivot targets actually live.

    Separate from the attacker's own network on purpose. If node-02 sat beside
    node-01, `ssh erp-web` would go straight there and the proxy would never
    see it — login events only, no commands, no intent, no adaptive decoys on
    two thirds of the estate.
    """
    name = _back_network_name(key)
    try:
        return _docker.networks.get(name)
    except NotFound:
        pass
    return _docker.networks.create(
        name,
        driver="bridge",
        internal=True,
        labels={"honeypot.role": "peer-net", "honeypot.key": key},
    )


def _proxy_interface_for(network_name: str) -> tuple[str, str] | None:
    """Find the proxy's interface and address on one attacker network.

    Docker names interfaces eth0, eth1, ... in attachment order, which is not
    predictable from outside, so the interface is located by matching the
    address Docker assigned rather than by guessing a name.
    """
    try:
        proxy = _docker.containers.get(PROXY_CONTAINER)
        proxy.reload()
        settings = proxy.attrs["NetworkSettings"]["Networks"].get(network_name)
        if not settings or not settings.get("IPAddress"):
            return None
        address = settings["IPAddress"]
        result = proxy.exec_run(
            ["sh", "-c", f"ip -o -4 addr show | grep -w {address} | awk '{{print $2}}'"],
            user="root",
        )
        iface = result.output.decode().strip().splitlines()
        return (iface[0], address) if iface else None
    except DockerException:
        log.warning("could not inspect proxy interfaces for %s", network_name, exc_info=True)
        return None


def _claim_peer_addresses(key: str, network: Any) -> dict[str, str]:
    """Give the proxy the addresses node-01 will resolve for its peers.

    This is what NET_ADMIN on the proxy buys. The alternative -- pointing both
    hostnames at the proxy's single address -- fails on its own terms: two
    departmental hosts resolving to one IP is something an attacker notices
    with one `getent hosts`.
    """
    found = _proxy_interface_for(network.name)
    if not found:
        return {}
    iface, proxy_address = found
    prefix = proxy_address.rsplit(".", 1)[0]

    mapping: dict[str, str] = {}
    try:
        proxy = _docker.containers.get(PROXY_CONTAINER)
        for octet, spec in PEER_PLAN.items():
            address = f"{prefix}.{octet}"
            # Idempotent: adding an address already present exits 2, which is
            # fine on a reconnect.
            proxy.exec_run(
                ["sh", "-c", f"ip addr add {address}/16 dev {iface} 2>/dev/null || true"],
                user="root",
            )
            # Verify rather than assume. The first version fired and forgot,
            # so when `ip` turned out to be missing from the proxy image the
            # claim silently did nothing while logging success -- and every
            # pivot failed with "No route to host" for a reason nothing
            # recorded. A capability that quietly does not work is worse than
            # one that is absent.
            check = proxy.exec_run(
                ["sh", "-c", f"ip -o -4 addr show dev {iface} | grep -c -w {address}"],
                user="root",
            )
            if check.output.decode().strip() == "0":
                log.error(
                    "failed to claim %s on %s (iface %s) -- pivots to %s will not "
                    "connect. Does the proxy have iproute2 and NET_ADMIN?",
                    address, network.name, iface, spec["hostname"],
                )
                continue
            mapping[spec["hostname"]] = address
    except DockerException:
        log.warning("could not claim peer addresses on %s", network.name, exc_info=True)
        return {}

    if mapping:
        log.info("proxy now answers for %s on %s", ", ".join(mapping), network.name)
    return mapping


def _network_name(key: str) -> str:
    """One network per attacker, named so it does not advertise anything.

    Reverse lookups include the network name, so this has to read like a
    departmental subnet rather than a per-attacker sandbox.
    """
    digest = hashlib.sha256(f"net:{key}".encode()).hexdigest()[:6]
    return f"{NODE_DOMAIN}-{digest}"


def _ensure_network(key: str) -> Any:
    """Create (or fetch) this attacker's private network.

    Strict isolation needs this. With every node on one shared network, an
    attacker who ran `nmap 10.60.0.0/24` found *other attackers' containers*
    and could connect straight to them — verified, not theoretical. Beyond
    being a containment failure it is also a realism failure: a second machine
    identical to the one you just compromised, appearing and disappearing as
    other people log in, is not something a real network does.

    Each attacker now gets their own network, so the environment they explore
    contains only their own nodes. Docker allocates the subnet, so the
    addresses differ per attacker and cannot be baked into the image — the
    broker injects the host entries at creation time instead.
    """
    name = _network_name(key)
    try:
        return _docker.networks.get(name)
    except NotFound:
        pass

    return _docker.networks.create(
        name,
        driver="bridge",
        internal=True,  # no route to the internet, the hub, or the brain
        labels={"honeypot.role": "attacker-net", "honeypot.key": key},
    )


def _attach_proxy(network: Any) -> None:
    """Put the SSH proxy on this attacker's network so it can bridge sessions.

    The proxy is the one component that must reach every attacker's
    environment; it is also the only one that does. Nodes still cannot reach
    the broker, the sidecar, or the brain.
    """
    if not PROXY_CONTAINER:
        return
    try:
        network.reload()
        attached = {c.get("Name") for c in network.attrs.get("Containers", {}).values()}
        if PROXY_CONTAINER in attached:
            return
        network.connect(PROXY_CONTAINER)
    except DockerException:
        log.warning("could not attach %s to %s", PROXY_CONTAINER, network.name, exc_info=True)


def _detach_proxy(network_name: str) -> None:
    try:
        network = _docker.networks.get(network_name)
        if PROXY_CONTAINER:
            try:
                network.disconnect(PROXY_CONTAINER, force=True)
            except DockerException:
                pass
        network.remove()
    except (NotFound, DockerException):
        pass


def _adopt_existing(name: str, key: str) -> Backend | None:
    """Reclaim a container this attacker already owns.

    Names are derived from the source IP, so they are stable across broker
    restarts — which means a restart finds its own containers still running
    under the names it is about to reuse. Failing on the name conflict would
    both break the session and, worse, silently sever an attacker from the
    environment they had been building up.

    Adopting instead makes a broker restart invisible: the attacker returns to
    their own container with their own changes intact, which is exactly the
    isolation guarantee we promise.
    """
    try:
        container = _docker.containers.get(name)
    except (NotFound, DockerException):
        return None

    container.reload()
    if container.status != "running":
        try:
            container.start()
            container.reload()
        except DockerException:
            log.info("stale container %s could not be started, replacing it", name)
            try:
                container.remove(force=True)
            except DockerException:
                pass
            return None

    log.info("adopted existing container %s for %s", name, key)
    return Backend(
        key=key,
        container_id=container.id,
        container_name=name,
        address=_address_of(container),
    )


def _peer_hosts(network: Any) -> dict[str, str]:
    """Addresses for the other nodes, inside *this* attacker's subnet.

    Each attacker now gets their own network with its own subnet, so the
    addresses the image used to bake into /etc/hosts (10.60.0.21 and friends)
    are no longer on any network they can see. Left alone, `ssh erp-web` fails
    with "Network is unreachable" — a routing error, which is not how a host
    on your own LAN behaves when it is merely down.

    Deriving them from the live subnet keeps the failure mode honest: the
    address is local, nothing answers, and it reads as a host that is off.
    """
    try:
        network.reload()
        config = network.attrs["IPAM"]["Config"][0]["Subnet"]
        prefix = config.rsplit(".", 1)[0]
    except Exception:
        return {}
    # .21/.31/.41 mirror the numbering the seeded notes and docs refer to.
    # .21 and .31 are answered by the proxy (see _claim_peer_addresses), so a
    # pivot is bridged and recorded. .41 has no node behind it and stays a
    # host that is simply off -- not every hostname in an estate is up.
    #
    # Both the short name and the FQDN, because the seeded ~/.ssh/config on
    # node-01 uses `HostName erp-web.cs.internal`. With only the short name
    # present, following our own breadcrumb failed with "Temporary failure in
    # name resolution" -- an attacker who does exactly what the config tells
    # them to should not hit a DNS error.
    offsets = [21, 31, 41]
    hosts: dict[str, str] = {}
    for host, offset in zip(PEER_NODES, offsets):
        address = f"{prefix}.{offset}"
        hosts[host] = address
        hosts[f"{host}.{NODE_DOMAIN}"] = address
    return hosts


def _create_container(key: str) -> Backend:
    name = _safe_name(key)
    network = _ensure_network(key)

    adopted = _adopt_existing(name, key)
    if adopted is not None:
        _attach_proxy(network)
        _claim_peer_addresses(key, network)
        return adopted

    container = _docker.containers.run(
        NODE_IMAGE,
        name=name,
        detach=True,
        hostname=NODE_HOSTNAME,
        domainname=NODE_DOMAIN,
        network=network.name,
        extra_hosts=_peer_hosts(network),
        # Not the cloud host's search domain (ap-southeast-2.compute.internal on AWS).
        dns_search=[NODE_DOMAIN],
        mac_address=_kvm_style_mac(key),
        **_runtime_options(),
        cap_drop=["ALL"],
        cap_add=NODE_CAPABILITIES,
        mem_limit=MEM_LIMIT,
        pids_limit=PIDS_LIMIT,
        cpu_quota=CPU_QUOTA,
        # No privileged mode, no host namespaces, no bind mounts, and no
        # Docker socket. The container has no route off the deception network.
        privileged=False,
        labels={
            "honeypot.role": "node",
            "honeypot.node": ENTRY_NODE_NAME,
            "honeypot.key": key,
        },
    )
    _attach_proxy(network)
    _claim_peer_addresses(key, network)
    container.reload()
    address = _address_of(container, network.name)
    return Backend(
        key=key,
        container_id=container.id,
        container_name=name,
        address=address,
    )


def _peer_container_name(key: str, node: str) -> str:
    digest = hashlib.sha256(f"{node}:{key}".encode()).hexdigest()[:6]
    hostname = next(s["hostname"] for s in PEER_PLAN.values() if s["node"] == node)
    return f"{hostname}-{digest}"


def _spawn_peer(key: str, octet: int) -> str:
    """Bring up a pivot target for one attacker, on demand.

    Lazily, because an estate of three nodes per attacker is three times the
    memory and most sessions never pivot at all. The node is created the first
    time someone actually reaches for it, which is also the moment the delay
    is least noticeable — a few seconds of SSH connecting looks like a loaded
    host, not like a container booting.
    """
    spec = PEER_PLAN[octet]
    name = _peer_container_name(key, spec["node"])
    back = _ensure_back_network(key)

    try:
        container = _docker.containers.get(name)
        container.reload()
        if container.status != "running":
            container.start()
            container.reload()
        # Same reason as the entry node: a recreated proxy has lost this
        # attachment even though the peer container is untouched.
        _attach_proxy(back)
        log.info("reusing peer %s for %s", name, key)
        return _address_of(container, back.name)
    except NotFound:
        pass

    # The pivot targets come up as a pair. node-02's config names db-01, so a
    # web node without a database behind it dead-ends the chain one hop from
    # the payload. Still lazy in the way that matters: nothing beyond node-01
    # exists until somebody actually pivots, and most sessions never do.
    # The database comes up first so the web node can be handed its address.
    # Docker's embedded DNS does not answer inside gVisor, so under runsc the
    # alias alone left `db-01` unresolvable from erp-web (AWS, 2026-11-05).
    hosts: dict[str, str] = {}
    if spec["node"] == "node-02-erp":
        for other_octet, other in PEER_PLAN.items():
            if other["node"] == spec["node"]:
                continue
            try:
                other_address = _spawn_peer(key, other_octet)
            except Exception:
                log.warning("could not pre-spawn %s", other["node"], exc_info=True)
                continue
            hosts[other["hostname"]] = other_address
            hosts[f"{other['hostname']}.{NODE_DOMAIN}"] = other_address

    container = _docker.containers.run(
        spec["image"],
        name=name,
        detach=True,
        hostname=spec["hostname"],
        domainname=NODE_DOMAIN,
        extra_hosts=hosts,
        # Otherwise Docker copies the host's search domain into resolv.conf,
        # and on AWS that is ap-southeast-2.compute.internal: a giveaway.
        dns_search=[NODE_DOMAIN],
        # On the back network only, from creation. It used to start on Docker's
        # default network and be connected to the back network afterwards:
        # - That left a second interface on the default bridge, which routes to
        #   the internet, so erp-web and db-01 could reach anything, the cloud
        #   metadata address included (found on the AWS server, 2026-11-05).
        # - gVisor never sees an interface added after start, so under runsc
        #   the back network was missing inside the peer and every pivot failed.
        # The aliases are needed because Docker's embedded DNS answers on the
        # container *name*, not its hostname. Without them node-02 could not
        # resolve `db-01`, and node-02's own settings.py names exactly that host.
        network=back.name,
        networking_config={
            back.name: _docker.api.create_endpoint_config(
                aliases=[spec["hostname"], f"{spec['hostname']}.{NODE_DOMAIN}"],
            ),
        },
        mac_address=_kvm_style_mac(f"{key}:{spec['node']}"),
        **_runtime_options(),
        cap_drop=["ALL"],
        cap_add=NODE_CAPABILITIES,
        mem_limit=os.environ.get("PEER_MEM_LIMIT", "640m"),
        pids_limit=PIDS_LIMIT,
        cpu_quota=CPU_QUOTA,
        privileged=False,
        labels={
            "honeypot.role": "node",
            "honeypot.node": spec["node"],
            "honeypot.key": key,
        },
    )
    _attach_proxy(back)

    container.reload()
    address = _address_of(container, back.name)
    log.info("spawned peer %s (%s) for %s at %s", name, spec["node"], key, address)
    return address


def _address_of(container: Any, network_name: str | None = None) -> str:
    networks = container.attrs["NetworkSettings"]["Networks"]
    if network_name and network_name in networks:
        return networks[network_name]["IPAddress"]
    if NODE_NETWORK in networks:
        return networks[NODE_NETWORK]["IPAddress"]
    # Fall back to whichever network it did land on.
    for settings in networks.values():
        if settings.get("IPAddress"):
            return settings["IPAddress"]
    raise RuntimeError(f"container {container.name} has no reachable address")


def _collect_changes(container_id: str) -> list[dict[str, Any]]:
    """What the attacker modified, from Docker's own layer diff.

    Cheap, and it survives the container being destroyed — so the record of
    what changed outlives the thing that changed.
    """
    try:
        container = _docker.containers.get(container_id)
        return container.diff() or []
    except (NotFound, DockerException):
        return []


async def _reap_oldest_locked() -> None:
    """Evict the least recently used backend. Caller must hold the lock."""
    if not state.backends:
        return
    key = min(state.backends, key=lambda k: state.backends[k].last_seen)
    await _destroy(key)


def _log_changes(changes: list[dict[str, Any]]) -> None:
    for change in changes[:200]:
        log.info("  changed: %s %s", change.get("Kind"), change.get("Path"))


async def _destroy(key: str) -> None:
    backend = state.backends.pop(key, None)
    if backend is None:
        return
    changes = await asyncio.to_thread(_collect_changes, backend.container_id)
    log.info(
        "reaping %s for %s after %d session(s); %d changed path(s)",
        backend.container_name,
        key,
        backend.session_count,
        len(changes),
    )
    _log_changes(changes)
    try:
        await asyncio.to_thread(_force_remove, backend.container_id)
        # The network goes with it, or we leak one per attacker we ever saw
        # and eventually exhaust Docker's address pool.
        await asyncio.to_thread(_detach_proxy, _network_name(key))
        await asyncio.to_thread(_destroy_peers, key)
    except Exception:
        log.error("failed to remove %s", backend.container_name, exc_info=True)


def _destroy_peers(key: str) -> None:
    """Remove the pivot targets one attacker reached, and the network they sat on.

    These used to outlive the jump host. Reaping removed node-01 only, so
    node-02 and node-03 stayed up forever: up to 640 MB each, uncounted by
    MAX_CONTAINERS, and still holding an attacker's old changes after their
    jump host had been replaced with a fresh one -- a world where the box they
    came in through had forgotten them and the boxes behind it had not.
    """
    for spec in PEER_PLAN.values():
        name = _peer_container_name(key, spec["node"])
        if not _peer_exists(name):
            continue
        changes = _collect_changes(name)
        log.info("reaping peer %s (%s) for %s; %d changed path(s)", name, spec["node"], key, len(changes))
        _log_changes(changes)
        try:
            _force_remove(name)
        except DockerException:
            log.warning("could not remove peer %s", name, exc_info=True)
    _detach_proxy(_back_network_name(key))


def _reap_orphans(owners: set[str]) -> int:
    """Remove what departed attackers left behind: pivot targets and networks.

    Left by pivot targets that `_destroy` did not remove before, or by a jump
    host deleted out from under the broker -- which strands its peers, its back
    network and its own network too, since only `_destroy` removes that. With
    no jump host the owner can never reach any of it again. A network a node
    is still attached to is refused by Docker, so this cannot pull one out from
    under a live environment. Returns how many owners were cleaned up after.
    """
    if _docker is None:
        return 0
    orphans: set[str] = set()
    for spec in PEER_PLAN.values():
        try:
            containers = _docker.containers.list(all=True, filters={"label": f"honeypot.node={spec['node']}"})
        except DockerException:
            log.warning("could not list %s containers", spec["node"], exc_info=True)
            continue
        for container in containers:
            owner = container.labels.get("honeypot.key")
            if owner and owner not in owners:
                orphans.add(owner)
    try:
        networks = _docker.networks.list(filters={"label": "honeypot.role=attacker-net"})
    except DockerException:
        log.warning("could not list attacker networks", exc_info=True)
        networks = []
    for network in networks:
        owner = (network.attrs.get("Labels") or {}).get("honeypot.key")
        if owner and owner not in owners:
            orphans.add(owner)
    for owner in orphans:
        _destroy_peers(owner)
        _detach_proxy(_network_name(owner))
    return len(orphans)


def _force_remove(container_id: str) -> None:
    container = _docker.containers.get(container_id)
    container.remove(force=True)


async def _reaper() -> None:
    while True:
        await asyncio.sleep(60)
        now = time.time()
        async with state.lock:
            stale = [k for k, b in state.backends.items() if now - b.last_seen > IDLE_TTL_SECONDS]
            for key in stale:
                await _destroy(key)


def _reconcile() -> list[Backend]:
    """Rebuild in-memory state from containers that outlived the broker.

    Without this the broker forgets every live attacker environment on
    restart: it would neither reap them nor route their owners back to them,
    and the TTL that bounds resource use would never fire for any of them.
    """
    if _docker is None:
        return []
    found: list[Backend] = []
    try:
        # ENTRY NODES ONLY.
        #
        # Every node an attacker owns -- the jump host and both pivot targets
        # -- carries the same honeypot.key, because the key is their source
        # IP. Filtering on honeypot.role=node therefore adopted all three
        # under one key and whichever Docker happened to list last won, so
        # after a broker restart a perimeter SSH session was routed to
        # erp-web or db-01 instead of the jump host. Nondeterministic, and it
        # broke the session outright.
        #
        # Peers are found through _spawn_peer by name when a pivot resolves,
        # so they never needed to be in this map at all.
        containers = _docker.containers.list(
            all=True, filters={"label": f"honeypot.node={ENTRY_NODE_NAME}"}
        )
    except DockerException:
        log.warning("could not list existing node containers", exc_info=True)
        return []

    for container in containers:
        key = container.labels.get("honeypot.key")
        if not key:
            continue
        try:
            container.reload()
            if container.status != "running":
                container.start()
                container.reload()
            found.append(
                Backend(
                    key=key,
                    container_id=container.id,
                    container_name=container.name,
                    address=_address_of(container),
                )
            )
        except Exception:
            log.debug("skipping unusable container %s", container.name, exc_info=True)
    return found


@app.on_event("startup")
async def _startup() -> None:
    recovered = await asyncio.to_thread(_reconcile)
    async with state.lock:
        for backend in recovered:
            state.backends[backend.key] = backend
    orphaned = await asyncio.to_thread(_reap_orphans, {b.key for b in recovered})

    log.info(
        "session broker up: image=%s network=%s runtime=%s idle_ttl=%ds max=%d | adopted %d "
        "existing environment(s), cleaned up after %d departed attacker(s)",
        NODE_IMAGE,
        NODE_NETWORK,
        NODE_RUNTIME or "default",
        IDLE_TTL_SECONDS,
        MAX_CONTAINERS,
        len(recovered),
        orphaned,
    )
    asyncio.create_task(_reaper())
