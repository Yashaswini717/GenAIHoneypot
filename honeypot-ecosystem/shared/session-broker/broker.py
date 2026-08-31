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

Containers are reaped after an idle TTL. On reap we record the changed paths
from `docker diff` into the event stream, so what an attacker modified is
preserved even though the container is not.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
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
    src_ip: str = Field(description="Which attacker's environment to plant into")
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
    actually place it, and only into the environment belonging to that source
    IP — never into another attacker's.
    """
    if _docker is None:
        raise HTTPException(status_code=503, detail="docker unavailable")

    backend = state.backends.get(request.src_ip)
    if backend is None:
        # Their session ended before the brain answered. Normal, not an error.
        return {"status": "no-active-session", "planted": 0}

    try:
        planted = await asyncio.to_thread(
            _write_files,
            backend.container_id,
            [(f.path, f.content, f.mode) for f in request.files],
        )
    except Exception as exc:
        log.error("could not plant decoys into %s", backend.container_name, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    backend.touch()
    log.info(
        "planted %s (intent=%s) into %s: %d file(s)",
        request.action,
        request.intent,
        backend.container_name,
        planted,
    )
    return {"status": "ok", "planted": planted, "container": backend.container_name}


def _write_files(container_id: str, files: list[tuple[str, str, int]]) -> int:
    """Place files inside a running container via the archive API.

    put_archive is used rather than `exec` because it leaves no process behind
    in the container's own process table. An attacker running `ps` while a
    decoy is being planted should see nothing at all — a stray `sh -c cat > ...`
    appearing mid-session would give away both the mechanism and the fact that
    something is watching them.
    """
    import io
    import tarfile
    import time as _time

    container = _docker.containers.get(container_id)
    written = 0

    # Group by directory: put_archive extracts a tar relative to one path.
    by_dir: dict[str, list[tuple[str, str, int]]] = {}
    for path, content, mode in files:
        directory, _, name = path.rpartition("/")
        by_dir.setdefault(directory or "/", []).append((name, content, mode))

    for directory, entries in by_dir.items():
        # The directory may not exist yet (.aws, /srv/exports and so on).
        container.exec_run(["mkdir", "-p", directory], user="root")

        # Ownership must match the directory the file lands in. put_archive
        # defaults to root:root, so decoys dropped into /home/devuser arrived
        # owned by root while every neighbouring file was devuser:devuser --
        # two root-owned files materialising mid-session is exactly the kind
        # of thing `ls -la ~` shows and nothing explains.
        owner = _owner_for(directory)

        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, content, mode in entries:
                payload = content.encode("utf-8")
                info = tarfile.TarInfo(name=name)
                info.size = len(payload)
                info.mode = mode
                info.uname = owner
                info.gname = owner
                # Timestamps land in the recent past rather than exactly now:
                # a file whose mtime is the current second, sitting in a home
                # directory whose other files are months old, is conspicuous.
                info.mtime = int(_time.time()) - 86400 * 3
                archive.addfile(info, io.BytesIO(payload))
        buffer.seek(0)

        if container.put_archive(directory, buffer.read()):
            written += len(entries)
            # uname/gname in the tar only apply if those names resolve inside
            # the container, so chown explicitly rather than trusting it.
            if owner != "root":
                paths = " ".join(f"{directory}/{name}" for name, _, _ in entries)
                container.exec_run(
                    ["sh", "-c", f"chown {owner}:{owner} {paths}"], user="root"
                )
                container.exec_run(["chown", owner, directory], user="root")

    return written


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
        mac_address=_kvm_style_mac(key),
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
            "honeypot.node": "node-01-jump",
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

    container = _docker.containers.run(
        spec["image"],
        name=name,
        detach=True,
        hostname=spec["hostname"],
        domainname=NODE_DOMAIN,
        # Attached below with aliases rather than here: Docker's embedded DNS
        # answers on the container *name*, not its hostname, so without an
        # alias node-02 could not resolve `db-01` at all -- and node-02's own
        # settings.py names exactly that host.
        network=None,
        mac_address=_kvm_style_mac(f"{key}:{spec['node']}"),
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
    back.connect(
        container,
        aliases=[spec["hostname"], f"{spec['hostname']}.{NODE_DOMAIN}"],
    )
    _attach_proxy(back)

    container.reload()
    address = _address_of(container, back.name)
    log.info("spawned peer %s (%s) for %s at %s", name, spec["node"], key, address)

    # The pivot targets come up as a pair. node-02's config names db-01, so a
    # web node without a database behind it dead-ends the chain one hop from
    # the payload. Still lazy in the way that matters: nothing beyond node-01
    # exists until somebody actually pivots, and most sessions never do.
    if spec["node"] == "node-02-erp":
        for other_octet, other in PEER_PLAN.items():
            if other["node"] != spec["node"]:
                try:
                    _spawn_peer(key, other_octet)
                except Exception:
                    log.warning("could not pre-spawn %s", other["node"], exc_info=True)

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
    for change in changes[:200]:
        log.info("  changed: %s %s", change.get("Kind"), change.get("Path"))
    try:
        await asyncio.to_thread(_force_remove, backend.container_id)
        # The network goes with it, or we leak one per attacker we ever saw
        # and eventually exhaust Docker's address pool.
        await asyncio.to_thread(_detach_proxy, _network_name(key))
    except Exception:
        log.error("failed to remove %s", backend.container_name, exc_info=True)


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
        containers = _docker.containers.list(
            all=True, filters={"label": "honeypot.role=node"}
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

    log.info(
        "session broker up: image=%s network=%s idle_ttl=%ds max=%d | adopted %d "
        "existing environment(s)",
        NODE_IMAGE,
        NODE_NETWORK,
        IDLE_TTL_SECONDS,
        MAX_CONTAINERS,
        len(recovered),
    )
    asyncio.create_task(_reaper())
