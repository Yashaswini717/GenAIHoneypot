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
    cleaned = "".join(c if c.isalnum() else "-" for c in src_ip)
    return f"hp-node01-{cleaned}-{int(time.time())}"


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
    import hashlib

    digest = hashlib.sha256(key.encode()).hexdigest()
    return "52:54:00:" + ":".join(digest[i : i + 2] for i in (0, 2, 4))


def _create_container(key: str) -> Backend:
    name = _safe_name(key)
    container = _docker.containers.run(
        NODE_IMAGE,
        name=name,
        detach=True,
        hostname=NODE_HOSTNAME,
        domainname=NODE_DOMAIN,
        network=NODE_NETWORK,
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
    container.reload()
    address = _address_of(container)
    return Backend(
        key=key,
        container_id=container.id,
        container_name=name,
        address=address,
    )


def _address_of(container: Any) -> str:
    networks = container.attrs["NetworkSettings"]["Networks"]
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


@app.on_event("startup")
async def _startup() -> None:
    log.info(
        "session broker up: image=%s network=%s idle_ttl=%ds max=%d",
        NODE_IMAGE,
        NODE_NETWORK,
        IDLE_TTL_SECONDS,
        MAX_CONTAINERS,
    )
    asyncio.create_task(_reaper())
