"""Proxy configuration, read from the environment.

Nothing here is a secret. The proxy is the internet-facing process, so it is
the most likely thing in the ecosystem to be attacked, and it deliberately
holds no credential that is worth stealing:

  * The HMAC signing key lives in the sidecar, not here.
  * The Docker socket lives in the session broker, not here.
  * The key used to reach backend nodes authorises a shell on a throwaway
    container and nothing else.

If the proxy is fully compromised, the attacker gains what they already had:
a shell on a honeypot node.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc


@dataclass(frozen=True)
class ProxyConfig:
    # -- listener ----------------------------------------------------------
    listen_host: str = _env("PROXY_LISTEN_HOST", "0.0.0.0")
    listen_port: int = _env_int("PROXY_LISTEN_PORT", 2222)

    #: Reported as dst_port on every event. When the container publishes 2222
    #: as host port 22, the attacker's view is port 22 — that is what belongs
    #: in telemetry, not our internal bind port.
    advertised_port: int = _env_int("PROXY_ADVERTISED_PORT", 22)

    #: Names this sensor in every event. The hub groups sessions by it.
    sensor_id: str = _env("SENSOR_ID", "node-01-jump")

    # -- host keys ---------------------------------------------------------
    #: Persisted across restarts. Regenerating host keys changes the
    #: fingerprint every reboot, which no real server does and which every
    #: returning attacker's known_hosts would flag.
    host_key_dir: Path = Path(_env("HOST_KEY_DIR", "/var/lib/honeypot/hostkeys"))

    # -- telemetry ---------------------------------------------------------
    #: Append-only NDJSON the sidecar tails, signs and ships. Lives on a
    #: volume shared with the sidecar and with nothing else. Note the node
    #: itself never writes telemetry at all under this architecture, so there
    #: is no event file inside the attacker's container to find or corrupt.
    event_path: Path = Path(_env("EVENT_PATH", "/var/spool/honeypot/events.ndjson"))

    #: Full PTY transcripts, one file per session, for forensic replay. Kept
    #: separate from the event stream: events go to the hub, transcripts stay
    #: local and are read by humans.
    transcript_dir: Path = Path(_env("TRANSCRIPT_DIR", "/var/spool/honeypot/transcripts"))

    # -- session broker ----------------------------------------------------
    #: Internal-only HTTP service that owns the Docker socket and hands out
    #: per-source-IP backend containers. Split from the proxy on purpose: the
    #: process exposed to the internet must not be the process that can
    #: create containers.
    broker_url: str = _env("BROKER_URL", "http://session-broker:8080")
    broker_timeout: float = float(_env("BROKER_TIMEOUT", "30"))

    # -- backend connection ------------------------------------------------
    backend_user: str = _env("BACKEND_USER", "devuser")
    backend_key_path: Path = Path(_env("BACKEND_KEY_PATH", "/var/lib/honeypot/backend_key"))
    backend_connect_timeout: float = float(_env("BACKEND_CONNECT_TIMEOUT", "20"))

    # -- behaviour ---------------------------------------------------------
    #: Cap on a single session's wall time. Generous by design — long dwell
    #: is the goal — but not unbounded, so one stuck session cannot pin a
    #: container forever.
    max_session_seconds: int = _env_int("MAX_SESSION_SECONDS", 6 * 60 * 60)

    log_level: str = _env("LOG_LEVEL", "INFO")

    def ensure_dirs(self) -> None:
        """Create the spool locations. Safe to call repeatedly."""
        self.host_key_dir.mkdir(parents=True, exist_ok=True)
        self.transcript_dir.mkdir(parents=True, exist_ok=True)
        self.event_path.parent.mkdir(parents=True, exist_ok=True)


config = ProxyConfig()
