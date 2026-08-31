"""Cowrie-schema event builders.

The intelligence hub's normalizer (`intelligence_hub/backend/ingest/normalizer.py`)
is hardcoded to Cowrie event ids and field names. That contract is fixed: the hub
must not change to accommodate us, so every sensor in this ecosystem emits events
shaped exactly like Cowrie's JSON log lines.

Fields the hub reads, and where they come from here:

    eventid    -> EventId.*            timestamp -> ISO-8601 with a trailing Z
    session    -> 12 hex chars         sensor    -> node id, e.g. "node-01-jump"
    src_ip     -> attacker             src_port  -> attacker
    dst_ip     -> our listener         dst_port  -> our listener
    username   -> login attempts       password  -> login attempts
    hassh      -> client KEXINIT       version   -> client ident string
    input      -> one shell command    duration  -> seconds, session close only
    message    -> human-readable line the hub stores as raw_message

Anything the hub does not read is still allowed through — it lands in
Elasticsearch alongside the mapped fields and costs nothing.
"""

from __future__ import annotations

import os
import secrets
from datetime import datetime, timezone
from typing import Any, Final


class EventId:
    """The nine event ids the hub's COWRIE_EVENT_MAP scores.

    Emitting an id outside this set is not an error — the hub maps unknown ids
    to ("unknown", 10) — but it will not be scored, so prefer these.
    """

    CONNECT: Final = "cowrie.session.connect"
    CLIENT_VERSION: Final = "cowrie.client.version"
    CLIENT_KEX: Final = "cowrie.client.kex"
    LOGIN_FAILED: Final = "cowrie.login.failed"
    LOGIN_SUCCESS: Final = "cowrie.login.success"
    COMMAND_INPUT: Final = "cowrie.command.input"
    DIRECT_TCPIP: Final = "cowrie.direct-tcpip.request"
    FILE_DOWNLOAD: Final = "cowrie.session.file_download"
    CLOSED: Final = "cowrie.session.closed"


#: Cowrie writes timestamps as ISO-8601 UTC with a trailing Z and microseconds.
#: Pydantic's datetime parser in the hub accepts this directly.
def utcnow_iso() -> str:
    """Current UTC time in Cowrie's timestamp format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def new_session_id() -> str:
    """A Cowrie-style session id: 12 lowercase hex characters."""
    return secrets.token_hex(6)


class SessionEventFactory:
    """Builds events for one attacker session, carrying the invariant fields.

    Every event from a single SSH connection shares the session id, the peer
    address, and the sensor name, so they are set once here rather than being
    passed to each call.
    """

    def __init__(
        self,
        *,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        sensor: str | None = None,
        session_id: str | None = None,
        protocol: str = "ssh",
    ) -> None:
        self.session_id = session_id or new_session_id()
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.sensor = sensor or os.environ.get("SENSOR_ID", "node-01-jump")
        self.protocol = protocol

        # Set once the client identifies itself, then echoed on later events so
        # a single event is enough to fingerprint the client.
        self.client_version: str | None = None
        self.hassh: str | None = None
        self.username: str | None = None

        self._opened_at = datetime.now(timezone.utc)

    # -- internals ---------------------------------------------------------

    def _base(self, eventid: str, message: str) -> dict[str, Any]:
        event: dict[str, Any] = {
            "eventid": eventid,
            "timestamp": utcnow_iso(),
            "session": self.session_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "sensor": self.sensor,
            "message": message,
        }
        # Carried forward once known so every downstream event is self-contained.
        if self.client_version:
            event["version"] = self.client_version
        if self.hassh:
            event["hassh"] = self.hassh
        return event

    @property
    def duration(self) -> float:
        """Seconds since the connection was accepted."""
        delta = datetime.now(timezone.utc) - self._opened_at
        return round(delta.total_seconds(), 3)

    # -- builders ----------------------------------------------------------

    def connect(self) -> dict[str, Any]:
        """TCP connection accepted, before the SSH banner exchange."""
        return self._base(
            EventId.CONNECT,
            f"New connection: {self.src_ip}:{self.src_port} "
            f"({self.dst_ip}:{self.dst_port}) [session: {self.session_id}]",
        )

    def client_ident(self, version: str) -> dict[str, Any]:
        """Client sent its SSH identification string."""
        self.client_version = version
        return self._base(EventId.CLIENT_VERSION, f"Remote SSH version: {version}")

    def client_kex(
        self,
        *,
        hassh: str,
        kex_algs: list[str],
        encryption_algs: list[str],
        mac_algs: list[str],
        compression_algs: list[str],
        host_key_algs: list[str] | None = None,
    ) -> dict[str, Any]:
        """Client KEXINIT parsed. Carries the HASSH the hub correlates on."""
        self.hassh = hassh
        event = self._base(
            EventId.CLIENT_KEX,
            f"SSH client hassh fingerprint: {hassh}",
        )
        event.update(
            {
                "hasshAlgorithms": ";".join(
                    [
                        ",".join(kex_algs),
                        ",".join(encryption_algs),
                        ",".join(mac_algs),
                        ",".join(compression_algs),
                    ]
                ),
                "kexAlgs": kex_algs,
                "encCS": encryption_algs,
                "macCS": mac_algs,
                "compCS": compression_algs,
            }
        )
        if host_key_algs:
            event["keyAlgs"] = host_key_algs
        return event

    def login_failed(self, username: str, password: str) -> dict[str, Any]:
        """A rejected password attempt. The hub scores these as brute force."""
        event = self._base(
            EventId.LOGIN_FAILED,
            f"login attempt [{username}/{password}] failed",
        )
        event["username"] = username
        event["password"] = password
        return event

    def login_success(self, username: str, password: str) -> dict[str, Any]:
        """An accepted password attempt. The hub scores this 95 — critical."""
        self.username = username
        event = self._base(
            EventId.LOGIN_SUCCESS,
            f"login attempt [{username}/{password}] succeeded",
        )
        event["username"] = username
        event["password"] = password
        return event

    def command(self, command: str) -> dict[str, Any]:
        """One reconstructed shell command. Feeds the brain's intent classifier."""
        event = self._base(EventId.COMMAND_INPUT, f"CMD: {command}")
        event["input"] = command
        if self.username:
            event["username"] = self.username
        return event

    def direct_tcpip(self, dst_host: str, dst_port: int) -> dict[str, Any]:
        """Port-forward request. The hub scores this as lateral movement."""
        event = self._base(
            EventId.DIRECT_TCPIP,
            f"direct-tcp connection request to {dst_host}:{dst_port}",
        )
        event["dst_host"] = dst_host
        event["dst_port_requested"] = dst_port
        return event

    def file_download(self, url: str, *, outfile: str = "", shasum: str = "") -> dict[str, Any]:
        """Attacker fetched a URL. Raised by the fake-internet gateway."""
        event = self._base(EventId.FILE_DOWNLOAD, f"Downloaded URL ({url})")
        event["url"] = url
        if outfile:
            event["outfile"] = outfile
        if shasum:
            event["shasum"] = shasum
        return event

    def closed(self) -> dict[str, Any]:
        """Session teardown. Carries the duration the hub records on the session."""
        duration = self.duration
        event = self._base(
            EventId.CLOSED,
            f"Connection lost after {duration} seconds",
        )
        event["duration"] = duration
        return event
