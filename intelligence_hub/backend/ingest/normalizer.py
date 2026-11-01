# backend/ingest/normalizer.py

import ipaddress
import json

from pydantic import BaseModel, field_validator
from typing import Optional
from datetime import datetime

COWRIE_EVENT_MAP = {
    "cowrie.session.connect":  ("connection",  30),
    "cowrie.login.failed":     ("brute_force", 60),
    "cowrie.login.success":    ("compromise",  95),  # critical
    "cowrie.command.input":    ("command_exec",80),
    "cowrie.session.closed":   ("session_end", 10),
    "cowrie.client.version":   ("recon",       20),
    "cowrie.client.kex":       ("recon",       20),
    "cowrie.direct-tcpip.request": ("lateral_move", 75),
    "cowrie.session.file_download": ("exfil",  90),
}

#: Where an event entered the hub. Set by the hub from the path the event
#: arrived on, never read from the event, which the sender controls.
#:
#: Only sensor events -- recorded live by the SSH proxy and delivered signed
#: by a sidecar -- are evidence about attackers. An upload is whatever file an
#: operator chose, so it is kept out of the retention figures.
SOURCE_SENSOR = "sensor"
SOURCE_OPERATOR_UPLOAD = "operator_upload"

#: Prefixed to the session id of every uploaded event. Without it, uploading
#: a log that overlaps live traffic -- the honeypot's own events.ndjson, say --
#: would merge into the live sessions it shares ids with: their event counts,
#: end times and attribution rewritten by a file, inside the very figures
#: the upload tag exists to protect.
UPLOAD_SESSION_PREFIX = "upload-"


class MalformedEvent(ValueError):
    """The event itself is wrong, so sending it again cannot help.

    Raised before anything is stored. The receiver answers with `status`, and
    a 4xx is what tells the sidecar to dead-letter the event rather than
    retry it -- retrying an event that can never succeed used to block every
    event queued behind it.
    """

    status = 422


class InvalidJSON(MalformedEvent):
    status = 400


class NormalizedEvent(BaseModel):
    raw_event_id:  str
    session_id:    str
    src_ip:        str
    src_port:      Optional[int]
    dst_ip:        Optional[str]
    dst_port:      Optional[int]
    protocol:      Optional[str] = "ssh"
    event_type:    str           # our category
    base_score:    int           # 0–100
    sensor_id:     str

    # Extensions beyond Cowrie. A Cowrie sensor is one host, so its schema has
    # no way to say "the same attacker, one hop deeper". Ours is an estate and
    # that is the measurement, so the sensor sends it and we carry it through.
    attacker_id:   Optional[str] = None
    adaptive:      Optional[bool] = None
    timestamp:     datetime
    username:      Optional[str]
    password:      Optional[str]
    hassh:         Optional[str]  # SSH fingerprint
    ssh_version:   Optional[str]
    command:       Optional[str]
    duration:      Optional[float]
    raw_message:   str
    source:        str = SOURCE_SENSOR
    # filled by enrichment pipeline
    country:       Optional[str] = None
    city:          Optional[str] = None
    latitude:      Optional[float] = None
    longitude:     Optional[float] = None
    asn:           Optional[str] = None
    mitre_tactic:  Optional[str] = None
    mitre_technique: Optional[str] = None
    threat_score:  Optional[int] = None

    # Elasticsearch maps both as `ip` and refuses anything else. Caught here
    # it is a 422 naming the field; caught there it was a 500, which the
    # sidecar retries forever.
    @field_validator("src_ip")
    @classmethod
    def _src_ip_is_an_address(cls, value: str) -> str:
        ipaddress.ip_address(value)
        return value

    @field_validator("dst_ip")
    @classmethod
    def _dst_ip_is_an_address(cls, value: Optional[str]) -> Optional[str]:
        if value is not None:
            ipaddress.ip_address(value)
        return value


def parse_event(body) -> dict:
    """One event's JSON, or MalformedEvent saying what is wrong with it."""
    try:
        raw = json.loads(body)
    except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError both
        raise InvalidJSON(f"Invalid JSON: {exc}") from None
    if not isinstance(raw, dict):
        raise MalformedEvent(f"An event must be a JSON object, not {type(raw).__name__}")
    return raw


def normalize(raw: dict, source: str = SOURCE_SENSOR) -> NormalizedEvent:
    try:
        return _normalize(raw, source)
    except (ValueError, TypeError, AttributeError) as exc:
        # pydantic's ValidationError is a ValueError. A missing timestamp, a
        # port that is not a number, a duration that is not a float: all of
        # them are facts about the event, not about the hub.
        raise MalformedEvent(f"Not a valid event: {exc}") from None


def _normalize(raw: dict, source: str) -> NormalizedEvent:
    event_id = raw.get("eventid", "unknown")
    event_type, base_score = COWRIE_EVENT_MAP.get(event_id, ("unknown", 10))

    session_id = raw.get("session", "")
    if source == SOURCE_OPERATOR_UPLOAD and isinstance(session_id, str):
        session_id = UPLOAD_SESSION_PREFIX + session_id

    return NormalizedEvent(
        raw_event_id = event_id,
        session_id   = session_id,
        src_ip       = raw.get("src_ip", ""),
        src_port     = raw.get("src_port"),
        dst_ip       = raw.get("dst_ip"),
        dst_port     = raw.get("dst_port"),
        protocol     = raw.get("protocol", "ssh"),
        event_type   = event_type,
        base_score   = base_score,
        sensor_id    = raw.get("sensor", ""),
        # Falls back to src_ip so events from a plain Cowrie sensor, or from
        # a honeypot build predating this field, still group by something
        # sensible instead of by nothing.
        attacker_id  = raw.get("attacker") or raw.get("src_ip", ""),
        adaptive     = raw.get("adaptive"),
        timestamp    = raw.get("timestamp"),
        username     = raw.get("username"),
        password     = raw.get("password"),
        hassh        = raw.get("hassh"),
        ssh_version  = raw.get("version"),
        command      = raw.get("input"),
        duration     = float(raw.get("duration", 0)) if raw.get("duration") else None,
        raw_message  = raw.get("message", ""),
        source       = source,
    )
