# backend/ingest/normalizer.py

from pydantic import BaseModel
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
    # filled by enrichment pipeline
    country:       Optional[str] = None
    city:          Optional[str] = None
    latitude:      Optional[float] = None
    longitude:     Optional[float] = None
    asn:           Optional[str] = None
    mitre_tactic:  Optional[str] = None
    mitre_technique: Optional[str] = None
    threat_score:  Optional[int] = None


def normalize(raw: dict) -> NormalizedEvent:
    event_id = raw.get("eventid", "unknown")
    event_type, base_score = COWRIE_EVENT_MAP.get(event_id, ("unknown", 10))

    return NormalizedEvent(
        raw_event_id = event_id,
        session_id   = raw.get("session", ""),
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
    )