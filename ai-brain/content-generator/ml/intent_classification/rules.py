from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from core.intent_taxonomy import INTENT_CLASSES


@dataclass
class RuleMatch:
    intent: str
    confidence: float
    matched_rules: list[str]


def _normalize_activity(activity: dict[str, Any]) -> tuple[str, str, str, str]:
    commands = " \n".join(str(value).lower() for value in activity.get("commands", []) if value)
    http_logs = " \n".join(str(value).lower() for value in activity.get("http_logs", []) if value)
    db_queries = " \n".join(str(value).lower() for value in activity.get("db_queries", []) if value)
    raw_activity = str(activity.get("raw_activity", "")).lower()
    return commands, http_logs, db_queries, raw_activity


def _extract_ips(text: str) -> list[str]:
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)


def _is_internal_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def _score_rules(activity: dict[str, Any]) -> dict[str, list[str]]:
    commands, http_logs, db_queries, raw_activity = _normalize_activity(activity)
    scores = {intent: [] for intent in INTENT_CLASSES}

    if "nmap" in commands:
        scores["reconnaissance"].append("command:nmap")
    if any(term in commands for term in ("whoami", "netstat", "ss -", "ifconfig", "ip a", "tasklist")):
        scores["reconnaissance"].append("command:host_enumeration")
    if any(term in http_logs for term in ("/admin", "/debug", "/.git", "/metrics", "/status")):
        scores["reconnaissance"].append("http:discovery_path")
    if any(term in db_queries for term in ("information_schema", "show databases", "show tables", "pg_catalog", "describe ")):
        scores["reconnaissance"].append("db:schema_enumeration")

    if any(term in commands for term in ("sudo", " su ", "chmod +s", "setcap", "visudo", "runas", "getsystem")):
        scores["privilege_escalation"].append("command:privilege_escalation")
    if any(term in http_logs for term in ("/token/elevate", "/session/impersonate", "/admin/users/role")):
        scores["privilege_escalation"].append("http:role_or_token_abuse")
    if any(term in db_queries for term in ("grant ", "alter role", "superuser", "create user", "set role", "xp_cmdshell")):
        scores["privilege_escalation"].append("db:privileged_change")

    if any(term in commands for term in ("crontab", "systemctl enable", "schtasks", "authorized_keys", "rc.local", "launchctl", "reg add")):
        scores["persistence"].append("command:persistence_mechanism")
    if any(term in http_logs for term in ("/cron", "/jobs/schedule", "/keys/authorized", "/startup")):
        scores["persistence"].append("http:persistence_path")
    if any(term in db_queries for term in ("create trigger", "create event", "create function", "alter system")):
        scores["persistence"].append("db:persistence_change")

    if any(term in commands for term in ("ssh ", "psexec", "wmic /node", "net use", "smbclient", "winrm", "mstsc")):
        scores["lateral_movement"].append("command:lateral_tooling")
    if any(term in http_logs for term in ("/remote/node/connect", "/internal/share", "/ssh/session", "/rdp")):
        scores["lateral_movement"].append("http:lateral_path")
    if any(term in db_queries for term in ("dblink", "openquery", "linked server", "federated")):
        scores["lateral_movement"].append("db:remote_query")

    if any(term in commands for term in ("tar ", "zip ", "gzip ", "base64 ", "aws s3 cp", "rsync")):
        scores["data_exfiltration"].append("command:archive_or_transfer")
    if any(term in commands for term in ("curl -f", "curl -x", "curl -t", "curl -F", "curl --upload-file")):
        scores["data_exfiltration"].append("command:curl_transfer")
    if "curl -i" in commands:
        scores["reconnaissance"].append("command:curl_probe")
    if "curl " in commands and not any(term in commands for term in ("curl -f", "curl -x", "curl -t", "curl -F", "curl --upload-file")) and any(term in http_logs for term in ("/admin", "/debug", "/api", "/metrics")):
        scores["reconnaissance"].append("command:http_probe")
    if any(term in http_logs for term in ("/download", "/archive/upload", "/reports/export", "/dump", "/export")):
        scores["data_exfiltration"].append("http:export_path")
    if any(term in db_queries for term in ("into outfile", "copy (select", "union select", "dumpfile")):
        scores["data_exfiltration"].append("db:bulk_export")

    for command in activity.get("commands", []):
        command_text = str(command).lower()
        if command_text.startswith("scp "):
            ips = _extract_ips(command_text)
            if ips and any(not _is_internal_ip(ip) for ip in ips):
                scores["data_exfiltration"].append("command:scp_external_transfer")
            else:
                scores["lateral_movement"].append("command:scp_internal_transfer")

    if "curl -i" in commands or "curl -i " in commands or "curl -I" in commands:
        scores["reconnaissance"].append("command:curl_head_probe")

    if "nc " in commands or "netcat" in commands:
        scores["data_exfiltration"].append("command:socket_transfer")

    return scores


def detect_intent_by_rules(activity: dict[str, Any]) -> RuleMatch | None:
    scored_rules = _score_rules(activity)
    counts = {intent: len(matches) for intent, matches in scored_rules.items()}
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    top_intent, top_count = ranked[0]
    second_count = ranked[1][1] if len(ranked) > 1 else 0

    if top_count == 0:
        return None

    # Use rules only when the signal is obvious enough to avoid biasing ambiguous activity.
    if top_count >= 2 or (top_count == 1 and second_count == 0):
        confidence = min(0.99, 0.7 + (0.1 * top_count) + (0.05 * (top_count - second_count)))
        return RuleMatch(
            intent=top_intent,
            confidence=confidence,
            matched_rules=scored_rules[top_intent],
        )

    return None
