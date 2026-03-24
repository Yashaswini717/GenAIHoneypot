from __future__ import annotations

import math
import re
import statistics
from collections import OrderedDict
from datetime import datetime
from typing import Any, Iterable

from core.intent_taxonomy import COMMAND_KEYWORDS, DB_QUERY_KEYWORDS, HTTP_PATH_KEYWORDS


HTTP_METHOD_PATTERN = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b", re.IGNORECASE)
HTTP_STATUS_PATTERN = re.compile(r"\b([1-5][0-9]{2})\b")
DB_VERB_PATTERN = re.compile(r"\b(select|insert|update|delete|grant|alter|create|drop|copy|show|describe)\b", re.IGNORECASE)
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


INTENT_SIGNATURES: dict[str, dict[str, tuple[str, ...]]] = {
    "reconnaissance": {
        "commands": (
            "nmap",
            "whoami",
            "uname",
            "hostname",
            "ifconfig",
            "ip a",
            "ipconfig",
            "netstat",
            "ss -",
            "tasklist",
            "find /",
            "cat /etc/passwd",
            "curl -i",
            "curl -i ",
            "curl -I",
            "wget ",
        ),
        "http": (
            "/admin",
            "/debug",
            "/.git",
            "/metrics",
            "/status",
            "/backup",
            "/api",
            "/login",
        ),
        "db": (
            "information_schema",
            "pg_catalog",
            "show tables",
            "show databases",
            "describe ",
            "select @@version",
        ),
    },
    "privilege_escalation": {
        "commands": (
            "sudo",
            "su ",
            "chmod +s",
            "setcap",
            "visudo",
            "sudoers",
            "runas",
            "getsystem",
            "seimpersonate",
            "passwd root",
            "chpasswd",
        ),
        "http": (
            "/token/elevate",
            "/session/impersonate",
            "/admin/users/role",
            "/sudo",
            "/role",
            "/impersonate",
        ),
        "db": (
            "grant ",
            "alter role",
            "superuser",
            "create user",
            "set role",
            "xp_cmdshell",
        ),
    },
    "persistence": {
        "commands": (
            "crontab",
            "systemctl enable",
            "schtasks",
            "reg add",
            "authorized_keys",
            "rc.local",
            "launchctl",
            "startup",
            "daemon-reload",
        ),
        "http": (
            "/cron",
            "/jobs/schedule",
            "/keys/authorized",
            "/startup",
            "/schedule",
        ),
        "db": (
            "create trigger",
            "create event",
            "create function",
            "alter system",
            "copy program",
        ),
    },
    "lateral_movement": {
        "commands": (
            "ssh ",
            "psexec",
            "wmic /node",
            "net use",
            "smbclient",
            "winrm",
            "mstsc",
            "mount -t cifs",
            "remote desktop",
        ),
        "http": (
            "/remote/node/connect",
            "/internal/share",
            "/ssh/session",
            "/rdp",
            "/node",
            "/share",
        ),
        "db": (
            "dblink",
            "openquery",
            "linked server",
            "federated",
        ),
    },
    "data_exfiltration": {
        "commands": (
            "tar -",
            "zip ",
            "gzip ",
            "base64 ",
            "aws s3 cp",
            "rsync",
            "curl -f",
            "curl -x",
            "curl -F",
            "nc ",
            "netcat",
            "upload",
            "archive",
            "export",
        ),
        "http": (
            "/download",
            "/archive/upload",
            "/reports/export",
            "/dump",
            "/export",
            "/archive",
        ),
        "db": (
            "into outfile",
            "copy (select",
            "union select",
            "dumpfile",
            "select * from customer",
            "select * from payroll",
        ),
    },
}


def _normalize_text(values: Iterable[str]) -> str:
    return " \n".join(value.strip().lower() for value in values if value and value.strip())


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value)
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        if raw.endswith("Z"):
            raw = raw[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(raw)
        except ValueError:
            return None
    return None


def _interval_stats(event_timestamps: list[Any]) -> dict[str, float]:
    parsed = [stamp for stamp in (_parse_timestamp(value) for value in event_timestamps) if stamp]
    if len(parsed) < 2:
        return {
            "timing_event_count": float(len(parsed)),
            "timing_avg_interval_sec": 0.0,
            "timing_min_interval_sec": 0.0,
            "timing_max_interval_sec": 0.0,
            "timing_burst_ratio": 0.0,
            "timing_stddev_interval_sec": 0.0,
            "timing_slow_ratio": 0.0,
        }

    parsed.sort()
    intervals = [
        max((parsed[idx] - parsed[idx - 1]).total_seconds(), 0.0)
        for idx in range(1, len(parsed))
    ]
    burst_ratio = sum(1 for interval in intervals if interval <= 3.0) / len(intervals)
    slow_ratio = sum(1 for interval in intervals if interval >= 20.0) / len(intervals)

    return {
        "timing_event_count": float(len(parsed)),
        "timing_avg_interval_sec": statistics.fmean(intervals),
        "timing_min_interval_sec": min(intervals),
        "timing_max_interval_sec": max(intervals),
        "timing_burst_ratio": burst_ratio,
        "timing_stddev_interval_sec": statistics.pstdev(intervals) if len(intervals) > 1 else 0.0,
        "timing_slow_ratio": slow_ratio,
    }


def _keyword_features(prefix: str, text: str, keywords: dict[str, tuple[str, ...]]) -> OrderedDict[str, float]:
    features: OrderedDict[str, float] = OrderedDict()
    for intent_name, intent_keywords in keywords.items():
        count = sum(text.count(keyword.lower()) for keyword in intent_keywords)
        features[f"{prefix}_{intent_name}_hits"] = float(count)
        features[f"{prefix}_{intent_name}_present"] = 1.0 if count else 0.0
    return features


def _signature_features(source_name: str, text: str) -> OrderedDict[str, float]:
    features: OrderedDict[str, float] = OrderedDict()
    for intent_name, signatures in INTENT_SIGNATURES.items():
        source_signatures = signatures[source_name]
        matches = sum(text.count(signature.lower()) for signature in source_signatures)
        features[f"{source_name}_{intent_name}_signature_hits"] = float(matches)
        features[f"{source_name}_{intent_name}_signature_present"] = 1.0 if matches else 0.0
    return features


def _source_summary_features(source_name: str, text: str) -> OrderedDict[str, float]:
    features: OrderedDict[str, float] = OrderedDict()
    signature_totals = {
        intent_name: sum(text.count(signature.lower()) for signature in signatures[source_name])
        for intent_name, signatures in INTENT_SIGNATURES.items()
    }
    dominant_intent = max(signature_totals, key=signature_totals.get) if signature_totals else "reconnaissance"
    dominant_value = float(signature_totals.get(dominant_intent, 0))
    total_matches = float(sum(signature_totals.values()))

    for intent_name in INTENT_SIGNATURES:
        features[f"{source_name}_{intent_name}_dominant"] = 1.0 if intent_name == dominant_intent and dominant_value > 0 else 0.0
        features[f"{source_name}_{intent_name}_share"] = (
            signature_totals[intent_name] / total_matches if total_matches else 0.0
        )

    features[f"{source_name}_signature_total_hits"] = total_matches
    features[f"{source_name}_single_intent_focus"] = 1.0 if dominant_value > 0 and dominant_value == total_matches else 0.0
    return features


def _http_features(http_logs: list[str]) -> OrderedDict[str, float]:
    text = _normalize_text(http_logs)
    methods = HTTP_METHOD_PATTERN.findall(text)
    statuses = [int(status) for status in HTTP_STATUS_PATTERN.findall(text)]
    features: OrderedDict[str, float] = OrderedDict()
    features["http_log_count"] = float(len(http_logs))
    features["http_method_get_count"] = float(sum(1 for method in methods if method.upper() == "GET"))
    features["http_method_post_count"] = float(sum(1 for method in methods if method.upper() == "POST"))
    features["http_error_ratio"] = (
        sum(1 for status in statuses if status >= 400) / len(statuses) if statuses else 0.0
    )
    features["http_query_param_hits"] = float(text.count("?"))
    features["http_admin_path_hits"] = float(sum(path in text for path in ("/admin", "/root", "/login")))
    features["http_export_path_hits"] = float(sum(path in text for path in ("/download", "/dump", "/export", "/archive")))
    features.update(_keyword_features("http", text, HTTP_PATH_KEYWORDS))
    features.update(_signature_features("http", text))
    features.update(_source_summary_features("http", text))
    return features


def _command_features(commands: list[str]) -> OrderedDict[str, float]:
    text = _normalize_text(commands)
    tokens = [token for token in re.split(r"\s+", text) if token]
    unique_tokens = set(tokens)
    ip_hits = len(IP_PATTERN.findall(text))
    features: OrderedDict[str, float] = OrderedDict()
    features["command_count"] = float(len(commands))
    features["command_token_count"] = float(len(tokens))
    features["command_unique_token_ratio"] = len(unique_tokens) / len(tokens) if tokens else 0.0
    features["command_avg_length"] = (
        statistics.fmean(len(command) for command in commands) if commands else 0.0
    )
    features["command_entropy"] = (
        -sum((tokens.count(token) / len(tokens)) * math.log2(tokens.count(token) / len(tokens)) for token in unique_tokens)
        if tokens
        else 0.0
    )
    features["command_ip_target_hits"] = float(ip_hits)
    features["command_has_pipe"] = 1.0 if "|" in text else 0.0
    features["command_has_redirect"] = 1.0 if ">" in text else 0.0
    features["command_has_remote_destination"] = 1.0 if re.search(r"@[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:", text) else 0.0
    features.update(_keyword_features("command", text, COMMAND_KEYWORDS))
    features.update(_signature_features("commands", text))
    features.update(_source_summary_features("commands", text))
    return features


def _db_features(db_queries: list[str]) -> OrderedDict[str, float]:
    text = _normalize_text(db_queries)
    verbs = DB_VERB_PATTERN.findall(text)
    features: OrderedDict[str, float] = OrderedDict()
    features["db_query_count"] = float(len(db_queries))
    features["db_select_ratio"] = (
        sum(1 for verb in verbs if verb.lower() == "select") / len(verbs) if verbs else 0.0
    )
    features["db_privileged_verb_ratio"] = (
        sum(1 for verb in verbs if verb.lower() in {"grant", "alter", "create", "drop"}) / len(verbs)
        if verbs
        else 0.0
    )
    features["db_schema_enum_hits"] = float(sum(term in text for term in ("information_schema", "pg_catalog", "sqlite_master")))
    features["db_export_hits"] = float(sum(term in text for term in ("into outfile", "copy (select", "dumpfile")))
    features.update(_keyword_features("db", text, DB_QUERY_KEYWORDS))
    features.update(_signature_features("db", text))
    features.update(_source_summary_features("db", text))
    return features


def _cross_source_features(command_text: str, http_text: str, db_text: str, timing: dict[str, float]) -> OrderedDict[str, float]:
    features: OrderedDict[str, float] = OrderedDict()

    recon_score = (
        sum(command_text.count(term) for term in ("nmap", "whoami", "netstat", "find /"))
        + sum(http_text.count(term) for term in ("/admin", "/debug", "/.git", "/metrics"))
        + sum(db_text.count(term) for term in ("information_schema", "show tables", "show databases"))
    )
    privesc_score = (
        sum(command_text.count(term) for term in ("sudo", "chmod +s", "setcap", "visudo", "runas"))
        + sum(http_text.count(term) for term in ("/token/elevate", "/session/impersonate", "/admin/users/role"))
        + sum(db_text.count(term) for term in ("grant ", "alter role", "superuser", "set role"))
    )
    persistence_score = (
        sum(command_text.count(term) for term in ("crontab", "systemctl enable", "schtasks", "authorized_keys", "rc.local"))
        + sum(http_text.count(term) for term in ("/cron", "/jobs/schedule", "/keys/authorized", "/startup"))
        + sum(db_text.count(term) for term in ("create trigger", "create event", "create function", "alter system"))
        + (2 if timing.get("timing_slow_ratio", 0.0) > 0.5 else 0)
    )
    lateral_score = (
        sum(command_text.count(term) for term in ("ssh ", "psexec", "wmic /node", "net use", "smbclient", "winrm"))
        + sum(http_text.count(term) for term in ("/remote/node/connect", "/internal/share", "/ssh/session", "/rdp"))
        + sum(db_text.count(term) for term in ("dblink", "openquery", "linked server"))
    )
    exfil_score = (
        sum(command_text.count(term) for term in ("tar -", "zip ", "gzip ", "base64 ", "aws s3 cp", "rsync", "curl -f", "curl -f", "curl -F", "nc "))
        + sum(http_text.count(term) for term in ("/download", "/archive/upload", "/reports/export", "/dump"))
        + sum(db_text.count(term) for term in ("into outfile", "copy (select", "union select", "dumpfile"))
        + (2 if timing.get("timing_burst_ratio", 0.0) > 0.75 and "base64 " in command_text else 0)
    )

    intent_scores = OrderedDict(
        reconnaissance=float(recon_score),
        privilege_escalation=float(privesc_score),
        persistence=float(persistence_score),
        lateral_movement=float(lateral_score),
        data_exfiltration=float(exfil_score),
    )
    total = sum(intent_scores.values())

    for intent_name, score in intent_scores.items():
        features[f"cross_{intent_name}_signal"] = score
        features[f"cross_{intent_name}_share"] = score / total if total else 0.0

    dominant_intent = max(intent_scores, key=intent_scores.get)
    for intent_name in intent_scores:
        features[f"cross_{intent_name}_dominant"] = 1.0 if intent_name == dominant_intent and intent_scores[intent_name] > 0 else 0.0

    features["cross_signal_total"] = float(total)
    features["cross_sparse_activity"] = 1.0 if total <= 2.0 else 0.0
    return features


def extract_features(activity: dict[str, Any]) -> OrderedDict[str, float]:
    commands = [str(command) for command in activity.get("commands", [])]
    http_logs = [str(log) for log in activity.get("http_logs", [])]
    db_queries = [str(query) for query in activity.get("db_queries", [])]
    event_timestamps = list(activity.get("event_timestamps", []))

    command_text = _normalize_text(commands)
    http_text = _normalize_text(http_logs)
    db_text = _normalize_text(db_queries)
    raw_text = " ".join(
        part for part in [
            command_text,
            http_text,
            db_text,
            str(activity.get("raw_activity", "")).lower(),
        ]
        if part
    )

    timing_features = OrderedDict(_interval_stats(event_timestamps))

    features: OrderedDict[str, float] = OrderedDict()
    features["activity_text_length"] = float(len(raw_text))
    features["activity_source_count"] = float(sum(bool(items) for items in (commands, http_logs, db_queries)))
    features["contains_base64_marker"] = 1.0 if "base64" in raw_text else 0.0
    features["contains_archive_marker"] = 1.0 if any(term in raw_text for term in ("tar ", "zip ", "gzip ")) else 0.0
    features["contains_remote_exec_marker"] = 1.0 if any(term in raw_text for term in ("ssh ", "psexec", "winrm", "wmic /node")) else 0.0
    features["contains_auth_marker"] = 1.0 if any(term in raw_text for term in ("sudo", "su ", "token/elevate", "password", "superuser")) else 0.0
    features["contains_persistence_marker"] = 1.0 if any(term in raw_text for term in ("crontab", "systemctl enable", "authorized_keys", "schtasks")) else 0.0
    features["contains_recon_marker"] = 1.0 if any(term in raw_text for term in ("nmap", "whoami", "netstat", "information_schema", "/admin")) else 0.0
    features.update(_command_features(commands))
    features.update(_http_features(http_logs))
    features.update(_db_features(db_queries))
    features.update(timing_features)
    features.update(_cross_source_features(command_text, http_text, db_text, timing_features))
    return features


def feature_names() -> list[str]:
    return list(extract_features({}).keys())


def feature_vector(activity: dict[str, Any]) -> list[float]:
    return list(extract_features(activity).values())
