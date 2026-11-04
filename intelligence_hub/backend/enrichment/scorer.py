import re
from datetime import datetime, timezone

#: Scores at or above this raise an alert: the bottom of the dashboard's "high"
#: band (AlertQueue.jsx and Overview.jsx colour 70-89 high, 90+ critical).
ALERT_THRESHOLD = 70

#: A word in command position: line start, after ; & | or (, or after sudo.
#: Tells `passwd root`, a credential change, apart from reading /etc/passwd.
_AT_COMMAND = r"(?:^|[;&|(]\s*|\bsudo\s+)"


def _any(*alternatives: str) -> re.Pattern:
    return re.compile("|".join(alternatives), re.IGNORECASE)


# A command scores by what it does, not by being a command. Every command used
# to reach 100 (80 base, +20 for T1059, +15 for carrying a command), so every
# keystroke raised an alert and a session's download-and-run was buried under
# its `uname -a` and `ls`. The first matching rule wins, so the most severe come
# first. A command no rule matches is ordinary shell use: it scores SHELL_SCORE,
# visible on the dashboard but never an alert by itself.
COMMAND_RULES: list[tuple[str, int, re.Pattern]] = [
    ("payload_execution", 95, _any(
        r"\|\s*(?:ba|da|z)?sh\b",                       # curl ... | sh
        r"\bbase64\s+(?:-d|--decode)\b",                # decode, then run
        r"\b(?:python[23]?|perl|php|ruby)\s+-[ce]\b",    # inline interpreter code
        _AT_COMMAND + r"\./\S",                         # run a dropped binary
        _AT_COMMAND + r"(?:ba)?sh\s+/(?:tmp|var/tmp|dev/shm)/",
    )),
    # Reading records out of a database is exfiltration in the brain's labelling
    # guide too, so the hub alerts on what the classifier calls data_exfiltration.
    ("data_exfiltration", 90, _any(
        r"\b(?:mysqldump|pg_dump|pg_dumpall|mongodump)\b",
        r"\bmysql\b[^;&|]*\s(?:-e|--execute)\b",          # mysql -e "select ..."
        r"\bpsql\b[^;&|]*\s(?:-c|--command)\b",
    )),
    ("persistence", 85, _any(
        r"authorized_keys",
        r"\bcrontab\b(?!\s+-l\b)",                      # crontab -l only reads
        r"/etc/(?:rc\.local|init\.d/|systemd/system/)",
        r"\bsystemctl\s+enable\b",
        _AT_COMMAND + r"(?:useradd|adduser|usermod|chpasswd|passwd)\b",
        r">>?\s*\S*\.(?:bashrc|profile)\b",
    )),
    ("lateral_movement", 85, _any(
        r"\bssh(?:pass)?\s[^;&|]*@",                    # ssh user@another-host
        r"\bscp\s[^;&|]*\S@",                           # copying out to a host
        r"\b(?:nmap|masscan|zmap|hydra|medusa)\b",
    )),
    ("tool_download", 80, _any(
        r"\b(?:wget|curl|tftp|ftpget|lwp-download)\b",
        r"\bscp\s+(?:-\w+\s+)*-t\b",                    # receiving an upload
    )),
    ("credential_access", 80, _any(
        r"/etc/shadow\b", r"\.ssh/id_", r"\.aws/credentials",
        r"\.bash_history", r"\.git-credentials",
    )),
    ("defense_evasion", 75, _any(
        r"\bhistory\s+-c\b", r"\bunset\s+HISTFILE\b", r"HISTFILE=/dev/null",
        r"\brm\s+(?:-\S+\s+)*/var/log", r"\bchattr\b", r"\biptables\s+-F\b",
        r"\bufw\s+disable\b", r"\bsetenforce\s+0\b",
    )),
]
SHELL_SCORE = 40


def _as_datetime(value) -> datetime | None:
    """Read a timestamp that may already have been serialised for storage.

    The ingest pipeline hands us a datetime, but it stringifies the field
    before Elasticsearch and Redis see it. When those two steps were ordered
    the other way round this function's caller silently lost its off-hours
    branch for every event ever ingested — nothing raised, the score was just
    quietly 5 lower. Accepting both shapes means the ordering can change again
    without taking the boost down with it.
    """
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def classify_command(command: str) -> tuple[str, int]:
    for category, score, pattern in COMMAND_RULES:
        if pattern.search(command):
            return category, score
    return "shell", SHELL_SCORE


def compute_threat_score(event: dict) -> dict:
    score = event.get("base_score", 10)

    command = event.get("command")
    if command:
        event["command_category"], score = classify_command(command)

    # slight boost for off-hours (UTC 0–6)
    try:
        ts = _as_datetime(event.get("timestamp"))
        if ts is not None:
            # A naive timestamp is already UTC here — the sensors emit
            # ISO-8601 UTC with a trailing Z — but astimezone() would read it
            # as local time and shift the hour on any non-UTC host.
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            hour = ts.astimezone(timezone.utc).hour
            if 0 <= hour < 6:
                score = min(score + 5, 100)
    except Exception:
        pass

    event["threat_score"] = score
    return event
