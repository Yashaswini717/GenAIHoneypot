# Lightweight pattern-based MITRE tagger
# No heavy library needed — maps cowrie event types to techniques

MITRE_MAP = {
    "brute_force":   ("TA0006", "T1110",  "Credential Access",  "Brute Force"),
    "compromise":    ("TA0001", "T1078",  "Initial Access",     "Valid Accounts"),
    "command_exec":  ("TA0002", "T1059",  "Execution",          "Command and Scripting Interpreter"),
    "exfil":         ("TA0010", "T1041",  "Exfiltration",       "Exfiltration Over C2 Channel"),
    "lateral_move":  ("TA0008", "T1021",  "Lateral Movement",   "Remote Services"),
    "recon":         ("TA0043", "T1595",  "Reconnaissance",     "Active Scanning"),
    "connection":    ("TA0043", "T1595",  "Reconnaissance",     "Active Scanning"),
    "session_end":   (None,      None,     None,                 None),
    "unknown":       (None,      None,     None,                 None),
}


def enrich_mitre(event: dict) -> dict:
    event_type = event.get("event_type", "unknown")
    tactic_id, technique_id, tactic, technique = MITRE_MAP.get(
        event_type, (None, None, None, None)
    )
    if technique_id:
        event["mitre_tactic"]     = tactic
        event["mitre_technique"]  = technique_id
    return event