from datetime import datetime, timezone


def compute_threat_score(event: dict) -> dict:
    score = event.get("base_score", 10)

    # boost for high-value techniques
    technique = event.get("mitre_technique")
    if technique in ("T1078", "T1059", "T1041"):
        score = min(score + 20, 100)

    # boost if login succeeded
    if event.get("event_type") == "compromise":
        score = 95

    # boost for command execution
    if event.get("command"):
        score = min(score + 15, 100)

    # slight boost for off-hours (UTC 0–6)
    try:
        ts = event.get("timestamp")
        if isinstance(ts, datetime):
            hour = ts.astimezone(timezone.utc).hour
            if 0 <= hour < 6:
                score = min(score + 5, 100)
    except Exception:
        pass

    event["threat_score"] = score
    return event