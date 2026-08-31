from fastapi import APIRouter

from ml.intent_classification.predict import classify_intent

router = APIRouter()


def _to_activity(data: dict) -> dict:
    """Normalize the legacy classify payload into the hybrid activity shape."""
    commands = data.get("commands")
    if commands is None:
        log_value = data.get("log", "")
        commands = [log_value] if log_value else []

    http_logs = data.get("http_logs", [])
    db_queries = data.get("db_queries", [])
    event_timestamps = data.get("event_timestamps", [])

    return {
        "commands": commands,
        "http_logs": http_logs,
        "db_queries": db_queries,
        "event_timestamps": event_timestamps,
        "raw_activity": data.get("log", ""),
    }


@router.post("/classify")
def classify(data: dict):
    activity = _to_activity(data)
    result = classify_intent(activity)
    return {
        "primary_intent": result.primary_intent,
        "all_intents": result.all_intents,
        "source": result.source,
    }
