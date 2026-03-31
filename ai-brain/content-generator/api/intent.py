from fastapi import APIRouter

from ml.intent_classification.predict import classify_intent

router = APIRouter()


def _to_activity(data: dict) -> dict:
    """Normalize the legacy classify payload into the hybrid activity shape."""
    commands = data.get("commands")
    if commands is None:
        message_value = data.get("message", "")
        log_value = data.get("log", "")
        command_value = message_value or log_value
        commands = [command_value] if command_value else []

    http_logs = data.get("http_logs", [])
    db_queries = data.get("db_queries", [])
    event_timestamps = data.get("event_timestamps", [])

    return {
        "commands": commands,
        "http_logs": http_logs,
        "db_queries": db_queries,
        "event_timestamps": event_timestamps,
        "raw_activity": data.get("message") or data.get("log", ""),
    }


@router.post("/classify")
async def classify(data: dict):
    activity = _to_activity(data)
    result = classify_intent(activity)
    command = data.get("message") or data.get("log") or (activity["commands"][0] if activity["commands"] else "")

    return {
        "intent": result.primary_intent,
        "command": command,
    }
