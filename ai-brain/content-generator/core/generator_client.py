from __future__ import annotations

from typing import Any

import requests

from config.logging_config import get_logger


GENERATOR_LOGS_URL = "http://127.0.0.1:8000/api/v1/generate/logs"
REQUEST_TIMEOUT_SECONDS = 10

logger = get_logger(__name__)


def _resolve_log_type(intent: str) -> str:
    mapping = {
        "reconnaissance": "auth",
        "privilege_escalation": "auth",
        "persistence": "syslog",
        "lateral_movement": "auth",
        "data_exfiltration": "application",
    }
    return mapping.get(intent, "syslog")


def build_logs_payload(intent: str, command: str) -> dict[str, Any]:
    """Build a generator request that preserves the detected intent and attacker command."""
    return {
        "log_type": _resolve_log_type(intent),
        "duration_hours": 1,
        "attack_activity": True,
        "context": {
            "intent": intent,
            "command": command,
            "message": command,
            "classifier_integration": "api_v1_classify",
        },
    }


def generate_logs_for_intent(intent: str, command: str) -> dict[str, Any]:
    """Call the existing generator API and return the parsed response or a structured error."""
    payload = build_logs_payload(intent, command)
    logger.info(
        "generator_request_start",
        url=GENERATOR_LOGS_URL,
        intent=intent,
        command=command,
        log_type=payload["log_type"],
    )

    try:
        response = requests.post(
            GENERATOR_LOGS_URL,
            json=payload,
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        data = response.json()
        logger.info(
            "generator_request_success",
            status_code=response.status_code,
            intent=intent,
        )
        return data
    except requests.RequestException as exc:
        logger.error(
            "generator_request_failed",
            intent=intent,
            command=command,
            error=str(exc),
        )
        return {
            "status": "error",
            "error": "generator_request_failed",
            "detail": str(exc),
        }
    except ValueError as exc:
        logger.error(
            "generator_response_invalid_json",
            intent=intent,
            command=command,
            error=str(exc),
        )
        return {
            "status": "error",
            "error": "invalid_generator_response",
            "detail": str(exc),
        }
