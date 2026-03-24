from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from core.intent_taxonomy import INTENT_CLASSES


class IntentClassificationRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    raw_activity: Optional[str] = Field(
        default=None,
        description="Raw attacker activity blob for fallback parsing",
    )
    commands: list[str] = Field(default_factory=list, description="Shell or host commands")
    http_logs: list[str] = Field(default_factory=list, description="HTTP access or application log lines")
    db_queries: list[str] = Field(default_factory=list, description="Observed database queries")
    event_timestamps: list[str] = Field(
        default_factory=list,
        description="Ordered event timestamps in ISO-8601 format for timing analysis",
    )
    source_ip: Optional[str] = Field(default=None, description="Source IP for the activity")
    session_id: Optional[str] = Field(default=None, description="Session or trace identifier")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Additional contextual attributes")
    model_type: str = Field(
        default="random_forest",
        description="Classifier backend. Supports random_forest and xgboost when available",
    )

    @field_validator("model_type")
    @classmethod
    def validate_model_type(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"random_forest", "xgboost"}:
            raise ValueError("model_type must be 'random_forest' or 'xgboost'")
        return normalized

    @field_validator("event_timestamps")
    @classmethod
    def validate_event_timestamps(cls, values: list[str]) -> list[str]:
        for value in values:
            parsed = value[:-1] + "+00:00" if value.endswith("Z") else value
            datetime.fromisoformat(parsed)
        return values


class IntentClassificationResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    intent: str = Field(description="Detected attacker intent")
    action: str = Field(description="Suggested decoy action for this intent")
    confidence: float = Field(description="Confidence score for the predicted intent", ge=0.0, le=1.0)
    source: str = Field(description="Classification source: rule or ml")
    probabilities: dict[str, float] = Field(description="Probability distribution across supported intents")
    model_name: str = Field(description="Underlying model used for inference")
    inference_time_ms: float = Field(description="Inference latency in milliseconds")
    feature_values: dict[str, float] = Field(description="Extracted feature vector for observability")
    matched_rules: list[str] = Field(default_factory=list, description="Rules that triggered the decision")

    @field_validator("intent")
    @classmethod
    def validate_intent(cls, value: str) -> str:
        if value not in INTENT_CLASSES:
            raise ValueError("intent is not a supported attacker intent")
        return value
