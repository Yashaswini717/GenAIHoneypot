from __future__ import annotations

from fastapi import APIRouter

from core.decision_engine import DecisionEngine
from api.schemas.intent_classification import (
    IntentClassificationRequest,
    IntentClassificationResponse,
)
from ml.intent_classification.predict import predict_intent_realtime


router = APIRouter(tags=["intent-classification"])
decision_engine = DecisionEngine()


@router.post("/intent-classify", response_model=IntentClassificationResponse)
async def classify_attacker_intent(
    request: IntentClassificationRequest,
) -> IntentClassificationResponse:
    activity = request.model_dump(exclude={"model_type"})
    result = predict_intent_realtime(activity=activity, model_type=request.model_type)
    action = decision_engine.suggest_action(result.intent)
    return IntentClassificationResponse(
        intent=result.intent,
        action=action.action,
        confidence=result.confidence,
        source=result.source,
        probabilities=result.probabilities,
        model_name=result.model_name,
        inference_time_ms=result.inference_time_ms,
        feature_values=result.feature_values,
        matched_rules=result.matched_rules,
    )
