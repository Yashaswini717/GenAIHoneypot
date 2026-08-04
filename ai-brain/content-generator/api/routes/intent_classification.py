from __future__ import annotations

from fastapi import APIRouter, Depends

from api.dependencies import get_adaptive_engine
from api.schemas.intent_classification import (
    IntentClassificationRequest,
    IntentClassificationResponse,
)
from core.adaptive_engine import AdaptiveDecisionEngine
from ml.intent_classification.predict import predict_intent_realtime


router = APIRouter(tags=["intent-classification"])


@router.post("/intent-classify", response_model=IntentClassificationResponse)
async def classify_attacker_intent(
    request: IntentClassificationRequest,
    decision_engine: AdaptiveDecisionEngine = Depends(get_adaptive_engine),
) -> IntentClassificationResponse:
    activity = request.model_dump(exclude={"model_type"})
    result = predict_intent_realtime(activity=activity, model_type=request.model_type)

    # honeypot_id isn't a first-class field on the request (keeps the wire
    # contract stable for existing callers) — callers that want honeytoken
    # signal included in the reward can pass it via metadata.
    honeypot_id = request.metadata.get("honeypot_id") if request.metadata else None

    decision = decision_engine.decide(
        intent=result.intent,
        session_id=request.session_id,
        honeypot_id=honeypot_id,
    )

    return IntentClassificationResponse(
        intent=result.intent,
        action=decision.action,
        confidence=result.confidence,
        source=result.source,
        probabilities=result.probabilities,
        model_name=result.model_name,
        inference_time_ms=result.inference_time_ms,
        feature_values=result.feature_values,
        matched_rules=result.matched_rules,
        decision_id=decision.decision_id,
        action_confidence=decision.posterior_mean,
        action_times_selected=decision.times_selected,
    )
