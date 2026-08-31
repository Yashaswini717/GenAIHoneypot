from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends

from api.dependencies import get_adaptive_engine, get_population_strategy
from api.schemas.intent_classification import (
    IntentClassificationRequest,
    IntentClassificationResponse,
)
from config.logging_config import get_logger
from config.settings import settings
from core.adaptive_actions import ACTION_TO_PROFILE
from core.adaptive_engine import AdaptiveDecisionEngine
from core.llm_client import LLMClient
from ml.intent_classification.predict import predict_intent_realtime


router = APIRouter(tags=["intent-classification"])
logger = get_logger(__name__)

# Marks a honeypot_id the instant deployment is scheduled — not just once
# the background task finishes writing files (which can take minutes).
# Without this, two /intent-classify calls close together (e.g. an
# attacker escalating through a couple of quick follow-up actions) would
# both find the folder missing and both schedule a deploy, since request
# handling is what checks "already deployed", and only the completed
# background task actually creates the folder. Process-lifetime only —
# fine here since it's a redundant fast-path in front of the filesystem
# check below, which still holds after a restart.
_honeypot_ids_being_deployed: set[str] = set()


async def _auto_deploy_profile(honeypot_id: str, profile_name: str, action: str) -> None:
    """
    Actually generate and deploy the decoy profile the bandit chose.

    Runs as a background task — a full population is ~8 sequential LLM
    calls and can take several minutes, which would make /intent-classify
    unusably slow for what's meant to be a real-time endpoint if done
    synchronously. Uses its own LLMClient (not the request-scoped one)
    since that dependency's cleanup runs on a timeline that isn't
    guaranteed to outlive a background task.
    """
    llm_client = LLMClient()
    try:
        strategy = await get_population_strategy(llm_client)
        result = await strategy.populate(honeypot_id, {"profile": profile_name, "action": action})
        logger.info(
            "adaptive_auto_deploy_completed",
            honeypot_id=honeypot_id,
            action=action,
            profile=profile_name,
            success=result.success,
            files_created=result.files_created,
        )
    except Exception as e:
        logger.error(
            "adaptive_auto_deploy_failed",
            honeypot_id=honeypot_id,
            action=action,
            profile=profile_name,
            error=str(e),
        )
    finally:
        await llm_client.close()


@router.post("/intent-classify", response_model=IntentClassificationResponse)
async def classify_attacker_intent(
    request: IntentClassificationRequest,
    background_tasks: BackgroundTasks,
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

    # Turn the chosen action into an actual generated/deployed decoy — but
    # only the FIRST time for a given honeypot_id. Files aren't cleared
    # before a populate call, only overwritten path-by-path, so deploying
    # again mid-session (e.g. the same attacker escalating through several
    # /intent-classify calls) would silently mix content from two
    # different profiles into one folder, or regenerate files an attacker
    # may already be looking at. A real machine's filesystem doesn't
    # reshuffle itself while someone's on it — the bandit keeps learning
    # from every decision, but only the first one actually deploys.
    deployment_triggered = False
    deployment_profile = ACTION_TO_PROFILE.get(decision.action) if honeypot_id else None
    if honeypot_id and deployment_profile:
        already_deployed = (
            honeypot_id in _honeypot_ids_being_deployed
            or (Path(settings.output_base_path) / honeypot_id).exists()
        )
        if already_deployed:
            logger.info(
                "adaptive_auto_deploy_skipped_already_deployed",
                honeypot_id=honeypot_id,
                action=decision.action,
            )
        else:
            _honeypot_ids_being_deployed.add(honeypot_id)
            background_tasks.add_task(_auto_deploy_profile, honeypot_id, deployment_profile, decision.action)
            deployment_triggered = True
            logger.info(
                "adaptive_auto_deploy_scheduled",
                honeypot_id=honeypot_id,
                action=decision.action,
                profile=deployment_profile,
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
        deployment_triggered=deployment_triggered,
        deployment_profile=deployment_profile,
    )
