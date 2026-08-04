from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_adaptive_engine
from api.schemas.adaptive import AdaptiveFeedbackRequest, AdaptiveFeedbackResponse
from config.settings import settings
from core.adaptive_engine import AdaptiveDecisionEngine
from storage.models import AdaptiveArmStats

router = APIRouter(prefix="/api/v1/adaptive", tags=["adaptive-learning"])


@router.post("/feedback", response_model=AdaptiveFeedbackResponse)
async def submit_feedback(
    request: AdaptiveFeedbackRequest,
    engine: AdaptiveDecisionEngine = Depends(get_adaptive_engine),
) -> AdaptiveFeedbackResponse:
    """
    Report an outcome for a session's pending decoy decision.

    `/intent-classify` already resolves the *previous* decision implicitly
    whenever it's called again for the same session. This endpoint is for
    signals it can never see on its own — most importantly
    `session_terminated`, since a session going quiet just means the
    classify endpoint stops being called, not that anyone told us why.
    """
    reward = request.resolved_reward()
    resolved_count = engine.resolve_feedback(request.session_id, reward, reason=request.signal.value)

    return AdaptiveFeedbackResponse(
        session_id=request.session_id,
        signal=request.signal,
        reward_applied=reward,
        decisions_resolved=resolved_count,
    )


@router.get("/stats", response_model=list[AdaptiveArmStats])
async def get_stats(
    intent: Optional[str] = None,
    engine: AdaptiveDecisionEngine = Depends(get_adaptive_engine),
) -> list[AdaptiveArmStats]:
    """
    Current posterior (alpha, beta, mean, times_selected) for every
    (intent, action) arm the bandit has explored so far. Feed this straight
    into an Intelligence Hub panel to show which decoy strategy the system
    currently trusts most per attacker intent.
    """
    return engine.get_stats(intent=intent)


@router.post("/reset")
async def reset_adaptive_state(
    engine: AdaptiveDecisionEngine = Depends(get_adaptive_engine),
) -> dict:
    """
    Wipe all bandit state back to a uniform prior.

    Development/demo utility only (e.g. resetting before a live review demo
    so the convergence is visible from scratch) — disabled outside the
    'development' environment so it can't accidentally wipe learned state.
    """
    if settings.environment != "development":
        raise HTTPException(
            status_code=403,
            detail="Adaptive state reset is only permitted in the development environment",
        )
    arms_deleted = engine.store.reset_all()
    return {"status": "reset", "arms_deleted": arms_deleted}
