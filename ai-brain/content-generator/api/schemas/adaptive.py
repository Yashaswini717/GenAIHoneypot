from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, model_validator


class FeedbackSignal(str, Enum):
    """Named outcomes an external caller (honeypot node, intelligence hub) can report."""

    HONEYTOKEN_TRIGGERED = "honeytoken_triggered"
    ESCALATED = "escalated"
    SESSION_CONTINUED = "session_continued"
    SESSION_TERMINATED = "session_terminated"
    CUSTOM = "custom"


# Default reward applied for each named signal. "custom" has no default —
# the caller must supply `reward` explicitly.
SIGNAL_REWARDS: dict[FeedbackSignal, float] = {
    FeedbackSignal.HONEYTOKEN_TRIGGERED: 1.0,
    FeedbackSignal.ESCALATED: 0.7,
    FeedbackSignal.SESSION_CONTINUED: 0.4,
    FeedbackSignal.SESSION_TERMINATED: 0.0,
}


class AdaptiveFeedbackRequest(BaseModel):
    """
    Explicit feedback for a session's pending decoy decision(s).

    This complements the implicit resolution that already happens inside
    `/intent-classify` (the next classify call for the same session resolves
    the previous decision automatically). It exists for signals that
    `/intent-classify` can never see on its own — most importantly a session
    disconnecting, which is when the classify endpoint simply stops being
    called and nothing would otherwise resolve the pending decision.
    """

    session_id: str = Field(description="Session this feedback applies to")
    signal: FeedbackSignal = Field(description="Observed outcome for the session's pending decoy action")
    reward: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Reward override in [0,1]. Required when signal='custom'; optional otherwise (overrides the signal's default).",
    )

    @model_validator(mode="after")
    def _require_reward_for_custom_signal(self) -> "AdaptiveFeedbackRequest":
        if self.signal == FeedbackSignal.CUSTOM and self.reward is None:
            raise ValueError("reward is required when signal='custom'")
        return self

    def resolved_reward(self) -> float:
        if self.reward is not None:
            return self.reward
        return SIGNAL_REWARDS[self.signal]


class AdaptiveFeedbackResponse(BaseModel):
    session_id: str
    signal: FeedbackSignal
    reward_applied: float
    decisions_resolved: int
