from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field


class GenerateDecoysRequest(BaseModel):
    """Ask for the decoy content behind one chosen action."""

    action: str = Field(description="Action label the bandit selected, e.g. 'populate_developer_workstation'")
    honeypot_id: str = Field(description="Which attacker's environment this is for; scopes the honeytokens")
    home_user: str = Field(
        default="devuser",
        description="Account whose home directory receives home-relative files",
    )


class DecoyFile(BaseModel):
    """One file, addressed the way the session broker expects to place it."""

    path: str = Field(description="Absolute path inside the attacker's container")
    content: str
    mode: int = Field(default=0o644)


class EmbeddedToken(BaseModel):
    token_type: str
    token_value: str


class GenerateDecoysResponse(BaseModel):
    action: str
    profile: Optional[str] = Field(description="Population profile the action mapped to, if any")
    generated: bool = Field(description="False when the action has no profile behind it")
    files: list[DecoyFile]
    tokens: list[EmbeddedToken] = Field(
        default_factory=list,
        description=(
            "Credentials embedded in the returned content. The caller must watch for "
            "these; a generated secret nothing is scanning for is a decoy with no "
            "tripwire behind it."
        ),
    )
    failed_steps: list[str] = Field(
        default_factory=list,
        description=(
            "Generation steps that failed. Non-empty means this profile is partial: "
            "the files present are real, some that were planned are missing. Reported "
            "rather than hidden so a flaky provider is visible instead of silently "
            "thinning every decoy set."
        ),
    )
