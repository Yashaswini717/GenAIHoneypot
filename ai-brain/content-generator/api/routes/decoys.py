"""Generated decoy content, handed back rather than written down.

The adaptive loop chooses an action, and something has to turn that action into
files an attacker can actually find. Two things used to do that, and only one of
them worked:

  * The sidecar planted a hardcoded bundle through the session broker. This
    reached the attacker, and it was the same fifteen string literals every
    time.
  * `/intent-classify` scheduled a background populate, which generated genuinely
    good content and wrote it to `./data/generated` inside *this* container --
    which has no volume, no Docker socket and no route to the deception
    network. Nothing could ever read it.

So the richest content in the system was written where nothing could see it,
while every attacker saw the same literals. This endpoint closes that: it
generates the profile for an action and returns the files, letting the caller
that can actually reach the attacker's container do the placing. The split
matches the one the rest of the system already uses -- the brain decides what,
the broker places it, and the process holding the signing key holds neither
capability.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_decoy_stock, get_llm_client, get_population_strategy
from api.schemas.decoys import DecoyFile, GenerateDecoysRequest, GenerateDecoysResponse
from config.logging_config import get_logger
from core.adaptive_actions import ACTION_TO_PROFILE
from core.llm_client import LLMClient
from populator.strategies import content_key

router = APIRouter(prefix="/api/v1/decoys", tags=["decoys"])
logger = get_logger(__name__)


#: First path segment that means "this is a system path, not a home-relative
#: one". The profiles emit relative paths because they were written to land in
#: a flat output directory -- `.bashrc` beside `var/log/auth.log` -- which is
#: unambiguous there and meaningless inside a real filesystem.
_SYSTEM_ROOTS = frozenset({"etc", "var", "opt", "srv", "usr", "tmp", "root"})


def to_container_path(relative: str, home_user: str) -> str:
    """Turn a profile-relative path into an absolute path inside a node.

    `var/log/auth.log` belongs at `/var/log/auth.log`; `.bashrc` belongs at
    `/home/devuser/.bashrc`. Getting this wrong is not a cosmetic problem --
    the broker derives file ownership from the directory a decoy lands in, so a
    misplaced file arrives root-owned in a user's home next to files owned by
    that user, which is exactly the kind of thing `ls -la` makes obvious.
    """
    cleaned = relative.lstrip("/")
    if not cleaned:
        raise ValueError("empty decoy path")

    first = cleaned.split("/", 1)[0]
    if first in _SYSTEM_ROOTS:
        return f"/{cleaned}"
    return f"/home/{home_user}/{cleaned}"


@router.post("/generate", response_model=GenerateDecoysResponse)
async def generate_decoys(
    request: GenerateDecoysRequest,
    llm_client: LLMClient = Depends(get_llm_client),
) -> GenerateDecoysResponse:
    """Generate the decoy files for one chosen action.

    Returns an empty file list rather than an error when the action has no
    profile behind it, so a caller can treat "nothing to generate" and "could
    not generate" as the same fallback path.
    """
    profile = ACTION_TO_PROFILE.get(request.action)
    if profile is None:
        logger.info("decoy_generation_skipped_unknown_action", action=request.action)
        return GenerateDecoysResponse(
            action=request.action, profile=None, generated=False, files=[], tokens=[]
        )

    strategy = await get_population_strategy(llm_client)
    context = {"profile": profile, "action": request.action}

    try:
        # The model-written half from stock when there is any: made ahead of
        # time, served to this attacker only, never again (storage/decoy_stock.py).
        # Otherwise generated now, as before -- slow, but still unique.
        stock = get_decoy_stock()
        stocked = stock.take(content_key(profile, request.action)) if stock is not None else None
        if stocked is not None:
            content, stocked_failures, source = stocked["files"], stocked["failures"], "stock"
        else:
            # The stock filler stands aside meanwhile: one rate-limited model
            # account serves both, and this attacker is waiting.
            marker = stock.live_started() if stock is not None else None
            try:
                content = await strategy.build_content(context)
            finally:
                if marker is not None:
                    stock.live_finished(marker)
            stocked_failures, source = [], "live"
            if stock is not None:
                stock.record_served(content)  # so no stocked set repeats it later
        # Always made now, for this attacker: new credentials registered to
        # their environment, so a tripwire says exactly who used one.
        specs = content + await strategy.build_personal(request.honeypot_id, context)
    except Exception as e:
        # `build` tolerates individual step failures now, so reaching here means
        # something structural went wrong rather than one model call stalling.
        logger.warning(
            "decoy_generation_failed",
            action=request.action,
            profile=profile,
            error=str(e),
        )
        raise HTTPException(
            status_code=503,
            detail=f"Could not generate content for {request.action}: {e}",
        ) from e

    failures = stocked_failures + strategy.failures

    # 503 only when the profile came back completely empty.
    #
    # A profile is six to ten sequential model calls, and against a flaky
    # provider one of them stalling used to discard the other seven. Partial
    # content is not a degraded outcome here -- an attacker cannot tell that a
    # home directory was meant to have eight files rather than six, so six real
    # ones beat falling all the way back to the offline bundle.
    if not specs:
        logger.warning(
            "decoy_generation_empty",
            action=request.action,
            profile=profile,
            failed_steps=failures,
        )
        raise HTTPException(
            status_code=503,
            detail=f"No content could be generated for {request.action} "
                   f"({len(failures)} step(s) failed)",
        )

    files = [
        DecoyFile(
            path=to_container_path(spec["path"], request.home_user),
            content=spec["content"],
            mode=spec.get("permissions", 0o644),
        )
        for spec in specs
    ]

    # The values matter as much as the files. A generated credential that
    # nothing is watching for is a decoy with no tripwire behind it.
    tokens = [
        {"token_type": t["token_type"], "token_value": t["token_value"]}
        for t in strategy.embedded_tokens
        if t.get("token_value")
    ]

    logger.info(
        "decoy_generation_completed",
        action=request.action,
        profile=profile,
        files=len(files),
        tokens=len(tokens),
        failed_steps=len(failures),
        partial=bool(failures),
        honeypot_id=request.honeypot_id,
        source=source,
    )

    return GenerateDecoysResponse(
        action=request.action,
        profile=profile,
        generated=True,
        files=files,
        tokens=tokens,
        failed_steps=failures,
        source=source,
    )
