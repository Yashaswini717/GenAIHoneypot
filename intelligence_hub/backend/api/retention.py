"""HTTP surface for the retention metric.

The maths lives in `analytics.retention`, which imports nothing from FastAPI
or SQLAlchemy so it can be tested on fixed input without a database or a web
stack. This module only fetches rows and hands them over.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from sqlalchemy import text

from analytics.retention import (
    ENGAGED_MIN_SECONDS,
    MIN_ARM_VISITS,
    VISIT_GAP_SECONDS,
    build_visits,
    summarise,
)
from database.postgres import AsyncSessionLocal

router = APIRouter()


_SESSIONS = """
SELECT
    COALESCE(attacker_id, src_ip)       AS attacker,
    COALESCE(adaptive, TRUE)            AS adaptive,
    sensor_id,
    started_at,
    COALESCE(ended_at, started_at)      AS ended_at,
    COALESCE(event_count, 0)            AS event_count,
    COALESCE(threat_score, 0)           AS threat_score
FROM sessions
WHERE started_at IS NOT NULL
ORDER BY COALESCE(attacker_id, src_ip), started_at
"""


async def _fetch_sessions() -> list[dict[str, Any]]:
    async with AsyncSessionLocal() as db:
        result = await db.execute(text(_SESSIONS))
        return [dict(row) for row in result.mappings().all()]


def _note(adaptive_n: int, control_n: int, mixed: int) -> str:
    """Wording for the comparison, including everything that qualifies it."""
    caveat = (
        f" {mixed} visit(s) spanned both arms and were excluded — the control "
        "ratio or salt changed mid-experiment."
        if mixed else ""
    )
    if not control_n:
        return (
            "Control arm is empty — assign attackers to both arms before "
            "drawing any comparison." + caveat
        )
    short = [
        f"{name} has {n}"
        for name, n in (("adaptive", adaptive_n), ("control", control_n))
        if n < MIN_ARM_VISITS
    ]
    if short:
        return (
            f"Too few engaged visits to compare ({', '.join(short)}; "
            f"{MIN_ARM_VISITS} needed per arm). A ratio from this little "
            "traffic reflects who happened to connect, not the deception."
            + caveat
        )
    return (
        "Both arms have enough engaged visits; uplift is the ratio of median "
        "visit length." + caveat
    )


@router.get("/")
async def retention() -> dict[str, Any]:
    """Retention overall, and split by experimental arm.

    `by_arm` is the comparison the research claim needs, and `comparable`
    guards it. Both arms are always reported; the uplift is withheld until
    each has enough engaged visits to mean anything, because a ratio computed
    from one or two sessions looks exactly like a finding and is not one.
    """
    visits = build_visits(await _fetch_sessions())

    # A visit that received both treatments belongs to neither arm. Left in,
    # it would count toward whichever arm it was labelled, which is how a
    # mid-experiment ratio change quietly biases the result.
    mixed = [v for v in visits if v["mixed_arm"]]
    clean = [v for v in visits if not v["mixed_arm"]]
    adaptive = [v for v in clean if v["adaptive"]]
    control = [v for v in clean if not v["adaptive"]]
    summary_adaptive = summarise(adaptive)
    summary_control = summarise(control)

    # Both arms must clear the floor. Counted on engaged visits, because a
    # connect-and-drop carries no retention signal and would let five scanner
    # hits unlock a comparison.
    adaptive_n = summary_adaptive["engaged_visits"]
    control_n = summary_control["engaged_visits"]
    comparable = adaptive_n >= MIN_ARM_VISITS and control_n >= MIN_ARM_VISITS
    uplift = None
    if comparable and summary_control["median_visit_seconds"] > 0:
        uplift = round(
            summary_adaptive["median_visit_seconds"]
            / summary_control["median_visit_seconds"], 2
        )

    return {
        "overall": summarise(visits),
        "by_arm": {"adaptive": summary_adaptive, "control": summary_control},
        "comparison": {
            # False while either arm is empty or below the floor. The arms'
            # own figures are still published either way -- what is withheld
            # is only the ratio, which is the part that reads as a result.
            "comparable": comparable,
            "median_visit_uplift": uplift,
            # Surfaced rather than logged. A non-zero count means the control
            # ratio or salt moved while attackers were being measured, and
            # whoever reads the uplift needs to know that before quoting it.
            "excluded_mixed_arm": len(mixed),
            # Published so the dashboard can say how far off the comparison is
            # instead of only that it is unavailable.
            "min_arm_visits": MIN_ARM_VISITS,
            "engaged_adaptive": adaptive_n,
            "engaged_control": control_n,
            "note": _note(adaptive_n, control_n, len(mixed)),
        },
        "method": {
            "visit_gap_seconds": VISIT_GAP_SECONDS,
            "engaged_min_seconds": ENGAGED_MIN_SECONDS,
            "note": "A visit ends after this much inactivity; returning later starts a new one.",
        },
    }


@router.get("/visits")
async def visits(limit: int = 50) -> dict[str, Any]:
    """The individual visits behind the summary, longest first."""
    all_visits = build_visits(await _fetch_sessions())
    all_visits.sort(key=lambda v: v["dwell_seconds"], reverse=True)
    return {"count": len(all_visits), "visits": all_visits[:limit]}
