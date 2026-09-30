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


async def _fetch_sessions() -> list[dict[str, Any]]:
    async with AsyncSessionLocal() as db:
        result = await db.execute(text(_SESSIONS))
        return [dict(row) for row in result.mappings().all()]


@router.get("/")
async def retention() -> dict[str, Any]:
    """Retention overall, and split by experimental arm.

    `by_arm` is the comparison the research claim needs. It only means
    anything once attackers are actually being assigned to both arms; until
    then the control arm is empty and `comparable` says so, rather than
    inviting a conclusion the data cannot support.
    """
    visits = build_visits(await _fetch_sessions())

    adaptive = [v for v in visits if v["adaptive"]]
    control = [v for v in visits if not v["adaptive"]]
    summary_adaptive = summarise(adaptive)
    summary_control = summarise(control)

    comparable = bool(adaptive) and bool(control)
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
            # Guarded deliberately. A ratio against an empty control arm is
            # not a rounding error, it is a claim with nothing behind it.
            "comparable": comparable,
            "median_visit_uplift": uplift,
            "note": (
                "Both arms populated; uplift is the ratio of median visit length."
                if comparable else
                "Control arm is empty — assign attackers to both arms before "
                "drawing any comparison."
            ),
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
