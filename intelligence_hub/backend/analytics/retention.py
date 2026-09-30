"""Retention metrics: how long the estate holds an attacker, and how deep.

This is the module the research claim rests on. Everything else in the hub
describes what happened; this measures whether the deception worked.

Four decisions worth knowing before reading the code.

**The unit is an attacker, not a session.** One visit is several sessions —
the jump host, then each pivot — and a pivot's `src_ip` is our own jump host
rather than the person driving it. Grouping by `src_ip` counts one attacker as
several and attributes their deepest sessions to a machine of ours.
`attacker_id` carries the original source address through every hop.

**Engagement is measured per visit, not first-seen to last-seen.** An attacker
who returns a week later has not been engaged for a week. Taking the span from
their first event to their last produced a 34-day "dwell" for a test address
that connected on two separate days. Sessions are therefore grouped into
visits, split wherever the attacker went quiet for longer than
`VISIT_GAP_SECONDS`, and each visit is measured on its own.

**Dwell within a visit is wall-clock, not the sum of session durations.** A
pivot session runs *inside* the jump-host session, so adding durations counts
the same minutes twice and inflates exactly the number the thesis depends on.

**Depth from sessions undercounts, by design.** Reaching the database over
MySQL from the ERP host is a command, not a session, so it does not raise the
session-derived depth. Reported separately rather than quietly folded in.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any


#: Sensor name to position in the estate: how far through they got.
NODE_DEPTH: dict[str, int] = {
    "node-01-jump": 1,
    "node-02-erp": 2,
    "node-03-db": 3,
}

#: Quiet for longer than this and the next session is a new visit. Thirty
#: minutes is the common sessionisation default and comfortably longer than
#: any pause inside a real intrusion, while being far shorter than the gap
#: between someone leaving and coming back.
VISIT_GAP_SECONDS = 30 * 60

#: Visits shorter than this are a connect-and-drop: a scanner completing a
#: handshake, not an attacker looking around. Counting them drags every mean
#: toward zero and hides the effect being measured, so they are reported
#: separately rather than silently dropped.
ENGAGED_MIN_SECONDS = 5.0


def _seconds(later: datetime, earlier: datetime) -> float:
    return max(0.0, (later - earlier).total_seconds())


def build_visits(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group an attacker's sessions into visits, split on inactivity.

    Pure and separated from the query so it can be tested on fixed input;
    the sessionisation rule is the part most likely to be wrong, and it is
    invisible in the output when it is.
    """
    by_attacker: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        by_attacker.setdefault(row["attacker"], []).append(row)

    visits: list[dict[str, Any]] = []
    for attacker, sessions in by_attacker.items():
        sessions.sort(key=lambda r: r["started_at"])
        current: list[dict[str, Any]] = []
        last_end: datetime | None = None

        for session in sessions:
            if last_end is not None and _seconds(session["started_at"], last_end) > VISIT_GAP_SECONDS:
                visits.append(_close_visit(attacker, current))
                current = []
            current.append(session)
            # max(), not assignment: a pivot session nested inside the
            # jump-host session ends earlier than its parent, and letting it
            # move the end backwards would split one visit in two.
            end = session["ended_at"]
            last_end = end if last_end is None else max(last_end, end)

        if current:
            visits.append(_close_visit(attacker, current))
    return visits


def _close_visit(attacker: str, sessions: list[dict[str, Any]]) -> dict[str, Any]:
    start = min(s["started_at"] for s in sessions)
    end = max(s["ended_at"] for s in sessions)
    hosts = {s["sensor_id"] for s in sessions if s["sensor_id"]}
    return {
        "attacker": attacker,
        # A visit is adaptive if adaptation was on for any session in it;
        # an attacker does not change arm mid-visit in practice.
        "adaptive": any(s["adaptive"] for s in sessions),
        "started_at": start,
        "ended_at": end,
        "dwell_seconds": _seconds(end, start),
        "sessions": len(sessions),
        "events": sum(int(s["event_count"]) for s in sessions),
        "hosts": sorted(hosts),
        "depth": max((NODE_DEPTH.get(h, 1) for h in hosts), default=1),
        "threat_score": max((int(s["threat_score"]) for s in sessions), default=0),
    }


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2


def summarise(visits: list[dict[str, Any]]) -> dict[str, Any]:
    """The figures that answer the question, from a list of visits."""
    if not visits:
        return {
            "attackers": 0, "visits": 0, "engaged_visits": 0,
            "median_visit_seconds": 0.0, "mean_visit_seconds": 0.0,
            "longest_visit_seconds": 0.0, "mean_commands": 0.0,
            "return_rate": 0.0, "pivot_rate": 0.0, "mean_depth": 0.0,
            "reached_erp": 0, "reached_db": 0,
        }

    engaged = [v for v in visits if v["dwell_seconds"] >= ENGAGED_MIN_SECONDS]
    dwells = [v["dwell_seconds"] for v in engaged]
    attackers: dict[str, int] = {}
    for visit in visits:
        attackers[visit["attacker"]] = attackers.get(visit["attacker"], 0) + 1

    pivoted = sum(1 for v in visits if v["depth"] > 1)
    returned = sum(1 for count in attackers.values() if count > 1)

    return {
        "attackers": len(attackers),
        "visits": len(visits),
        # Reported alongside the total, never instead of it: a honeypot mostly
        # hit by scanners is a true fact about the deployment, and hiding it
        # would flatter every other number here.
        "engaged_visits": len(engaged),
        "median_visit_seconds": round(_median(dwells), 2),
        "mean_visit_seconds": round(sum(dwells) / len(dwells), 2) if dwells else 0.0,
        "longest_visit_seconds": round(max(dwells), 2) if dwells else 0.0,
        "mean_commands": round(sum(v["events"] for v in engaged) / len(engaged), 2) if engaged else 0.0,
        # Coming back is retention too, and arguably the stronger signal: a
        # static honeypot is rarely worth a second visit.
        "return_rate": round(returned / len(attackers), 3) if attackers else 0.0,
        "pivot_rate": round(pivoted / len(visits), 3),
        "mean_depth": round(sum(v["depth"] for v in visits) / len(visits), 2),
        "reached_erp": sum(1 for v in visits if v["depth"] >= 2),
        "reached_db": sum(1 for v in visits if v["depth"] >= 3),
    }
