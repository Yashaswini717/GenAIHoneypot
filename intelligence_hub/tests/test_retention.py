"""Sessionisation tests for the retention metric.

The retention number is the one figure the research claim rests on, and every
way it can be wrong is silent: it still returns a plausible float. These tests
pin the two rules that were actually got wrong while building it.

1. Measuring an attacker from first-ever to last-ever event reported a 34-day
   "dwell" for an address that connected on two separate days a month apart.
2. A pivot session is nested inside the jump-host session that launched it, so
   its earlier end time must not drag the visit's end backwards.

`build_visits` and `summarise` are pure, so these run without a database.

Run with:  pytest intelligence_hub/tests/ -v
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

from analytics.retention import (  # noqa: E402
    ENGAGED_MIN_SECONDS,
    MIN_ARM_VISITS,
    VISIT_GAP_SECONDS,
    build_visits,
    summarise,
)

T0 = datetime(2026, 9, 30, 10, 0, 0)


def session(attacker, start_offset, length, sensor="node-01-jump", events=5, adaptive=True):
    start = T0 + timedelta(seconds=start_offset)
    return {
        "attacker": attacker,
        "adaptive": adaptive,
        "sensor_id": sensor,
        "started_at": start,
        "ended_at": start + timedelta(seconds=length),
        "event_count": events,
        "threat_score": 50,
    }


def test_one_visit_when_sessions_are_close_together():
    visits = build_visits([
        session("1.2.3.4", 0, 120),
        session("1.2.3.4", 200, 100, sensor="node-02-erp"),
    ])
    assert len(visits) == 1
    assert visits[0]["dwell_seconds"] == 300  # first start to last end


def test_a_long_gap_starts_a_new_visit():
    """The bug this exists for: a return days later is not one long visit."""
    visits = build_visits([
        session("1.2.3.4", 0, 120),
        session("1.2.3.4", VISIT_GAP_SECONDS + 600, 180),
    ])
    assert len(visits) == 2
    assert [v["dwell_seconds"] for v in visits] == [120, 180]
    assert max(v["dwell_seconds"] for v in visits) < VISIT_GAP_SECONDS


def test_a_month_apart_is_not_a_month_of_dwell():
    """Regression: this reported 2,935,710 seconds before sessionisation."""
    visits = build_visits([
        session("1.2.3.4", 0, 300),
        session("1.2.3.4", 34 * 24 * 3600, 300),
    ])
    assert len(visits) == 2
    assert all(v["dwell_seconds"] == 300 for v in visits)


def test_nested_pivot_does_not_shorten_the_visit():
    """A pivot ends before its parent; the visit must still end with the parent.

    Tracking the previous end by assignment rather than max() moved the
    boundary backwards and split one visit into two.
    """
    visits = build_visits([
        session("1.2.3.4", 0, 3000),                              # jump host, long
        session("1.2.3.4", 60, 90, sensor="node-02-erp"),         # pivot, nested
        session("1.2.3.4", 2000, 60, sensor="node-02-erp"),       # another pivot
    ])
    assert len(visits) == 1, "nested pivots must not split the visit"
    assert visits[0]["dwell_seconds"] == 3000


def test_attackers_are_kept_apart():
    visits = build_visits([session("1.1.1.1", 0, 100), session("2.2.2.2", 10, 100)])
    assert len(visits) == 2
    assert {v["attacker"] for v in visits} == {"1.1.1.1", "2.2.2.2"}


def test_depth_comes_from_the_deepest_host_touched():
    visits = build_visits([
        session("1.2.3.4", 0, 100),
        session("1.2.3.4", 10, 50, sensor="node-02-erp"),
        session("1.2.3.4", 20, 50, sensor="node-03-db"),
    ])
    assert visits[0]["depth"] == 3
    assert visits[0]["hosts"] == ["node-01-jump", "node-02-erp", "node-03-db"]


def test_scanner_visits_are_excluded_from_means_but_still_counted():
    """A connect-and-drop must not drag the mean down, nor vanish."""
    visits = build_visits([
        session("1.1.1.1", 0, 600),
        session("2.2.2.2", 0, 1),            # scanner
        session("3.3.3.3", 0, 2),            # scanner
    ])
    s = summarise(visits)
    assert s["visits"] == 3
    assert s["engaged_visits"] == 1
    assert s["median_visit_seconds"] == 600
    assert ENGAGED_MIN_SECONDS > 2


def test_return_rate_counts_attackers_not_visits():
    visits = build_visits([
        session("1.1.1.1", 0, 100),
        session("1.1.1.1", VISIT_GAP_SECONDS + 500, 100),   # returned
        session("2.2.2.2", 0, 100),                          # did not
    ])
    s = summarise(visits)
    assert s["attackers"] == 2
    assert s["visits"] == 3
    assert s["return_rate"] == 0.5


def test_empty_input_is_zeroed_not_an_error():
    s = summarise([])
    assert s["visits"] == 0
    assert s["median_visit_seconds"] == 0.0
    assert s["return_rate"] == 0.0


def test_a_gap_exactly_at_the_threshold_stays_one_visit():
    """The rule is strictly greater, so the boundary belongs to the same visit.

    Pinned because it is the kind of off-by-one that silently changes every
    retention figure if someone later switches the comparison to >=.
    """
    first_end = 100
    visits = build_visits([
        session("1.2.3.4", 0, first_end),
        session("1.2.3.4", first_end + VISIT_GAP_SECONDS, 60),
    ])
    assert len(visits) == 1

    visits = build_visits([
        session("1.2.3.4", 0, first_end),
        session("1.2.3.4", first_end + VISIT_GAP_SECONDS + 1, 60),
    ])
    assert len(visits) == 2


@pytest.mark.parametrize("adaptive", [True, False])
def test_arm_is_carried_onto_the_visit(adaptive):
    visits = build_visits([session("1.2.3.4", 0, 100, adaptive=adaptive)])
    assert visits[0]["adaptive"] is adaptive


def test_a_visit_spanning_both_arms_is_flagged_not_absorbed():
    """The rule that replaced any(), which biased the headline number.

    Flipping the control ratio mid-session gave one address adaptive sessions
    and then control sessions 11 minutes apart. any() labelled the merged
    visit adaptive, so the control sessions were counted as adaptive ones and
    the control arm read as empty -- silently, and in the direction that
    flatters the claim.
    """
    visits = build_visits([
        session("1.2.3.4", 0, 100, adaptive=True),
        session("1.2.3.4", 700, 100, adaptive=False),   # same visit, other arm
    ])
    assert len(visits) == 1
    assert visits[0]["mixed_arm"] is True
    assert visits[0]["adaptive"] is False, "a contaminated visit must not read as adaptive"


def test_an_uncontaminated_visit_is_not_flagged():
    """Negative control: the flag must not fire on ordinary traffic."""
    for arm in (True, False):
        visits = build_visits([
            session("1.2.3.4", 0, 100, adaptive=arm),
            session("1.2.3.4", 700, 100, sensor="node-02-erp", adaptive=arm),
        ])
        assert len(visits) == 1
        assert visits[0]["mixed_arm"] is False
        assert visits[0]["adaptive"] is arm


def test_arm_change_across_separate_visits_is_not_contamination():
    """Each visit is judged on its own sessions, not the attacker's history.

    Two visits far enough apart are two clean measurements even if the arm
    moved between them, so neither should be discarded.
    """
    visits = build_visits([
        session("1.2.3.4", 0, 100, adaptive=True),
        session("1.2.3.4", VISIT_GAP_SECONDS + 500, 100, adaptive=False),
    ])
    assert len(visits) == 2
    assert [v["mixed_arm"] for v in visits] == [False, False]
    assert [v["adaptive"] for v in visits] == [True, False]


def test_engaged_visits_is_what_the_comparison_floor_counts():
    """The floor must not be satisfiable by scanner noise.

    MIN_ARM_VISITS is checked against engaged_visits rather than visits, so a
    handful of connect-and-drops cannot unlock a comparison that has no
    retention signal behind it at all.
    """
    scanners = [session(f"9.9.9.{i}", 0, 1) for i in range(MIN_ARM_VISITS + 3)]
    s = summarise(build_visits(scanners))
    assert s["visits"] > MIN_ARM_VISITS
    assert s["engaged_visits"] == 0, "scanner hits must not count toward the floor"
