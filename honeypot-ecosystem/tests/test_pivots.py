"""One line typed into a pivot is one command, not two.

An attacker inside `ssh deploy@erp-web` keeps typing through their node-01
session, so the perimeter and the peer gateway both recorded every line: two
tripwires, two classifications and two alerts for one database query (seen in
the 2026-11-04 rehearsal). pivots.py marks the outer copy nested; these tests
pin which session that is, and when.

Run with:  pytest honeypot-ecosystem/tests/ -v
"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared" / "ssh-proxy"))

import pivots  # noqa: E402
from pivots import LAUNCH_WINDOW, PivotTracker  # noqa: E402

OWNER = "203.0.113.5"


class Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def setup(monkeypatch):
    clock = Clock()
    tracker = PivotTracker(clock)
    monkeypatch.setattr(pivots, "TRACKER", tracker)
    return SimpleNamespace(tracker=tracker, clock=clock)


def test_the_session_that_typed_ssh_is_nested_while_its_pivot_is_open(setup):
    t = setup.tracker
    t.typed(OWNER, "s1", "ssh -i /tmp/k -o StrictHostKeyChecking=no deploy@erp-web")
    pivot = object()
    t.opened(pivot, OWNER)

    assert t.nested(OWNER, "s1")
    assert not t.nested(OWNER, "s2"), "a second terminal on node-01 must keep counting"

    t.closed(pivot)
    assert not t.nested(OWNER, "s1"), "back on node-01, commands count again"


def test_a_pivot_no_session_typed_marks_nothing(setup):
    setup.tracker.opened(object(), OWNER)    # a script, or a one-shot command
    assert not setup.tracker.nested(OWNER, "s1")


def test_an_old_ssh_does_not_claim_a_later_pivot(setup):
    setup.tracker.typed(OWNER, "s1", "ssh deploy@erp-web")
    setup.clock.now += LAUNCH_WINDOW + 1
    setup.tracker.opened(object(), OWNER)
    assert not setup.tracker.nested(OWNER, "s1")


def test_another_attackers_pivot_does_not_nest_this_session(setup):
    setup.tracker.typed(OWNER, "s1", "ssh deploy@erp-web")
    setup.tracker.opened(object(), "198.51.100.9")
    assert not setup.tracker.nested(OWNER, "s1")


@pytest.mark.parametrize("command", [
    "ssh deploy@erp-web",
    "ssh -i /tmp/k deploy@erp-web",
    "sudo ssh root@db-01",
    "cd /tmp; ssh -i k deploy@erp-web",
    "sshpass -p hunter2 ssh deploy@erp-web",
])
def test_ssh_as_a_command_can_launch_a_pivot(setup, command):
    setup.tracker.typed(OWNER, "s1", command)
    setup.tracker.opened(object(), OWNER)
    assert setup.tracker.nested(OWNER, "s1")


@pytest.mark.parametrize("command", [
    "cat ~/.ssh/config",
    "ssh-keygen -t ed25519",
    "ls /etc/ssh/",
    "systemctl status sshd",
])
def test_mentioning_ssh_is_not_launching_one(setup, command):
    setup.tracker.typed(OWNER, "s1", command)
    setup.tracker.opened(object(), OWNER)
    assert not setup.tracker.nested(OWNER, "s1")


def test_mark_tags_the_outer_copy_only_while_inside(setup):
    events = SimpleNamespace(
        attacker=OWNER, src_ip=OWNER, session_id="s1",
        command=lambda text: {"eventid": "cowrie.command.input", "input": text},
    )

    launch = pivots.mark(events, "ssh -i /tmp/k deploy@erp-web")
    pivot = object()
    setup.tracker.opened(pivot, OWNER)
    inside = pivots.mark(events, "mysql -h db-01 -u erp_admin -e 'select 1'")
    setup.tracker.closed(pivot)
    after = pivots.mark(events, "ls")

    assert "nested" not in launch, "the ssh itself is node-01's command"
    assert inside["nested"] is True
    assert "nested" not in after
