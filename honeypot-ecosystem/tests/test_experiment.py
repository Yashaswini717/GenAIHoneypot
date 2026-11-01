"""Arm assignment for the adaptive-vs-static comparison.

The comparison is the research claim, and every way the assignment can be
wrong invalidates it silently: attackers still get an arm, the dashboard still
shows two columns, and the number at the end means nothing.

Three properties, each guarding a specific failure:

  stable         a returning attacker must land in the same arm, or one
                 attacker's history mixes both treatments and return rate --
                 itself a compared metric -- becomes meaningless
  deterministic  survives a restart and agrees across processes, so
                 Python's per-process-randomised hash() cannot be used
  uncorrelated   arms must not track subnet or scanner family, or a botnet
                 sorts itself entirely into one side

Run with:  pytest honeypot-ecosystem/tests/ -v
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared" / "common"))

from experiment import bucket_for, is_adaptive  # noqa: E402

SAMPLE = [f"203.0.113.{i % 256}" for i in range(256)] + [
    f"198.51.{a}.{b}" for a in range(20) for b in range(50)
]


def test_assignment_is_stable_for_one_attacker():
    """The property everything else depends on."""
    address = "198.51.100.7"
    first = is_adaptive(address)
    assert all(is_adaptive(address) is first for _ in range(50))


def test_assignment_survives_a_new_process():
    """Python's hash() is randomised per process; this must not be.

    A restarted proxy that reassigns everyone would split each attacker's
    history across both arms with nothing recording that it happened.
    """
    script = (
        "import sys; sys.path.insert(0, %r)\n"
        "from experiment import bucket_for\n"
        "print(bucket_for('198.51.100.7'))\n"
        % str(Path(__file__).resolve().parents[1] / "shared" / "common")
    )
    runs = {
        subprocess.run([sys.executable, "-c", script], capture_output=True, text=True).stdout.strip()
        for _ in range(3)
    }
    assert len(runs) == 1, f"bucket differs between processes: {runs}"
    assert runs.pop() == str(bucket_for("198.51.100.7"))


def test_split_is_close_to_the_requested_ratio():
    adaptive = sum(is_adaptive(a, control_ratio=0.5) for a in SAMPLE)
    share = adaptive / len(SAMPLE)
    assert 0.44 < share < 0.56, f"50/50 split came out {share:.1%} adaptive"


@pytest.mark.parametrize(("ratio", "expected"), [(0.0, 1.0), (0.25, 0.75), (0.75, 0.25), (1.0, 0.0)])
def test_other_ratios_are_honoured(ratio, expected):
    share = sum(is_adaptive(a, control_ratio=ratio) for a in SAMPLE) / len(SAMPLE)
    assert abs(share - expected) < 0.06, f"ratio {ratio} gave {share:.1%} adaptive"


def test_ratio_zero_disables_the_experiment():
    """Turning the experiment off must give everybody adaptation, not nobody."""
    assert all(is_adaptive(a, control_ratio=0.0) for a in SAMPLE)


def test_neighbouring_addresses_do_not_share_an_arm():
    """A subnet must not sort itself into one side.

    Splitting on something structural -- an even last octet, a hash of the
    /24 -- would put a whole botnet in one arm and call the result an effect.
    """
    block = [f"192.0.2.{i}" for i in range(256)]
    adaptive = sum(is_adaptive(a, control_ratio=0.5) for a in block)
    assert 0.35 < adaptive / len(block) < 0.65, (
        f"one /24 split {adaptive}/256 adaptive — assignment tracks the subnet"
    )


def test_changing_the_salt_reshuffles():
    """Documented as start-a-new-experiment only, so it must actually reshuffle."""
    moved = sum(
        is_adaptive(a, control_ratio=0.5, salt="one") != is_adaptive(a, control_ratio=0.5, salt="two")
        for a in SAMPLE
    )
    assert moved > len(SAMPLE) * 0.3, "a different salt barely changed the assignment"


def test_buckets_stay_in_range():
    assert all(0 <= bucket_for(a) < 10000 for a in SAMPLE)
