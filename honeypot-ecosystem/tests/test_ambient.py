"""Schedules for the ambient activity engine.

The engine's whole purpose is that live activity continues the seeded history
without a seam. That property lives entirely in `Schedule`, which generates
both the crontab line and the historical timestamps -- so if the two
interpretations of one schedule ever diverge, the box gets a log whose cadence
changes at the exact moment it booted, which is a sharper tell than the silence
the engine was built to fix.

These tests pin that agreement, and the two bugs found while writing it:

1. `*/N` fires at clock minutes divisible by N, not N minutes after the daemon
   started. Seeding from the window's start instead produced history on a
   cadence the live job would never use.
2. Rounding the cursor back to a clock position emitted one occurrence before
   the requested window.

Run with:  pytest honeypot-ecosystem/tests/ -v
"""

from __future__ import annotations

import random
import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared" / "node-build"))

from ambient import AMBIENT_JOBS, Schedule  # noqa: E402

# 28 Sep 2026 is a Monday, 3 Oct a Saturday, 4 Oct a Sunday.
MONDAY = datetime(2026, 9, 28, 0, 0)


# -- the crontab line ------------------------------------------------------


@pytest.mark.parametrize(("schedule", "expected"), [
    (Schedule(every_minutes=20), "*/20 * * * *"),
    (Schedule(every_minutes=20, hours="9-18", days="1-5"), "*/20 9-18 * * 1-5"),
    (Schedule(at="02:17"), "17 2 * * *"),
    (Schedule(at="02:17", days="1-5"), "17 2 * * 1-5"),
    (Schedule(at="00:05"), "5 0 * * *"),
])
def test_cron_expression(schedule, expected):
    assert schedule.to_cron() == expected


# -- seeded occurrences agree with that line -------------------------------


def test_interval_lands_on_clock_positions():
    """cron's */20 fires at :00 :20 :40, whatever time the seeding starts.

    Seeding relative to the window start instead would give history at
    intervals the live job never produces, which is visible by diffing
    timestamps either side of the boot.
    """
    occurrences = Schedule(every_minutes=20).occurrences(
        datetime(2026, 9, 28, 10, 7), datetime(2026, 9, 28, 11, 0)
    )
    assert [m.strftime("%H:%M") for m in occurrences] == ["10:20", "10:40", "11:00"]
    assert all(m.minute % 20 == 0 for m in occurrences)


def test_occurrences_stay_inside_the_window():
    """Regression: rounding back to a clock position escaped the window."""
    start = datetime(2026, 9, 28, 10, 7)
    end = datetime(2026, 9, 28, 11, 0)
    for step in (5, 15, 20, 30, 60):
        for moment in Schedule(every_minutes=step).occurrences(start, end):
            assert start <= moment <= end, f"step {step} produced {moment}"


def test_hours_window_is_honoured():
    occurrences = Schedule(every_minutes=60, hours="9-11").occurrences(
        MONDAY, MONDAY.replace(hour=23, minute=59)
    )
    assert [m.hour for m in occurrences] == [9, 10, 11]


def test_weekday_window_excludes_the_weekend():
    """A monitoring log ticking through Sunday 4am, on a box whose other logs
    go quiet then, is a contradiction between two things we wrote ourselves."""
    occurrences = Schedule(at="02:17", days="1-5").occurrences(
        datetime(2026, 9, 26), datetime(2026, 10, 4, 23, 59)
    )
    labels = [m.strftime("%a") for m in occurrences]
    assert labels == ["Mon", "Tue", "Wed", "Thu", "Fri"]
    assert "Sat" not in labels and "Sun" not in labels


def test_cron_sunday_is_zero_not_seven():
    """Cron numbers Sunday 0 (or 7); Python numbers Monday 0. Getting this
    wrong shifts every weekday window by one day, which looks like nothing."""
    sunday_only = Schedule(at="03:00", days="0").occurrences(
        datetime(2026, 9, 28), datetime(2026, 10, 4, 23, 59)
    )
    assert [m.strftime("%a") for m in sunday_only] == ["Sun"]

    also_sunday = Schedule(at="03:00", days="7").occurrences(
        datetime(2026, 9, 28), datetime(2026, 10, 4, 23, 59)
    )
    assert [m.strftime("%a") for m in also_sunday] == ["Sun"]


def test_daily_job_runs_once_per_matching_day():
    occurrences = Schedule(at="02:17").occurrences(
        datetime(2026, 9, 28), datetime(2026, 10, 1, 23, 59)
    )
    assert len(occurrences) == 4
    assert {(m.hour, m.minute) for m in occurrences} == {(2, 17)}


# -- schedules that cannot be honoured must not be accepted ----------------


@pytest.mark.parametrize("kwargs", [
    {},                                        # neither
    {"every_minutes": 20, "at": "02:17"},      # both
    {"every_minutes": 0},
    {"every_minutes": 5000},
    {"at": "25:00"},
    {"at": "02:99"},
    {"at": "0217"},
])
def test_impossible_schedules_are_rejected(kwargs):
    with pytest.raises(ValueError):
        Schedule(**kwargs)


@pytest.mark.parametrize("field", ["hours", "days"])
@pytest.mark.parametrize("spec", ["*/5", "9-", "abc", "99", "9-99"])
def test_unsupported_schedule_fields_raise(field, spec):
    """Silently reading an unsupported field as "always" would seed history on
    a cadence the live job never uses -- the one failure this class exists to
    prevent, so it raises rather than degrading.

    Raised at construction, so a typo in an identity.yaml fails while
    rendering that node rather than at seeding time.
    """
    with pytest.raises(ValueError):
        Schedule(every_minutes=30, **{field: spec})


# -- the job catalogue ------------------------------------------------------


def test_every_job_seeds_a_line_and_writes_the_log_it_seeds():
    rng = random.Random(0)
    for name, job in AMBIENT_JOBS.items():
        tail = job.seed_tail(rng, datetime(2026, 9, 25, 2, 15))
        assert tail and "\n" not in tail, f"{name} seeded a bad line: {tail!r}"
        assert job.log in job.body, (
            f"{name} seeds {job.log} but its script never writes there"
        )


def test_scripts_are_shell_and_fail_loudly():
    for name, job in AMBIENT_JOBS.items():
        assert job.body.startswith("#!/bin/sh\n"), f"{name} has no shebang"
        assert "set -eu" in job.body, f"{name} would continue after a failure"


def test_no_job_reveals_what_this_is():
    """Root can read every one of these scripts."""
    forbidden = ("honeypot", "decoy", "attacker", "cowrie", "sidecar", "broker")
    for name, job in AMBIENT_JOBS.items():
        haystack = (job.body + job.script + job.log).lower()
        for word in forbidden:
            assert word not in haystack, f"{name} mentions {word!r}"


def test_db_backup_line_names_a_file_matching_its_own_timestamp():
    """A log line whose timestamp and filename disagree is a line nothing
    produced, and the filename is right there in the same line."""
    moment = datetime(2026, 9, 25, 2, 15)
    tail = AMBIENT_JOBS["db-backup"].seed_tail(random.Random(0), moment)
    assert moment.strftime("%Y%m%d-%H%M") in tail


def test_session_counts_follow_the_working_day():
    """Seeded at a flat rate, this log showed two or three people logged into
    the bastion at 3am every night -- on a box whose auth.log has logins only
    during working hours. Two files we wrote ourselves, disagreeing about
    whether anybody was there.
    """
    job = AMBIENT_JOBS["session-audit"]
    rng = random.Random(11)

    def total(day, hour, samples=120):
        return sum(
            int(job.seed_tail(rng, datetime(2026, 9, day, hour, 0)).split()[0].split("=")[1])
            for _ in range(samples)
        )

    workday = total(30, 15)    # Wed 30 Sep 2026, afternoon
    overnight = total(30, 3)   # Wed 30 Sep 2026, 3am
    weekend = total(27, 15)    # Sun 27 Sep 2026, afternoon

    assert workday > overnight * 5, f"workday {workday} vs overnight {overnight}"
    assert weekend < workday / 3, f"weekend {weekend} not quiet next to workday {workday}"


def test_established_connections_are_never_fewer_than_sessions():
    """A login session with no connection behind it cannot happen."""
    job = AMBIENT_JOBS["session-audit"]
    rng = random.Random(3)
    for hour in range(24):
        for _ in range(40):
            tail = job.seed_tail(rng, datetime(2026, 9, 30, hour, 0))
            sessions = int(tail.split()[0].split("=")[1])
            sshd = int(tail.split()[1].split("=")[1])
            assert sshd >= sessions, tail
