#!/usr/bin/env python3
"""Ambient activity: the part of the box that is still happening.

Everything `render_node.py` seeds is history -- true at build time and frozen
from then on. A machine like that survives a glance and fails a stakeout. An
attacker who tails a log, or runs the same command twice ten minutes apart, is
the attacker most worth holding, and a box where nothing ever changes loses
them at exactly that moment.

**Real cron, no daemon of our own.** cron is already running on every node and
making things happen on a schedule is the entire reason it exists, so ambient
activity is ordinary scripts in ordinary places with ordinary crontab entries.
A process of ours in `ps` -- whatever we named it -- would be a worse tell than
the silence it fixed. As a side effect cron logs every invocation to syslog by
itself, so `/var/log/syslog` grows without anything writing lines on cron's
behalf.

**No faked live sessions.** It is tempting to make `w` and `last` show
colleagues working, and it is the one thing here that must not be done: a `w`
entry with no matching pty and no process behind it is an instant, certain
tell. On a real bastion at 3am, `w` showing nobody but you is simply correct.
Seeded logins in the past plus an empty `w` now is a coherent machine; a
fabricated present is not.

**One source of truth for each schedule.** A `*/20` cron job writes its log at
exact twenty-minute intervals, so seeded history has to as well -- irregular
gaps in a fixed-schedule log are their own tell. The cron expression and the
seeded timestamps are therefore both derived from the same structured fields
rather than written twice and kept in step by hand.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable


@dataclass(frozen=True)
class AmbientJob:
    """One cron job, its script, and how to seed the log it appends to."""

    script: str
    log: str
    body: str
    #: The part of a historical line after the timestamp. Takes the rng
    #: because seeded readings have to vary the way real samples do -- five
    #: hundred identical lines is not the log of a machine doing anything --
    #: and the moment, because a line that names a file has to name one whose
    #: date matches the line's own.
    seed_tail: Callable[[random.Random, datetime], str]
    log_owner: str = "root:root"
    log_mode: int = 0o644


@dataclass(frozen=True)
class Schedule:
    """When a job runs, in the one form both cron and the seeder read.

    Either `every_minutes` (a fixed interval) or `at` (a daily time), never
    both. `hours` and `days` narrow it to an academic timetable, which is what
    the seeded history in `seed_history.py` already follows -- a monitoring log
    that ticks steadily through Sunday at 4am on a box whose other logs go
    quiet is a contradiction between two things we wrote ourselves.
    """

    every_minutes: int | None = None
    at: str | None = None
    hours: str | None = None
    days: str | None = None

    def __post_init__(self) -> None:
        if (self.every_minutes is None) == (self.at is None):
            raise ValueError("a schedule needs exactly one of every_minutes or at")
        if self.every_minutes is not None and not 1 <= self.every_minutes <= 720:
            raise ValueError(f"every_minutes out of range: {self.every_minutes}")
        if self.at is not None:
            hour, _, minute = self.at.partition(":")
            if not (hour.isdigit() and minute.isdigit()):
                raise ValueError(f"at must be HH:MM, got {self.at!r}")
            if not (0 <= int(hour) <= 23 and 0 <= int(minute) <= 59):
                raise ValueError(f"at is not a real time: {self.at!r}")
        # Parsed now rather than when seeding, so a typo in an identity.yaml
        # fails while rendering the node that contains it instead of quietly
        # widening the schedule it was meant to narrow.
        _expand_range(self.hours, 0, 23)
        _expand_range(self.days, 0, 7)

    # -- cron ---------------------------------------------------------------

    def to_cron(self) -> str:
        """The five schedule fields of a crontab line."""
        hours = self.hours or "*"
        days = self.days or "*"
        if self.every_minutes is not None:
            return f"*/{self.every_minutes} {hours} * * {days}"
        hour, _, minute = self.at.partition(":")  # type: ignore[union-attr]
        return f"{int(minute)} {int(hour)} * * {days}"

    # -- seeding ------------------------------------------------------------

    def _hours_allowed(self) -> set[int] | None:
        return _expand_range(self.hours, 0, 23)

    def _days_allowed(self) -> set[int] | None:
        """Cron weekdays: 0 and 7 are both Sunday."""
        allowed = _expand_range(self.days, 0, 7)
        if allowed is None:
            return None
        if 7 in allowed:
            allowed = (allowed - {7}) | {0}
        return allowed

    def occurrences(self, start: datetime, end: datetime) -> list[datetime]:
        """Every moment this job would have run between start and end.

        Generated from the same fields `to_cron` uses, so seeded history lands
        on the clock positions the live job will land on. A reader diffing the
        intervals before and after this boot finds the same cadence.
        """
        hours = self._hours_allowed()
        days = self._days_allowed()
        step = self.every_minutes
        results: list[datetime] = []

        if step is not None:
            # cron's */N fires at minutes divisible by N, not N minutes after
            # whenever the daemon happened to start.
            cursor = start.replace(second=0, microsecond=0)
            cursor -= timedelta(minutes=cursor.minute % step)
            while cursor <= end:
                # `cursor` was rounded back to a clock position, so the first
                # one can precede the window; the window is the caller's and
                # must not be widened.
                if cursor >= start and _matches(cursor, hours, days):
                    results.append(cursor)
                cursor += timedelta(minutes=step)
            return results

        hour, _, minute = self.at.partition(":")  # type: ignore[union-attr]
        cursor = start.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)
        while cursor <= end:
            if cursor >= start and _matches(cursor, hours, days):
                results.append(cursor)
            cursor += timedelta(days=1)
        return results


def _expand_range(spec: str | None, low: int, high: int) -> set[int] | None:
    """Parse the subset of cron syntax a schedule is allowed to use.

    Deliberately narrow: "9-18", "1-5", "2,14", or a bare number. Anything
    else raises rather than being silently ignored, because a schedule that
    parses to "always" here while cron reads it correctly would put seeded
    history on a cadence the live job never uses.
    """
    if spec is None or spec == "*":
        return None
    allowed: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            first, _, last = part.partition("-")
            if not (first.isdigit() and last.isdigit()):
                raise ValueError(f"bad range in schedule: {part!r}")
            allowed.update(range(int(first), int(last) + 1))
        elif part.isdigit():
            allowed.add(int(part))
        else:
            raise ValueError(f"unsupported schedule field: {part!r}")
    if not allowed or min(allowed) < low or max(allowed) > high:
        raise ValueError(f"schedule field out of range {low}-{high}: {spec!r}")
    return allowed


def _matches(moment: datetime, hours: set[int] | None, days: set[int] | None) -> bool:
    if hours is not None and moment.hour not in hours:
        return False
    if days is not None:
        # Python: Monday is 0. Cron: Sunday is 0.
        cron_dow = (moment.weekday() + 1) % 7
        if cron_dow not in days:
            return False
    return True


# Taken verbatim from a real `mysqldump --single-transaction erp` on node-03.
#
# The seeded schema on its own begins "CREATE DATABASE IF NOT EXISTS", which
# mysqldump never emits: a file named as last night's dump, in a directory the
# backup script writes, that could not have been produced by the tool that
# script runs. An attacker who gunzips one is already deep enough to be worth
# not losing over a preamble.
MYSQLDUMP_HEADER = "\n".join([
    r"/*M!999999\- enable the sandbox mode */ ",
    "-- MariaDB dump 10.19  Distrib 10.6.23-MariaDB, for debian-linux-gnu (x86_64)",
    "--",
    "-- Host: localhost    Database: erp",
    "-- ------------------------------------------------------",
    "-- Server version\t10.6.23-MariaDB-0ubuntu0.22.04.1-log",
    "",
    "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;",
    "/*!40103 SET TIME_ZONE='+00:00' */;",
    "/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;",
    "/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;",
    "",
    "",
])

MYSQLDUMP_FOOTER = "\n".join([
    "",
    "/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;",
    "/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;",
    "/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;",
    "",
])


def as_mysqldump(schema: str, when: datetime) -> str:
    """The seeded schema, wrapped so it reads as mysqldump output.

    mysqldump writes the hour without a leading zero, so 02:15 appears as
    " 2:15:03" with the two spaces its format produces. Reproduced because the
    completion line is the last thing in the file and the easiest to compare
    against a dump the attacker takes themselves.
    """
    stamp = f"{when.strftime('%Y-%m-%d')} {when.hour:>2d}:{when.strftime('%M:%S')}"
    return (
        MYSQLDUMP_HEADER
        + schema.rstrip("\n")
        + "\n"
        + MYSQLDUMP_FOOTER
        + f"\n-- Dump completed on {stamp}\n"
    )


def _sessions_at(rng: random.Random, when: datetime) -> str:
    """Concurrent sessions, following the working day.

    Not a flat random count. Seeded at a constant rate this log showed two or
    three people logged into the bastion at 3am every night, on a box whose
    auth.log has logins only during working hours -- two files we wrote
    ourselves, disagreeing about whether anyone was there.
    """
    weekend = when.weekday() >= 5
    if 9 <= when.hour < 18 and not weekend:
        sessions = rng.choices([1, 2, 3, 4], weights=[30, 40, 20, 10])[0]
    elif 7 <= when.hour < 21 and not weekend:
        sessions = rng.choices([0, 1, 2], weights=[45, 40, 15])[0]
    else:
        # Overnight and weekends: usually nobody, occasionally one person
        # finishing something, which is what the seeded 2am cron burst and the
        # odd late login in auth.log already imply.
        sessions = rng.choices([0, 1], weights=[92, 8])[0]
    # sshd connections cannot be fewer than login sessions, and a session
    # being torn down leaves the count briefly higher.
    established = sessions + rng.choices([0, 1], weights=[85, 15])[0]
    return f"sessions={sessions} sshd={established}"


def _pct(rng: random.Random, low: int, high: int) -> str:
    return f"{rng.randint(low, high)}%"


#: The catalogue. A node's identity.yaml names which of these it runs and on
#: what schedule; nothing here is installed unless a node asks for it.
#:
#: Every entry has to earn all three of: a departmental sysadmin would have
#: written it and the script reads that way to whoever cats it (root can);
#: it leaves behind something that was not there ten minutes ago; and its log
#: carries history at the cadence it will keep running at.
AMBIENT_JOBS: dict[str, AmbientJob] = {
    # The most ordinary cron job in existence, which is the point: nobody
    # looks twice at it, and it gives the box a log visibly still being
    # written.
    "disk-report": AmbientJob(
        script="/usr/local/sbin/disk-report",
        log="/var/log/disk-report.log",
        body=(
            "#!/bin/sh\n"
            "# Capacity sampling for the monthly infrastructure review.\n"
            "# Raised as ITS-1884; keep until the dashboards cover it.\n"
            "set -eu\n"
            "LOG=/var/log/disk-report.log\n"
            "USED=$(df -P / | awk 'NR==2 {print $5}')\n"
            "INODES=$(df -Pi / | awk 'NR==2 {print $5}')\n"
            "echo \"$(date '+%Y-%m-%d %H:%M:%S') root=$USED inodes=$INODES\" >> \"$LOG\"\n"
        ),
        seed_tail=lambda rng, when: f"root={_pct(rng, 38, 44)} inodes={_pct(rng, 11, 14)}",
    ),
    # Counts the attacker's own session, so what they read is true and
    # includes them. The box is measuring them, not performing for them.
    "session-audit": AmbientJob(
        script="/usr/local/sbin/session-audit",
        log="/var/log/session-audit.log",
        body=(
            "#!/bin/sh\n"
            "# Concurrent bastion sessions, sampled for the termly access report.\n"
            "set -eu\n"
            "LOG=/var/log/session-audit.log\n"
            "SESSIONS=$(who 2>/dev/null | wc -l)\n"
            "ESTAB=$(ss -tn state established 2>/dev/null | grep -c ':22' || true)\n"
            "echo \"$(date '+%Y-%m-%d %H:%M:%S') sessions=$SESSIONS sshd=$ESTAB\" >> \"$LOG\"\n"
        ),
        seed_tail=lambda rng, when: _sessions_at(rng, when),
    ),
    # Worth more than the line it writes: the probe goes through nginx, so the
    # access log an attacker greps first keeps growing on its own.
    "portal-healthcheck": AmbientJob(
        script="/usr/local/sbin/portal-healthcheck",
        log="/var/log/portal-health.log",
        body=(
            "#!/bin/sh\n"
            "# Availability probe feeding the ITS status board.\n"
            "set -eu\n"
            "LOG=/var/log/portal-health.log\n"
            "CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 http://127.0.0.1/ "
            "|| echo 000)\n"
            "echo \"$(date '+%Y-%m-%d %H:%M:%S') portal=$CODE\" >> \"$LOG\"\n"
        ),
        # Always 200, deliberately. A seeded 502 here would need a matching
        # 502 in nginx's access log at the same second -- nginx logs the
        # upstream failure too -- and two independently drawn randoms do not
        # correlate. A week of 200s is what a healthy service's probe log
        # actually looks like.
        seed_tail=lambda rng, when: "portal=200",
    ),
    # Leaves a real file in /var/backups/mysql that an attacker can find,
    # size, and gunzip -- a genuine dump of the data they came for, which is a
    # better reason to keep digging than any log line.
    "db-backup": AmbientJob(
        script="/usr/local/sbin/db-backup",
        log="/var/log/db-backup.log",
        body=(
            "#!/bin/sh\n"
            "# Logical backup of the ERP schema. Retention is 8 files; ITS-2104\n"
            "# asked for 14 and is waiting on a bigger volume.\n"
            "set -eu\n"
            "LOG=/var/log/db-backup.log\n"
            "DEST=/var/backups/mysql\n"
            "mkdir -p \"$DEST\"\n"
            "FILE=\"$DEST/erp-$(date '+%Y%m%d-%H%M').sql.gz\"\n"
            "if mysqldump --single-transaction erp 2>/dev/null | gzip > \"$FILE\"; then\n"
            "    echo \"$(date '+%Y-%m-%d %H:%M:%S') ok $(basename \"$FILE\") "
            "$(stat -c %s \"$FILE\") bytes\" >> \"$LOG\"\n"
            "else\n"
            "    rm -f \"$FILE\"\n"
            "    echo \"$(date '+%Y-%m-%d %H:%M:%S') FAILED mysqldump erp\" >> \"$LOG\"\n"
            "fi\n"
            "ls -1t \"$DEST\" 2>/dev/null | tail -n +9 | while read -r old; do\n"
            "    rm -f \"$DEST/$old\"\n"
            "done\n"
        ),
        # The filename carries the moment the backup was taken, because it
        # does in the live script -- a log line whose timestamp and
        # filename disagree is a line nothing produced.
        seed_tail=lambda rng, when: (
            f"ok erp-{when.strftime('%Y%m%d-%H%M')}.sql.gz "
            f"{rng.randint(5100, 5900)} bytes"
        ),
    ),
}
