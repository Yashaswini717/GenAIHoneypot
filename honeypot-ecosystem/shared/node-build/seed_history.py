"""Give the node a past.

A freshly built container has no history, and the absence is loud. `last`
prints nothing, `lastlog` says "**Never logged in**" for every account,
/var/log/auth.log starts at the moment the image was built, and every file
shares one mtime. Each of those alone is enough to tell an attacker the box
was created minutes ago; together they are conclusive.

So the image ships with a past. Login records go into wtmp and lastlog in the
real binary formats those tools read, and the text logs are backdated with an
activity curve that follows an academic timetable rather than a flat rate --
busy during working hours, quiet overnight, quieter at weekends, and with the
occasional 2am cron burst that a real machine has.

This is seeded history, not live history. Once the golden master runs
continuously it accrues genuine uptime and genuinely growing logs on its own,
and the live ambient engine in phase 2 takes over from here. What this
guarantees is that the box is never empty on day one.
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass
from datetime import datetime, timedelta, tzinfo
from pathlib import Path
from zoneinfo import ZoneInfo


def zone(name: str) -> tzinfo:
    """The node's declared timezone, from identity.yaml."""
    return ZoneInfo(name)


def _epoch(when: datetime) -> int:
    """Seconds since the epoch, refusing naive datetimes.

    This guard exists because of a real bug. `datetime.timestamp()` on a naive
    value silently interprets it in the *build machine's* local zone, so a
    history seeded as "09:00-18:00 working hours" came out at 03:30-12:30 UTC
    and displayed inside the container as a box whose every login happened
    between 3am and 5am. Worse, the same Dockerfile built in two countries
    would produce two different histories.

    Timestamps must be explicitly zoned, so building is reproducible and
    working hours actually look like working hours.
    """
    if when.tzinfo is None:
        raise ValueError(
            f"refusing to seed history from a naive datetime ({when!r}); "
            "build it in the node's declared timezone via zone()"
        )
    return int(when.timestamp())

# -- utmp/wtmp binary format (Linux x86_64, 384 bytes per record) -----------

UTMP_STRUCT = struct.Struct("<h2xi32s4s32s256shhiii16s20s")
assert UTMP_STRUCT.size == 384, f"utmp record must be 384 bytes, got {UTMP_STRUCT.size}"

RUN_LVL = 1
BOOT_TIME = 2
USER_PROCESS = 7
DEAD_PROCESS = 8

# -- lastlog binary format (292 bytes per record, indexed by uid) -----------

LASTLOG_STRUCT = struct.Struct("<i32s256s")
assert LASTLOG_STRUCT.size == 292, f"lastlog record must be 292 bytes, got {LASTLOG_STRUCT.size}"


def _fixed(value: str, length: int) -> bytes:
    raw = value.encode("utf-8")[: length - 1]
    return raw + b"\x00" * (length - len(raw))


@dataclass
class LoginRecord:
    user: str
    line: str
    host: str
    started: datetime
    duration_minutes: int
    pid: int


def build_utmp_record(
    *,
    ut_type: int,
    pid: int,
    line: str,
    ut_id: str,
    user: str,
    host: str,
    when: datetime,
) -> bytes:
    return UTMP_STRUCT.pack(
        ut_type,
        pid,
        _fixed(line, 32),
        _fixed(ut_id, 4),
        _fixed(user, 32),
        _fixed(host, 256),
        0,  # ut_exit.e_termination
        0,  # ut_exit.e_exit
        0,  # ut_session
        _epoch(when),
        random.randint(0, 999999),  # tv_usec
        b"\x00" * 16,  # ut_addr_v6
        b"\x00" * 20,  # __unused
    )


def write_wtmp(path: Path, logins: list[LoginRecord], boot_time: datetime) -> None:
    """Write the login history `last` reads.

    A boot record first, then paired USER_PROCESS / DEAD_PROCESS entries so
    `last` can compute session durations instead of showing everything as
    "still logged in", which would itself look wrong.
    """
    records: list[tuple[datetime, bytes]] = []

    records.append(
        (
            boot_time,
            build_utmp_record(
                ut_type=BOOT_TIME,
                pid=0,
                line="~",
                ut_id="~~",
                user="reboot",
                host="5.15.0-118-generic",
                when=boot_time,
            ),
        )
    )
    records.append(
        (
            boot_time,
            build_utmp_record(
                ut_type=RUN_LVL,
                pid=0,
                line="~",
                ut_id="~~",
                user="runlevel",
                host="5.15.0-118-generic",
                when=boot_time,
            ),
        )
    )

    for entry in logins:
        ended = entry.started + timedelta(minutes=entry.duration_minutes)
        ut_id = entry.line[-4:]
        records.append(
            (
                entry.started,
                build_utmp_record(
                    ut_type=USER_PROCESS,
                    pid=entry.pid,
                    line=entry.line,
                    ut_id=ut_id,
                    user=entry.user,
                    host=entry.host,
                    when=entry.started,
                ),
            )
        )
        records.append(
            (
                ended,
                build_utmp_record(
                    ut_type=DEAD_PROCESS,
                    pid=entry.pid,
                    line=entry.line,
                    ut_id=ut_id,
                    user="",
                    host="",
                    when=ended,
                ),
            )
        )

    records.sort(key=lambda item: item[0])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"".join(payload for _, payload in records))


def write_lastlog(path: Path, last_by_uid: dict[int, LoginRecord]) -> None:
    """Write the per-uid record `lastlog` reads.

    The file is a flat array indexed by uid, so it must be padded out to the
    highest uid present -- sparse writes would misalign every later account.
    """
    if not last_by_uid:
        return
    highest = max(last_by_uid)
    blob = bytearray()
    for uid in range(highest + 1):
        entry = last_by_uid.get(uid)
        if entry is None:
            blob += LASTLOG_STRUCT.pack(0, _fixed("", 32), _fixed("", 256))
        else:
            blob += LASTLOG_STRUCT.pack(
                _epoch(entry.started),
                _fixed(entry.line, 32),
                _fixed(entry.host, 256),
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(blob))


# -- activity curve ---------------------------------------------------------


def activity_weight(when: datetime, workday_start: int, workday_end: int) -> float:
    """How busy the machine should look at a given moment.

    Flat-rate log generation is a tell in its own right: real machines have a
    shape. This one follows a teaching timetable.
    """
    hour = when.hour
    weekday = when.weekday()

    if weekday >= 5:  # weekend
        base = 0.18
    else:
        base = 1.0

    if workday_start <= hour < workday_end:
        curve = 1.0
        if 12 <= hour < 14:  # lunch dip
            curve = 0.55
    elif hour in (workday_end, workday_start - 1):
        curve = 0.4
    elif 0 <= hour < 5:
        curve = 0.06  # overnight: cron and little else
    else:
        curve = 0.15

    return base * curve


def scatter_events(
    start: datetime,
    end: datetime,
    per_active_hour: float,
    workday_start: int,
    workday_end: int,
    rng: random.Random,
) -> list[datetime]:
    """Timestamps distributed along the activity curve, not uniformly."""
    moments: list[datetime] = []
    cursor = start.replace(minute=0, second=0, microsecond=0)
    while cursor < end:
        weight = activity_weight(cursor, workday_start, workday_end)
        expected = per_active_hour * weight
        count = int(expected) + (1 if rng.random() < (expected % 1) else 0)
        for _ in range(count):
            moments.append(
                cursor
                + timedelta(
                    minutes=rng.randint(0, 59),
                    seconds=rng.randint(0, 59),
                )
            )
        cursor += timedelta(hours=1)
    moments.sort()
    return moments
