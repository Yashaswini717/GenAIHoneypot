"""Assigning attackers to experimental arms.

The research claim is that adaptive deception holds attackers longer than
static deception. Comparing our honeypot against someone else's published
figures cannot support that: different bait, different exposure, different
traffic, so any difference is unattributable. Comparing our honeypot against
*itself* with adaptation switched off can, because only one thing differs.

That makes the control arm a static honeypot built from identical bait —
same three nodes, same seeded decoys baked into the images, same credentials
— receiving the same traffic at the same moment. It simply never has decoys
generated and planted for it mid-session.

Three properties this has to have, and each one is a way the experiment can
quietly stop being valid:

**Stable.** An attacker who returns must land in the same arm. Reassigning
them would mix both treatments into one visit and into one attacker's
history, and return rate is one of the metrics being compared.

**Deterministic.** Derived from the address, not drawn at random and stored,
so a restarted proxy, a second proxy, or a replay of the same traffic all
agree without sharing state.

**Uncorrelated with anything else.** A hash, so arms do not track subnet,
geography or scanner family. Splitting on something like "even last octet"
would quietly sort botnets into one arm.
"""

from __future__ import annotations

import hashlib
import os


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


#: Fraction of attackers held back as the control arm, in [0, 1].
#:
#: 0.5 is the most statistical power per attacker seen, which matters when
#: traffic is the scarce resource. Lower it to bias toward the adaptive arm
#: once the comparison is already significant and the honeypot is wanted at
#: its best; 0.0 disables the experiment and gives everyone adaptation.
CONTROL_RATIO = _env_float("EXPERIMENT_CONTROL_RATIO", 0.5)

#: Changing this reshuffles every assignment.
#:
#: Which is exactly what you must not do mid-experiment -- attackers already
#: measured under one arm would silently switch to the other, and their
#: earlier visits would be attributed to a treatment they never received. It
#: exists for starting a clean experiment, not for tuning one.
SALT = os.environ.get("EXPERIMENT_SALT", "genai-honeypot-v1")

#: Resolution of the bucketing. 10000 buckets means a control ratio is
#: honoured to one basis point, far finer than any honeypot's traffic.
_BUCKETS = 10000


def bucket_for(attacker: str, salt: str = SALT) -> int:
    """Stable bucket in [0, _BUCKETS) for one attacker.

    SHA-256 rather than Python's hash(), which is randomised per process:
    that would reassign every attacker on restart, which is the one thing
    this must never do.
    """
    digest = hashlib.sha256(f"{salt}:{attacker}".encode("utf-8")).digest()
    return int.from_bytes(digest[:4], "big") % _BUCKETS


def is_adaptive(attacker: str, control_ratio: float = CONTROL_RATIO, salt: str = SALT) -> bool:
    """True when this attacker should receive adaptive decoys.

    Returns True for everybody when `control_ratio` is 0, so the experiment
    can be switched off without changing any other behaviour.
    """
    if control_ratio <= 0:
        return True
    if control_ratio >= 1:
        return False
    return bucket_for(attacker, salt) >= control_ratio * _BUCKETS


def describe() -> str:
    """One line for the startup log, so the running split is never a guess."""
    if CONTROL_RATIO <= 0:
        return "experiment off - every attacker receives adaptive decoys"
    return (
        f"experiment on - {CONTROL_RATIO:.0%} of attackers held back as control "
        f"(salt {SALT!r})"
    )
