"""Placement tests for the session broker.

The broker is what an attacker actually sees the results of: where a decoy
lands, who owns it, and when it claims to have been written. All three are
realism-critical and none of them raises when wrong — a decoy with the wrong
mtime works perfectly and simply looks planted.

The helpers are extracted from source rather than imported, because importing
broker.py pulls in docker, fastapi and pydantic to test two pure functions.

Run with:  pytest honeypot-ecosystem/tests/ -v
"""

from __future__ import annotations

import hashlib
import re
import sys
import time
from pathlib import Path

import pytest

BROKER = Path(__file__).resolve().parents[1] / "shared" / "session-broker" / "broker.py"


def _load_helpers():
    src = BROKER.read_text()
    ns: dict = {"hashlib": hashlib, "time": time}
    for name in ("_decoy_mtime", "_owned_ancestors", "_owner_for"):
        m = re.search(rf"^def {name}\(.*?(?=\n(?:def |#: |@|\Z))", src, re.S | re.M)
        assert m, f"could not extract {name} from broker.py"
        exec(m.group(0), ns)
    for const in ("_DECOY_AGE_MIN_DAYS", "_DECOY_AGE_MAX_DAYS"):
        m = re.search(rf"^{const} = (\d+)", src, re.M)
        assert m, f"could not extract {const}"
        ns[const] = int(m.group(1))
    return ns


H = _load_helpers()
decoy_mtime = H["_decoy_mtime"]
owned_ancestors = H["_owned_ancestors"]
owner_for = H["_owner_for"]
AGE_MIN = H["_DECOY_AGE_MIN_DAYS"]
AGE_MAX = H["_DECOY_AGE_MAX_DAYS"]

DAY = 86400

#: Stands in for a container created a day ago. The real anchor is
#: container.attrs["Created"], which never moves once the container exists.
ANCHOR = int(time.time()) - DAY

# A realistic single plant: one bundle plus a generated profile.
PLANTED = [
    "/home/devuser/.aws/credentials",
    "/home/devuser/.config/gh/hosts.yml",
    "/home/devuser/.my.cnf",
    "/home/devuser/.netrc",
    "/home/devuser/scratch/ps-audit.txt",
    "/home/devuser/Documents/api-endpoints.md",
    "/home/devuser/projects/erp-backend/.env.local",
    "/etc/cron.d/erp-report",
]


# --------------------------------------------------------------------------
# timestamps
# --------------------------------------------------------------------------


def test_files_planted_together_do_not_share_a_timestamp():
    """The cluster is the tell.

    A fixed `now - 3 days` stamped every file in a plant identically. Half a
    dozen files sharing an mtime to the second, among neighbours dated across
    months, is what `ls -lat` puts at the top of the listing.
    """
    stamps = [decoy_mtime(ANCHOR, "container-abc", p) for p in PLANTED]

    assert len(set(stamps)) == len(stamps), "planted files share timestamps"

    spread_days = (max(stamps) - min(stamps)) / DAY
    assert spread_days > 20, f"only {spread_days:.1f} days of spread; still reads as a batch"


def test_a_decoy_keeps_its_timestamp_across_replants():
    """A returning attacker must not see mtimes move.

    Keeping the attacker's container is the whole point — they come back and
    find things as they left them. A file whose mtime changed between two
    logins is a louder tell than one that merely looks recent.
    """
    path = "/home/devuser/.aws/credentials"
    first = decoy_mtime(ANCHOR, "container-abc", path)
    time.sleep(1.1)
    second = decoy_mtime(ANCHOR, "container-abc", path)

    # Anchored to container creation, not the clock. An earlier version
    # subtracted from now(), which kept the relative age fixed while the
    # absolute mtime crept forward — so a returning attacker would have found
    # every decoy's timestamp had moved along with them.
    assert first == second

    # And explicitly: two days of wall time must not move it either.
    assert decoy_mtime(ANCHOR, "container-abc", path) == first


def test_two_attackers_see_different_timestamps():
    """Separate environments should look like separate machines."""
    a = [decoy_mtime(ANCHOR, "container-aaa", p) for p in PLANTED]
    b = [decoy_mtime(ANCHOR, "container-bbb", p) for p in PLANTED]

    assert a != b
    assert not set(a) & set(b), "timestamps collided between environments"


def test_timestamps_are_plausibly_aged():
    for path in PLANTED:
        age_days = (ANCHOR - decoy_mtime(ANCHOR, "container-abc", path)) / DAY
        assert AGE_MIN <= age_days <= AGE_MAX, f"{path} aged {age_days:.1f}d"


def test_no_decoy_is_ever_in_the_future_or_freshly_written():
    """Never newer than the floor — that is the case that stands out most."""
    now = int(time.time())
    for i in range(300):
        stamp = decoy_mtime(ANCHOR, f"c{i}", f"/home/devuser/f{i}")
        assert stamp < now, "decoy dated in the future"
        assert ANCHOR - stamp >= AGE_MIN * DAY, "decoy looks freshly written"


# --------------------------------------------------------------------------
# ownership
# --------------------------------------------------------------------------


@pytest.mark.parametrize("directory,expected", [
    ("/home/devuser/.config/gh", ["/home/devuser/.config", "/home/devuser/.config/gh"]),
    ("/home/devuser/.aws", ["/home/devuser/.aws"]),
    ("/home/devuser/projects/erp-backend",
     ["/home/devuser/projects", "/home/devuser/projects/erp-backend"]),
    ("/home/devuser", []),          # exists in the image, already correct
    ("/etc/cron.d", []),            # root's, legitimately
    ("/srv/exports", []),
])
def test_every_created_parent_gets_chowned(directory, expected):
    """`mkdir -p` creates intermediates as root.

    Chowning only the leaf left `.config` root-owned in a user's home — the
    first line of `ls -la ~`. Flat bundles never exposed it; generated profiles
    have several levels.
    """
    assert owned_ancestors(directory, "devuser") == expected


def test_ancestors_refuses_a_mismatched_owner():
    assert owned_ancestors("/home/other/.ssh", "devuser") == []


@pytest.mark.parametrize("directory,expected", [
    ("/home/devuser/.aws", "devuser"),
    ("/home/ta_miller/.ssh", "ta_miller"),
    ("/etc/cron.d", "root"),
    ("/srv/exports", "root"),
])
def test_owner_is_derived_from_the_path(directory, expected):
    assert owner_for(directory) == expected


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
