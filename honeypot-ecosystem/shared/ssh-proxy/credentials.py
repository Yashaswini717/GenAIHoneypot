"""Which logins succeed, and how failures feel.

Two things here are honeypot tells if you get them wrong.

**What is accepted.** Cowrie's default — accept the Nth guess whatever it is —
is among the most recognisable honeypot behaviours in existence. An attacker
who watches a wrong password work on the fourth try leaves immediately. So we
accept a small fixed set and reject everything else, forever, exactly like a
real host.

The set is deliberately weak, because weak credentials are the single most
common cause of real SSH compromise. `test/test123` and `ubuntu/ubuntu` on a
university box that has had many hands on it over several years is not a
contrivance, it is the ordinary state of the world. It also means ordinary
brute-force bots hit us, which is the point: we want sessions, not just a
graph of failed logins.

**How rejection feels.** An instant reject is a tell, and so is a reject whose
timing differs between real and nonexistent users — that leaks user
enumeration, and real OpenSSH deliberately does not leak it (it runs a dummy
password hash for unknown users so the timing matches). We mirror that: every
failure costs roughly the same, whoever it was for.

Tune the credential set without touching code by mounting a YAML file and
pointing HONEYPOT_CREDENTIALS_PATH at it.
"""

from __future__ import annotations

import asyncio
import logging
import os
import random
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

#: Shipped default. Every entry appears in commodity brute-force wordlists,
#: which is what converts scanning traffic into real sessions.
#:
#: `devuser` is the account whose home carries the decoy chain, so it is given
#: the least guessable password of the set — an attacker who lands as `test`
#: still reaches it, because /home/devuser is readable like any normal home.
DEFAULT_CREDENTIALS: dict[str, str] = {
    "test": "test123",
    "ubuntu": "ubuntu",
    "git": "git",
    "student": "student123",
    "devuser": "dev@123",
}

#: Failure cost, in seconds. Drawn per attempt so the timing is not itself a
#: constant to fingerprint, but drawn from the same distribution regardless of
#: whether the username exists.
_FAIL_DELAY_RANGE = (0.12, 0.26)

#: Successful auth is quicker than a failure on a real host — no retry loop,
#: no dummy hash — but not instant.
_SUCCESS_DELAY_RANGE = (0.04, 0.09)


@dataclass(frozen=True)
class AuthOutcome:
    accepted: bool
    username: str
    password: str


class CredentialStore:
    """The fixed set of accepted logins, plus realistic auth latency."""

    def __init__(self, credentials: dict[str, str] | None = None) -> None:
        self._credentials = dict(credentials or DEFAULT_CREDENTIALS)
        log.info(
            "credential store loaded: %d accounts (%s)",
            len(self._credentials),
            ", ".join(sorted(self._credentials)),
        )

    @classmethod
    def from_env(cls) -> "CredentialStore":
        """Load from HONEYPOT_CREDENTIALS_PATH, falling back to the defaults.

        The file is `username: password` YAML. A malformed or missing file
        falls back rather than failing closed — a honeypot that refuses every
        login because of a config typo is a honeypot that collects nothing.
        """
        path_raw = os.environ.get("HONEYPOT_CREDENTIALS_PATH", "").strip()
        if not path_raw:
            return cls()

        path = Path(path_raw)
        if not path.is_file():
            log.warning("credential file %s not found, using defaults", path)
            return cls()

        try:
            import yaml  # imported lazily so the default path needs no dependency

            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(loaded, dict) or not loaded:
                raise ValueError("expected a non-empty username: password mapping")
            return cls({str(u): str(p) for u, p in loaded.items()})
        except Exception:
            log.warning("could not parse %s, using defaults", path, exc_info=True)
            return cls()

    # -- queries -----------------------------------------------------------

    @property
    def usernames(self) -> list[str]:
        return sorted(self._credentials)

    def knows_user(self, username: str) -> bool:
        return username in self._credentials

    async def authenticate(self, username: str, password: str) -> AuthOutcome:
        """Check a password attempt, paying realistic latency either way."""
        expected = self._credentials.get(username)
        accepted = expected is not None and _constant_time_eq(expected, password)

        if accepted:
            await asyncio.sleep(random.uniform(*_SUCCESS_DELAY_RANGE))
        else:
            # Same cost whether or not the user exists — no enumeration oracle.
            await asyncio.sleep(random.uniform(*_FAIL_DELAY_RANGE))

        return AuthOutcome(accepted=accepted, username=username, password=password)


def _constant_time_eq(a: str, b: str) -> bool:
    """Compare without leaking length or content through timing.

    Overkill against a brute-force bot, but the proxy is internet-facing and
    the habit is cheap.
    """
    import hmac

    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
