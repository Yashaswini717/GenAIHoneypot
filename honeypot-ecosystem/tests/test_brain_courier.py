"""Decision-resolution tests for the brain courier.

The bandit only learns from decisions that get *resolved*. `/intent-classify`
resolves a session's previous decision each time it is called again for that
session, which means a decision scores only if the session survives to be
classified twice — four commands, at CLASSIFY_EVERY = 2. Anything shorter used
to leave its decision pending forever, and short sessions are the common case,
so the arms the bandit picked most often were the ones it learned least about.

These tests pin the two exits that now close that gap: a session that ends, and
a session that goes idle and is expired. Both must report an outcome, and the
outcome must distinguish "shown a decoy and left" from "kept working".

Run with:  pytest honeypot-ecosystem/tests/ -v
"""

from __future__ import annotations

import asyncio
from collections import Counter
import json
import sys
from pathlib import Path

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "shared" / "sidecar"))

from brain_courier import (  # noqa: E402
    ALL_TOKEN_VALUES,
    BUNDLE_TOKEN_SPEC,
    BUNDLE_TOKENS,
    CLASSIFY_WINDOW,
    DECOY_BUNDLES,
    BrainCourier,
    SessionState,
    _extract_tokens,
)


# --------------------------------------------------------------------------
# harness
# --------------------------------------------------------------------------


class Recorder:
    """Stands in for the brain and the broker, capturing what the courier sends."""

    def __init__(
        self,
        intent: str = "reconnaissance",
        action: str = "show_fake_endpoints",
        generated: dict | None = None,
    ):
        self.calls: list[tuple[str, dict]] = []
        self.intent = intent
        self.action = action
        #: What /decoys/generate answers. None means the brain cannot generate,
        #: which is the deployed default (no model key configured).
        self.generated = generated

    def handler(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else {}
        self.calls.append((request.url.path, body))

        if request.url.path.endswith("/intent-classify"):
            return httpx.Response(
                200,
                json={
                    "intent": self.intent,
                    "action": self.action,
                    "confidence": 0.63,
                    "source": "ml",
                    "decision_id": "dec-1",
                },
            )
        if request.url.path.endswith("/adaptive/feedback"):
            return httpx.Response(
                200,
                json={
                    "session_id": body.get("session_id"),
                    "signal": body.get("signal"),
                    "reward_applied": 0.0,
                    "decisions_resolved": 1,
                },
            )
        if request.url.path.endswith("/decoys/generate"):
            if self.generated is None:
                return httpx.Response(503, json={"detail": "no model key configured"})
            return httpx.Response(200, json=self.generated)
        if request.url.path == "/api/v1/honeytokens/":
            return httpx.Response(201, json={"token_id": "tok-1"})
        if request.url.path.endswith("/honeytokens/check"):
            return httpx.Response(200, json={"is_honeytoken": True, "message": "ALERT"})
        # /session/decoys on the broker
        return httpx.Response(200, json={"status": "ok", "planted": 1})

    def paths(self) -> list[str]:
        return [path for path, _ in self.calls]

    def feedback(self) -> list[dict]:
        return [body for path, body in self.calls if path.endswith("/adaptive/feedback")]

    def registrations(self) -> list[dict]:
        return [b for p, b in self.calls if p == "/api/v1/honeytokens/"]

    def checks(self) -> list[dict]:
        return [b for p, b in self.calls if p.endswith("/honeytokens/check")]

    def plants(self) -> list[dict]:
        return [b for p, b in self.calls if p.endswith("/session/decoys")]

    def classifies(self) -> list[dict]:
        return [b for p, b in self.calls if p.endswith("/intent-classify")]


def build_courier(recorder: Recorder) -> BrainCourier:
    courier = BrainCourier(
        brain_url="http://ai-brain:8000",
        broker_url="http://session-broker:8080",
    )
    courier.client = httpx.AsyncClient(transport=httpx.MockTransport(recorder.handler))
    return courier


def command(session: str, text: str) -> dict:
    return {
        "eventid": "cowrie.command.input",
        "session": session,
        "src_ip": "10.0.0.5",
        "sensor": "node-01-jump",
        "timestamp": "2026-09-09T03:14:00.000000Z",
        "input": text,
    }


def closed(session: str) -> dict:
    return {"eventid": "cowrie.session.closed", "session": session, "duration": 12.0}


def drive(courier: BrainCourier, events: list[dict]) -> None:
    """Feed events in order, letting background work settle between them.

    Generation runs alongside the queue rather than in it, so without a settle
    step an assertion can run before the task it is about to check has started.
    Draining between events also matches the thing being modelled: an attacker
    types one command at a time, with real seconds in between.
    """

    async def run() -> None:
        for event in events:
            await courier._handle(event)
            while courier._tasks:
                await asyncio.gather(*list(courier._tasks), return_exceptions=True)
        await courier.client.aclose()

    asyncio.run(run())


#: A plausible /decoys/generate answer: absolute paths, and a credential the
#: courier has never seen before because it was generated for this environment.
GENERATED = {
    "action": "populate_developer_workstation",
    "profile": "developer_workstation",
    "generated": True,
    "files": [
        {"path": "/home/devuser/.bashrc", "content": "export EDITOR=vim\n", "mode": 0o644},
        {
            "path": "/home/devuser/.aws/credentials",
            "content": "[default]\naws_access_key_id = AKIAZZ99TESTGEN0001\n",
            "mode": 0o600,
        },
    ],
    "tokens": [{"token_type": "aws_access_key", "token_value": "AKIAZZ99TESTGEN0001"}],
}


# --------------------------------------------------------------------------
# a session that ends
# --------------------------------------------------------------------------


def test_short_session_still_resolves_its_decision():
    """Two commands then a disconnect: the classic case that used to leak."""
    rec = Recorder()
    courier = build_courier(rec)

    drive(courier, [command("s1", "whoami"), command("s1", "uname -a"), closed("s1")])

    assert "/api/v1/intent-classify" in rec.paths(), "the session should have been classified"
    feedback = rec.feedback()
    assert len(feedback) == 1, f"expected exactly one resolution, got {rec.paths()}"
    assert feedback[0]["session_id"] == "s1"
    assert feedback[0]["signal"] == "session_terminated"
    assert courier.resolved == 1


def test_activity_after_the_decoy_scores_as_continued():
    """A command lands after the decoy, so the attacker did not simply bounce."""
    rec = Recorder()
    courier = build_courier(rec)

    drive(
        courier,
        [
            command("s2", "whoami"),
            command("s2", "uname -a"),   # classify fires here
            command("s2", "ls -la /home"),  # engaged afterwards
            closed("s2"),
        ],
    )

    feedback = rec.feedback()
    assert len(feedback) == 1
    assert feedback[0]["signal"] == "session_continued"


def test_unclassified_session_sends_no_feedback():
    """One command never reaches the bandit, so there is nothing to resolve."""
    rec = Recorder()
    courier = build_courier(rec)

    drive(courier, [command("s3", "whoami"), closed("s3")])

    assert rec.feedback() == []
    assert "/api/v1/intent-classify" not in rec.paths()
    assert courier.resolved == 0


def test_close_without_any_session_state_is_harmless():
    """A close for a session the courier never saw must not raise."""
    rec = Recorder()
    courier = build_courier(rec)

    drive(courier, [closed("never-seen")])

    assert rec.feedback() == []


def test_brain_unreachable_on_close_does_not_raise():
    """The hub branch has already shipped the event; a failure here is survivable."""

    def explode(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/adaptive/feedback"):
            raise httpx.ConnectError("brain is down")
        return httpx.Response(
            200,
            json={"intent": "reconnaissance", "action": "show_fake_endpoints",
                  "confidence": 0.5, "source": "ml", "decision_id": "dec-1"},
        )

    courier = BrainCourier(brain_url="http://ai-brain:8000", broker_url="http://b:8080")
    courier.client = httpx.AsyncClient(transport=httpx.MockTransport(explode))

    drive(courier, [command("s4", "whoami"), command("s4", "id"), closed("s4")])

    assert courier.resolved == 0  # nothing counted, but no exception escaped


# --------------------------------------------------------------------------
# a session that goes idle
# --------------------------------------------------------------------------


def test_expired_session_is_resolved_not_dropped():
    """An idle session never emits session.closed, so expiry must score it too."""
    rec = Recorder()
    courier = build_courier(rec)

    state = SessionState(session_id="s5", src_ip="10.0.0.9", sensor="node-01-jump")
    state.pending_decision = "dec-1"
    state.last_seen = 0.0  # far past the TTL
    courier.sessions["s5"] = state

    expired = courier._expire_sessions()

    assert [s.session_id for s in expired] == ["s5"], "expiry must hand the state back"
    assert "s5" not in courier.sessions, "and still drop it from the table"

    async def run() -> None:
        for s in expired:
            await courier._resolve_on_close(s, reason="idle")
        await courier.client.aclose()

    asyncio.run(run())

    feedback = rec.feedback()
    assert len(feedback) == 1
    assert feedback[0]["session_id"] == "s5"


def test_expiry_leaves_live_sessions_alone():
    rec = Recorder()
    courier = build_courier(rec)

    live = SessionState(session_id="s6", src_ip="10.0.0.9", sensor="node-01-jump")
    courier.sessions["s6"] = live

    assert courier._expire_sessions() == []
    assert "s6" in courier.sessions

    asyncio.run(courier.client.aclose())


# --------------------------------------------------------------------------
# the tripwire
# --------------------------------------------------------------------------


def test_tripwire_values_are_not_duplicated_in_source():
    """The values live in the bundles and nowhere else.

    They used to be copied into a parallel table, which meant the same secret
    appeared twice in the file and the two copies could drift apart. It also
    doubled what a secret scanner finds — and GitHub push protection does block
    this repository, because convincing fake credentials are the product.
    """
    source = (Path(__file__).resolve().parents[1]
              / "shared" / "sidecar" / "brain_courier.py").read_text()

    # Everything from TOKEN_PATTERNS onward is locators and extraction logic.
    # A credential appearing in that region means someone has gone back to
    # declaring values by hand alongside the bundles that already contain them.
    #
    # Counting occurrences file-wide would be the wrong test: one password
    # legitimately appears in two different bundles — which is precisely why
    # registration has to be idempotent — and several appear in prose
    # explaining the mechanism.
    marker = "TOKEN_PATTERNS: dict[str, re.Pattern[str]]"
    assert marker in source, "locator table not found; did it get renamed?"
    locator_region = source[source.index(marker):]

    for token_type, value in ALL_TOKEN_VALUES:
        assert value not in locator_region, (
            f"{token_type} value is written out in the locator region of "
            "brain_courier.py; it should be extracted from its bundle, not copied"
        )


def test_every_bundle_yields_the_credentials_it_is_meant_to():
    """Extraction must find what each bundle promises.

    A locator that stops matching leaves that credential with no tripwire
    behind it, and nothing would raise — the decoy still plants perfectly, it
    just stops being watched.
    """
    for action, expected in BUNDLE_TOKEN_SPEC.items():
        got = Counter(t for t, _ in BUNDLE_TOKENS[action])
        for token_type, count in expected.items():
            assert got[token_type] == count, (
                f"{action}: expected {count} {token_type}, extracted {got[token_type]}"
            )


def test_a_reworded_decoy_fails_loudly_at_import():
    """Drift must break the build, not the tripwire."""
    original = DECOY_BUNDLES["populate_production_server"]
    DECOY_BUNDLES["populate_production_server"] = [
        (p, c.replace("VAULT_TOKEN=hvs.", "VAULT=xx."), m) for p, c, m in original
    ]
    try:
        with pytest.raises(AssertionError, match="vault_token"):
            _extract_tokens()
    finally:
        DECOY_BUNDLES["populate_production_server"] = original


def test_extracted_values_are_long_enough_to_match_safely():
    for token_type, value in ALL_TOKEN_VALUES:
        assert len(value) >= 10, f"{token_type} is {len(value)} chars; too short"


def test_using_a_planted_credential_trips_and_scores_it():
    """The README's own demo command — the credential appears in plain text."""
    rec = Recorder()
    courier = build_courier(rec)

    drive(
        courier,
        [
            command("t1", "whoami"),
            command("t1", "cat /home/devuser/.my.cnf"),   # classify fires
            command("t1", 'mysql -h db-01 -u erp_admin -pTr3llis!84m -e "select 1"'),
        ],
    )

    assert courier.tripped == 1, "the credential should have tripped exactly one token"
    assert any(r["token_value"] == "Tr3llis!84m" for r in rec.registrations())
    assert any(c["token_value"] == "Tr3llis!84m" for c in rec.checks())

    scored = [f for f in rec.feedback() if f["signal"] == "honeytoken_triggered"]
    assert len(scored) == 1, f"expected one 1.0 resolution, saw {rec.feedback()}"
    assert scored[0]["session_id"] == "t1"


def test_reading_the_decoy_file_is_not_a_trip():
    """Finding the bait is not the same as believing it."""
    rec = Recorder()
    courier = build_courier(rec)

    drive(
        courier,
        [
            command("t2", "ls -la /home/devuser/.aws"),
            command("t2", "cat /home/devuser/.aws/credentials"),
            closed("t2"),
        ],
    )

    assert courier.tripped == 0
    assert rec.checks() == []
    assert all(f["signal"] != "honeytoken_triggered" for f in rec.feedback())


def test_the_same_credential_is_reported_once_per_session():
    """Running the same command five times tells us one thing, not five."""
    rec = Recorder()
    courier = build_courier(rec)

    use = 'mysql -u erp_admin -pTr3llis!84m -e "select 1"'
    drive(courier, [command("t3", "whoami"), command("t3", use), command("t3", use), command("t3", use)])

    assert courier.tripped == 1
    assert len(rec.checks()) == 1


def test_ordinary_commands_never_trip():
    """Every declared value must be distinctive enough to avoid false positives."""
    rec = Recorder()
    courier = build_courier(rec)

    benign = [
        "ls -la /var/log", "ps aux | head", "cat /etc/passwd", "uname -a",
        "netstat -tulpn", "find / -name '*.conf' 2>/dev/null", "sudo su -",
        "grep -r password /etc", "curl http://erp-web:8080/api/results",
    ]
    drive(courier, [command("t4", c) for c in benign])

    assert courier.tripped == 0, "a benign command matched a decoy value"


def test_tripwire_survives_the_brain_being_down():
    def explode(request: httpx.Request) -> httpx.Response:
        if "honeytoken" in request.url.path or "feedback" in request.url.path:
            raise httpx.ConnectError("brain is down")
        return httpx.Response(
            200,
            json={"intent": "data_exfiltration", "action": "populate_database_server",
                  "confidence": 0.8, "source": "ml", "decision_id": "dec-9"},
        )

    courier = BrainCourier(brain_url="http://ai-brain:8000", broker_url="http://b:8080")
    courier.client = httpx.AsyncClient(transport=httpx.MockTransport(explode))

    drive(
        courier,
        [
            command("t5", "whoami"),
            command("t5", "id"),
            command("t5", "mysql -pTr3llis!84m"),
        ],
    )

    assert courier.tripped == 1      # detection is local and still happened
    assert courier.resolved == 0     # but nothing was scored, and nothing raised


def test_honeypot_id_is_per_attacker_not_per_node():
    """Two attackers on one sensor must not share honeytoken attribution."""
    a = SessionState(session_id="x", src_ip="10.60.0.5", sensor="node-01-jump")
    b = SessionState(session_id="y", src_ip="10.60.0.9", sensor="node-01-jump")

    assert a.honeypot_id != b.honeypot_id
    assert a.src_ip in a.honeypot_id
    assert ":" not in SessionState(
        session_id="z", src_ip="fe80::1", sensor="node-01-jump"
    ).honeypot_id, "must stay usable as a directory name"


def test_planting_registers_that_bundle_up_front():
    rec = Recorder(intent="privilege_escalation", action="plant_honeytoken_credentials")
    courier = build_courier(rec)

    drive(courier, [command("t6", "sudo -l"), command("t6", "cat /etc/sudoers")])

    registered = {r["token_value"] for r in rec.registrations()}
    expected = {v for _, v in BUNDLE_TOKENS["plant_honeytoken_credentials"]}
    assert expected <= registered, f"missing {expected - registered}"
    assert all(r["honeypot_id"].endswith("10.0.0.5") for r in rec.registrations())


# --------------------------------------------------------------------------
# what the classifier is actually shown
# --------------------------------------------------------------------------


def test_classification_sees_a_sliding_window_not_the_whole_session():
    """The window has to slide, or intent can never leave reconnaissance.

    Sending the accumulated history meant the opening recon commands outvoted
    everything that followed for the rest of the session. Every classification
    this system ever made was `reconnaissance`, which also silenced the
    bandit's progression reward, since that is defined as intent moving.
    """
    rec = Recorder()
    courier = build_courier(rec)

    # Driven directly rather than through _handle: MIN_CLASSIFY_INTERVAL rate
    # limits back-to-back commands, so a scripted session only classifies once
    # and would not show the window moving.
    seq = [f"cmd-{i}" for i in range(1, 13)]
    state = SessionState(session_id="w1", src_ip="10.0.0.5", sensor="node-01-jump")

    async def run() -> None:
        for c in seq:
            state.commands.append(c)
            state.timestamps.append("2026-09-09T03:14:00.000000Z")
            await courier._classify(state)
        await courier.client.aclose()

    asyncio.run(run())

    sent = rec.classifies()
    assert len(sent) == len(seq), "every step should have been classified"

    for payload in sent:
        assert len(payload["commands"]) <= CLASSIFY_WINDOW, (
            f"sent {len(payload['commands'])} commands; the window is {CLASSIFY_WINDOW}"
        )

    # It must be the RECENT commands. A window pinned to the start of the
    # session would bound the payload while changing nothing about the bug.
    for i, payload in enumerate(sent, start=1):
        expected = seq[max(0, i - CLASSIFY_WINDOW):i]
        assert payload["commands"] == expected, (
            f"after {i} commands expected {expected}, got {payload['commands']}"
        )


def test_the_window_is_narrow_enough_to_track_a_changing_attacker():
    """Guards the constant itself.

    Measured against a labelled attack, correct classifications by window size
    were 2->11/13, 3->9/13, 5->7/13, 8->4/13, 40->4/13. Widening this silently
    undoes the fix without breaking anything else.
    """
    assert 2 <= CLASSIFY_WINDOW <= 4, (
        f"CLASSIFY_WINDOW={CLASSIFY_WINDOW} is too wide to follow an attacker "
        "through the kill chain"
    )


def test_timestamps_use_the_same_window_as_commands():
    """Mismatched windows would hand the classifier misaligned features."""
    rec = Recorder()
    courier = build_courier(rec)

    drive(courier, [command("w2", f"cmd-{i}") for i in range(1, 9)])

    for payload in rec.classifies():
        assert len(payload["event_timestamps"]) <= CLASSIFY_WINDOW


# --------------------------------------------------------------------------
# generated content actually reaching the attacker
# --------------------------------------------------------------------------


def test_generated_content_is_planted_through_the_broker():
    """The half that used to be written where nothing could read it."""
    rec = Recorder(action="populate_developer_workstation", generated=GENERATED)
    courier = build_courier(rec)

    drive(courier, [command("g1", "whoami"), command("g1", "ls -la ~")])

    plants = rec.plants()
    assert len(plants) == 2, "the bundle, then the generated profile"

    generated_plant = [p for p in plants if p["action"].endswith(":generated")]
    assert len(generated_plant) == 1
    paths = [f["path"] for f in generated_plant[0]["files"]]
    assert paths == ["/home/devuser/.bashrc", "/home/devuser/.aws/credentials"]
    assert all(p.startswith("/") for p in paths), "the broker needs absolute paths"


def test_the_bundle_is_planted_first_and_does_not_wait_on_generation():
    """Generation is minutes of model calls; the attacker must see something now."""
    rec = Recorder(action="populate_developer_workstation", generated=GENERATED)
    courier = build_courier(rec)

    drive(courier, [command("g2", "whoami"), command("g2", "ls -la ~")])

    ordered = [p["action"] for p in rec.plants()]
    assert ordered[0] == "populate_developer_workstation"
    assert ordered[1].endswith(":generated")


def test_generated_credentials_join_the_tripwire():
    """A generated secret nothing scans for is a decoy with no tripwire."""
    rec = Recorder(action="populate_developer_workstation", generated=GENERATED)
    courier = build_courier(rec)

    # The value is not in ALL_TOKEN_VALUES — it only exists for this session.
    assert all(v != "AKIAZZ99TESTGEN0001" for _, v in ALL_TOKEN_VALUES)

    drive(
        courier,
        [
            command("g3", "whoami"),
            command("g3", "ls -la ~"),   # classify -> plant -> generate
            command("g3", "aws sts get-caller-identity --profile AKIAZZ99TESTGEN0001"),
        ],
    )

    assert courier.tripped == 1
    assert any(c["token_value"] == "AKIAZZ99TESTGEN0001" for c in rec.checks())


def test_no_model_key_leaves_the_bundle_standing_alone():
    """503 from the brain is the deployed default, not an error path."""
    rec = Recorder(action="populate_developer_workstation", generated=None)
    courier = build_courier(rec)

    drive(courier, [command("g4", "whoami"), command("g4", "ls -la ~")])

    plants = rec.plants()
    assert len(plants) == 1
    assert plants[0]["action"] == "populate_developer_workstation"
    assert not any(p["action"].endswith(":generated") for p in plants)


def test_generation_failure_never_disturbs_the_bundle():
    def half_broken(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/decoys/generate"):
            raise httpx.ConnectError("brain went away mid-generation")
        if request.url.path.endswith("/intent-classify"):
            return httpx.Response(
                200,
                json={"intent": "reconnaissance", "action": "populate_developer_workstation",
                      "confidence": 0.6, "source": "ml", "decision_id": "dec-2"},
            )
        return httpx.Response(200, json={"status": "ok", "planted": 2})

    courier = BrainCourier(brain_url="http://ai-brain:8000", broker_url="http://b:8080")
    courier.client = httpx.AsyncClient(transport=httpx.MockTransport(half_broken))

    drive(courier, [command("g5", "whoami"), command("g5", "ls -la ~")])

    assert courier.deployed == 1, "the bundle still went in"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
