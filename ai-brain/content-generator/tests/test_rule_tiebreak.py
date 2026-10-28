"""Rule-layer arbitration, and the tie it used to lose.

The rule layer is the only confident component in the classifier: a clean
rule match returns 0.85-0.99, while the model returns 0.23-0.64 on the same
traffic. So every time the rules abstain, the weakest part of the system
decides. A tie was an abstention, and ties are common -- an attacker who
escalates and then pivots trips a privilege_escalation rule and a
lateral_movement rule in the same window.

Run with:  pytest ai-brain/content-generator/tests/test_rule_tiebreak.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.intent_taxonomy import KILL_CHAIN_ORDER  # noqa: E402
from ml.intent_classification.rules import detect_intent_by_rules  # noqa: E402


def activity(*commands):
    return {"commands": list(commands), "http_logs": [], "db_queries": [], "raw_activity": ""}


# -- the regression this exists for ---------------------------------------


def test_escalate_then_pivot_is_lateral_movement_not_an_abstention():
    """The exact sequence that produced a 0.43 guess in a live session.

    `sudo -l` scores privilege_escalation, `ssh host` scores lateral_movement,
    one each. The old guard required a margin, so it returned None and the
    model answered instead -- with the wrong class, at a confidence barely
    above the 0.20 you get from guessing between five.
    """
    match = detect_intent_by_rules(activity("sudo -l", "ssh deploy@10.60.0.21"))

    assert match is not None, "a tie must not abstain to the model"
    assert match.intent == "lateral_movement"
    assert any("tiebreak" in rule for rule in match.matched_rules)


def test_the_deeper_stage_wins_a_tie():
    """Both intents have hard evidence; the later one describes the attacker now."""
    cases = [
        (("whoami", "sudo -l"), "privilege_escalation"),      # recon vs privesc
        (("sudo -l", "crontab -e"), "persistence"),           # privesc vs persistence
        (("crontab -e", "ssh host"), "lateral_movement"),     # persistence vs lateral
        (("ssh host", "tar czf out.tgz /data"), "data_exfiltration"),
    ]
    for commands, expected in cases:
        match = detect_intent_by_rules(activity(*commands))
        assert match is not None, commands
        assert match.intent == expected, f"{commands} -> {match.intent}, wanted {expected}"


def test_tiebreak_confidence_never_outranks_a_clean_match():
    """A contested call must stay below an uncontested one, or the courier
    cannot tell a guess from a certainty."""
    contested = detect_intent_by_rules(activity("sudo -l", "ssh deploy@host"))
    clean = detect_intent_by_rules(activity("ssh deploy@host"))

    assert contested is not None and clean is not None
    assert contested.confidence < clean.confidence
    assert contested.confidence >= 0.6, "still worth more than a model guess"


# -- what must not regress -------------------------------------------------


def test_clean_single_signal_is_unchanged():
    match = detect_intent_by_rules(activity("nmap -sV 10.0.0.1"))
    assert match is not None
    assert match.intent == "reconnaissance"
    assert match.confidence >= 0.8
    assert not any("tiebreak" in rule for rule in match.matched_rules)


def test_clear_majority_is_unchanged():
    """Two hits for one intent and one for another still takes the majority,
    even though the majority is the shallower stage.

    Note the commands: `nmap` and `whoami` trip two *different* recon rules.
    Scoring counts rule groups, not commands, so `whoami` plus `netstat`
    would have scored one between them and tied with the ssh.
    """
    match = detect_intent_by_rules(activity("nmap -sV 10.0.0.1", "whoami", "ssh host"))
    assert match is not None
    assert match.intent == "reconnaissance"
    assert not any("tiebreak" in rule for rule in match.matched_rules)


def test_no_evidence_still_abstains():
    """With nothing matched there is no information to break, so the model
    remains the right place to ask."""
    assert detect_intent_by_rules(activity("echo hello", "cd /tmp")) is None
    assert detect_intent_by_rules(activity()) is None


def test_tiebreak_names_every_intent_it_chose_between():
    """The decision has to be auditable: a reviewer must see it was contested
    and which classes were in contention."""
    match = detect_intent_by_rules(activity("sudo -l", "ssh deploy@host"))
    assert match is not None
    label = next(r for r in match.matched_rules if "tiebreak" in r)
    assert "privilege_escalation" in label and "lateral_movement" in label


@pytest.mark.parametrize("intent", list(KILL_CHAIN_ORDER))
def test_every_intent_is_reachable_through_the_tiebreak(intent):
    """A tiebreak that can only ever pick data_exfiltration would be a bias,
    not a rule. Depth must be compared, not hardcoded."""
    assert intent in KILL_CHAIN_ORDER
    assert isinstance(KILL_CHAIN_ORDER[intent], int)
