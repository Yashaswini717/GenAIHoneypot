"""Tests for the adaptive (contextual bandit) decision engine.

Covers the bandit store in isolation (storage/adaptive_store.py), the
reward calculator (core/reward.py), and the end-to-end engine
(core/adaptive_engine.py) that ties intent -> action -> feedback together.
"""

from __future__ import annotations

import random

import pytest

from core.adaptive_actions import ACTION_CATALOG, get_candidate_actions
from core.adaptive_engine import AdaptiveDecisionEngine
from core.intent_taxonomy import INTENT_CLASSES
from core.reward import (
    REWARD_HONEYTOKEN_TRIGGERED,
    REWARD_SESSION_CONTINUED,
    RewardCalculator,
    progression_reward,
)
from storage.adaptive_store import AdaptiveLearningStore


@pytest.fixture
def adaptive_store(test_database_url):
    store = AdaptiveLearningStore(database_url=test_database_url)
    yield store
    store.close()


@pytest.fixture
def adaptive_engine(adaptive_store):
    return AdaptiveDecisionEngine(store=adaptive_store, reward_calculator=RewardCalculator())


class TestActionCatalog:
    def test_every_intent_has_multiple_candidate_actions(self):
        # A bandit needs >1 option per state or there's nothing to learn.
        for intent in INTENT_CLASSES:
            candidates = get_candidate_actions(intent)
            assert len(candidates) >= 2
            assert len(candidates) == len(set(candidates)), "candidates must be unique"

    def test_catalog_covers_every_intent_class(self):
        assert set(ACTION_CATALOG) == set(INTENT_CLASSES)


class TestProgressionReward:
    def test_escalation_beats_continuation_beats_deescalation(self):
        escalate = progression_reward("reconnaissance", "privilege_escalation")
        continue_ = progression_reward("reconnaissance", "reconnaissance")
        deescalate = progression_reward("data_exfiltration", "reconnaissance")

        assert escalate.reward > continue_.reward > deescalate.reward
        assert escalate.reason == "intent_escalated"
        assert continue_.reason == "session_continued"
        assert deescalate.reason == "intent_deescalated"


class TestRewardCalculator:
    def test_falls_back_to_progression_without_honeytoken_store(self):
        calc = RewardCalculator(honeytoken_store=None)
        breakdown = calc.compute(
            previous_intent="reconnaissance",
            new_intent="privilege_escalation",
            honeypot_id="hp-1",
        )
        assert breakdown.reason == "intent_escalated"

    def test_no_honeypot_id_also_falls_back_to_progression(self):
        calc = RewardCalculator(honeytoken_store=None)
        breakdown = calc.compute(previous_intent="reconnaissance", new_intent="reconnaissance", honeypot_id=None)
        assert breakdown.reward == REWARD_SESSION_CONTINUED


class TestAdaptiveLearningStore:
    def test_select_action_creates_arms_with_uniform_prior(self, adaptive_store):
        action, stats, decision_id = adaptive_store.select_action(
            intent="reconnaissance",
            candidate_actions=["show_fake_endpoints", "populate_developer_workstation"],
        )
        assert action in {"show_fake_endpoints", "populate_developer_workstation"}
        assert stats.times_selected == 1
        assert decision_id is None  # no session_id -> nothing persisted to resolve later

    def test_select_action_with_session_id_persists_pending_decision(self, adaptive_store):
        action, _stats, decision_id = adaptive_store.select_action(
            intent="reconnaissance",
            candidate_actions=["show_fake_endpoints", "populate_developer_workstation"],
            session_id="session-abc",
            honeypot_id="hp-1",
        )
        assert decision_id is not None

        pending = adaptive_store.get_pending_decision("session-abc")
        assert pending is not None
        assert pending.decision_id == decision_id
        assert pending.action == action
        assert pending.resolved is False

    def test_resolve_decision_updates_posterior_and_clears_pending(self, adaptive_store):
        _action, _stats, decision_id = adaptive_store.select_action(
            intent="reconnaissance",
            candidate_actions=["show_fake_endpoints"],
            session_id="session-xyz",
        )

        updated = adaptive_store.resolve_decision(decision_id, reward=1.0, reason="honeytoken_triggered")
        assert updated is not None
        # Started at Beta(1,1); a full reward of 1.0 should push alpha up by 1.
        assert updated.alpha == pytest.approx(2.0)
        assert updated.beta == pytest.approx(1.0)
        assert updated.posterior_mean > 0.5

        assert adaptive_store.get_pending_decision("session-xyz") is None

    def test_resolve_decision_is_idempotent(self, adaptive_store):
        _action, _stats, decision_id = adaptive_store.select_action(
            intent="reconnaissance",
            candidate_actions=["show_fake_endpoints"],
            session_id="session-once",
        )
        first = adaptive_store.resolve_decision(decision_id, reward=1.0)
        second = adaptive_store.resolve_decision(decision_id, reward=1.0)
        assert first is not None
        assert second is None  # already resolved, can't double-count reward

    def test_reset_all_clears_arms(self, adaptive_store):
        adaptive_store.select_action(intent="reconnaissance", candidate_actions=["show_fake_endpoints"])
        assert len(adaptive_store.get_arm_stats()) == 1
        adaptive_store.reset_all()
        assert len(adaptive_store.get_arm_stats()) == 0


class TestAdaptiveDecisionEngine:
    def test_decide_rejects_unknown_intent(self, adaptive_engine):
        with pytest.raises(ValueError):
            adaptive_engine.decide(intent="not_a_real_intent")

    def test_decide_returns_action_from_intent_catalog(self, adaptive_engine):
        suggestion = adaptive_engine.decide(intent="data_exfiltration")
        assert suggestion.action in get_candidate_actions("data_exfiltration")
        assert suggestion.intent == "data_exfiltration"

    def test_next_call_for_same_session_resolves_previous_decision(self, adaptive_engine):
        first = adaptive_engine.decide(intent="reconnaissance", session_id="s1")
        assert first.decision_id is not None

        # Attacker escalated -> the previous decision should resolve with a
        # positive reward, bumping that arm's posterior above baseline.
        adaptive_engine.decide(intent="privilege_escalation", session_id="s1")

        stats = {s.action: s for s in adaptive_engine.get_stats(intent="reconnaissance")}
        assert stats[first.action].posterior_mean > 0.5

    def test_resolve_feedback_resolves_pending_decision_directly(self, adaptive_engine):
        suggestion = adaptive_engine.decide(intent="data_exfiltration", session_id="s2")
        assert suggestion.decision_id is not None

        resolved_count = adaptive_engine.resolve_feedback("s2", reward=REWARD_HONEYTOKEN_TRIGGERED)
        assert resolved_count == 1

        stats = {s.action: s for s in adaptive_engine.get_stats(intent="data_exfiltration")}
        assert stats[suggestion.action].posterior_mean > 0.5

    def test_bandit_converges_toward_the_better_action(self, adaptive_engine):
        """
        Simulate many sessions where 'good_action' always gets rewarded and
        'bad_action' never does. Thompson Sampling should visibly shift
        preference toward 'good_action' well before the run ends — this is
        the actual "learns from the attacker" behaviour the static
        DecisionEngine could never exhibit.
        """
        random.seed(1234)
        intent = "reconnaissance"
        good_action, bad_action = "good_action", "bad_action"

        # Monkeypatch the candidate set for this intent to a controlled pair.
        import core.adaptive_actions as actions_module

        original_catalog = actions_module.ACTION_CATALOG[intent]
        actions_module.ACTION_CATALOG[intent] = [good_action, bad_action]
        try:
            good_picks_early = 0
            good_picks_late = 0
            n_rounds = 200

            for i in range(n_rounds):
                session_id = f"sim-{i}"
                suggestion = adaptive_engine.decide(intent=intent, session_id=session_id)
                reward = 1.0 if suggestion.action == good_action else 0.0
                adaptive_engine.resolve_feedback(session_id, reward=reward)

                if suggestion.action == good_action:
                    if i < n_rounds // 4:
                        good_picks_early += 1
                    elif i >= 3 * n_rounds // 4:
                        good_picks_late += 1

            # The bandit should pick the good action noticeably more often
            # in the final quarter of rounds than in the first quarter.
            assert good_picks_late > good_picks_early
            stats = {s.action: s for s in adaptive_engine.get_stats(intent=intent)}
            assert stats[good_action].posterior_mean > stats[bad_action].posterior_mean
        finally:
            actions_module.ACTION_CATALOG[intent] = original_catalog
