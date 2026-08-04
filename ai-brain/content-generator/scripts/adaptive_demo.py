"""
Standalone demo: watch the adaptive bandit learn.

No server, no LLM API key, no honeypot required — this simulates attacker
sessions directly against `AdaptiveDecisionEngine` with a throwaway SQLite
database, so it's safe to run repeatedly (e.g. live during a project review)
without touching `data/honeypot.db`.

For each intent, one candidate action is secretly designated the "true best"
decoy strategy with a higher simulated success probability than its
siblings; the rest share a lower one. The script then runs many simulated
sessions per intent and, every `--report-every` rounds, prints each arm's
current posterior mean — you should see the true-best action's mean pull
ahead of the others as evidence accumulates. That's the actual "adaptive
learning" the old static `DecisionEngine` could never demonstrate: identical
input (the same intent) now increasingly favours a specific action because
of what happened in previous sessions.

Usage:
    python scripts/adaptive_demo.py
    python scripts/adaptive_demo.py --rounds 300 --report-every 25 --seed 7
"""

from __future__ import annotations

import argparse
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.adaptive_actions import ACTION_CATALOG  # noqa: E402
from core.adaptive_engine import AdaptiveDecisionEngine  # noqa: E402
from core.reward import RewardCalculator  # noqa: E402
from storage.adaptive_store import AdaptiveLearningStore  # noqa: E402

TRUE_BEST_SUCCESS_RATE = 0.75
OTHER_SUCCESS_RATE = 0.30


def pick_ground_truth() -> dict[str, str]:
    """Secretly designate one 'true best' decoy action per intent."""
    return {intent: random.choice(actions) for intent, actions in ACTION_CATALOG.items()}


def simulate_reward(intent: str, action: str, ground_truth: dict[str, str]) -> float:
    """Stochastic reward: the true-best action wins more often, but not always."""
    success_rate = TRUE_BEST_SUCCESS_RATE if action == ground_truth[intent] else OTHER_SUCCESS_RATE
    return 1.0 if random.random() < success_rate else 0.0


def print_report(engine: AdaptiveDecisionEngine, ground_truth: dict[str, str], round_number: int) -> None:
    print(f"\n--- after {round_number} simulated sessions ---")
    for intent in ACTION_CATALOG:
        stats = {s.action: s for s in engine.get_stats(intent=intent)}
        print(f"  {intent}  (true best: {ground_truth[intent]})")
        for action in ACTION_CATALOG[intent]:
            s = stats.get(action)
            marker = "*" if action == ground_truth[intent] else " "
            if s is None:
                print(f"    {marker} {action:<32} not yet tried")
                continue
            print(
                f"    {marker} {action:<32} mean={s.posterior_mean:0.2f}  "
                f"(alpha={s.alpha:0.1f}, beta={s.beta:0.1f}, n={s.times_selected})"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rounds", type=int, default=200, help="simulated sessions per intent")
    parser.add_argument("--report-every", type=int, default=40, help="print a progress snapshot every N rounds")
    parser.add_argument("--seed", type=int, default=42, help="random seed for reproducibility")
    args = parser.parse_args()

    random.seed(args.seed)
    ground_truth = pick_ground_truth()

    with tempfile.TemporaryDirectory() as tmp_dir:
        db_url = f"sqlite:///{Path(tmp_dir) / 'adaptive_demo.db'}"
        store = AdaptiveLearningStore(database_url=db_url)
        engine = AdaptiveDecisionEngine(store=store, reward_calculator=RewardCalculator())

        print("True best action per intent (hidden from the bandit):")
        for intent, action in ground_truth.items():
            print(f"  {intent}: {action}")

        intents = list(ACTION_CATALOG)
        for round_number in range(1, args.rounds + 1):
            intent = random.choice(intents)
            session_id = f"demo-{round_number}"
            suggestion = engine.decide(intent=intent, session_id=session_id)
            reward = simulate_reward(intent, suggestion.action, ground_truth)
            engine.resolve_feedback(session_id, reward=reward)

            if round_number % args.report_every == 0 or round_number == args.rounds:
                print_report(engine, ground_truth, round_number)

        print("\nDone. The '*' action in each block is the hidden ground truth - its posterior")
        print("mean should have pulled ahead of its siblings by the final report.")

        store.close()


if __name__ == "__main__":
    main()
