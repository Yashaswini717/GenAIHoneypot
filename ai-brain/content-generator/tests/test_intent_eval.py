"""How well intent classification scores on labelled sessions, and why that number can be trusted.

The floors below sit just under the figures measured when this suite was
written (see intent_model_metadata.json for the current run). Everything here
is deterministic -- seeded generator, seeded model, pinned scikit-learn -- so a
drop is a change in behaviour, not noise.

The other tests guard the measurement itself: a classifier can only look this
good honestly if the training data does not leak its labels and the
evaluation sessions are not in the training data.

Run with:  pytest ai-brain/content-generator/tests/test_intent_eval.py -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import joblib  # noqa: E402

from core.intent_taxonomy import INTENT_CLASSES  # noqa: E402
from ml.intent_classification.dataset import build_training_dataset, generate_session  # noqa: E402
from ml.intent_classification.eval_transcripts import TRANSCRIPTS  # noqa: E402
from ml.intent_classification.evaluation import evaluate, iter_windows, run, standard_predictors  # noqa: E402
from ml.intent_classification.feature_engineering import _interval_stats  # noqa: E402
from ml.intent_classification.pipeline import DEFAULT_MODEL_TYPE, MODEL_PATH, stale_reason  # noqa: E402

#: (split, predictor) -> minimum accuracy. Measured at writing (dataset v9),
#: dev / test:
#:   session (deployed: hybrid + previous_intent)  0.922 / 0.961
#:   hybrid, stateless                             0.922 / 0.943
#:   model alone                                   0.935 / 0.830
#: Test now holds both retired holdouts: v1 (0.844 stateless, 32 windows) and
#: v2 (0.841 stateless, 0.861 with session context, 151 windows). Holdout v3
#: is 30 real SSH sessions from the CyberLab honeynet (captured_sessions.json,
#: 509 windows), labelled by the rules' author before it was scored once:
#: session 0.768, hybrid 0.758, model 0.668 (0.815 traffic-weighted). The
#: original classifier scored 0.481 dev and 0.522 test on the first sets.
FLOORS = {
    ("dev", "session"): 0.90,
    ("test", "session"): 0.95,
    ("holdout", "session"): 0.75,
    ("dev", "hybrid"): 0.90,
    ("test", "hybrid"): 0.93,
    ("holdout", "hybrid"): 0.74,
    ("dev", "ml"): 0.90,
    ("test", "ml"): 0.82,
    ("holdout", "ml"): 0.65,
}


@pytest.fixture(scope="module")
def reports():
    return run()


@pytest.fixture(scope="module")
def predictors():
    return standard_predictors()


@pytest.mark.parametrize("split, predictor", sorted(FLOORS))
def test_accuracy_floor(reports, split, predictor):
    report = reports[split][predictor]
    assert report.accuracy >= FLOORS[split, predictor], (
        f"{split}/{predictor} accuracy {report.accuracy:.3f} fell below {FLOORS[split, predictor]}"
    )


NEUTRAL_WINDOWS = [
    ["[Unit]", "Description=Sync agent", "[Service]"],   # a heredoc being typed
    ["cd /tmp", "chmod +x run.sh", "./run.sh"],          # a tool being run
]


#: The sidecar always sends timestamps; other /intent-classify callers may not.
TIMESTAMPS = {
    "sidecar": ["2026-10-01T09:00:00.000000Z", "2026-10-01T09:00:04.200000Z", "2026-10-01T09:00:09.900000Z"],
    "none": [],
}


@pytest.mark.parametrize("stamps", sorted(TIMESTAMPS))
@pytest.mark.parametrize("commands", NEUTRAL_WINDOWS)
@pytest.mark.parametrize("previous", list(INTENT_CLASSES))
def test_a_window_with_nothing_in_it_keeps_the_sessions_stage(commands, previous, stamps):
    """The point of previous_intent: these commands carry no stage, and the
    attacker has not changed stage by typing them."""
    from ml.intent_classification.predict import predict_intent_realtime

    result = predict_intent_realtime(
        {"commands": commands, "event_timestamps": TIMESTAMPS[stamps], "previous_intent": previous}
    )
    assert result.intent == previous, f"{commands} ({stamps}) with previous={previous} -> {result.intent}"


def test_previous_intent_never_outranks_evidence():
    from ml.intent_classification.predict import predict_intent_realtime

    result = predict_intent_realtime({"commands": ["id", "sudo -l"], "previous_intent": "data_exfiltration"})
    assert result.intent == "privilege_escalation" and result.source == "rule"


def test_no_intent_is_starved(predictors):
    """A classifier that never predicts a class can still post a decent accuracy."""
    windows = iter_windows(split="dev") + iter_windows(split="test")
    per_class = evaluate(predictors["hybrid"], windows, "dev+test").per_class()
    starved = {intent: round(row["recall"], 2) for intent, row in per_class.items() if row["recall"] < 0.6}
    assert not starved, f"recall below 0.6: {starved}"


def test_tempo_alone_does_not_predict_the_label():
    """The first generator gave each class its own timestamp count and spacing,
    and timestamps alone predicted the label 98.7% of the time. Tempo is now a
    property of the session, so it should sit near chance (0.20 balanced)."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_score

    windows = build_training_dataset(seed=7, sessions=400)
    X = [list(_interval_stats(w["event_timestamps"]).values()) for w in windows]
    y = [w["label"] for w in windows]
    model = RandomForestClassifier(n_estimators=50, max_depth=6, random_state=0, class_weight="balanced")
    score = cross_val_score(model, X, y, cv=3, scoring="balanced_accuracy").mean()
    assert score < 0.30, f"timestamps alone reach {score:.3f} balanced accuracy -- the generator leaks"


def test_scored_sessions_are_not_in_the_training_data():
    """No test or holdout window may appear verbatim among the training windows.

    Dev is exempt: it is the set tuned against, so overlap there inflates
    nothing that is reported. It does happen -- two common commands such as
    `id` then `uname -r` occasionally come up together in a generated session.

    Captured sessions are exempt too. They are real traffic, so a window the
    generator also produces is two scripts agreeing, not one copied into the
    other; captures.py counts those windows per session ("training_overlap").
    """
    training = {tuple(w["commands"]) for w in build_training_dataset()}
    captured = {t.name for t in TRANSCRIPTS if t.stamps}
    scored = [w for w in iter_windows() if w.split != "dev" and w.transcript not in captured]
    leaked = [(w.split, w.transcript, tuple(w.activity["commands"])) for w in scored if tuple(w.activity["commands"]) in training]
    assert not leaked, f"{len(leaked)} scored window(s) appear verbatim in training: {leaked[:3]}"


def test_committed_model_matches_this_code():
    """A stale model is retrained in memory at startup, which costs every worker
    tens of seconds. If this fails, run `python -m ml.intent_classification.train`
    and commit the refreshed intent_model.joblib and metadata."""
    reason = stale_reason(joblib.load(MODEL_PATH), DEFAULT_MODEL_TYPE)
    assert reason is None, reason


def test_features_do_not_depend_on_the_hash_seed():
    """Retraining on identical data once produced a different model every time.

    `command_entropy` was summed over a set, whose order follows the process's
    hash seed, so the float result changed in its last bits from run to run --
    enough to move histogram bin edges. Two processes with different seeds must
    now extract identical features.
    """
    import os
    import subprocess

    script = (
        "import json, sys; sys.path.insert(0, %r);"
        "from ml.intent_classification.feature_engineering import extract_features;"
        "print(json.dumps(list(extract_features({'commands': ['ls -la /tmp a b a', 'tar czf x.tgz /srv /srv', 'id']}).values())))"
    ) % str(Path(__file__).resolve().parents[1])
    outputs = set()
    for seed in ("1", "2", "3"):
        result = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True, text=True, check=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        outputs.add(result.stdout.strip().splitlines()[-1])
    assert len(outputs) == 1, "feature values differ between processes"


def test_transcripts_are_well_formed():
    names = [t.name for t in TRANSCRIPTS]
    assert len(names) == len(set(names)), "duplicate transcript names"
    for transcript in TRANSCRIPTS:
        assert transcript.split in {"dev", "test", "holdout"}
        assert transcript.tempo in {"bot", "human"}
        assert len(transcript.steps) >= 2, transcript.name
        assert transcript.stamps is None or len(transcript.stamps) == len(transcript.steps), transcript.name
        for command, label in transcript.steps:
            assert command.strip(), transcript.name
            assert label is None or label in INTENT_CLASSES, (transcript.name, label)


def test_generated_sessions_use_every_stage():
    import random

    rng = random.Random(0)
    seen = {stage for _ in range(300) for _, stage in generate_session(rng)[0]}
    assert seen == set(INTENT_CLASSES)
