"""Training, persistence and inference for the intent model.

The model answers only when the rules abstain (predict.py), which in live
traffic means windows made of commands the rules do not recognise. It is
trained on generated sessions (dataset.py) and judged on hand-labelled ones
(evaluation.py); the figures from the last training run are written into
intent_model_metadata.json alongside the model.

A committed model is only valid for the code that produced it. Pickles from
another scikit-learn version may load and quietly mispredict, and a model
trained on a different feature list maps values onto the wrong columns. So
the artifact records what it was built from, and `load_or_train` retrains
instead of trusting one that no longer matches.
"""

from __future__ import annotations

import hashlib
import json
import logging
import warnings
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any

import joblib
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier

from core.intent_taxonomy import INTENT_CLASSES

from .dataset import DATASET_VERSION, build_training_dataset
from .feature_engineering import extract_features, feature_names

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover - optional dependency
    XGBClassifier = None

log = logging.getLogger(__name__)

MODEL_DIR = Path(__file__).resolve().parent
MODEL_PATH = MODEL_DIR / "intent_model.joblib"
METADATA_PATH = MODEL_DIR / "intent_model_metadata.json"

#: Gradient boosting replaced the random forest as the default: on the
#: labelled transcripts it scored higher (0.935 vs 0.779 on dev) from an
#: artifact about a seventh the size (0.46 MB vs 3.3 MB), and predicts faster.
DEFAULT_MODEL_TYPE = "gradient_boosting"
MODEL_TYPES = ("gradient_boosting", "random_forest", "xgboost")


@dataclass
class PredictionResult:
    predicted_intent: str
    confidence: float
    probabilities: dict[str, float]
    feature_values: dict[str, float]
    inference_time_ms: float
    model_name: str


def _build_classifier(model_type: str = DEFAULT_MODEL_TYPE):
    if model_type == "xgboost" and XGBClassifier is not None:
        # NOTE: XGBClassifier needs integer labels; untested here because
        # xgboost is not a dependency, so the option only works once that is
        # handled. Without xgboost installed this falls through to the default.
        return XGBClassifier(
            n_estimators=120,
            max_depth=5,
            learning_rate=0.1,
            subsample=0.9,
            colsample_bytree=0.9,
            objective="multi:softprob",
            eval_metric="mlogloss",
            tree_method="hist",
            random_state=42,
            verbosity=0,
        )
    if model_type == "random_forest":
        return RandomForestClassifier(
            n_estimators=60,
            min_samples_leaf=6,
            class_weight="balanced",
            random_state=42,
            n_jobs=1,
        )
    return HistGradientBoostingClassifier(
        max_iter=200,
        learning_rate=0.1,
        max_leaf_nodes=31,
        class_weight="balanced",
        random_state=42,
    )


def _fingerprint(names: list[str]) -> dict[str, str]:
    """What a model was built from. Any difference makes it stale."""
    return {
        "sklearn_version": sklearn.__version__,
        "dataset_version": DATASET_VERSION,
        "feature_names_sha256": hashlib.sha256("\n".join(names).encode("utf-8")).hexdigest(),
    }


def train(model_type: str = DEFAULT_MODEL_TYPE) -> dict[str, Any]:
    """Train a model in memory and return its artifact."""
    started = perf_counter()
    dataset = build_training_dataset()
    rows = [extract_features(sample) for sample in dataset]
    labels = [str(sample["label"]) for sample in dataset]
    names = list(rows[0].keys())

    model = _build_classifier(model_type)
    model.fit([list(row.values()) for row in rows], labels)

    artifact = {
        "model": model,
        "feature_names": names,
        "labels": list(INTENT_CLASSES),
        "model_name": model.__class__.__name__,
        "model_type": model_type,
        "training_samples": len(dataset),
        "class_balance": dict(Counter(labels)),
        **_fingerprint(names),
    }
    log.info("trained %s on %d windows in %.1fs", artifact["model_name"], len(dataset), perf_counter() - started)
    return artifact


def train_and_persist(model_type: str = DEFAULT_MODEL_TYPE) -> dict[str, Any]:
    """Train, evaluate on the labelled transcripts, and write model + metadata."""
    from .evaluation import run

    artifact = train(model_type)
    joblib.dump(artifact, MODEL_PATH, compress=3)

    results = run(IntentClassifier(artifact=artifact))
    metadata = {
        key: artifact[key]
        for key in (
            "model_name", "model_type", "labels", "training_samples", "class_balance",
            "sklearn_version", "dataset_version", "feature_names_sha256",
        )
    }
    metadata["feature_count"] = len(artifact["feature_names"])
    metadata["evaluation"] = {
        "note": "Measured on ml/intent_classification/eval_transcripts.py, never on generated data.",
        **{
            split: {name: report.summary() for name, report in reports.items()}
            for split, reports in results.items()
        },
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    artifact["evaluation"] = results
    return artifact


def stale_reason(artifact: dict[str, Any], model_type: str) -> str | None:
    """Why an artifact cannot be used as-is, or None when it can."""
    if artifact.get("model_type", "random_forest") != model_type:
        return f"model type is {artifact.get('model_type')!r}, wanted {model_type!r}"
    expected = _fingerprint(feature_names())
    for key, value in expected.items():
        if artifact.get(key) != value:
            return f"{key} is {artifact.get(key)!r}, current code has {value!r}"
    return None


def load_or_train(model_type: str = DEFAULT_MODEL_TYPE) -> dict[str, Any]:
    """The committed model when it matches this code, otherwise a fresh one.

    A fresh model is trained in memory only. Writing it back silently would
    leave an unexplained binary diff in the working tree; the warning says how
    to refresh the committed artifact instead.
    """
    reason = "no model file"
    if MODEL_PATH.exists():
        try:
            with warnings.catch_warnings():
                # Version mismatches are detected below, deliberately and with
                # a reason, rather than as a pickle warning nobody reads.
                warnings.simplefilter("ignore")
                artifact = joblib.load(MODEL_PATH)
        except Exception as exc:  # corrupt file, missing class, ...
            reason = f"model file unreadable ({exc})"
        else:
            reason = stale_reason(artifact, model_type)
            if reason is None:
                return artifact

    log.warning(
        "intent model at %s cannot be used (%s); training %s in memory. "
        "Run `python -m ml.intent_classification.train` to refresh the committed model.",
        MODEL_PATH, reason, model_type,
    )
    return train(model_type)


class IntentClassifier:
    def __init__(self, model_type: str = DEFAULT_MODEL_TYPE, artifact: dict[str, Any] | None = None):
        self.artifact = artifact if artifact is not None else load_or_train(model_type=model_type)
        self.model = self.artifact["model"]
        self.feature_names = list(self.artifact["feature_names"])
        self.labels = list(self.artifact["labels"])
        self.model_name = str(self.artifact["model_name"])

    def predict(self, activity: dict[str, Any]) -> PredictionResult:
        feature_map = extract_features(activity)
        vector = [feature_map[name] for name in self.feature_names]
        started = perf_counter()
        probabilities_raw = self.model.predict_proba([vector])[0]
        inference_time_ms = (perf_counter() - started) * 1000
        # The model's own probabilities. They used to be blended 55/45 with a
        # keyword-count heuristic; on the labelled transcripts the blend cost
        # 13 points of dev accuracy (0.753 -> 0.623) and gained nothing on test.
        probabilities = {label: 0.0 for label in self.labels}
        probabilities.update(
            {str(label): float(p) for label, p in zip(self.model.classes_, probabilities_raw)}
        )
        predicted_intent = max(probabilities, key=probabilities.get)
        return PredictionResult(
            predicted_intent=predicted_intent,
            confidence=probabilities[predicted_intent],
            probabilities=probabilities,
            feature_values=dict(feature_map),
            inference_time_ms=inference_time_ms,
            model_name=self.model_name,
        )
