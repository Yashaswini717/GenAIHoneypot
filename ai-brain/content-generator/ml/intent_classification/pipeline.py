from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter
from typing import Any

import joblib
from sklearn.ensemble import RandomForestClassifier

from core.intent_taxonomy import INTENT_CLASSES

from .dataset import build_training_dataset
from .feature_engineering import extract_features

try:
    from xgboost import XGBClassifier
except Exception:  # pragma: no cover - optional dependency
    XGBClassifier = None


MODEL_DIR = Path(__file__).resolve().parent
MODEL_PATH = MODEL_DIR / "intent_model.joblib"
METADATA_PATH = MODEL_DIR / "intent_model_metadata.json"


@dataclass
class PredictionResult:
    predicted_intent: str
    confidence: float
    probabilities: dict[str, float]
    feature_values: dict[str, float]
    inference_time_ms: float
    model_name: str


def _normalized(values: dict[str, float]) -> dict[str, float]:
    total = sum(max(value, 0.0) for value in values.values())
    if total <= 0:
        uniform = 1.0 / len(INTENT_CLASSES)
        return {intent: uniform for intent in INTENT_CLASSES}
    return {intent: max(values.get(intent, 0.0), 0.0) / total for intent in INTENT_CLASSES}


def _feature_signal_probabilities(feature_map: dict[str, float]) -> dict[str, float]:
    signals = {
        "reconnaissance": (
            feature_map.get("cross_reconnaissance_signal", 0.0)
            + 2.0 * feature_map.get("commands_reconnaissance_signature_hits", 0.0)
            + 1.5 * feature_map.get("http_reconnaissance_signature_hits", 0.0)
            + 1.5 * feature_map.get("db_reconnaissance_signature_hits", 0.0)
            + 1.0 * feature_map.get("contains_recon_marker", 0.0)
        ),
        "privilege_escalation": (
            feature_map.get("cross_privilege_escalation_signal", 0.0)
            + 2.0 * feature_map.get("commands_privilege_escalation_signature_hits", 0.0)
            + 1.5 * feature_map.get("http_privilege_escalation_signature_hits", 0.0)
            + 1.5 * feature_map.get("db_privilege_escalation_signature_hits", 0.0)
            + 1.0 * feature_map.get("contains_auth_marker", 0.0)
        ),
        "persistence": (
            feature_map.get("cross_persistence_signal", 0.0)
            + 2.0 * feature_map.get("commands_persistence_signature_hits", 0.0)
            + 1.5 * feature_map.get("http_persistence_signature_hits", 0.0)
            + 1.5 * feature_map.get("db_persistence_signature_hits", 0.0)
            + 1.0 * feature_map.get("contains_persistence_marker", 0.0)
        ),
        "lateral_movement": (
            feature_map.get("cross_lateral_movement_signal", 0.0)
            + 2.0 * feature_map.get("commands_lateral_movement_signature_hits", 0.0)
            + 1.5 * feature_map.get("http_lateral_movement_signature_hits", 0.0)
            + 1.5 * feature_map.get("db_lateral_movement_signature_hits", 0.0)
            + 1.0 * feature_map.get("contains_remote_exec_marker", 0.0)
        ),
        "data_exfiltration": (
            feature_map.get("cross_data_exfiltration_signal", 0.0)
            + 2.0 * feature_map.get("commands_data_exfiltration_signature_hits", 0.0)
            + 1.5 * feature_map.get("http_data_exfiltration_signature_hits", 0.0)
            + 1.5 * feature_map.get("db_data_exfiltration_signature_hits", 0.0)
            + 1.0 * feature_map.get("contains_archive_marker", 0.0)
            + 1.0 * feature_map.get("contains_base64_marker", 0.0)
        ),
    }
    return _normalized(signals)


def _blend_probabilities(
    model_probabilities: dict[str, float],
    feature_probabilities: dict[str, float],
) -> dict[str, float]:
    blended = {
        intent: (0.55 * model_probabilities.get(intent, 0.0)) + (0.45 * feature_probabilities.get(intent, 0.0))
        for intent in INTENT_CLASSES
    }
    return _normalized(blended)


def _build_classifier(model_type: str = "random_forest"):
    if model_type == "xgboost" and XGBClassifier is not None:
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

    return RandomForestClassifier(
        n_estimators=160,
        max_depth=10,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=1,
        class_weight="balanced"
        
    )


def train_and_persist(model_type: str = "random_forest") -> dict[str, Any]:
    dataset = build_training_dataset()
    rows = [extract_features(sample) for sample in dataset]
    labels = [str(sample["label"]) for sample in dataset]
    feature_names = list(rows[0].keys()) if rows else []
    matrix = [list(row.values()) for row in rows]

    model = _build_classifier(model_type)
    model.fit(matrix, labels)

    artifact = {
        "model": model,
        "feature_names": feature_names,
        "labels": INTENT_CLASSES,
        "model_name": model.__class__.__name__,
    }
    joblib.dump(artifact, MODEL_PATH)
    metadata = {
        "model_name": artifact["model_name"],
        "model_type": model_type if artifact["model_name"] != "RandomForestClassifier" else "random_forest",
        "labels": INTENT_CLASSES,
        "feature_count": len(feature_names),
        "training_samples": len(dataset),
        "class_balance": dict(Counter(labels)),
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    return artifact


def load_or_train(model_type: str = "random_forest") -> dict[str, Any]:
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    return train_and_persist(model_type=model_type)


class IntentClassifier:
    def __init__(self, model_type: str = "random_forest"):
        self.artifact = load_or_train(model_type=model_type)
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
        model_probabilities = {
            label: float(probability)
            for label, probability in zip(self.model.classes_, probabilities_raw)
        }
        feature_probabilities = _feature_signal_probabilities(feature_map)
        probabilities = _blend_probabilities(model_probabilities, feature_probabilities)
        predicted_intent = max(probabilities, key=probabilities.get)
        return PredictionResult(
            predicted_intent=predicted_intent,
            confidence=probabilities.get(predicted_intent, 0.0),
            probabilities={label: probabilities.get(label, 0.0) for label in self.labels},
            feature_values=feature_map,
            inference_time_ms=inference_time_ms,
            model_name=self.model_name,
        )
