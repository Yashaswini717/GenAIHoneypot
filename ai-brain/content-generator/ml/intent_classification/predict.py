from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

from core.intent_taxonomy import INTENT_CLASSES

from .feature_engineering import extract_features
from .pipeline import DEFAULT_MODEL_TYPE, IntentClassifier
from .rules import detect_intent_by_rules, evidenced_intents


@dataclass
class HybridPredictionResult:
    intent: str
    confidence: float
    source: str
    probabilities: dict[str, float]
    feature_values: dict[str, float]
    inference_time_ms: float
    model_name: str
    matched_rules: list[str]


@dataclass
class IntentClassificationResult:
    primary_intent: str
    all_intents: list[str]
    source: str


_classifiers: dict[str, IntentClassifier] = {}
_classifiers_lock = threading.Lock()


def get_intent_classifier(model_type: str = DEFAULT_MODEL_TYPE) -> IntentClassifier:
    """One classifier per model type, built once.

    Locked rather than lru_cached: the route runs in FastAPI's threadpool, and
    two first requests arriving together would otherwise both load -- or, for a
    stale model, both train -- the same model at once.
    """
    with _classifiers_lock:
        if model_type not in _classifiers:
            _classifiers[model_type] = IntentClassifier(model_type=model_type)
        return _classifiers[model_type]


def predict_intent_realtime(activity: dict[str, Any], model_type: str = DEFAULT_MODEL_TYPE) -> HybridPredictionResult:
    """Rules first; the model when no command in the window is evidence.

    The model also sees `previous_intent` -- what this endpoint returned for
    the session's last window, sent by the sidecar. A window can hold nothing
    at all to go on (`cd`, `chmod +x`, heredoc lines), and the attacker has not
    changed stage by typing those, so the model learns to keep the previous
    stage there. It is context rather than an override: carrying the old stage
    forward unconditionally scored no better, because it also overruled the
    windows where the model correctly saw a change the rules cannot name -- an
    exploit compiled and run, an app patched with `sed -i`.
    """
    rule_match = detect_intent_by_rules(activity)
    if rule_match is not None:
        return HybridPredictionResult(
            intent=rule_match.intent,
            confidence=rule_match.confidence,
            source="rule",
            probabilities={intent: 1.0 if intent == rule_match.intent else 0.0 for intent in INTENT_CLASSES},
            feature_values=dict(extract_features(activity)),
            inference_time_ms=0.0,
            model_name="rule_engine",
            matched_rules=rule_match.matched_rules,
        )

    ml_result = get_intent_classifier(model_type=model_type).predict(activity)
    return HybridPredictionResult(
        intent=ml_result.predicted_intent,
        confidence=ml_result.confidence,
        source="ml",
        probabilities=ml_result.probabilities,
        feature_values=ml_result.feature_values,
        inference_time_ms=ml_result.inference_time_ms,
        model_name=ml_result.model_name,
        matched_rules=[],
    )


def classify_intent(activity: dict[str, Any], model_type: str = DEFAULT_MODEL_TYPE) -> IntentClassificationResult:
    """The legacy /classify endpoint, answered by the same classifier as /intent-classify.

    It used to run a second, looser rule set of its own -- any `curl` meant
    exfiltration, any `chmod` meant privilege escalation -- so the two
    endpoints could disagree about the same commands. `all_intents` keeps its
    meaning: every intent with evidence in the window, after the primary one.
    """
    result = predict_intent_realtime(activity, model_type=model_type)
    others = [intent for intent in evidenced_intents(activity) if intent != result.intent]
    return IntentClassificationResult(
        primary_intent=result.intent,
        all_intents=[result.intent] + others,
        source=result.source,
    )
