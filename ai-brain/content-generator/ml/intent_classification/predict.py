from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from .pipeline import IntentClassifier, PredictionResult
from .feature_engineering import extract_features
from .rules import detect_intent_by_rules


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


INTENT_PRIORITY = {
    "data_exfiltration": 0,
    "privilege_escalation": 1,
    "lateral_movement": 2,
    "persistence": 3,
    "reconnaissance": 4,
}


def _sort_intents_by_priority(intents: set[str]) -> list[str]:
    return sorted(intents, key=lambda intent: INTENT_PRIORITY[intent])


def rule_based_intent(activity: dict[str, Any]) -> list[str]:
    """Return all direct intent matches for obvious command patterns."""
    commands = " \n".join(str(command).lower() for command in activity.get("commands", []) if command)
    detected_intents: set[str] = set()

    if "nmap" in commands:
        detected_intents.add("reconnaissance")
    if "scan" in commands or "scanning" in commands:
        detected_intents.add("reconnaissance")
    if "sudo" in commands or "chmod" in commands:
        detected_intents.add("privilege_escalation")
    if any(
        term in commands
        for term in (
            "cron",
            "crontab",
            ".bashrc",
            ".bash_profile",
            "/etc/profile",
            "/etc/profile.d/",
            "startup",
            "rc.local",
            "launchctl",
            "schtasks",
            "authorized_keys",
            "systemctl enable",
        )
    ):
        detected_intents.add("persistence")
    if "ssh " in commands or "psexec" in commands:
        detected_intents.add("lateral_movement")
    if any(term in commands for term in ("scp", "curl", "ftp", "upload")):
        detected_intents.add("data_exfiltration")

    return _sort_intents_by_priority(detected_intents)


@lru_cache(maxsize=1)
def get_intent_classifier(model_type: str = "random_forest") -> IntentClassifier:
    return IntentClassifier(model_type=model_type)


def predict_intent_realtime(activity: dict[str, Any], model_type: str = "random_forest") -> HybridPredictionResult:
    rule_match = detect_intent_by_rules(activity)
    if rule_match is not None:
        feature_values = extract_features(activity)
        return HybridPredictionResult(
            intent=rule_match.intent,
            confidence=rule_match.confidence,
            source="rule",
            probabilities={
                "reconnaissance": 1.0 if rule_match.intent == "reconnaissance" else 0.0,
                "privilege_escalation": 1.0 if rule_match.intent == "privilege_escalation" else 0.0,
                "persistence": 1.0 if rule_match.intent == "persistence" else 0.0,
                "lateral_movement": 1.0 if rule_match.intent == "lateral_movement" else 0.0,
                "data_exfiltration": 1.0 if rule_match.intent == "data_exfiltration" else 0.0,
            },
            feature_values=feature_values,
            inference_time_ms=0.0,
            model_name="rule_engine",
            matched_rules=rule_match.matched_rules,
        )

    classifier = get_intent_classifier(model_type=model_type)
    ml_result = classifier.predict(activity)
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


def classify_intent(activity: dict[str, Any], model_type: str = "random_forest") -> IntentClassificationResult:
    """Classify intent with rule-first hybrid logic for the legacy API endpoint."""
    direct_rule_intents = rule_based_intent(activity)
    if direct_rule_intents:
        return IntentClassificationResult(
            primary_intent=direct_rule_intents[0],
            all_intents=direct_rule_intents,
            source="rule",
        )

    rule_match = detect_intent_by_rules(activity)
    if rule_match is not None:
        return IntentClassificationResult(
            primary_intent=rule_match.intent,
            all_intents=[rule_match.intent],
            source="rule",
        )

    ml_result = predict_intent_realtime(activity, model_type=model_type)
    return IntentClassificationResult(
        primary_intent=ml_result.intent,
        all_intents=[ml_result.intent],
        source="ml",
    )
