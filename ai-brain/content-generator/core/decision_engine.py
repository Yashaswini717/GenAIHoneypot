from __future__ import annotations

from dataclasses import dataclass

from core.intent_taxonomy import INTENT_CLASSES


INTENT_TO_ACTION = {
    "reconnaissance": "show_fake_endpoints",
    "privilege_escalation": "inject_fake_sudo_config",
    "persistence": "simulate_cron_jobs",
    "lateral_movement": "expose_fake_internal_ips",
    "data_exfiltration": "serve_fake_sensitive_files",
}


@dataclass
class ActionSuggestion:
    intent: str
    action: str


class DecisionEngine:
    """Maps attacker intent to a decoy action suggestion."""

    def suggest_action(self, intent: str) -> ActionSuggestion:
        if intent not in INTENT_CLASSES:
            raise ValueError(f"Unsupported intent: {intent}")
        return ActionSuggestion(intent=intent, action=INTENT_TO_ACTION[intent])
