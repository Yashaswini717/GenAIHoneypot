from typing import Any

from prompts.base_prompts import get_system_prompt
from prompts.log_prompts import (
    get_apache_access_prompt,
    get_application_log_prompt,
    get_audit_log_prompt,
    get_auth_log_prompt,
    get_bash_history_prompt,
    get_nginx_access_prompt,
    get_security_event_log_prompt,
    get_syslog_prompt,
)

from .base import BaseGenerator, GeneratedContent


class SystemLogGenerator(BaseGenerator):
    """Generate realistic system log files."""

    def get_system_prompt(self, artifact_layer: str = "system") -> str:
        """Get system prompt for log generation."""
        return get_system_prompt("logs", artifact_layer)

    def build_prompt(self, context: dict[str, Any]) -> str:
        """Build prompt for log generation based on log_type and log_category."""
        log_type = context.get("log_type", "auth")
        log_category = context.get("log_category", "system")
        
        # Map log_type to prompt builders
        prompt_builders = {
            "auth": get_auth_log_prompt,
            "syslog": get_syslog_prompt,
            "bash_history": get_bash_history_prompt,
            "apache_access": get_apache_access_prompt,
            "nginx_access": get_nginx_access_prompt,
            "application": get_application_log_prompt,
            "audit": get_audit_log_prompt,
            "security": get_security_event_log_prompt,
        }
        
        # If log_category is specified, override log_type selection for category-specific behavior
        if log_category == "application" and log_type not in ["application"]:
            builder = get_application_log_prompt
        elif log_category == "audit":
            builder = get_audit_log_prompt
            # Force analysis layer for audit logs (SIEM/compliance content)
            context["artifact_layer"] = "analysis"
        elif log_category == "security":
            builder = get_security_event_log_prompt
            # Force analysis layer for security event logs (SIEM content)
            context["artifact_layer"] = "analysis"
        elif log_category == "access":
            # Use nginx_access or apache_access based on log_type
            builder = prompt_builders.get(log_type, get_nginx_access_prompt)
        else:
            builder = prompt_builders.get(log_type, get_auth_log_prompt)
        
        return builder(context)

    async def generate(self, context: dict[str, Any]) -> GeneratedContent:
        """
        Generate system log.

        Args:
            context: Must contain 'log_type' and optional params:
                - duration_hours: Duration of log entries
                - attack_activity: Include attack patterns
                - log_category: Category (system, application, access, security, audit)
                - log_format: Explicit format (syslog, json, combined, clf)
                - industry: Industry context for relevant content

        Returns:
            GeneratedContent with log data
        """
        log_type = context.get("log_type", "auth")
        log_category = context.get("log_category", "system")
        
        # Map log_type to a more specific file_type for format-aware validation
        file_type_map = {
            "auth": "syslog",
            "syslog": "syslog",
            "bash_history": "generic",
            "apache_access": "access_log",
            "nginx_access": "access_log",
            "application": "generic",
            "audit": "generic",
            "security": "generic",
        }
        file_type = file_type_map.get(log_type, "generic")
        
        # Set default temperature for logs
        if "temperature" not in context:
            context = {**context, "temperature": 0.9}
        
        # Pass log_type into validation context
        context = {**context, "log_type": log_type}
        
        return await self._generate_and_enforce(
            context=context,
            content_type="logs",
            file_type=file_type,
            log_type=log_type,
            log_category=log_category,
            duration_hours=context.get("duration_hours", 24),
        )
