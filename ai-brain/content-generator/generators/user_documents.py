from typing import Any

from prompts.base_prompts import get_system_prompt
from prompts.document_prompts import (
    get_api_docs_prompt,
    get_architecture_doc_prompt,
    get_changelog_prompt,
    get_notes_prompt,
    get_readme_prompt,
    get_runbook_prompt,
    get_todo_prompt,
)

from .base import BaseGenerator, GeneratedContent


class UserDocumentGenerator(BaseGenerator):
    """Generate realistic user documents."""

    def get_system_prompt(self, artifact_layer: str = "system") -> str:
        """Get system prompt for document generation."""
        return get_system_prompt("document", artifact_layer)

    def build_prompt(self, context: dict[str, Any]) -> str:
        """Build prompt for document generation."""
        doc_type = context.get("doc_type", "notes")
        
        prompt_builders = {
            "notes": get_notes_prompt,
            "readme": get_readme_prompt,
            "todo": get_todo_prompt,
            "api_docs": get_api_docs_prompt,
            "runbook": get_runbook_prompt,
            "changelog": get_changelog_prompt,
            "architecture": get_architecture_doc_prompt,
        }
        
        builder = prompt_builders.get(doc_type, get_notes_prompt)
        return builder(context)

    async def generate(self, context: dict[str, Any]) -> GeneratedContent:
        """
        Generate user document.

        Args:
            context: Must contain 'doc_type' and type-specific params:
                - audience: Target audience (internal, external, attacker, developer)
                - realism_level: Level of realism (low, medium, high)
                - hide_honeypot_concepts: Whether to hide honeypot mentions
                - industry: Industry context

        Returns:
            GeneratedContent with document
        """
        doc_type = context.get("doc_type", "notes")
        
        # Set default temperature for documents
        if "temperature" not in context:
            context = {**context, "temperature": 0.8}
        
        return await self._generate_and_enforce(
            context=context,
            content_type="document",
            file_type="generic",
            doc_type=doc_type,
            audience=context.get("audience", "internal"),
            realism_level=context.get("realism_level", "high"),
        )
