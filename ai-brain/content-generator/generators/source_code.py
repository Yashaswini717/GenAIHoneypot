from typing import Any

from prompts.base_prompts import get_system_prompt
from prompts.source_code_prompts import (
    get_go_prompt,
    get_javascript_prompt,
    get_python_prompt,
    get_shell_prompt,
)

from .base import BaseGenerator, GeneratedContent


class SourceCodeGenerator(BaseGenerator):
    """Generate realistic source code files."""

    def get_system_prompt(self, artifact_layer: str = "system") -> str:
        """Get system prompt for source code generation."""
        return get_system_prompt("source_code", artifact_layer)

    def build_prompt(self, context: dict[str, Any]) -> str:
        """Build prompt for source code generation."""
        language = context.get("language", "python")
        
        prompt_builders = {
            "python": get_python_prompt,
            "javascript": get_javascript_prompt,
            "shell": get_shell_prompt,
            "go": get_go_prompt,
        }
        
        builder = prompt_builders.get(language, get_python_prompt)
        return builder(context)

    async def generate(self, context: dict[str, Any]) -> GeneratedContent:
        """
        Generate source code.

        Args:
            context: Must contain 'language' and optionally:
                - script_type: Type of script (webapp, cli, etc.)
                - purpose: Purpose description
                - features: List of features to include

        Returns:
            GeneratedContent with source code
        """
        language = context.get("language", "python")
        
        return await self._generate_and_enforce(
            context=context,
            content_type="source_code",
            file_type=language,
            language=language,
            script_type=context.get("script_type"),
            purpose=context.get("purpose"),
        )
