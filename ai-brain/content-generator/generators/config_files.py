from typing import Any

from prompts.base_prompts import get_system_prompt
from prompts.config_prompts import (
    get_bashrc_prompt,
    get_docker_compose_prompt,
    get_env_file_prompt,
    get_nginx_conf_prompt,
    get_ssh_config_prompt,
)

from .base import BaseGenerator, GeneratedContent


class ConfigGenerator(BaseGenerator):
    """Generate realistic configuration files."""

    def get_system_prompt(self) -> str:
        """Get system prompt for config generation."""
        return get_system_prompt("config")

    def build_prompt(self, context: dict[str, Any]) -> str:
        """Build prompt for config generation."""
        config_type = context.get("config_type", "bashrc")
        
        prompt_builders = {
            "bashrc": get_bashrc_prompt,
            "ssh_config": get_ssh_config_prompt,
            "env": get_env_file_prompt,
            "nginx": get_nginx_conf_prompt,
            "docker_compose": get_docker_compose_prompt,
        }
        
        builder = prompt_builders.get(config_type, get_bashrc_prompt)
        return builder(context)

    async def generate(self, context: dict[str, Any]) -> GeneratedContent:
        """
        Generate configuration file.

        Args:
            context: Must contain 'config_type' and type-specific params

        Returns:
            GeneratedContent with configuration
        """
        config_type = context.get("config_type", "bashrc")
        
        # Determine file type for validation
        file_type_map = {
            "bashrc": "shell",
            "ssh_config": "generic",
            "env": "generic",
            "nginx": "nginx",
            "docker_compose": "yaml",
        }
        file_type = file_type_map.get(config_type, "generic")
        
        # Build and generate
        prompt = self.build_prompt(context)
        config = await self._generate_with_llm(prompt, temperature=0.8)
        
        # Validate
        validation_results = await self._validate_content(
            content=config,
            file_type=file_type,
            context=context,
        )
        
        return self._create_content(
            content=config,
            content_type="config",
            file_type=file_type,
            validation_results=validation_results,
            config_type=config_type,
        )
