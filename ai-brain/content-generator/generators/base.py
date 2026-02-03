from abc import ABC, abstractmethod
from typing import Any

from config.logging_config import LoggerMixin
from core.llm_client import LLMClient
from validators.base import ValidationResult
from validators.realism import RealismValidator
from validators.security import SecurityValidator
from validators.syntax import SyntaxValidator


class GeneratedContent:
    """Container for generated content with metadata."""

    def __init__(
        self,
        content: str,
        content_type: str,
        file_type: str,
        metadata: dict[str, Any] | None = None,
        validation_results: dict[str, ValidationResult] | None = None,
    ):
        self.content = content
        self.content_type = content_type
        self.file_type = file_type
        self.metadata = metadata or {}
        self.validation_results = validation_results or {}

    @property
    def is_valid(self) -> bool:
        """Check if all validations passed."""
        return all(result.valid for result in self.validation_results.values())

    @property
    def overall_score(self) -> float:
        """Calculate overall quality score."""
        if not self.validation_results:
            return 0.0
        return sum(r.score for r in self.validation_results.values()) / len(self.validation_results)

    def __repr__(self) -> str:
        return (
            f"GeneratedContent(type={self.content_type}, "
            f"length={len(self.content)}, "
            f"valid={self.is_valid}, "
            f"score={self.overall_score:.2f})"
        )


class BaseGenerator(ABC, LoggerMixin):
    """Abstract base class for content generators."""

    def __init__(self, llm_client: LLMClient):
        """
        Initialize generator.

        Args:
            llm_client: LLM client for generation
        """
        self.llm_client = llm_client
        self.syntax_validator = SyntaxValidator()
        self.realism_validator = RealismValidator()
        self.security_validator = SecurityValidator()
        
        self.logger.debug(f"{self.__class__.__name__}_initialized")

    @abstractmethod
    async def generate(self, context: dict[str, Any]) -> GeneratedContent:
        """
        Generate content based on context.

        Args:
            context: Generation context with parameters

        Returns:
            GeneratedContent instance
        """
        pass

    @abstractmethod
    def get_system_prompt(self) -> str:
        """Get system prompt for this generator."""
        pass

    @abstractmethod
    def build_prompt(self, context: dict[str, Any]) -> str:
        """Build user prompt from context."""
        pass

    async def _generate_with_llm(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
    ) -> str:
        """
        Generate content using LLM.

        Args:
            prompt: User prompt
            system_prompt: System prompt
            temperature: Temperature override

        Returns:
            Generated text
        """
        system_prompt = system_prompt or self.get_system_prompt()
        
        self.logger.debug(
            "generating_with_llm",
            generator=self.__class__.__name__,
            prompt_length=len(prompt),
        )
        
        content = await self.llm_client.generate(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
        )
        
        return content

    async def _validate_content(
        self,
        content: str,
        file_type: str,
        context: dict[str, Any],
    ) -> dict[str, ValidationResult]:
        """
        Validate generated content.

        Args:
            content: Content to validate
            file_type: File type for syntax validation
            context: Additional context

        Returns:
            Dictionary of validation results
        """
        validation_context = {
            "file_type": file_type,
            **context,
        }
        
        results = {}
        
        # Syntax validation
        results["syntax"] = await self.syntax_validator.validate(content, validation_context)
        
        # Realism validation
        results["realism"] = await self.realism_validator.validate(content, validation_context)
        
        # Security validation
        results["security"] = await self.security_validator.validate(content, validation_context)
        
        self.logger.info(
            "content_validated",
            generator=self.__class__.__name__,
            file_type=file_type,
            syntax_valid=results["syntax"].valid,
            realism_score=results["realism"].score,
            security_valid=results["security"].valid,
        )
        
        return results

    def _create_content(
        self,
        content: str,
        content_type: str,
        file_type: str,
        validation_results: dict[str, ValidationResult],
        **metadata: Any,
    ) -> GeneratedContent:
        """Helper to create GeneratedContent instance."""
        return GeneratedContent(
            content=content,
            content_type=content_type,
            file_type=file_type,
            metadata=metadata,
            validation_results=validation_results,
        )
