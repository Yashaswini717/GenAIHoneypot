from abc import ABC, abstractmethod
from typing import Any

from config.logging_config import LoggerMixin


class ValidationResult:
    """Result of validation operation."""

    def __init__(
        self,
        valid: bool,
        score: float = 1.0,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        self.valid = valid
        self.score = score  # 0.0 to 1.0
        self.errors = errors or []
        self.warnings = warnings or []
        self.metadata = metadata or {}

    def __bool__(self) -> bool:
        """Allow using result in boolean context."""
        return self.valid

    def __repr__(self) -> str:
        return f"ValidationResult(valid={self.valid}, score={self.score:.2f}, errors={len(self.errors)})"


class BaseValidator(ABC, LoggerMixin):
    """Abstract base class for validators."""

    def __init__(self):
        """Initialize validator."""
        self.logger.debug(f"{self.__class__.__name__}_initialized")

    @abstractmethod
    async def validate(self, content: str, context: dict[str, Any] | None = None) -> ValidationResult:
        """
        Validate content.

        Args:
            content: Content to validate
            context: Additional context for validation

        Returns:
            ValidationResult
        """
        pass

    def _create_result(
        self,
        valid: bool,
        score: float = 1.0,
        errors: list[str] | None = None,
        warnings: list[str] | None = None,
        **metadata: Any,
    ) -> ValidationResult:
        """Helper to create validation result."""
        return ValidationResult(
            valid=valid,
            score=score,
            errors=errors,
            warnings=warnings,
            metadata=metadata,
        )
