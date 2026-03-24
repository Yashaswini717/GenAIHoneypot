from abc import ABC, abstractmethod
from typing import Any

from config.logging_config import LoggerMixin


class PopulationResult:
    """Result of population operation."""

    def __init__(
        self,
        success: bool,
        files_created: int = 0,
        errors: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ):
        self.success = success
        self.files_created = files_created
        self.errors = errors or []
        self.metadata = metadata or {}

    def __bool__(self) -> bool:
        return self.success

    def __repr__(self) -> str:
        return f"PopulationResult(success={self.success}, files={self.files_created}, errors={len(self.errors)})"


class BasePopulator(ABC, LoggerMixin):
    """Abstract base class for populators."""

    @abstractmethod
    async def populate(self, honeypot_id: str, context: dict[str, Any]) -> PopulationResult:
        """Populate honeypot with content."""
        pass

    def _create_result(
        self,
        success: bool,
        files_created: int = 0,
        errors: list[str] | None = None,
        **metadata: Any,
    ) -> PopulationResult:
        """Helper to create result."""
        return PopulationResult(
            success=success,
            files_created=files_created,
            errors=errors,
            metadata=metadata,
        )
