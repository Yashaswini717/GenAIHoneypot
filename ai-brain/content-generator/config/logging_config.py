import logging
import sys
from pathlib import Path
from typing import Any

import structlog
from structlog.types import Processor

from .settings import settings


def setup_logging() -> None:
    """Configure structured logging with JSON output."""

    # Determine log level
    log_level = getattr(logging, settings.log_level.value)

    # Configure standard logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    # Shared processors for both dev and prod
    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    # Add format-specific processors
    if settings.log_format == "json":
        processors: list[Processor] = shared_processors + [
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Console-friendly format for development
        processors = shared_processors + [
            structlog.processors.ExceptionPrettyPrinter(),
            structlog.dev.ConsoleRenderer(),
        ]

    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Configure file logging if specified
    if settings.log_file:
        log_file = Path(settings.log_file)
        log_file.parent.mkdir(parents=True, exist_ok=True)

        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_handler.setFormatter(logging.Formatter("%(message)s"))

        root_logger = logging.getLogger()
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """
    Get a configured logger instance.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured structlog logger
    """
    return structlog.get_logger(name)


class LoggerMixin:
    """Mixin to add logging capabilities to classes."""

    @property
    def logger(self) -> structlog.stdlib.BoundLogger:
        """Get logger for this class."""
        return get_logger(self.__class__.__name__)

    def log_operation(
        self,
        operation: str,
        level: str = "info",
        **context: Any,
    ) -> None:
        """
        Log an operation with context.

        Args:
            operation: Operation name
            level: Log level (debug, info, warning, error)
            **context: Additional context to log
        """
        log_func = getattr(self.logger, level)
        log_func(operation, **context)
