class ContentGeneratorError(Exception):
    """Base exception for content generator errors."""

    def __init__(self, message: str, details: dict | None = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class LLMError(ContentGeneratorError):
    """Base exception for LLM-related errors."""

    pass


class LLMConnectionError(LLMError):
    """Raised when LLM service is unreachable."""

    pass


class LLMTimeoutError(LLMError):
    """Raised when LLM request times out."""

    pass


class LLMRateLimitError(LLMError):
    """Raised when LLM rate limit is exceeded."""

    pass


class LLMInvalidResponseError(LLMError):
    """Raised when LLM returns invalid or malformed response."""

    pass


class LLMEmptyResponseError(LLMInvalidResponseError):
    """
    Raised specifically when the provider returns zero choices — usually
    a transient upstream hiccup (momentary overload, mid-batch blip),
    not a permanent problem like a bad model name or malformed request.
    Kept distinct from the generic LLMInvalidResponseError so it can be
    retried without also retrying genuinely permanent failures.
    """

    pass


class LLMAuthenticationError(LLMError):
    """Raised when LLM authentication fails."""

    pass


class ValidationError(ContentGeneratorError):
    """Base exception for validation errors."""

    pass


class SyntaxValidationError(ValidationError):
    """Raised when syntax validation fails."""

    pass


class RealismValidationError(ValidationError):
    """Raised when realism validation fails."""

    pass


class SecurityValidationError(ValidationError):
    """Raised when security validation fails (e.g., real secrets detected)."""

    pass


class GenerationError(ContentGeneratorError):
    """Base exception for content generation errors."""

    pass


class TemplateError(GenerationError):
    """Raised when template rendering fails."""

    pass


class PromptError(GenerationError):
    """Raised when prompt construction fails."""

    pass


class StorageError(ContentGeneratorError):
    """Base exception for storage-related errors."""

    pass


class FileSystemError(StorageError):
    """Raised when filesystem operations fail."""

    pass


class DatabaseError(StorageError):
    """Raised when database operations fail."""

    pass


class ConfigurationError(ContentGeneratorError):
    """Raised when configuration is invalid or missing."""

    pass


class PopulatorError(ContentGeneratorError):
    """Raised when honeypot population fails."""

    pass


class ConsistencyError(PopulatorError):
    """Raised when cross-file consistency checks fail."""

    pass
