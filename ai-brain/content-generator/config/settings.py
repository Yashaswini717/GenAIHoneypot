from enum import Enum
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    AZURE_OPENAI = "azure_openai"
    OLLAMA = "ollama"


class LogLevel(str, Enum):
    """Log levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = Field(default="AI Content Generator", alias="APP_NAME")
    app_version: str = Field(default="1.0.0", alias="APP_VERSION")
    environment: str = Field(default="development", alias="ENVIRONMENT")
    debug: bool = Field(default=False, alias="DEBUG")

    # API Server
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000, alias="API_PORT")
    api_workers: int = Field(default=4, alias="API_WORKERS")
    api_reload: bool = Field(default=False, alias="API_RELOAD")

    # LLM Configuration
    llm_provider: LLMProvider = Field(default=LLMProvider.OPENAI, alias="LLM_PROVIDER")
    llm_model: str = Field(
        default="google/gemini-2.0-flash-exp:free", alias="LLM_MODEL"
    )
    llm_temperature: float = Field(default=0.7, alias="LLM_TEMPERATURE")
    llm_max_tokens: int = Field(default=2048, alias="LLM_MAX_TOKENS")
    llm_timeout: int = Field(default=60, alias="LLM_TIMEOUT")
    llm_max_retries: int = Field(default=3, alias="LLM_MAX_RETRIES")
    llm_retry_delay: int = Field(default=2, alias="LLM_RETRY_DELAY")

    # OpenAI / OpenRouter
    openai_api_key: Optional[str] = Field(default=None, alias="OPENAI_API_KEY")
    openai_org_id: Optional[str] = Field(default=None, alias="OPENAI_ORG_ID")
    openai_base_url: Optional[str] = Field(
        default="https://openrouter.ai/api/v1", alias="OPENAI_BASE_URL"
    )

    # Azure OpenAI
    azure_openai_api_key: Optional[str] = Field(
        default=None, alias="AZURE_OPENAI_API_KEY"
    )
    azure_openai_endpoint: Optional[str] = Field(
        default=None, alias="AZURE_OPENAI_ENDPOINT"
    )
    azure_openai_deployment: Optional[str] = Field(
        default=None, alias="AZURE_OPENAI_DEPLOYMENT"
    )
    azure_openai_api_version: str = Field(
        default="2024-02-15-preview", alias="AZURE_OPENAI_API_VERSION"
    )

    # Ollama
    ollama_base_url: str = Field(
        default="http://localhost:11434", alias="OLLAMA_BASE_URL"
    )
    ollama_model: str = Field(default="llama2", alias="OLLAMA_MODEL")

    # Database
    database_url: str = Field(
        default="sqlite:///./data/honeypot.db",
        alias="DATABASE_URL",
    )
    database_echo: bool = Field(default=False, alias="DATABASE_ECHO")

    # Storage
    output_base_path: Path = Field(
        default=Path("./data/generated"),
        alias="OUTPUT_BASE_PATH",
    )
    template_path: Path = Field(
        default=Path("./ai-brain/content-generator/templates"),
        alias="TEMPLATE_PATH",
    )

    # Logging
    log_level: LogLevel = Field(default=LogLevel.INFO, alias="LOG_LEVEL")
    log_format: str = Field(default="json", alias="LOG_FORMAT")
    log_file: Optional[Path] = Field(default=None, alias="LOG_FILE")

    # Security
    max_file_size_mb: int = Field(default=10, alias="MAX_FILE_SIZE_MB")
    allowed_file_types: list[str] = Field(
        default=[
            ".py",
            ".js",
            ".sh",
            ".go",
            ".conf",
            ".yml",
            ".yaml",
            ".json",
            ".txt",
            ".md",
            ".log",
        ],
        alias="ALLOWED_FILE_TYPES",
    )

    # Content Generation
    enable_caching: bool = Field(default=True, alias="ENABLE_CACHING")
    cache_ttl_seconds: int = Field(default=3600, alias="CACHE_TTL_SECONDS")
    uniqueness_threshold: float = Field(default=0.8, alias="UNIQUENESS_THRESHOLD")
    realism_threshold: float = Field(default=0.7, alias="REALISM_THRESHOLD")

    # Rate Limiting
    rate_limit_enabled: bool = Field(default=True, alias="RATE_LIMIT_ENABLED")
    rate_limit_requests: int = Field(default=100, alias="RATE_LIMIT_REQUESTS")
    rate_limit_period: int = Field(default=60, alias="RATE_LIMIT_PERIOD")

    @field_validator("output_base_path", "template_path")
    @classmethod
    def validate_path(cls, v: Path) -> Path:
        """Ensure path is absolute."""
        if not v.is_absolute():
            return Path.cwd() / v
        return v

    @field_validator("llm_temperature")
    @classmethod
    def validate_temperature(cls, v: float) -> float:
        """Validate temperature is between 0 and 2."""
        if not 0 <= v <= 2:
            raise ValueError("Temperature must be between 0 and 2")
        return v

    @field_validator("llm_max_tokens")
    @classmethod
    def validate_max_tokens(cls, v: int) -> int:
        """Validate max tokens is positive."""
        if v <= 0:
            raise ValueError("Max tokens must be positive")
        return v

    def get_api_key(self) -> Optional[str]:
        """Get API key based on provider."""
        if self.llm_provider == LLMProvider.OPENAI:
            return self.openai_api_key
        elif self.llm_provider == LLMProvider.AZURE_OPENAI:
            return self.azure_openai_api_key
        return None

    def validate_provider_config(self) -> None:
        """Validate provider-specific configuration."""
        if self.llm_provider == LLMProvider.OPENAI and not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY is required for OpenAI provider")
        elif self.llm_provider == LLMProvider.AZURE_OPENAI:
            if not all(
                [
                    self.azure_openai_api_key,
                    self.azure_openai_endpoint,
                    self.azure_openai_deployment,
                ]
            ):
                raise ValueError(
                    "AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, and "
                    "AZURE_OPENAI_DEPLOYMENT are required for Azure OpenAI provider"
                )


# Global settings instance
settings = Settings()
