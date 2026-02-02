import asyncio
from typing import Any

import httpx
from openai import AsyncAzureOpenAI, AsyncOpenAI

from config.logging_config import LoggerMixin
from config.settings import LLMProvider, settings
from core.exceptions import (
    LLMAuthenticationError,
    LLMConnectionError,
    LLMInvalidResponseError,
    LLMRateLimitError,
    LLMTimeoutError,
)


class LLMClient(LoggerMixin):
    """
    Unified LLM client supporting multiple providers.

    Supports OpenAI, Azure OpenAI, and Ollama with async operations,
    automatic retries, and timeout handling.
    """

    def __init__(self):
        """Initialize LLM client based on configured provider."""
        self.provider = settings.llm_provider
        self.model = settings.llm_model
        self.temperature = settings.llm_temperature
        self.max_tokens = settings.llm_max_tokens
        self.timeout = settings.llm_timeout
        self.max_retries = settings.llm_max_retries
        self.retry_delay = settings.llm_retry_delay

        # Initialize provider-specific client
        if self.provider == LLMProvider.OPENAI:
            self._init_openai()
        elif self.provider == LLMProvider.AZURE_OPENAI:
            self._init_azure_openai()
        elif self.provider == LLMProvider.OLLAMA:
            self._init_ollama()

        self.logger.info(
            "llm_client_initialized",
            provider=self.provider.value,
            model=self.model,
        )

    def _init_openai(self) -> None:
        """Initialize OpenAI client."""
        if not settings.openai_api_key:
            raise LLMAuthenticationError("OpenAI API key not configured")

        # Build default headers for OpenRouter compatibility
        default_headers = {}
        if "openrouter.ai" in (settings.openai_base_url or ""):
            default_headers = {
                "HTTP-Referer": "https://github.com/gowrishn17/honeypot_ai",
                "X-Title": "Honeypot AI Content Generator",
            }

        self.client = AsyncOpenAI(
            api_key=settings.openai_api_key,
            organization=settings.openai_org_id,
            base_url=settings.openai_base_url,
            timeout=self.timeout,
            max_retries=0,  # We handle retries manually
            default_headers=default_headers if default_headers else None,
        )

    def _init_azure_openai(self) -> None:
        """Initialize Azure OpenAI client."""
        if not all([
            settings.azure_openai_api_key,
            settings.azure_openai_endpoint,
            settings.azure_openai_deployment,
        ]):
            raise LLMAuthenticationError("Azure OpenAI configuration incomplete")

        self.client = AsyncAzureOpenAI(
            api_key=settings.azure_openai_api_key,
            azure_endpoint=settings.azure_openai_endpoint,
            api_version=settings.azure_openai_api_version,
            timeout=self.timeout,
            max_retries=0,
        )
        self.model = settings.azure_openai_deployment

    def _init_ollama(self) -> None:
        """Initialize Ollama client."""
        self.base_url = settings.ollama_base_url
        self.model = settings.ollama_model
        self.client = httpx.AsyncClient(timeout=self.timeout)

    async def generate(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """
        Generate content using configured LLM.

        Args:
            prompt: User prompt
            system_prompt: System prompt (optional)
            temperature: Override default temperature
            max_tokens: Override default max tokens

        Returns:
            Generated text

        Raises:
            LLMError: If generation fails
        """
        temperature = temperature if temperature is not None else self.temperature
        max_tokens = max_tokens if max_tokens is not None else self.max_tokens

        self.logger.debug(
            "llm_generate_start",
            provider=self.provider.value,
            prompt_length=len(prompt),
            temperature=temperature,
        )

        # Retry logic
        for attempt in range(self.max_retries):
            try:
                if self.provider in [LLMProvider.OPENAI, LLMProvider.AZURE_OPENAI]:
                    result = await self._generate_openai(prompt, system_prompt, temperature, max_tokens)
                else:
                    result = await self._generate_ollama(prompt, system_prompt, temperature, max_tokens)

                self.logger.info(
                    "llm_generate_success",
                    provider=self.provider.value,
                    output_length=len(result),
                    attempt=attempt + 1,
                )
                return result

            except (LLMTimeoutError, LLMConnectionError, LLMRateLimitError) as e:
                if attempt < self.max_retries - 1:
                    wait_time = self.retry_delay * (2 ** attempt)  # Exponential backoff
                    self.logger.warning(
                        "llm_generate_retry",
                        error=str(e),
                        attempt=attempt + 1,
                        wait_time=wait_time,
                    )
                    await asyncio.sleep(wait_time)
                else:
                    self.logger.error(
                        "llm_generate_failed",
                        error=str(e),
                        attempts=self.max_retries,
                    )
                    raise

        raise LLMConnectionError("Max retries exceeded")

    async def _generate_openai(
        self,
        prompt: str,
        system_prompt: str | None,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Generate using OpenAI/Azure OpenAI."""
        try:
            messages = []
            if system_prompt:
                messages.append({"role": "system", "content": system_prompt})
            messages.append({"role": "user", "content": prompt})

            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )

            if not response.choices:
                raise LLMInvalidResponseError("No choices in response")

            content = response.choices[0].message.content
            if not content:
                raise LLMInvalidResponseError("Empty content in response")

            return content.strip()

        except asyncio.TimeoutError as e:
            raise LLMTimeoutError(f"Request timed out after {self.timeout}s") from e
        except Exception as e:
            error_msg = str(e).lower()
            if "rate limit" in error_msg or "429" in error_msg:
                raise LLMRateLimitError("Rate limit exceeded") from e
            elif "authentication" in error_msg or "401" in error_msg:
                raise LLMAuthenticationError("Authentication failed") from e
            elif "connection" in error_msg or "timeout" in error_msg:
                raise LLMConnectionError("Connection failed") from e
            else:
                raise LLMInvalidResponseError(f"Unexpected error: {e}") from e

    async def _generate_ollama(
        self,
        prompt: str,
        system_prompt: str | None,
        temperature: float,
        max_tokens: int,
    ) -> str:
        """Generate using Ollama."""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "system": system_prompt or "",
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            }

            response = await self.client.post(
                f"{self.base_url}/api/generate",
                json=payload,
            )
            response.raise_for_status()

            data = response.json()
            if "response" not in data:
                raise LLMInvalidResponseError("Invalid response format")

            return data["response"].strip()

        except httpx.TimeoutException as e:
            raise LLMTimeoutError(f"Request timed out after {self.timeout}s") from e
        except httpx.ConnectError as e:
            raise LLMConnectionError(f"Cannot connect to Ollama at {self.base_url}") from e
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise LLMRateLimitError("Rate limit exceeded") from e
            elif e.response.status_code == 401:
                raise LLMAuthenticationError("Authentication failed") from e
            else:
                raise LLMConnectionError(f"HTTP error {e.response.status_code}") from e
        except Exception as e:
            raise LLMInvalidResponseError(f"Unexpected error: {e}") from e

    async def close(self) -> None:
        """Close client connections."""
        if self.provider == LLMProvider.OLLAMA and hasattr(self, "client"):
            await self.client.aclose()
        elif hasattr(self, "client"):
            await self.client.close()

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
