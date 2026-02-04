import pytest
from unittest.mock import patch
import os


def test_openrouter_default_settings():
    """Test that default settings use OpenRouter configuration."""
    # Clear environment to get true defaults
    with patch.dict(os.environ, {}, clear=True):
        from config.settings import Settings

        settings = Settings(_env_file=None)

        # Should default to OpenRouter base URL
        assert settings.openai_base_url == "https://openrouter.ai/api/v1"

        # Should default to Google Gemini 2.0 Flash model
        assert settings.llm_model == "google/gemini-2.0-flash-exp:free"


def test_openrouter_custom_settings():
    """Test custom OpenRouter settings."""
    env_vars = {
        "OPENAI_API_KEY": "sk-or-v1-test-key",
        "OPENAI_BASE_URL": "https://openrouter.ai/api/v1",
        "LLM_MODEL": "google/gemini-2.0-flash-exp:free",
    }

    with patch.dict(os.environ, env_vars, clear=True):
        from config.settings import Settings

        settings = Settings(_env_file=None)

        assert settings.openai_api_key == "sk-or-v1-test-key"
        assert settings.openai_base_url == "https://openrouter.ai/api/v1"
        assert settings.llm_model == "google/gemini-2.0-flash-exp:free"


def test_openai_direct_settings():
    """Test that direct OpenAI settings can override OpenRouter."""
    env_vars = {
        "OPENAI_API_KEY": "sk-test-key",
        "OPENAI_BASE_URL": "https://api.openai.com/v1",
        "LLM_MODEL": "gpt-4-turbo-preview",
    }

    with patch.dict(os.environ, env_vars, clear=True):
        from config.settings import Settings

        settings = Settings(_env_file=None)

        assert settings.openai_api_key == "sk-test-key"
        assert settings.openai_base_url == "https://api.openai.com/v1"
        assert settings.llm_model == "gpt-4-turbo-preview"


def test_llm_client_accepts_base_url():
    """Test that LLM client can be initialized with custom base_url."""
    # This test verifies that the LLMClient code accepts base_url parameter
    from config import settings as settings_module

    # Patch settings to have test values
    with patch.object(settings_module.settings, "openai_api_key", "test-key"):
        with patch.object(
            settings_module.settings, "openai_base_url", "https://openrouter.ai/api/v1"
        ):
            with patch.object(
                settings_module.settings,
                "llm_model",
                "google/gemini-2.0-flash-exp:free",
            ):
                from core.llm_client import LLMClient

                # This should not raise an error
                client = LLMClient()

                # Verify client attributes
                assert client.model == "google/gemini-2.0-flash-exp:free"
                assert hasattr(client, "client")


def test_openrouter_headers():
    """Test that OpenRouter-specific headers are set."""
    from config import settings as settings_module

    with patch.object(settings_module.settings, "openai_api_key", "sk-or-v1-test"):
        with patch.object(settings_module.settings, "openai_base_url", "https://openrouter.ai/api/v1"):
            with patch.object(settings_module.settings, "llm_model", "google/gemini-2.0-flash-exp:free"):
                from core.llm_client import LLMClient
                client = LLMClient()
                # Verify headers are set for OpenRouter
                assert hasattr(client, "client")
                # The client should have default_headers set when using OpenRouter
                assert client.client.default_headers is not None
                assert "HTTP-Referer" in client.client.default_headers
                assert "X-Title" in client.client.default_headers
                assert client.client.default_headers["HTTP-Referer"] == "https://github.com/gowrishn17/honeypot_ai"
                assert client.client.default_headers["X-Title"] == "Honeypot AI Content Generator"


def test_direct_openai_no_openrouter_headers():
    """Test that OpenRouter headers are NOT set when using direct OpenAI."""
    from config import settings as settings_module

    with patch.object(settings_module.settings, "openai_api_key", "sk-test-key"):
        with patch.object(settings_module.settings, "openai_base_url", "https://api.openai.com/v1"):
            with patch.object(settings_module.settings, "llm_model", "gpt-4-turbo-preview"):
                from core.llm_client import LLMClient
                client = LLMClient()
                # Verify headers are NOT set for direct OpenAI
                assert hasattr(client, "client")
                # The client will have its own default headers, but not our custom OpenRouter headers
                headers = dict(client.client.default_headers) if client.client.default_headers else {}
                assert "HTTP-Referer" not in headers
                assert "X-Title" not in headers


def test_settings_with_env_variables():
    """Test that settings can be loaded from environment variables."""
    env_vars = {
        "OPENAI_API_KEY": "sk-or-v1-env-key",
        "OPENAI_BASE_URL": "https://openrouter.ai/api/v1",
        "LLM_MODEL": "qwen/qwen-2.5-7b-instruct:free",
    }

    with patch.dict(os.environ, env_vars, clear=True):
        from config.settings import Settings

        settings = Settings(_env_file=None)

        assert settings.openai_api_key == "sk-or-v1-env-key"
        assert settings.openai_base_url == "https://openrouter.ai/api/v1"
        assert settings.llm_model == "qwen/qwen-2.5-7b-instruct:free"
