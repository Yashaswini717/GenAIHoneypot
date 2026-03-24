import pytest
import pytest_asyncio
from pathlib import Path
import tempfile

from core.llm_client import LLMClient
from config.settings import settings
from storage.honeytoken_store import HoneytokenStore
from storage.generation_log import GenerationLog


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def test_database_url(temp_dir):
    """Create temporary test database."""
    return f"sqlite:///{temp_dir}/test.db"


@pytest_asyncio.fixture
async def llm_client():
    """Create LLM client for tests."""
    # Mock or use test API key
    client = LLMClient()
    yield client
    await client.close()


@pytest.fixture
def honeytoken_store(test_database_url):
    """Create honeytoken store for tests."""
    store = HoneytokenStore(database_url=test_database_url)
    yield store
    store.close()


@pytest.fixture
def generation_log(test_database_url):
    """Create generation log for tests."""
    log = GenerationLog(database_url=test_database_url)
    yield log
    log.close()


@pytest.fixture
def sample_context():
    """Sample context for generation."""
    return {
        "language": "python",
        "script_type": "webapp",
        "purpose": "test API server",
    }
