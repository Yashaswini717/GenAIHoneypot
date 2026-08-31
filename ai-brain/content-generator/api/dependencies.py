from typing import AsyncGenerator

from config.settings import settings
from core.adaptive_engine import AdaptiveDecisionEngine
from core.llm_client import LLMClient
from core.reward import RewardCalculator
from populator.filesystem import FilesystemPopulator
from populator.strategies import PopulationStrategy
from storage.adaptive_store import AdaptiveLearningStore
from storage.generation_log import GenerationLog
from storage.honeytoken_store import HoneytokenStore

# Singleton instances for shared state across requests
_honeytoken_store: HoneytokenStore | None = None
_adaptive_store: AdaptiveLearningStore | None = None
_adaptive_engine: AdaptiveDecisionEngine | None = None


async def get_llm_client() -> AsyncGenerator[LLMClient, None]:
    """Get LLM client dependency."""
    client = LLMClient()
    try:
        yield client
    finally:
        await client.close()


def get_honeytoken_store() -> HoneytokenStore:
    """Get honeytoken store dependency (singleton)."""
    global _honeytoken_store
    if _honeytoken_store is None:
        _honeytoken_store = HoneytokenStore()
    return _honeytoken_store


def get_generation_log() -> GenerationLog:
    """Get generation log dependency."""
    return GenerationLog()


def get_filesystem_populator() -> FilesystemPopulator:
    """Get filesystem populator dependency."""
    return FilesystemPopulator()


async def get_population_strategy(
    llm_client: LLMClient,
) -> PopulationStrategy:
    """Get population strategy dependency with honeytoken store wired in."""
    filesystem_populator = get_filesystem_populator()
    honeytoken_store = get_honeytoken_store()
    return PopulationStrategy(llm_client, filesystem_populator, honeytoken_store)


def get_adaptive_store() -> AdaptiveLearningStore:
    """Get adaptive (bandit) learning store dependency (singleton)."""
    global _adaptive_store
    if _adaptive_store is None:
        _adaptive_store = AdaptiveLearningStore()
    return _adaptive_store


def get_adaptive_engine() -> AdaptiveDecisionEngine:
    """
    Get the adaptive decision engine dependency (singleton).

    Wires the honeytoken store into the reward calculator so honeytoken
    triggers count as reward signal, not just kill-chain progression.
    """
    global _adaptive_engine
    if _adaptive_engine is None:
        _adaptive_engine = AdaptiveDecisionEngine(
            store=get_adaptive_store(),
            reward_calculator=RewardCalculator(honeytoken_store=get_honeytoken_store()),
        )
    return _adaptive_engine
