from typing import AsyncGenerator

from config.settings import settings
from core.adaptive_engine import AdaptiveDecisionEngine
from core.llm_client import LLMClient
from core.reward import RewardCalculator
from populator.filesystem import FilesystemPopulator
from populator.strategies import PopulationStrategy
from storage.adaptive_store import AdaptiveLearningStore
from storage.decoy_stock import DecoyStock, StepPacer
from storage.generation_log import GenerationLog
from storage.honeytoken_store import HoneytokenStore

# Singleton instances for shared state across requests
_honeytoken_store: HoneytokenStore | None = None
_adaptive_store: AdaptiveLearningStore | None = None
_adaptive_engine: AdaptiveDecisionEngine | None = None
_decoy_stock: DecoyStock | None = None
_stock_pacer: StepPacer | None = None


def get_decoy_stock() -> DecoyStock | None:
    """The ready-made decoy stock, or None when it is switched off."""
    global _decoy_stock
    if not settings.decoy_stock_enabled:
        return None
    if _decoy_stock is None:
        _decoy_stock = DecoyStock(settings.resolved_decoy_stock_dir(), settings.decoy_stock_per_key)
    return _decoy_stock


async def make_stock_content(context: dict[str, str]) -> tuple[list[dict], list[str]]:
    """Generate one set of model-written files for the stock: (files, failed steps).

    No honeytoken store: stock content carries no credentials, by design.
    """
    client = LLMClient()
    try:
        strategy = PopulationStrategy(client, get_filesystem_populator(), honeytoken_store=None)
        stock = get_decoy_stock()
        if stock is not None:
            # Gentle on the model's rate limit, and an attacker's live
            # generation goes first. One pacer across sets, so the spacing holds.
            global _stock_pacer
            if _stock_pacer is None:
                _stock_pacer = StepPacer(stock, settings.decoy_stock_step_seconds)
            strategy.step_gate = _stock_pacer
        files = await strategy.build_content(context)
        return files, strategy.failures
    finally:
        await client.close()


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
