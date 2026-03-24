from fastapi import APIRouter, Depends

from api.dependencies import get_generation_log, get_honeytoken_store
from api.schemas.responses import HealthResponse, MetricsResponse
from config.settings import settings
from storage.generation_log import GenerationLog
from storage.honeytoken_store import HoneytokenStore

router = APIRouter(prefix="/api/v1", tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        version=settings.app_version,
        llm_provider=settings.llm_provider.value,
        database=settings.database_url.split(":")[0],
    )


@router.get("/metrics", response_model=MetricsResponse)
async def get_metrics(
    gen_log: GenerationLog = Depends(get_generation_log),
    token_store: HoneytokenStore = Depends(get_honeytoken_store),
):
    """Get system metrics."""
    # This is a simplified version - in production, use proper metrics collection
    all_logs = gen_log.get_logs(limit=10000)
    all_tokens = token_store.list_honeytokens(active_only=False, limit=10000)
    active_tokens = token_store.list_honeytokens(active_only=True, limit=10000)
    
    # Calculate metrics
    avg_score = sum(log.validation_score for log in all_logs) / len(all_logs) if all_logs else 0.0
    
    generations_by_type = {}
    for log in all_logs:
        generations_by_type[log.content_type] = generations_by_type.get(log.content_type, 0) + 1
    
    return MetricsResponse(
        total_generations=len(all_logs),
        total_honeytokens=len(all_tokens),
        active_honeytokens=len(active_tokens),
        average_validation_score=avg_score,
        generations_by_type=generations_by_type,
    )
