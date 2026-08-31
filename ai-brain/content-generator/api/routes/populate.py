from fastapi import APIRouter, Depends

from api.dependencies import get_llm_client, get_population_strategy
from api.schemas.requests import PopulateRequest
from api.schemas.responses import PopulateResponse
from core.llm_client import LLMClient
from core.utils import sanitize_filename
from populator.strategies import PopulationStrategy

router = APIRouter(prefix="/api/v1/populate", tags=["population"])


def _sanitize_honeypot_id(honeypot_id: str) -> str:
    """Sanitize honeypot_id to be safe for filesystem paths."""
    return sanitize_filename(honeypot_id)


@router.post("/{honeypot_id}", response_model=PopulateResponse)
async def populate_honeypot(
    honeypot_id: str,
    request: PopulateRequest,
    llm_client: LLMClient = Depends(get_llm_client),
):
    """Populate honeypot with generated content."""
    # Sanitize honeypot_id for safe filesystem use
    safe_honeypot_id = _sanitize_honeypot_id(honeypot_id)
    
    strategy = await get_population_strategy(llm_client)
    
    context = {
        "profile": request.profile,
        "custom_files": request.custom_files,
        **request.context,
    }
    
    result = await strategy.populate(safe_honeypot_id, context)
    
    return PopulateResponse(
        honeypot_id=safe_honeypot_id,
        success=result.success,
        files_created=result.files_created,
        errors=result.errors,
        honeypot_path=result.metadata.get("honeypot_path", ""),
    )


@router.post("/{honeypot_id}/profile/{profile_name}", response_model=PopulateResponse)
async def populate_with_profile(
    honeypot_id: str,
    profile_name: str,
    llm_client: LLMClient = Depends(get_llm_client),
):
    """Populate honeypot using predefined profile."""
    # Sanitize honeypot_id for safe filesystem use
    safe_honeypot_id = _sanitize_honeypot_id(honeypot_id)
    
    strategy = await get_population_strategy(llm_client)
    
    context = {"profile": profile_name}
    result = await strategy.populate(safe_honeypot_id, context)
    
    return PopulateResponse(
        honeypot_id=safe_honeypot_id,
        success=result.success,
        files_created=result.files_created,
        errors=result.errors,
        honeypot_path=result.metadata.get("honeypot_path", ""),
    )
