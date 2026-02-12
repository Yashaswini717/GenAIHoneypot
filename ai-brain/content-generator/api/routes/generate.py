import time

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies import get_honeytoken_store, get_llm_client
from api.schemas.requests import (
    ConfigRequest,
    DocumentRequest,
    HoneytokenRequest,
    LogRequest,
    SourceCodeRequest,
)
from api.schemas.responses import GenerateResponse, ValidationDetail
from core.llm_client import LLMClient
from core.utils import calculate_hash, generate_unique_id
from generators.config_files import ConfigGenerator
from generators.honeytokens import HoneytokenGenerator
from generators.source_code import SourceCodeGenerator
from generators.system_logs import SystemLogGenerator
from generators.user_documents import UserDocumentGenerator
from storage.honeytoken_store import HoneytokenStore
from storage.models import HoneytokenCreate

router = APIRouter(prefix="/api/v1/generate", tags=["generation"])


@router.post("/source-code", response_model=GenerateResponse)
async def generate_source_code(
    request: SourceCodeRequest,
    llm_client: LLMClient = Depends(get_llm_client),
):
    """Generate source code."""
    start_time = time.time()
    
    generator = SourceCodeGenerator(llm_client)
    context = {
        "language": request.language,
        "script_type": request.script_type,
        "purpose": request.purpose,
        "artifact_layer": request.artifact_layer.value,
        **request.context,
    }
    
    result = await generator.generate(context)
    generation_time_ms = int((time.time() - start_time) * 1000)
    
    validation = {
        name: ValidationDetail(
            valid=vr.valid,
            score=vr.score,
            errors=vr.errors,
            warnings=vr.warnings,
        )
        for name, vr in result.validation_results.items()
    }
    
    return GenerateResponse(
        generation_id=generate_unique_id(),
        content=result.content,
        content_type=result.content_type,
        file_type=result.file_type,
        metadata={**result.metadata, "generation_time_ms": generation_time_ms},
        validation=validation,
        is_valid=result.is_valid,
        overall_score=result.overall_score,
    )


@router.post("/config", response_model=GenerateResponse)
async def generate_config(
    request: ConfigRequest,
    llm_client: LLMClient = Depends(get_llm_client),
):
    """Generate configuration file."""
    start_time = time.time()
    
    generator = ConfigGenerator(llm_client)
    context = {
        "config_type": request.config_type,
        "persona": request.persona,
        "artifact_layer": request.artifact_layer.value,
        **request.context,
    }
    
    result = await generator.generate(context)
    generation_time_ms = int((time.time() - start_time) * 1000)
    
    validation = {
        name: ValidationDetail(
            valid=vr.valid,
            score=vr.score,
            errors=vr.errors,
            warnings=vr.warnings,
        )
        for name, vr in result.validation_results.items()
    }
    
    return GenerateResponse(
        generation_id=generate_unique_id(),
        content=result.content,
        content_type=result.content_type,
        file_type=result.file_type,
        metadata={**result.metadata, "generation_time_ms": generation_time_ms},
        validation=validation,
        is_valid=result.is_valid,
        overall_score=result.overall_score,
    )


@router.post("/logs", response_model=GenerateResponse)
async def generate_logs(
    request: LogRequest,
    llm_client: LLMClient = Depends(get_llm_client),
):
    """Generate system logs."""
    start_time = time.time()
    
    generator = SystemLogGenerator(llm_client)
    context = {
        "log_type": request.log_type,
        "duration_hours": request.duration_hours,
        "attack_activity": request.attack_activity,
        "log_category": request.log_category.value if request.log_category else "system",
        "log_format": request.log_format,
        "industry": request.industry,
        "compliance": request.compliance,
        "artifact_layer": request.artifact_layer.value,
        **request.context,
    }
    
    result = await generator.generate(context)
    generation_time_ms = int((time.time() - start_time) * 1000)
    
    validation = {
        name: ValidationDetail(
            valid=vr.valid,
            score=vr.score,
            errors=vr.errors,
            warnings=vr.warnings,
        )
        for name, vr in result.validation_results.items()
    }
    
    return GenerateResponse(
        generation_id=generate_unique_id(),
        content=result.content,
        content_type=result.content_type,
        file_type=result.file_type,
        metadata={**result.metadata, "generation_time_ms": generation_time_ms},
        validation=validation,
        is_valid=result.is_valid,
        overall_score=result.overall_score,
    )


@router.post("/document", response_model=GenerateResponse)
async def generate_document(
    request: DocumentRequest,
    llm_client: LLMClient = Depends(get_llm_client),
):
    """Generate user document."""
    start_time = time.time()
    
    generator = UserDocumentGenerator(llm_client)
    context = {
        "doc_type": request.doc_type,
        "persona": request.persona,
        "topic": request.topic,
        "audience": request.audience.value if request.audience else "internal",
        "realism_level": request.realism_level.value if request.realism_level else "high",
        "hide_honeypot_concepts": request.hide_honeypot_concepts,
        "industry": request.industry,
        "compliance": request.compliance,
        "artifact_layer": request.artifact_layer.value,
        **request.context,
    }
    
    result = await generator.generate(context)
    generation_time_ms = int((time.time() - start_time) * 1000)
    
    validation = {
        name: ValidationDetail(
            valid=vr.valid,
            score=vr.score,
            errors=vr.errors,
            warnings=vr.warnings,
        )
        for name, vr in result.validation_results.items()
    }
    
    return GenerateResponse(
        generation_id=generate_unique_id(),
        content=result.content,
        content_type=result.content_type,
        file_type=result.file_type,
        metadata={**result.metadata, "generation_time_ms": generation_time_ms},
        validation=validation,
        is_valid=result.is_valid,
        overall_score=result.overall_score,
    )


@router.post("/honeytoken", response_model=GenerateResponse)
async def generate_honeytoken(
    request: HoneytokenRequest,
    llm_client: LLMClient = Depends(get_llm_client),
    honeytoken_store: HoneytokenStore = Depends(get_honeytoken_store),
):
    """Generate honeytoken and persist it to the store."""
    start_time = time.time()
    
    generator = HoneytokenGenerator(llm_client)
    context = {
        "token_type": request.token_type,
        **request.context,
    }
    
    result = await generator.generate(context)
    generation_time_ms = int((time.time() - start_time) * 1000)
    
    # Persist the generated honeytoken to the store
    token_create = HoneytokenCreate(
        token_type=request.token_type,
        token_value=result.content,
        honeypot_id=request.honeypot_id,
        file_path=request.context.get("file_path"),
        token_metadata={
            "generation_time_ms": generation_time_ms,
            **result.metadata,
        },
    )
    stored_token = honeytoken_store.create_honeytoken(token_create)
    
    validation = {
        name: ValidationDetail(
            valid=vr.valid,
            score=vr.score,
            errors=vr.errors,
            warnings=vr.warnings,
        )
        for name, vr in result.validation_results.items()
    }
    
    return GenerateResponse(
        generation_id=stored_token.token_id,  # Use the stored token_id as generation_id
        content=result.content,
        content_type=result.content_type,
        file_type=result.file_type,
        metadata={
            **result.metadata,
            "generation_time_ms": generation_time_ms,
            "token_id": stored_token.token_id,
            "honeypot_id": request.honeypot_id,
        },
        validation=validation,
        is_valid=result.is_valid,
        overall_score=result.overall_score,
    )
