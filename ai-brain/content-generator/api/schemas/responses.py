from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class ValidationDetail(BaseModel):
    """Validation result detail."""

    valid: bool
    score: float
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class GenerateResponse(BaseModel):
    """Response for content generation."""

    generation_id: str
    content: str
    content_type: str
    file_type: str
    metadata: dict[str, Any]
    validation: dict[str, ValidationDetail]
    is_valid: bool
    overall_score: float
    generated_at: datetime = Field(default_factory=datetime.now)


class PopulateResponse(BaseModel):
    """Response for honeypot population."""

    honeypot_id: str
    success: bool
    files_created: int
    errors: list[str] = Field(default_factory=list)
    honeypot_path: str
    populated_at: datetime = Field(default_factory=datetime.now)


class HoneytokenResponse(BaseModel):
    """Response for honeytoken operations."""

    token_id: str
    token_type: str
    token_value: Optional[str] = None  # Optionally return value for verification
    honeypot_id: Optional[str]
    file_path: Optional[str] = None
    is_active: bool
    created_at: datetime
    accessed_at: Optional[datetime]
    access_count: int
    token_metadata: dict[str, Any] = Field(default_factory=dict)


class HoneytokenCheckResponse(BaseModel):
    """Response for honeytoken check."""

    is_honeytoken: bool
    token_info: Optional[HoneytokenResponse] = None
    message: str


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    version: str
    timestamp: datetime = Field(default_factory=datetime.now)
    llm_provider: str
    database: str


class MetricsResponse(BaseModel):
    """Metrics response."""

    total_generations: int
    total_honeytokens: int
    active_honeytokens: int
    average_validation_score: float
    generations_by_type: dict[str, int]
