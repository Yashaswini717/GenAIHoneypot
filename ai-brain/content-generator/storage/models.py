from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func

Base = declarative_base()


# SQLAlchemy Models
class HoneytokenDB(Base):
    """Database model for honeytokens."""

    __tablename__ = "honeytokens"

    id = Column(Integer, primary_key=True, autoincrement=True)
    token_id = Column(String(100), unique=True, nullable=False, index=True)
    token_type = Column(String(50), nullable=False)
    token_value = Column(Text, nullable=False)
    honeypot_id = Column(String(100), index=True)
    file_path = Column(String(500))
    created_at = Column(DateTime, default=func.now(), nullable=False)
    accessed_at = Column(DateTime)
    access_count = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    token_metadata = Column(JSON)


class GenerationLogDB(Base):
    """Database model for generation logs."""

    __tablename__ = "generation_logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    generation_id = Column(String(100), unique=True, nullable=False, index=True)
    content_type = Column(String(50), nullable=False)
    file_type = Column(String(50))
    honeypot_id = Column(String(100), index=True)
    prompt_hash = Column(String(64))
    validation_score = Column(Float)
    is_valid = Column(Boolean)
    created_at = Column(DateTime, default=func.now(), nullable=False)
    generation_time_ms = Column(Integer)
    token_metadata = Column(JSON)


# Pydantic Models
class HoneytokenCreate(BaseModel):
    """Pydantic model for creating honeytoken."""

    token_type: str
    token_value: str
    honeypot_id: Optional[str] = None
    file_path: Optional[str] = None
    token_metadata: dict = Field(default_factory=dict)


class HoneytokenResponse(BaseModel):
    """Pydantic model for honeytoken response."""

    id: int
    token_id: str
    token_type: str
    token_value: str
    honeypot_id: Optional[str]
    file_path: Optional[str]
    created_at: datetime
    accessed_at: Optional[datetime]
    access_count: int
    is_active: bool
    token_metadata: dict

    class Config:
        from_attributes = True


class HoneytokenAccessLog(BaseModel):
    """Log when honeytoken is accessed."""

    token_id: str
    accessed_at: datetime = Field(default_factory=datetime.now)
    access_source: Optional[str] = None
    access_metadata: dict = Field(default_factory=dict)


class GenerationLogCreate(BaseModel):
    """Pydantic model for creating generation log."""

    content_type: str
    file_type: str
    honeypot_id: Optional[str] = None
    prompt_hash: str
    validation_score: float
    is_valid: bool
    generation_time_ms: int
    token_metadata: dict = Field(default_factory=dict)


class GenerationLogResponse(BaseModel):
    """Pydantic model for generation log response."""

    id: int
    generation_id: str
    content_type: str
    file_type: str
    honeypot_id: Optional[str]
    prompt_hash: str
    validation_score: float
    is_valid: bool
    created_at: datetime
    generation_time_ms: int
    token_metadata: dict

    class Config:
        from_attributes = True
