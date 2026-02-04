from typing import Optional

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from config.logging_config import LoggerMixin
from config.settings import settings
from core.exceptions import DatabaseError
from core.utils import generate_unique_id

from .models import Base, GenerationLogCreate, GenerationLogDB, GenerationLogResponse


class GenerationLog(LoggerMixin):
    """Log all content generation operations."""

    def __init__(self, database_url: Optional[str] = None):
        """Initialize generation log."""
        self.database_url = database_url or settings.database_url
        self.engine = create_engine(self.database_url, echo=settings.database_echo)
        self.SessionLocal = sessionmaker(bind=self.engine)
        Base.metadata.create_all(self.engine)
        self.logger.info("generation_log_initialized")

    def log_generation(self, log_entry: GenerationLogCreate) -> GenerationLogResponse:
        """Log a generation operation."""
        try:
            with self.SessionLocal() as session:
                db_log = GenerationLogDB(
                    generation_id=generate_unique_id(),
                    content_type=log_entry.content_type,
                    file_type=log_entry.file_type,
                    honeypot_id=log_entry.honeypot_id,
                    prompt_hash=log_entry.prompt_hash,
                    validation_score=log_entry.validation_score,
                    is_valid=log_entry.is_valid,
                    generation_time_ms=log_entry.generation_time_ms,
                    token_metadata=log_entry.token_metadata,
                )
                session.add(db_log)
                session.commit()
                session.refresh(db_log)
                return GenerationLogResponse.model_validate(db_log)
        except Exception as e:
            self.logger.error("generation_log_failed", error=str(e))
            raise DatabaseError(f"Failed to log generation: {e}") from e

    def get_logs(
        self,
        honeypot_id: Optional[str] = None,
        content_type: Optional[str] = None,
        limit: int = 100,
    ) -> list[GenerationLogResponse]:
        """Get generation logs with filters."""
        try:
            with self.SessionLocal() as session:
                stmt = select(GenerationLogDB)
                if honeypot_id:
                    stmt = stmt.where(GenerationLogDB.honeypot_id == honeypot_id)
                if content_type:
                    stmt = stmt.where(GenerationLogDB.content_type == content_type)
                stmt = stmt.limit(limit).order_by(GenerationLogDB.created_at.desc())
                results = session.execute(stmt).scalars().all()
                return [GenerationLogResponse.model_validate(r) for r in results]
        except Exception as e:
            self.logger.error("get_logs_failed", error=str(e))
            raise DatabaseError(f"Failed to get logs: {e}") from e
