from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, Enum
from sqlalchemy.dialects.postgresql import ARRAY
from datetime import datetime
import enum

from config import DATABASE_URL

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class AlertStatus(str, enum.Enum):
    open       = "open"
    acked      = "acked"
    escalated  = "escalated"
    suppressed = "suppressed"


class Session(Base):
    __tablename__ = "sessions"

    session_id   = Column(String, primary_key=True)
    src_ip       = Column(String, nullable=False)
    sensor_id    = Column(String)
    protocol     = Column(String, default="ssh")
    started_at   = Column(DateTime, default=datetime.utcnow)
    ended_at     = Column(DateTime, nullable=True)
    duration     = Column(Float, nullable=True)
    event_count  = Column(Integer, default=0)
    login_attempts = Column(Integer, default=0)
    hassh        = Column(String, nullable=True)
    ssh_version  = Column(String, nullable=True)
    country      = Column(String, nullable=True)
    city         = Column(String, nullable=True)
    threat_score = Column(Integer, default=0)
    mitre_tactics = Column(ARRAY(String), default=list)


class Alert(Base):
    __tablename__ = "alerts"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    session_id   = Column(String, nullable=False)
    src_ip       = Column(String, nullable=False)
    alert_type   = Column(String, nullable=False)
    description  = Column(Text)
    threat_score = Column(Integer, default=0)
    mitre_technique = Column(String, nullable=True)
    country      = Column(String, nullable=True)
    status       = Column(Enum(AlertStatus), default=AlertStatus.open)
    created_at   = Column(DateTime, default=datetime.utcnow)
    updated_at   = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


async def init_postgres():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("✓ PostgreSQL tables ready")


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session