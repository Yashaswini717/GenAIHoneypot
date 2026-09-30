from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from sqlalchemy import text, Boolean, Column, String, Integer, Float, DateTime, Text, Enum
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

    # Who the session belongs to, which is not always who it came from.
    #
    # On a pivot the peer is our own jump host, so src_ip is an internal
    # address: grouping retention by src_ip counts one attacker as several
    # and attributes their deepest sessions to a machine of ours. attacker_id
    # carries the original source address through every hop, so a jump-host
    # session and the pivots that follow it join into one journey.
    attacker_id  = Column(String, index=True)

    # Which experimental arm this attacker was in when the session ran.
    # Recorded per session rather than derived later, because the assignment
    # is a property of the moment and config changes underneath it.
    adaptive     = Column(Boolean, default=True, index=True)

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


#: Columns added after the sessions table already existed in deployments.
#:
#: create_all() creates missing TABLES and silently ignores missing COLUMNS,
#: so a model change alone leaves every existing database without them and
#: every insert failing on a column that is not there. ADD COLUMN IF NOT
#: EXISTS is idempotent, so this is safe to run on every startup and needs no
#: migration tool for a change this size.
_SESSION_COLUMNS = (
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS attacker_id VARCHAR",
    "ALTER TABLE sessions ADD COLUMN IF NOT EXISTS adaptive BOOLEAN DEFAULT TRUE",
    "CREATE INDEX IF NOT EXISTS ix_sessions_attacker_id ON sessions (attacker_id)",
    "CREATE INDEX IF NOT EXISTS ix_sessions_adaptive ON sessions (adaptive)",
)


async def init_postgres():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for statement in _SESSION_COLUMNS:
            await conn.execute(text(statement))
    print("✓ PostgreSQL tables ready")


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session