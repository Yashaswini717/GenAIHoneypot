import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker
from storage.models import Base, HoneytokenDB, GenerationLogDB, HoneytokenCreate, GenerationLogCreate


def test_honeytoken_db_uses_token_metadata():
    """Test that HoneytokenDB uses token_metadata instead of metadata."""
    # Get columns from HoneytokenDB
    columns = [c.name for c in HoneytokenDB.__table__.columns]
    
    # Should have token_metadata, not metadata
    assert 'token_metadata' in columns
    assert 'metadata' not in columns
    
    # Should not conflict with SQLAlchemy's Base.metadata
    assert hasattr(Base, 'metadata')
    assert Base.metadata is not None


def test_generation_log_db_uses_token_metadata():
    """Test that GenerationLogDB uses token_metadata instead of metadata."""
    # Get columns from GenerationLogDB
    columns = [c.name for c in GenerationLogDB.__table__.columns]
    
    # Should have token_metadata, not metadata
    assert 'token_metadata' in columns
    assert 'metadata' not in columns


def test_honeytoken_create_pydantic_model():
    """Test that HoneytokenCreate Pydantic model uses token_metadata."""
    # Create instance
    honeytoken = HoneytokenCreate(
        token_type="aws_access_key",
        token_value="AKIAIOSFODNN7EXAMPLE",
        token_metadata={"test": "value"}
    )
    
    # Should have token_metadata attribute
    assert hasattr(honeytoken, 'token_metadata')
    assert honeytoken.token_metadata == {"test": "value"}


def test_generation_log_create_pydantic_model():
    """Test that GenerationLogCreate Pydantic model uses token_metadata."""
    # Create instance
    log = GenerationLogCreate(
        content_type="source_code",
        file_type="python",
        prompt_hash="abc123",
        validation_score=0.95,
        is_valid=True,
        generation_time_ms=1500,
        token_metadata={"model": "gpt-4"}
    )
    
    # Should have token_metadata attribute
    assert hasattr(log, 'token_metadata')
    assert log.token_metadata == {"model": "gpt-4"}


def test_database_operations_with_token_metadata():
    """Test that database operations work with token_metadata."""
    # Create in-memory database
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    
    with SessionLocal() as session:
        # Create honeytoken with token_metadata
        honeytoken = HoneytokenDB(
            token_id="test-token-123",
            token_type="aws_access_key",
            token_value="AKIAIOSFODNN7EXAMPLE",
            token_metadata={"source": "test", "validated": True}
        )
        session.add(honeytoken)
        session.commit()
        session.refresh(honeytoken)
        
        # Verify it was saved correctly
        assert honeytoken.id is not None
        assert honeytoken.token_metadata == {"source": "test", "validated": True}
        
        # Query it back
        result = session.query(HoneytokenDB).filter_by(token_id="test-token-123").first()
        assert result is not None
        assert result.token_metadata == {"source": "test", "validated": True}


def test_no_sqlalchemy_metadata_conflict():
    """Test that there's no conflict with SQLAlchemy's metadata."""
    # This would raise an error if metadata column conflicts with Base.metadata
    try:
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        
        # Inspect the tables
        inspector = inspect(engine)
        tables = inspector.get_table_names()
        
        assert 'honeytokens' in tables
        assert 'generation_logs' in tables
        
        # Check columns
        honeytoken_cols = [col['name'] for col in inspector.get_columns('honeytokens')]
        assert 'token_metadata' in honeytoken_cols
        assert 'metadata' not in honeytoken_cols
        
    except Exception as e:
        if 'metadata' in str(e).lower() and 'reserved' in str(e).lower():
            pytest.fail(f"SQLAlchemy metadata conflict detected: {e}")
        raise
