import pytest
from storage.models import HoneytokenCreate


def test_create_honeytoken(honeytoken_store):
    """Test honeytoken creation."""
    token = HoneytokenCreate(
        token_type="aws_access_key",
        token_value="AKIAIOSFODNN7EXAMPLE",
        honeypot_id="test-001",
    )
    
    result = honeytoken_store.create_honeytoken(token)
    
    assert result.token_id is not None
    assert result.token_type == "aws_access_key"
    assert result.token_value == "AKIAIOSFODNN7EXAMPLE"
    assert result.access_count == 0


def test_check_honeytoken(honeytoken_store):
    """Test honeytoken checking."""
    # Create honeytoken
    token = HoneytokenCreate(
        token_type="api_token",
        token_value="secret_token_123",
        honeypot_id="test-001",
    )
    honeytoken_store.create_honeytoken(token)
    
    # Check it
    result = honeytoken_store.check_honeytoken("secret_token_123")
    
    assert result is not None
    assert result.access_count == 1
    
    # Check again
    result = honeytoken_store.check_honeytoken("secret_token_123")
    assert result.access_count == 2


def test_list_honeytokens(honeytoken_store):
    """Test listing honeytokens."""
    # Create multiple tokens
    for i in range(3):
        token = HoneytokenCreate(
            token_type="test_token",
            token_value=f"token_{i}",
            honeypot_id="test-001",
        )
        honeytoken_store.create_honeytoken(token)
    
    tokens = honeytoken_store.list_honeytokens(honeypot_id="test-001")
    assert len(tokens) == 3


def test_deactivate_honeytoken(honeytoken_store):
    """Test honeytoken deactivation."""
    token = HoneytokenCreate(
        token_type="test",
        token_value="test_value",
    )
    result = honeytoken_store.create_honeytoken(token)
    
    # Deactivate
    success = honeytoken_store.deactivate_honeytoken(result.token_id)
    assert success is True
    
    # Should not appear in active list
    active_tokens = honeytoken_store.list_honeytokens(active_only=True)
    assert len(active_tokens) == 0
