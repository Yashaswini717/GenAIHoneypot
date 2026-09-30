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


def test_register_is_idempotent_by_value(honeytoken_store):
    """The same decoy value must converge on one row, however often it is sent.

    The sidecar registers a bundle's credentials every time it plants it, and
    the same database password appears in two different bundles, so repeats are
    the normal case.
    """
    token = HoneytokenCreate(
        token_type="database_password",
        token_value="Tr3llis!84m",
        honeypot_id="node-01-jump-10.60.0.5",
    )

    first = honeytoken_store.register_honeytoken(token)
    second = honeytoken_store.register_honeytoken(token)

    assert first.token_id == second.token_id
    assert len(honeytoken_store.list_honeytokens(active_only=False)) == 1


def test_duplicate_values_would_break_the_tripwire(honeytoken_store):
    """Why idempotency is correctness, not tidiness.

    check_honeytoken resolves a value with scalar_one_or_none(), which raises
    when two rows share it. A duplicate would not merely clutter the table — it
    would disable that value's tripwire permanently. Registering twice must
    leave the lookup working.
    """
    token = HoneytokenCreate(token_type="vault_token", token_value="hvs.CAESIJx7Kd0pQ")
    honeytoken_store.register_honeytoken(token)
    honeytoken_store.register_honeytoken(token)

    hit = honeytoken_store.check_honeytoken("hvs.CAESIJx7Kd0pQ")

    assert hit is not None
    assert hit.access_count == 1


def test_register_rearms_a_deactivated_token_without_losing_evidence(honeytoken_store):
    token = HoneytokenCreate(token_type="api_token", token_value="gl-8QxTv2NmKdRw7ZpLcYh")
    created = honeytoken_store.register_honeytoken(token)
    honeytoken_store.check_honeytoken("gl-8QxTv2NmKdRw7ZpLcYh")  # one access on record
    honeytoken_store.deactivate_honeytoken(created.token_id)

    revived = honeytoken_store.register_honeytoken(token)

    assert revived.token_id == created.token_id
    assert revived.is_active is True
    assert revived.access_count == 1, "prior access evidence must survive re-arming"


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
