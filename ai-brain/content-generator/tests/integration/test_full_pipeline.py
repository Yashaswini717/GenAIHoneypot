import pytest
from pathlib import Path


@pytest.mark.asyncio
async def test_full_generation_pipeline(llm_client, temp_dir):
    """Test complete generation pipeline."""
    from generators.honeytokens import HoneytokenGenerator
    from populator.filesystem import FilesystemPopulator
    
    # Generate honeytoken
    token_gen = HoneytokenGenerator(llm_client)
    token_result = await token_gen.generate({"token_type": "api_token"})
    
    assert token_result.is_valid
    assert len(token_result.content) > 20
    
    # Deploy to filesystem
    populator = FilesystemPopulator(base_path=temp_dir)
    
    context = {
        "files": [
            {
                "path": ".env",
                "content": f"API_KEY={token_result.content}",
                "permissions": 0o600,
            }
        ]
    }
    
    pop_result = await populator.populate("test-honeypot", context)
    
    assert pop_result.success
    assert pop_result.files_created == 1
    
    # Verify file exists
    env_file = temp_dir / "test-honeypot" / ".env"
    assert env_file.exists()
    assert token_result.content in env_file.read_text()


@pytest.mark.asyncio
async def test_honeytoken_tracking(llm_client, honeytoken_store):
    """Test end-to-end honeytoken tracking."""
    from generators.honeytokens import HoneytokenGenerator
    from storage.models import HoneytokenCreate
    
    # Generate token
    token_gen = HoneytokenGenerator(llm_client)
    result = await token_gen.generate({"token_type": "github_token"})
    
    # Store in database
    token_create = HoneytokenCreate(
        token_type="github_token",
        token_value=result.content,
        honeypot_id="tracking-test",
    )
    
    stored_token = honeytoken_store.create_honeytoken(token_create)
    
    # Simulate access
    accessed = honeytoken_store.check_honeytoken(result.content)
    
    assert accessed is not None
    assert accessed.token_id == stored_token.token_id
    assert accessed.access_count == 1
