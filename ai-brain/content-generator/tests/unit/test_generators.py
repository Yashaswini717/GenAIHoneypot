import pytest
from generators.source_code import SourceCodeGenerator
from generators.config_files import ConfigGenerator
from generators.honeytokens import HoneytokenGenerator


@pytest.mark.asyncio
async def test_source_code_generator(llm_client):
    """Test source code generation."""
    generator = SourceCodeGenerator(llm_client)
    
    context = {
        "language": "python",
        "script_type": "webapp",
        "purpose": "Flask API",
    }
    
    # This would require actual LLM or mocking
    # For now, just test initialization
    assert generator is not None
    assert generator.llm_client is not None


@pytest.mark.asyncio
async def test_honeytoken_generator(llm_client):
    """Test honeytoken generation."""
    generator = HoneytokenGenerator(llm_client)
    
    # Test AWS key generation
    context = {"token_type": "aws_access_key"}
    result = await generator.generate(context)
    
    assert result.content.startswith("AKIA")
    assert len(result.content) == 20
    assert result.metadata["is_honeytoken"] is True


@pytest.mark.asyncio
async def test_github_token_generation(llm_client):
    """Test GitHub token generation."""
    generator = HoneytokenGenerator(llm_client)
    
    context = {"token_type": "github_token"}
    result = await generator.generate(context)
    
    assert result.content.startswith("ghp_")
    assert len(result.content) == 40


@pytest.mark.asyncio
async def test_ssh_key_generation(llm_client):
    """Test SSH private key generation."""
    generator = HoneytokenGenerator(llm_client)
    
    context = {"token_type": "ssh_private_key"}
    result = await generator.generate(context)
    
    assert "BEGIN OPENSSH PRIVATE KEY" in result.content
    assert "END OPENSSH PRIVATE KEY" in result.content
