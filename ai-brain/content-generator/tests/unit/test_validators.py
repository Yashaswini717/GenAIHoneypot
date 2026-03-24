import pytest
from validators.syntax import SyntaxValidator
from validators.realism import RealismValidator
from validators.security import SecurityValidator


@pytest.mark.asyncio
async def test_python_syntax_validator():
    """Test Python syntax validation."""
    validator = SyntaxValidator()
    
    valid_code = """
def hello():
    print("Hello, World!")
"""
    
    result = await validator.validate(valid_code, {"file_type": "python"})
    assert result.valid is True
    
    invalid_code = "def hello(\n    print 'invalid'"
    result = await validator.validate(invalid_code, {"file_type": "python"})
    assert result.valid is False


@pytest.mark.asyncio
async def test_realism_validator():
    """Test realism validation."""
    validator = RealismValidator()
    
    realistic_code = """
import os
from flask import Flask

app = Flask(__name__)

@app.route('/')
def index():
    return {'status': 'ok'}

if __name__ == '__main__':
    app.run()
"""
    
    result = await validator.validate(realistic_code, {"file_type": "python"})
    assert result.score > 0.5


@pytest.mark.asyncio
async def test_security_validator():
    """Test security validation."""
    validator = SecurityValidator()
    
    # Safe content
    safe_content = "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE  # honeytoken"
    result = await validator.validate(safe_content, {})
    assert result.valid is True
    
    # Suspicious content (real-looking JWT)
    suspicious_content = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    result = await validator.validate(suspicious_content, {})
    # Should have warnings
    assert len(result.warnings) > 0 or len(result.errors) > 0
