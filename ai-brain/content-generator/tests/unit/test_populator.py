import pytest
from populator.filesystem import FilesystemPopulator
from datetime import datetime


@pytest.mark.asyncio
async def test_filesystem_populator(temp_dir):
    """Test filesystem population."""
    populator = FilesystemPopulator(base_path=temp_dir)
    
    context = {
        "files": [
            {
                "path": "test.txt",
                "content": "Hello, World!",
                "permissions": 0o644,
            },
            {
                "path": "scripts/test.sh",
                "content": "#!/bin/bash\necho 'test'",
                "permissions": 0o755,
            },
        ]
    }
    
    result = await populator.populate("honeypot-001", context)
    
    assert result.success is True
    assert result.files_created == 2
    
    # Check files exist
    test_file = temp_dir / "honeypot-001" / "test.txt"
    assert test_file.exists()
    assert test_file.read_text() == "Hello, World!"
    
    script_file = temp_dir / "honeypot-001" / "scripts" / "test.sh"
    assert script_file.exists()
    assert script_file.stat().st_mode & 0o777 == 0o755


@pytest.mark.asyncio
async def test_deploy_single_file(temp_dir):
    """Test deploying a single file."""
    populator = FilesystemPopulator(base_path=temp_dir)
    
    file_path = await populator.deploy_file(
        honeypot_id="test-002",
        relative_path="config.yml",
        content="key: value\n",
        permissions=0o600,
    )
    
    assert file_path.exists()
    assert file_path.stat().st_mode & 0o777 == 0o600
