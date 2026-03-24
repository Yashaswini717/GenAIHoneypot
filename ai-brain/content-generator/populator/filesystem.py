import os
from datetime import datetime
from pathlib import Path
from typing import Any

from config.settings import settings
from core.exceptions import FileSystemError
from core.utils import ensure_directory, random_datetime

from .base import BasePopulator, PopulationResult


class FilesystemPopulator(BasePopulator):
    """Deploy generated content to filesystem with realistic attributes."""

    def __init__(self, base_path: Path | None = None):
        """
        Initialize filesystem populator.

        Args:
            base_path: Base path for file deployment
        """
        self.base_path = base_path or settings.output_base_path
        ensure_directory(self.base_path)
        self.logger.info("filesystem_populator_initialized", base_path=str(self.base_path))

    async def populate(self, honeypot_id: str, context: dict[str, Any]) -> PopulationResult:
        """
        Populate honeypot filesystem with content.

        Args:
            honeypot_id: Honeypot identifier
            context: Population context with 'files' list

        Returns:
            PopulationResult
        """
        files = context.get("files", [])
        if not files:
            return self._create_result(False, errors=["No files to deploy"])

        honeypot_path = self.base_path / honeypot_id
        ensure_directory(honeypot_path)

        errors = []
        files_created = 0

        for file_spec in files:
            try:
                await self._deploy_file(honeypot_path, file_spec)
                files_created += 1
            except Exception as e:
                errors.append(f"Failed to deploy {file_spec.get('path')}: {e}")
                self.logger.error("file_deployment_failed", error=str(e))

        success = len(errors) == 0
        self.logger.info(
            "population_completed",
            honeypot_id=honeypot_id,
            files_created=files_created,
            errors=len(errors),
        )

        return self._create_result(
            success=success,
            files_created=files_created,
            errors=errors,
            honeypot_path=str(honeypot_path),
        )

    async def _deploy_file(self, base_path: Path, file_spec: dict[str, Any]) -> None:
        """
        Deploy a single file with proper permissions and timestamps.

        Args:
            base_path: Base deployment path
            file_spec: File specification with path, content, permissions, timestamp
        """
        relative_path = file_spec["path"]
        content = file_spec["content"]
        permissions = file_spec.get("permissions", 0o644)
        timestamp = file_spec.get("timestamp")

        # Create full path
        file_path = base_path / relative_path
        ensure_directory(file_path.parent)

        # Write content
        if isinstance(content, str):
            file_path.write_text(content, encoding="utf-8")
        else:
            file_path.write_bytes(content)

        # Set permissions
        os.chmod(file_path, permissions)

        # Set realistic timestamp
        if timestamp:
            if isinstance(timestamp, datetime):
                timestamp_unix = timestamp.timestamp()
            else:
                timestamp_unix = timestamp
        else:
            # Random timestamp within last year
            timestamp_unix = random_datetime().timestamp()

        os.utime(file_path, (timestamp_unix, timestamp_unix))

        self.logger.debug(
            "file_deployed",
            path=str(file_path),
            size=len(content) if isinstance(content, str) else len(content),
            permissions=oct(permissions),
        )

    async def deploy_file(
        self,
        honeypot_id: str,
        relative_path: str,
        content: str | bytes,
        permissions: int = 0o644,
        timestamp: datetime | None = None,
    ) -> Path:
        """
        Deploy a single file (convenience method).

        Args:
            honeypot_id: Honeypot ID
            relative_path: Relative path within honeypot
            content: File content
            permissions: Unix permissions (octal)
            timestamp: File timestamp

        Returns:
            Path to deployed file
        """
        honeypot_path = self.base_path / honeypot_id
        ensure_directory(honeypot_path)

        file_spec = {
            "path": relative_path,
            "content": content,
            "permissions": permissions,
            "timestamp": timestamp,
        }

        await self._deploy_file(honeypot_path, file_spec)
        return honeypot_path / relative_path
