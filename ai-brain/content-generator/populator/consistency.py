import re
from typing import Any

from config.logging_config import LoggerMixin


class ConsistencyManager(LoggerMixin):
    """Ensure consistency across generated files."""

    def __init__(self):
        """Initialize consistency manager."""
        self.context: dict[str, Any] = {}

    def set_context(self, key: str, value: Any) -> None:
        """Set a consistency context value."""
        self.context[key] = value
        self.logger.debug("consistency_context_set", key=key)

    def get_context(self, key: str, default: Any = None) -> Any:
        """Get a consistency context value."""
        return self.context.get(key, default)

    def ensure_username_consistency(self, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Ensure consistent username across files.

        Args:
            files: List of file specifications

        Returns:
            Updated files with consistent usernames
        """
        username = self.get_context("username", "developer")
        
        for file in files:
            content = file.get("content", "")
            if isinstance(content, str):
                # Replace common username patterns
                content = re.sub(r'/home/\w+/', f'/home/{username}/', content)
                content = re.sub(r'User: \w+', f'User: {username}', content)
                file["content"] = content
        
        return files

    def ensure_hostname_consistency(self, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Ensure consistent hostname across files."""
        hostname = self.get_context("hostname", "dev-server-01")
        
        for file in files:
            content = file.get("content", "")
            if isinstance(content, str):
                content = re.sub(r'@[\w\-]+\s', f'@{hostname} ', content)
                file["content"] = content
        
        return files

    def ensure_ip_consistency(self, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Ensure consistent internal IP addresses."""
        ip_address = self.get_context("ip_address", "192.168.1.100")
        
        for file in files:
            content = file.get("content", "")
            if isinstance(content, str):
                # Replace first occurrence of private IP with consistent one
                content = re.sub(
                    r'\b192\.168\.\d+\.\d+\b',
                    ip_address,
                    content,
                    count=1,
                )
                file["content"] = content
        
        return files

    def apply_consistency(self, files: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Apply all consistency rules.

        Args:
            files: List of file specifications

        Returns:
            Files with consistency applied
        """
        files = self.ensure_username_consistency(files)
        files = self.ensure_hostname_consistency(files)
        files = self.ensure_ip_consistency(files)
        
        self.logger.info("consistency_applied", files_count=len(files))
        return files
