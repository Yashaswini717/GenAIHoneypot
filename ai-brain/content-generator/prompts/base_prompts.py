# System prompts for different content types
SYSTEM_PROMPTS = {
    "general": """You are an expert content generator for realistic honeypot systems.
Generate authentic, production-quality content that mimics real development environments.
Content must be syntactically valid, contextually appropriate, and highly realistic.
Never include placeholder text, TODOs, or obviously fake data.
Use realistic naming conventions, coding patterns, and configuration values.""",
    
    "source_code": """You are an expert software developer generating realistic source code.
Write production-quality code with proper error handling, documentation, and best practices.
Include realistic variable names, comments, and logic. Code must be syntactically valid.
Mimic the style of experienced developers. Include some technical debt and legacy patterns.""",
    
    "config": """You are a senior DevOps engineer generating realistic configuration files.
Create production-ready configs with appropriate security settings, realistic values, and comments.
Include both good practices and occasional misconfigurations that appear in real systems.""",
    
    "logs": """You are a system administrator generating realistic log files.
Create authentic log entries with proper timestamps, IP addresses, and event sequences.
Include normal operations, occasional errors, and realistic access patterns.
Mix successful and failed operations in realistic proportions.""",
    
    "document": """You are a developer creating realistic documentation and notes.
Write authentic developer documentation, notes, and TODO lists.
Include incomplete thoughts, technical jargon, and realistic work-in-progress content.
Mimic how real developers document their work.""",
}

# Few-shot examples for better generation
FEW_SHOT_EXAMPLES = {
    "python_script": {
        "prompt": "Generate a Python script for database backup",
        "output": '''#!/usr/bin/env python3
"""
Database backup utility with compression and rotation.
"""
import argparse
import gzip
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BackupManager:
    def __init__(self, backup_dir: str, retention_days: int = 7):
        self.backup_dir = Path(backup_dir)
        self.retention_days = retention_days
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def create_backup(self, db_name: str, host: str = "localhost") -> Path:
        """Create compressed database backup."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{db_name}_{timestamp}.sql.gz"
        filepath = self.backup_dir / filename
        
        logger.info(f"Creating backup: {filename}")
        dump_cmd = f"pg_dump -h {host} {db_name}"
        
        try:
            with gzip.open(filepath, 'wb') as f:
                result = subprocess.run(
                    dump_cmd.split(),
                    stdout=subprocess.PIPE,
                    check=True
                )
                f.write(result.stdout)
            logger.info(f"Backup completed: {filepath}")
            return filepath
        except subprocess.CalledProcessError as e:
            logger.error(f"Backup failed: {e}")
            raise

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--backup-dir", default="/var/backups/db")
    args = parser.parse_args()
    
    manager = BackupManager(args.backup_dir)
    manager.create_backup(args.db)
''',
    },
    
    "ssh_config": {
        "prompt": "Generate an SSH config file for a developer",
        "output": """# SSH Config
Host github
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_rsa_github
    
Host prod-web
    HostName 10.0.1.50
    User deploy
    Port 22
    IdentityFile ~/.ssh/id_rsa_prod
    ForwardAgent yes
    
Host *.internal.company.com
    User admin
    ProxyJump bastion.company.com
    IdentityFile ~/.ssh/id_rsa_work
    
Host bastion
    HostName bastion.company.com
    User admin
    Port 22
    IdentityFile ~/.ssh/id_rsa_work
""",
    },
    
    "auth_log": {
        "prompt": "Generate realistic auth.log entries",
        "output": """Dec 15 08:32:15 web-server-01 sshd[12453]: Accepted password for ubuntu from 192.168.1.100 port 52341 ssh2
Dec 15 08:32:15 web-server-01 sshd[12453]: pam_unix(sshd:session): session opened for user ubuntu by (uid=0)
Dec 15 08:45:22 web-server-01 sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/bin/apt update
Dec 15 08:45:22 web-server-01 sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
Dec 15 09:12:33 web-server-01 sshd[12890]: Failed password for invalid user admin from 203.0.113.42 port 48322 ssh2
Dec 15 09:12:35 web-server-01 sshd[12890]: Connection closed by 203.0.113.42 port 48322 [preauth]
Dec 15 09:15:18 web-server-01 sshd[12453]: pam_unix(sshd:session): session closed for user ubuntu
""",
    },
}


def get_system_prompt(content_type: str) -> str:
    """
    Get system prompt for content type.
    
    Args:
        content_type: Type of content (source_code, config, logs, document)
    
    Returns:
        System prompt string
    """
    return SYSTEM_PROMPTS.get(content_type, SYSTEM_PROMPTS["general"])


def get_few_shot_examples(category: str) -> list[dict[str, str]]:
    """
    Get few-shot examples for a category.
    
    Args:
        category: Example category
    
    Returns:
        List of example dictionaries
    """
    return [FEW_SHOT_EXAMPLES.get(category, {})]


def build_prompt_with_examples(
    user_prompt: str,
    examples: list[dict[str, str]] | None = None,
) -> str:
    """
    Build prompt with few-shot examples.
    
    Args:
        user_prompt: Main prompt
        examples: Few-shot examples
    
    Returns:
        Complete prompt with examples
    """
    if not examples:
        return user_prompt
    
    parts = ["Here are examples of the expected output:\n"]
    for i, example in enumerate(examples, 1):
        parts.append(f"\n--- Example {i} ---")
        parts.append(f"Input: {example.get('prompt', '')}")
        parts.append(f"Output:\n{example.get('output', '')}\n")
    
    parts.append(f"\nNow generate content for:\n{user_prompt}")
    return "\n".join(parts)
