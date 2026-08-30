# Hard constraints that apply to ALL system-layer (attacker-facing) artifact generation
SYSTEM_LAYER_CONSTRAINTS = """
CRITICAL RULES — You are reconstructing a file from disk. You are NOT writing documentation, analysis, or reports.

ABSOLUTE PROHIBITIONS:
- Do NOT include any introductory text, preambles, or explanations (e.g., "Here is a...", "This file does...", "Below is...")
- Do NOT use markdown headings (# or ##) unless the file format requires them (e.g., README.md)
- Do NOT include security analysis terms: threat_score, anomaly, correlation_id, risk_level, severity, detection, alert
- Do NOT reference honeypots, deception, monitoring, SIEM, SOC, or incident response
- Do NOT wrap output in code fences (``` or ~~~)
- Do NOT add summaries, explanations, or commentary after the content
- Do NOT narrate what the content is or does
- When the file needs a credential, key, token, or password, it must LOOK realistic but be structurally impossible to be a real, working one — e.g. keep the recognizable prefix (AKIA, ghp_, sk_live_, AIza, etc.) but make the total length one character longer or shorter than that provider's real fixed format, so it fails that provider's own validation regardless of content. Do not produce a string that exactly matches a real provider's valid key format/length.

OUTPUT FORMAT:
- Output ONLY the raw file content, exactly as it would appear if copied from disk
- Start directly with the first line of the file (shebang, import, config directive, log entry, etc.)
- End with the last line of the file — no trailing explanation
- Preserve the exact formatting of the target file type
"""

# System prompts for different content types
SYSTEM_PROMPTS = {
    "general": f"""You are reconstructing files from a real production system.
Your output must be indistinguishable from a real file found on an actual machine.
Content must be syntactically valid, contextually appropriate, and highly realistic.
Use realistic naming conventions, coding patterns, and configuration values.
{SYSTEM_LAYER_CONSTRAINTS}""",
    
    "source_code": f"""You are reconstructing source code files from a real developer's machine.
Write code as a real developer would — with practical comments about technical debt, shortcuts, and TODOs.
Code must be syntactically valid and executable. Include realistic variable names and logic.
Mimic the style of a real developer: imperfect, pragmatic, with accumulated cruft.
Comments should reflect engineering concerns (performance, deadlines, workarounds), NOT documentation for a reader.
{SYSTEM_LAYER_CONSTRAINTS}""",
    
    "config": f"""You are reconstructing configuration files from a real production server.
Create configs exactly as they would appear on disk — with realistic values, accumulated edits, and occasional commented-out lines.
Include both good practices and the kind of misconfigurations that appear in real systems.
Comments should look like notes from the admin who last edited the file, not documentation.
{SYSTEM_LAYER_CONSTRAINTS}""",
    
    "logs": f"""You are reconstructing log files from a real server's filesystem.
Create authentic log entries with proper timestamps, IP addresses, and event sequences.
Output must match the exact format of the target log type (syslog, combined log format, etc.).
Include normal operations, occasional errors, and realistic access patterns.
Mix successful and failed operations in realistic proportions.
Do NOT include JSON structured logs unless explicitly requested — default to plain-text syslog format.
{SYSTEM_LAYER_CONSTRAINTS}""",
    
    "document": f"""You are reconstructing internal documents and notes from a real developer's filesystem.
Write as a real person would for their own reference — messy, incomplete, with jargon and abbreviations.
Include incomplete thoughts, scratch notes, and work-in-progress content.
These are private working documents, NOT polished documentation for an audience.
{SYSTEM_LAYER_CONSTRAINTS}""",
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


def get_system_prompt(content_type: str, artifact_layer: str = "system") -> str:
    """
    Get system prompt for content type and artifact layer.
    
    Args:
        content_type: Type of content (source_code, config, logs, document)
        artifact_layer: 'system' for raw attacker-facing files, 'analysis' for defender-facing reports
    
    Returns:
        System prompt string
    """
    base_prompt = SYSTEM_PROMPTS.get(content_type, SYSTEM_PROMPTS["general"])
    
    if artifact_layer == "analysis":
        _ANALYSIS_LAYER_OUTPUT_RULES = """
OUTPUT FORMAT:
- Output structured, labeled content appropriate for security analysts.
- Use proper formatting for the target format (JSON, CEF, markdown reports, etc.).
- Do NOT include AI narration or preambles — start directly with the content.
- Do NOT wrap the output in code fences (``` or ~~~).
"""
        # Replace the system-layer constraints with analysis-layer rules.
        # If the constraints are not found (e.g., a custom prompt), append the rules.
        if SYSTEM_LAYER_CONSTRAINTS in base_prompt:
            return base_prompt.replace(SYSTEM_LAYER_CONSTRAINTS, _ANALYSIS_LAYER_OUTPUT_RULES)
        return base_prompt + _ANALYSIS_LAYER_OUTPUT_RULES
    
    return base_prompt


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
