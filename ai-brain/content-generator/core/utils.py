import hashlib
import math
import random
import re
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import ulid


def generate_unique_id() -> str:
    """
    Generate a unique, sortable identifier using ULID.

    Returns:
        ULID string
    """
    return str(ulid.ULID())


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.

    Args:
        length: Token length

    Returns:
        Secure random token
    """
    return secrets.token_urlsafe(length)


def calculate_entropy(text: str) -> float:
    """
    Calculate Shannon entropy of text.

    Args:
        text: Input text

    Returns:
        Entropy value (higher = more random)
    """
    if not text:
        return 0.0

    # Count character frequencies
    freq: dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1

    # Calculate entropy
    length = len(text)
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            # Proper Shannon entropy calculation
            entropy -= probability * math.log2(probability)

    return entropy


def calculate_hash(content: str, algorithm: str = "sha256") -> str:
    """
    Calculate hash of content.

    Args:
        content: Content to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)

    Returns:
        Hex digest of hash
    """
    hash_func = getattr(hashlib, algorithm)
    return hash_func(content.encode()).hexdigest()


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to be safe for filesystem.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    # Remove or replace unsafe characters
    safe_name = re.sub(r'[^\w\s\-\.]', '_', filename)
    # Remove multiple spaces/underscores
    safe_name = re.sub(r'[\s_]+', '_', safe_name)
    # Limit length
    if len(safe_name) > 255:
        name, ext = safe_name.rsplit('.', 1) if '.' in safe_name else (safe_name, '')
        safe_name = name[:250] + ('.' + ext if ext else '')
    return safe_name


def random_datetime(
    start: datetime | None = None,
    end: datetime | None = None,
) -> datetime:
    """
    Generate a random datetime between start and end.

    Args:
        start: Start datetime (default: 1 year ago)
        end: End datetime (default: now)

    Returns:
        Random datetime
    """
    if end is None:
        end = datetime.now()
    if start is None:
        start = end - timedelta(days=365)

    time_between = end - start
    random_seconds = random.randint(0, int(time_between.total_seconds()))
    return start + timedelta(seconds=random_seconds)


def random_choice_weighted(choices: dict[Any, float]) -> Any:
    """
    Make a random choice from weighted options.

    Args:
        choices: Dictionary of {option: weight}

    Returns:
        Selected option
    """
    items = list(choices.keys())
    weights = list(choices.values())
    return random.choices(items, weights=weights, k=1)[0]


def mask_sensitive_data(data: str, mask_char: str = "*", visible: int = 4) -> str:
    """
    Mask sensitive data, showing only first/last few characters.

    Args:
        data: Sensitive data to mask
        mask_char: Character to use for masking
        visible: Number of visible characters at start/end

    Returns:
        Masked string
    """
    if len(data) <= visible * 2:
        return mask_char * len(data)

    return data[:visible] + mask_char * (len(data) - visible * 2) + data[-visible:]


def generate_realistic_username() -> str:
    """
    Generate a realistic username.

    Returns:
        Username string
    """
    first_names = ["john", "jane", "admin", "root", "dev", "test", "user", "mike", "sarah", "alex"]
    last_names = ["smith", "doe", "admin", "user", "developer", "ops", "johnson", "williams"]
    formats = [
        lambda: random.choice(first_names),
        lambda: f"{random.choice(first_names)}{random.choice(last_names)}",
        lambda: f"{random.choice(first_names)}.{random.choice(last_names)}",
        lambda: f"{random.choice(first_names)}_{random.choice(last_names)}",
        lambda: f"{random.choice(first_names)}{random.randint(1, 99)}",
    ]
    return random.choice(formats)()


def generate_realistic_hostname() -> str:
    """
    Generate a realistic hostname.

    Returns:
        Hostname string
    """
    prefixes = ["web", "app", "db", "api", "prod", "dev", "staging", "worker", "cache", "mail"]
    suffixes = ["server", "node", "host", "box", "machine", "instance"]
    formats = [
        lambda: f"{random.choice(prefixes)}-{random.choice(suffixes)}-{random.randint(1, 99)}",
        lambda: f"{random.choice(prefixes)}{random.randint(1, 99)}",
        lambda: f"{random.choice(prefixes)}-{random.randint(100, 999)}",
    ]
    return random.choice(formats)()


def generate_realistic_ip() -> str:
    """
    Generate a realistic IP address (private ranges).

    Returns:
        IP address string
    """
    ranges = [
        lambda: f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        lambda: f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        lambda: f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
    ]
    return random.choice(ranges)()


def ensure_directory(path: Path) -> None:
    """
    Ensure directory exists, create if necessary.

    Args:
        path: Directory path
    """
    path.mkdir(parents=True, exist_ok=True)


def get_file_extension(content_type: str) -> str:
    """
    Get file extension for content type.

    Args:
        content_type: Content type (source_code, config, logs, document)

    Returns:
        File extension including dot
    """
    extensions = {
        "python": ".py",
        "javascript": ".js",
        "shell": ".sh",
        "go": ".go",
        "bashrc": "",
        "ssh_config": "",
        "env": ".env",
        "nginx": ".conf",
        "docker_compose": ".yml",
        "auth_log": ".log",
        "syslog": ".log",
        "bash_history": "",
        "apache_log": ".log",
        "nginx_log": ".log",
        "readme": ".md",
        "notes": ".txt",
        "todo": ".md",
    }
    return extensions.get(content_type, ".txt")


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted size string
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


# ──────────────────────────────────────────────
# Shared patterns for AI narration detection
# ──────────────────────────────────────────────

# Patterns that indicate AI narration leaking into output
AI_NARRATION_PATTERNS = [
    re.compile(r'^(?:Here(?:\'s| is) (?:a|an|the) .+?[:\.]\s*\n)', re.IGNORECASE),
    re.compile(r'^(?:Below is .+?[:\.]\s*\n)', re.IGNORECASE),
    re.compile(r'^(?:This (?:script|file|code|config|log|document) .+?[:\.]\s*\n)', re.IGNORECASE),
    re.compile(r'^(?:I\'ve (?:created|generated|written) .+?[:\.]\s*\n)', re.IGNORECASE),
    re.compile(r'^(?:Sure[,!].*?\n)', re.IGNORECASE),
    re.compile(r'^(?:Certainly[,!] .+?[:\.]\s*\n)', re.IGNORECASE),
    re.compile(r'^(?:Of course[,!] .+?[:\.]\s*\n)', re.IGNORECASE),
    re.compile(r'^(?:Let me .+?[:\.]\s*\n)', re.IGNORECASE),
    re.compile(r'^(?:As requested[,.:] .+?\n)', re.IGNORECASE),
    re.compile(r'^(?:The following .+?[:\.]\s*\n)', re.IGNORECASE),
    re.compile(r'^(?:Here you go[,!:.].*?\n)', re.IGNORECASE),
    re.compile(r'^(?:I have (?:created|generated|written|prepared) .+?[:\.]\s*\n)', re.IGNORECASE),
]

# Trailing AI narration patterns (appended after main content)
AI_TRAILING_PATTERNS = [
    re.compile(r'\n(?:This (?:script|file|code|config|log|document) (?:demonstrates|shows|provides|contains|implements|includes) .+?)$', re.IGNORECASE),
    re.compile(r'\n(?:Note(?:s)?:\s*.+?)$', re.IGNORECASE | re.DOTALL),
    re.compile(r'\n(?:Key (?:features|points|highlights):\s*.+?)$', re.IGNORECASE | re.DOTALL),
    re.compile(r'\n(?:Feel free to .+?)$', re.IGNORECASE),
    re.compile(r'\n(?:Let me know if .+?)$', re.IGNORECASE),
    re.compile(r'\n(?:I hope this .+?)$', re.IGNORECASE),
    re.compile(r'\n(?:You can (?:modify|adjust|customize) .+?)$', re.IGNORECASE),
    re.compile(r'\n(?:Make sure to .+?)$', re.IGNORECASE),
    re.compile(r'\n(?:Remember to .+?)$', re.IGNORECASE),
    re.compile(r'\n(?:Don\'t forget to .+?)$', re.IGNORECASE),
    re.compile(r'\n(?:If you (?:need|want|have) .+?)$', re.IGNORECASE),
    re.compile(r'\n(?:Hope this helps.*)$', re.IGNORECASE),
    re.compile(r'\n(?:Happy coding.*)$', re.IGNORECASE),
]

# Analysis-layer terms that should not appear in system-layer artifacts
ANALYSIS_LAYER_TERMS = [
    "threat_score", "anomaly_score", "risk_level", "detection_rule",
    "correlation_id", "alert_severity", "ioc_match", "siem",
    "honeypot", "deception", "canary_token",
    "indicator_of_compromise", "malware_analysis", "forensic",
    "triage", "incident_response", "threat_intel",
    "detection_engine", "alert_triggered", "security_orchestration",
    "event_category", "event_type", "severity", "suspicious",
    "detected", "alert", "threat_intelligence", "security_event",
    "event_severity", "risk_score",
]

# Pre-compiled regex for efficient analysis-term detection in a single pass
ANALYSIS_LAYER_TERMS_PATTERN = re.compile(
    r'\b(?:' + '|'.join(re.escape(term) for term in ANALYSIS_LAYER_TERMS) + r')\b',
    re.IGNORECASE,
)

# Syslog format pattern: "Mon DD HH:MM:SS hostname process[pid]: message"
# Matches: 3-letter month, 1-2 digit day, HH:MM:SS time, hostname, process identifier
SYSLOG_LINE_PATTERN = re.compile(
    r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+',
)

# Combined Log Format (Apache/nginx):
# Matches: IPv4 address, identity field, userid field, opening bracket of timestamp
# Full format: IP identity userid [timestamp] "request" status size
COMBINED_LOG_PATTERN = re.compile(
    r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\S+\s+\S+\s+\[',
)
