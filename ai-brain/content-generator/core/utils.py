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
