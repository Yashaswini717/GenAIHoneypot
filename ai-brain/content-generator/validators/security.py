import re
from typing import Any

from .base import BaseValidator, ValidationResult


class SecurityValidator(BaseValidator):
    """Validate that content doesn't contain real secrets."""

    # Patterns for real secrets (to block)
    SECRET_PATTERNS = {
        "aws_access_key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "aws_secret_key": re.compile(r'aws_secret.*[=:]\s*[A-Za-z0-9/+=]{40}', re.IGNORECASE),
        "github_token": re.compile(r'ghp_[A-Za-z0-9]{36}'),
        "github_oauth": re.compile(r'gho_[A-Za-z0-9]{36}'),
        "slack_token": re.compile(r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24,}'),
        "slack_webhook": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}'),
        "private_key": re.compile(r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----'),
        "google_api": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "google_oauth": re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
        "stripe_key": re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
        "twilio_api": re.compile(r'SK[0-9a-fA-F]{32}'),
        "jwt": re.compile(r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'),
    }

    # Patterns for common credentials in config files
    CREDENTIAL_PATTERNS = {
        "database_url": re.compile(r'postgresql://.*:.*@', re.IGNORECASE),
        "mysql_url": re.compile(r'mysql://.*:.*@', re.IGNORECASE),
        "connection_string": re.compile(r'Server=.*Password=', re.IGNORECASE),
        "api_key_assignment": re.compile(r'api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})', re.IGNORECASE),
    }

    # Patterns for valid honeytokens (should pass)
    HONEYTOKEN_MARKERS = {
        "aws_honeytoken": re.compile(r'AKIA[0-9A-Z]{16}.*#\s*honeytoken', re.IGNORECASE),
        "marked_honeytoken": re.compile(r'#.*honeytoken|honeytoken.*#', re.IGNORECASE),
    }

    async def validate(self, content: str, context: dict[str, Any] | None = None) -> ValidationResult:
        """
        Validate that content doesn't contain real secrets.

        Args:
            content: Content to validate
            context: Additional context

        Returns:
            ValidationResult with security findings
        """
        errors = []
        warnings = []
        findings = []

        # Check for real secrets
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = pattern.finditer(content)
            for match in matches:
                # Check if it's marked as honeytoken
                line_start = content.rfind('\n', 0, match.start())
                line_end = content.find('\n', match.end())
                # Handle case when there's no newline before or after the match
                line_start = line_start + 1 if line_start != -1 else 0
                line = content[line_start:line_end] if line_end != -1 else content[line_start:]
                
                is_honeytoken = any(marker.search(line) for marker in self.HONEYTOKEN_MARKERS.values())
                
                if not is_honeytoken:
                    errors.append(f"Potential real {secret_type} detected at position {match.start()}")
                    findings.append({
                        "type": secret_type,
                        "position": match.start(),
                        "preview": match.group()[:20] + "...",
                    })

        # Check for credentials
        for cred_type, pattern in self.CREDENTIAL_PATTERNS.items():
            matches = pattern.finditer(content)
            for match in matches:
                # Extract the matched credential
                matched_text = match.group()
                
                # Check if it looks too real (e.g., complex password)
                if "password=" in matched_text.lower():
                    password_match = re.search(r'password=([^;\s&]+)', matched_text, re.IGNORECASE)
                    if password_match:
                        password = password_match.group(1)
                        # Real passwords are usually complex
                        if len(password) > 15 and re.search(r'[A-Z]', password) and re.search(r'[0-9]', password):
                            warnings.append(f"Potentially real password in {cred_type}")

        # Check for IP addresses that might be real public IPs
        public_ip_pattern = re.compile(r'\b(?!10\.|172\.16\.|192\.168\.)(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        public_ips = public_ip_pattern.findall(content)
        if public_ips:
            # Check if they look like real IPs (not test ranges)
            real_ips = [ip for ip in public_ips if not ip.startswith(('0.', '127.', '255.'))]
            if real_ips:
                warnings.append(f"Found {len(real_ips)} potential public IP addresses")

        # Check for email addresses (might be real)
        email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        emails = email_pattern.findall(content)
        if emails:
            # Filter out obviously fake emails
            suspicious_emails = [
                email for email in emails
                if not any(fake in email.lower() for fake in ['example.com', 'test.com', 'fake.', 'dummy', 'sample'])
            ]
            if suspicious_emails:
                warnings.append(f"Found {len(suspicious_emails)} email addresses that may be real")

        is_valid = len(errors) == 0
        score = 1.0 if is_valid else 0.0
        
        if warnings:
            score = max(score, 0.7)  # Warnings don't completely invalidate
        
        self.logger.debug(
            "security_validation",
            valid=is_valid,
            errors=len(errors),
            warnings=len(warnings),
            findings=len(findings),
        )
        
        return self._create_result(
            valid=is_valid,
            score=score,
            errors=errors,
            warnings=warnings,
            findings=findings,
        )

    def mask_secrets(self, content: str) -> str:
        """
        Mask any detected secrets in content.

        Args:
            content: Content to mask

        Returns:
            Content with secrets masked
        """
        masked = content
        
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            masked = pattern.sub(lambda m: '*' * len(m.group()), masked)
        
        return masked
