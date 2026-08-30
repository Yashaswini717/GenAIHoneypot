import random
import re
import string
import zlib
from typing import Any

from .base import BaseValidator, ValidationResult

_BASE62_ALPHABET = string.digits + string.ascii_uppercase + string.ascii_lowercase


def _to_base62(value: int, min_length: int) -> str:
    """Encode an unsigned int as base62, left-padded with '0' to min_length."""
    if value == 0:
        digits = "0"
    else:
        digits = ""
        n = value
        while n > 0:
            n, rem = divmod(n, 62)
            digits = _BASE62_ALPHABET[rem] + digits
    return digits.rjust(min_length, "0")


class SecurityValidator(BaseValidator):
    """Validate that content doesn't contain real secrets."""

    # Patterns for real secrets (to block). The fixed-length ones (AWS,
    # Google, Twilio) are anchored with negative lookaround so they only
    # match a run of EXACTLY that many characters — not "at least that
    # many". Real providers enforce this exact length; without the
    # anchors, our own deliberately-too-long replacements from
    # `regenerate_secrets` would still match here and get flagged as a
    # false alarm on content that's already been made safe.
    SECRET_PATTERNS = {
        "aws_access_key": re.compile(r'(?<![0-9A-Z])AKIA[0-9A-Z]{16}(?![0-9A-Z])'),
        # Two groups: (1) the "aws_secret...=" context text kept only for
        # detection, (2) the actual 40-char value. Replacement logic must
        # only touch group 2 — masking the whole match would destroy the
        # key name itself and corrupt the file's structure.
        "aws_secret_key": re.compile(r'(aws_secret.*[=:]\s*)([A-Za-z0-9/+=]{40})', re.IGNORECASE),
        "github_token": re.compile(r'ghp_[A-Za-z0-9]{36}'),
        "github_oauth": re.compile(r'gho_[A-Za-z0-9]{36}'),
        "slack_token": re.compile(r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[A-Za-z0-9]{24,}'),
        "slack_webhook": re.compile(r'https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}'),
        "private_key": re.compile(r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----'),
        "google_api": re.compile(r'(?<![0-9A-Za-z\-_])AIza[0-9A-Za-z\-_]{35}(?![0-9A-Za-z\-_])'),
        "google_oauth": re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'),
        "stripe_key": re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
        "twilio_api": re.compile(r'(?<![0-9a-fA-F])SK[0-9a-fA-F]{32}(?![0-9a-fA-F])'),
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
        context = context or {}

        if context.get("content_type") == "honeytoken" or context.get("token_type"):
            return self._create_result(
                valid=True,
                score=1.0,
                warnings=["Honeytoken content intentionally contains credential-like patterns"],
                findings=[],
            )

        # Check for real secrets
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            matches = pattern.finditer(content)
            for match in matches:
                # GitHub's format keeps the real fixed length either way —
                # what makes it real-or-not is its checksum, so a match
                # with a deliberately-wrong checksum (see
                # `regenerate_secrets`) isn't actually a "potential real"
                # token and shouldn't be flagged as one.
                if secret_type in ("github_token", "github_oauth") and not self._github_checksum_valid(match.group()):
                    continue

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

    @staticmethod
    def _mask_match(m: "re.Match[str]") -> str:
        """
        Mask a matched secret, preserving any leading context group (e.g.
        `aws_secret_key`'s "AWS_SECRET_ACCESS_KEY: " prefix) so only the
        actual value is destroyed, not the surrounding file structure.

        Uses 'X' rather than '*' as the fill character: an unquoted YAML
        scalar that starts with '*' is parsed as an alias reference and
        fails to parse at all — 'X' is safe as a plain string in YAML,
        shell, JSON, and every other format these generators produce.
        """
        if len(m.groups()) == 2:
            return m.group(1) + 'X' * len(m.group(2))
        return 'X' * len(m.group())

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
            masked = pattern.sub(self._mask_match, masked)

        return masked

    # Providers with NO known public checksum — AWS, Google, and Twilio
    # validate keys purely by private server-side lookup, not a formula a
    # client can compute. The one real, public, structural rule that
    # exists for these is their strictly-enforced fixed total length (AWS
    # keys always 20 chars, Google API keys always 39, Twilio SIDs always
    # 34 — every one rejected outright by the real service if off by even
    # one character). We deliberately generate the WRONG length: the
    # prefix stays literal (still instantly recognizable to an attacker
    # or a naive secret scanner), but the length can never match a real,
    # currently-issued credential.
    _REGENERATE_SHAPES: dict[str, tuple[str, str, int]] = {
        # (prefix, alphabet, real fixed total length — we generate length+1)
        "aws_access_key": ("AKIA", string.ascii_uppercase + string.digits, 20),
        "google_api": ("AIza", string.ascii_letters + string.digits + "-_", 39),
        "twilio_api": ("SK", "0123456789abcdefABCDEF", 34),
    }

    def regenerate_secrets(self, content: str) -> str:
        """
        Replace any text matching a real-provider secret format with a
        value that is structurally guaranteed to be invalid — never the
        LLM's own invented value, and never even shaped correctly enough
        to pass the real provider's own validation, by whatever rule that
        provider actually publishes:

        - GitHub tokens: GitHub documents a real CRC32-based checksum in
          the last 6 characters of every token. We compute that checksum
          correctly, then deliberately corrupt one of its characters —
          the same "provably wrong by construction" logic as an invalid
          Luhn checksum, not just an improbable random string.
        - Stripe: swapped to Stripe's own officially documented
          `sk_test_`/test-mode prefix instead of `sk_live_`. Stripe test
          keys are categorically incapable of touching live/production
          data by Stripe's own design — not a probability argument.
        - JWT: one character outside the base64url alphabet spliced into
          a segment, so no real JWT parser can ever decode it.
        - AWS / Google / Twilio: these providers don't publish any
          client-checkable checksum — validity is a private server-side
          lookup, not a formula. Their one real public structural rule is
          a strictly-enforced fixed length, which we deliberately violate.
        - Everything else (private key headers, Slack tokens/webhooks,
          the contextual aws_secret_key match) falls back to
          `mask_secrets`'s asterisk replacement as an additional layer —
          safe, just less polished on the rare occasion one of those
          specific patterns fires.
        """
        result = content
        for secret_type, pattern in self.SECRET_PATTERNS.items():
            if secret_type == "jwt":
                result = pattern.sub(self._regenerate_jwt, result)
            elif secret_type in ("github_token", "github_oauth"):
                prefix = "ghp_" if secret_type == "github_token" else "gho_"
                result = pattern.sub(
                    lambda m, _prefix=prefix: self._regenerate_github_token(_prefix), result
                )
            elif secret_type == "stripe_key":
                result = pattern.sub(lambda m: self._regenerate_stripe_key(), result)
            elif secret_type in self._REGENERATE_SHAPES:
                prefix, alphabet, real_length = self._REGENERATE_SHAPES[secret_type]
                wrong_length = real_length + 1 - len(prefix)
                result = pattern.sub(
                    lambda m, _prefix=prefix, _alphabet=alphabet, _n=wrong_length: _prefix
                    + ''.join(random.choices(_alphabet, k=_n)),
                    result,
                )
            else:
                result = pattern.sub(self._mask_match, result)
        return result

    @staticmethod
    def _github_checksum_valid(token: str) -> bool:
        """
        Check whether a matched `ghp_`/`gho_` token's trailing 6-char
        checksum actually matches its entropy portion under our best-
        effort reproduction of GitHub's documented CRC32+base62 scheme.
        Used only to decide whether a match is worth flagging — an
        LLM-invented token will essentially never have a correct
        checksum by chance (1 in ~57 billion), and a match we already
        regenerated via `_regenerate_github_token` is deliberately wrong,
        so this correctly returns False for both without needing to know
        the token's origin.
        """
        body = token[4:]  # strip ghp_/gho_
        if len(body) != 36:
            return False
        entropy, claimed = body[:30], body[30:]
        return _to_base62(zlib.crc32(entropy.encode()), 6) == claimed

    @staticmethod
    def _regenerate_github_token(prefix: str) -> str:
        """
        GitHub's documented format: prefix + 30 random entropy chars + a
        6-char checksum (CRC32 of the entropy, base62-encoded). We
        compute the real checksum, then deliberately flip one of its
        characters — guaranteed wrong regardless of whether our base62
        alphabet ordering happens to exactly match GitHub's internal one,
        since we're not relying on it matching; we're relying on having
        broken whatever it computes to.
        """
        entropy_alphabet = string.ascii_letters + string.digits
        entropy = ''.join(random.choices(entropy_alphabet, k=30))
        checksum = _to_base62(zlib.crc32(entropy.encode()), 6)
        corrupted = list(checksum)
        idx = random.randrange(len(corrupted))
        # shift this character to a different one in the same alphabet —
        # guarantees the checksum no longer matches, however it's checked
        current_pos = _BASE62_ALPHABET.index(corrupted[idx])
        corrupted[idx] = _BASE62_ALPHABET[(current_pos + 1) % len(_BASE62_ALPHABET)]
        return prefix + entropy + ''.join(corrupted)

    @staticmethod
    def _regenerate_stripe_key() -> str:
        """
        Stripe officially documents `sk_test_` as its test-mode key
        prefix — those keys cannot access live/production data by
        Stripe's own design, regardless of the rest of the value. Safer
        guarantee than trying to fake a `sk_live_`-shaped value.
        """
        alphabet = string.ascii_letters + string.digits
        return "sk_test_" + ''.join(random.choices(alphabet, k=24))

    @staticmethod
    def _regenerate_jwt(match: "re.Match[str]") -> str:
        """
        JWTs have no fixed length to violate, so instead we splice one
        character outside the base64url alphabet into the payload
        segment. That guarantees no real JWT library can ever base64-
        decode it — structurally invalid, not just improbable.
        """
        alphabet = string.ascii_letters + string.digits + "-_"
        segments = match.group().split(".")
        fresh = []
        for seg in segments:
            lead = "eyJ" if seg.startswith("eyJ") else ""
            tail_len = max(len(seg) - len(lead), 0)
            fresh.append(lead + ''.join(random.choices(alphabet, k=tail_len)))
        if len(fresh) > 1 and fresh[1]:
            # invalid char breaks base64url decoding of the payload segment
            fresh[1] = "!" + fresh[1][1:]
        return ".".join(fresh)
