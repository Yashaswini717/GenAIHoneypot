import random
import re
import string
import zlib
from typing import Any

from core.utils import calculate_entropy

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
        "aws_secret_key": re.compile(
            r'(aws_secret.*[=:]\s*)([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])', re.IGNORECASE
        ),
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
        # npm publish tokens: documented fixed format, npm_ + 36 chars = 40 total.
        "npm_token": re.compile(r'(?<![A-Za-z0-9])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])'),
        # Azure Storage account keys: always exactly 88 base64 characters,
        # ending in '==' padding (64 raw bytes base64-encoded) — a
        # documented, fixed Microsoft format. Two groups like aws_secret_key:
        # keep the "AccountKey=" context, only touch the value.
        "azure_storage_key": re.compile(r'(AccountKey=)([A-Za-z0-9+/]{86}==)'),
        # Heroku API keys are standard UUID v4s — documented, and UUID v4
        # has a real structural rule we can deliberately violate (the
        # version nibble must be '4').
        "heroku_api_key": re.compile(
            r'(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?![0-9a-f])',
            re.IGNORECASE,
        ),
        # SendGrid API keys: documented fixed format SG.<22 chars>.<43 chars>.
        "sendgrid_key": re.compile(r'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'),
    }

    # Generic fallback for providers not named above: a variable whose
    # NAME suggests a credential (contains "key"/"secret"/"token"/
    # "password"/"credential"/"auth"), assigned a long, high-entropy
    # value. Deliberately broader and less precise than the exact-format
    # patterns — this exists to catch *unknown* formats (Cloudflare,
    # Mailgun, DigitalOcean, whatever wasn't specifically named), at the
    # cost of being a heuristic rather than a certainty. Entropy is
    # checked at match time (see `_mask_generic_credential`) to avoid
    # flagging low-randomness values like "localhost" or "production".
    _GENERIC_CREDENTIAL_PATTERN = re.compile(
        r'(?im)^([ \t]*[A-Za-z_][A-Za-z0-9_]*'
        r'(?:key|secret|token|password|passwd|pwd|credential|auth)'
        r'[A-Za-z0-9_]*\s*[=:]\s*["\']?)'
        r'([A-Za-z0-9+/_.\-]{20,})'
        r'(["\']?\s*)$'
    )
    _GENERIC_ENTROPY_THRESHOLD = 3.5

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

        # Generic fallback: a credential-named variable holding a long,
        # high-entropy value in a format none of the specific patterns
        # above recognize. Heuristic, not certain — warning, not an
        # error, since it can't distinguish "an unrecognized real
        # provider's key" from "just a realistic-looking random string
        # the generator made up on its own."
        for match in self._GENERIC_CREDENTIAL_PATTERN.finditer(content):
            value = match.group(2)
            if calculate_entropy(value) < self._GENERIC_ENTROPY_THRESHOLD:
                continue
            if any(pattern.search(value) for pattern in self.SECRET_PATTERNS.values()):
                continue  # already covered, more precisely, above
            warnings.append(f"High-entropy value in a credential-named variable at position {match.start()}")

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
        "npm_token": ("npm_", string.ascii_letters + string.digits, 40),
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
        Runs the generic high-entropy fallback FIRST, so any value already
        recognized by one of the specific patterns above is left for that
        more precise, format-aware handling instead of being blunt-masked
        here too.
        """
        result = self._GENERIC_CREDENTIAL_PATTERN.sub(self._mask_generic_credential, content)
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
            elif secret_type == "azure_storage_key":
                result = pattern.sub(self._regenerate_azure_key, result)
            elif secret_type == "heroku_api_key":
                result = pattern.sub(self._regenerate_heroku_key, result)
            elif secret_type == "sendgrid_key":
                result = pattern.sub(lambda m: self._regenerate_sendgrid_key(), result)
            elif secret_type == "aws_secret_key":
                result = pattern.sub(self._regenerate_aws_secret_key, result)
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

    def _mask_generic_credential(self, m: "re.Match[str]") -> str:
        """
        Replacement for `_GENERIC_CREDENTIAL_PATTERN`. Two checks before
        touching anything, to keep false positives down:

        1. Entropy — skip predictable values like "localhost" or
           "production" that happen to sit in a credential-named
           variable but aren't actually secret-shaped.
        2. Already covered by a specific pattern above — if so, leave it
           for that pass to handle with its more precise, provider-aware
           logic instead of blunt-masking it here.
        """
        prefix, value, suffix = m.group(1), m.group(2), m.group(3)

        if calculate_entropy(value) < self._GENERIC_ENTROPY_THRESHOLD:
            return m.group(0)

        if any(pattern.search(value) for pattern in self.SECRET_PATTERNS.values()):
            return m.group(0)

        return prefix + 'X' * len(value) + suffix

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
    def _regenerate_aws_secret_key(match: "re.Match[str]") -> str:
        """
        AWS Secret Access Keys are documented as always exactly 40
        characters. Deliberately generate 41, same technique as
        aws_access_key/google_api/twilio_api — and critically, NOT built
        from the same character class the whole-match 'X'-fill masking
        would use, since a same-length/charset mask would still match
        this pattern's own {40} requirement and get re-flagged as a false
        positive on our own already-safe output (exactly what happened
        before this fix existed).
        """
        alphabet = string.ascii_letters + string.digits + "/+="
        return match.group(1) + ''.join(random.choices(alphabet, k=41))

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
    def _regenerate_azure_key(match: "re.Match[str]") -> str:
        """
        Azure Storage account keys are always exactly 88 base64 characters
        (64 raw bytes) ending in '==' padding — a documented Microsoft
        format. Deliberately generate 87 instead of 88, which breaks both
        the fixed length AND the base64 padding requirement (a base64
        string's length must be a multiple of 4) at once.
        """
        alphabet = string.ascii_letters + string.digits + "+/"
        return match.group(1) + ''.join(random.choices(alphabet, k=85)) + "=="

    @staticmethod
    def _regenerate_heroku_key(match: "re.Match[str]") -> str:
        """
        Heroku API keys are standard UUID v4s. RFC 4122 requires the
        version nibble to be '4' and the variant nibble to be one of
        8/9/a/b — we deliberately set the version nibble to something
        else, so the result fails UUID v4 validation by construction, not
        just by having the wrong random bytes.
        """
        hex_chars = "0123456789abcdef"
        p1 = ''.join(random.choices(hex_chars, k=8))
        p2 = ''.join(random.choices(hex_chars, k=4))
        bad_version = random.choice("0123567890abcdef".replace("4", ""))
        p3 = bad_version + ''.join(random.choices(hex_chars, k=3))
        p4 = random.choice("89ab") + ''.join(random.choices(hex_chars, k=3))
        p5 = ''.join(random.choices(hex_chars, k=12))
        return f"{p1}-{p2}-{p3}-{p4}-{p5}"

    @staticmethod
    def _regenerate_sendgrid_key() -> str:
        """
        SendGrid's documented format: SG.<22 chars>.<43 chars>. Generate
        the second segment one character short of its real fixed length.
        """
        alphabet = string.ascii_letters + string.digits + "_-"
        part1 = ''.join(random.choices(alphabet, k=22))
        part2 = ''.join(random.choices(alphabet, k=42))  # 42, not the real 43
        return f"SG.{part1}.{part2}"

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
