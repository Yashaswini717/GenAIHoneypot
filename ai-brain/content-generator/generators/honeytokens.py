import random
import secrets
import string
from datetime import datetime, timedelta
from typing import Any

from .base import BaseGenerator, GeneratedContent


class HoneytokenGenerator(BaseGenerator):
    """Generate realistic but fake honeytokens."""

    def get_system_prompt(self, artifact_layer: str = "system") -> str:
        """Honeytokens don't use LLM, so this returns empty."""
        return ""

    def build_prompt(self, context: dict[str, Any]) -> str:
        """Honeytokens don't use LLM prompts."""
        return ""

    async def generate(self, context: dict[str, Any]) -> GeneratedContent:
        """
        Generate honeytoken.

        Args:
            context: Must contain 'token_type':
                - aws_access_key
                - aws_secret_key
                - github_token
                - ssh_private_key
                - database_password
                - api_token
                - jwt_secret
                - patient_id (healthcare structured data)
                - ssn (Social Security Number format)
                - credit_card (credit card number format)
                - employee_id (employee identifier)
                - medical_record_number (MRN format)

        Returns:
            GeneratedContent with honeytoken
        """
        token_type = context.get("token_type", "api_token")
        format_hint = context.get("format_hint")
        
        generators = {
            "aws_access_key": self._generate_aws_access_key,
            "aws_secret_key": self._generate_aws_secret_key,
            "github_token": self._generate_github_token,
            "ssh_private_key": self._generate_ssh_private_key,
            "database_password": self._generate_database_password,
            "api_token": self._generate_api_token,
            "jwt_secret": self._generate_jwt_secret,
            # Structured data honeytokens for specific industries
            "patient_id": self._generate_patient_id,
            "ssn": self._generate_ssn,
            "credit_card": self._generate_credit_card,
            "employee_id": self._generate_employee_id,
            "medical_record_number": self._generate_mrn,
        }
        
        generator = generators.get(token_type, self._generate_api_token)
        token_content = generator(context)
        
        # Validate
        validation_results = await self._validate_content(
            content=token_content,
            file_type="generic",
            context=context,
        )
        
        return self._create_content(
            content=token_content,
            content_type="honeytoken",
            file_type="generic",
            validation_results=validation_results,
            token_type=token_type,
            is_honeytoken=True,
            format_hint=format_hint,
        )

    def _generate_aws_access_key(self, context: dict[str, Any]) -> str:
        """Generate fake AWS access key (AKIA format)."""
        chars = string.ascii_uppercase + string.digits
        key_id = "AKIA" + ''.join(random.choices(chars, k=16))
        return key_id

    def _generate_aws_secret_key(self, context: dict[str, Any]) -> str:
        """Generate fake AWS secret key."""
        chars = string.ascii_letters + string.digits + "+/="
        return ''.join(random.choices(chars, k=40))

    def _generate_github_token(self, context: dict[str, Any]) -> str:
        """Generate fake GitHub personal access token (ghp_ format)."""
        chars = string.ascii_letters + string.digits
        token = "ghp_" + ''.join(random.choices(chars, k=36))
        return token

    def _generate_ssh_private_key(self, context: dict[str, Any]) -> str:
        """Generate fake SSH private key structure."""
        # Generate fake key data
        key_data_lines = []
        chars = string.ascii_letters + string.digits + "+/="
        
        for _ in range(25):
            # Use secrets for cryptographic-looking content
            line = ''.join(secrets.choice(chars) for _ in range(64))
            key_data_lines.append(line)
        
        # Last line is shorter
        key_data_lines.append(''.join(secrets.choice(chars) for _ in range(random.randint(20, 40))))
        
        key = "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        key += "\n".join(key_data_lines)
        key += "\n-----END OPENSSH PRIVATE KEY-----\n"
        
        return key

    def _generate_database_password(self, context: dict[str, Any]) -> str:
        """Generate realistic but fake database password."""
        # Mix of uppercase, lowercase, numbers, and special chars
        parts = [
            ''.join(random.choices(string.ascii_uppercase, k=3)),
            ''.join(random.choices(string.ascii_lowercase, k=5)),
            ''.join(random.choices(string.digits, k=3)),
            ''.join(random.choices("!@#$%^&*", k=2)),
        ]
        random.shuffle(parts)
        return ''.join(parts)

    def _generate_api_token(self, context: dict[str, Any]) -> str:
        """Generate generic API token."""
        return secrets.token_urlsafe(32)

    def _generate_jwt_secret(self, context: dict[str, Any]) -> str:
        """Generate JWT secret."""
        return secrets.token_urlsafe(48)

    def _generate_patient_id(self, context: dict[str, Any]) -> str:
        """Generate realistic patient ID for healthcare context."""
        format_hint = context.get("format_hint", "YYYYMMDD-NNNN")
        
        if format_hint == "YYYYMMDD-NNNN":
            # Date-based patient ID (common in healthcare)
            birth_date = datetime.now() - timedelta(days=random.randint(365*20, 365*80))
            date_part = birth_date.strftime("%Y%m%d")
            seq_part = f"{random.randint(1000, 9999)}"
            return f"{date_part}-{seq_part}"
        elif format_hint == "P-NNNNNN":
            # Sequential patient ID
            return f"P-{random.randint(100000, 999999)}"
        else:
            # Generic format: Facility code + sequence
            facility_codes = ["NYC", "LAX", "CHI", "HOU", "PHX"]
            return f"{random.choice(facility_codes)}-{random.randint(10000000, 99999999)}"

    def _generate_ssn(self, context: dict[str, Any]) -> str:
        """Generate fake SSN (Social Security Number format).
        
        Uses SSA-invalid area numbers (900-999) per Social Security Administration rules:
        https://www.ssa.gov/employer/stateweb.htm
        Area numbers 900-999 were never assigned and are safe for testing.
        """
        # Area numbers 900-999 are invalid per SSA - they were never issued
        area = random.randint(900, 999)
        group = random.randint(10, 99)
        serial = random.randint(1000, 9999)
        return f"{area}-{group:02d}-{serial}"

    def _generate_credit_card(self, context: dict[str, Any]) -> str:
        """Generate fake credit card number (test/invalid format).
        
        Uses well-known test card prefixes that won't pass production validation:
        - 4111: Visa test card prefix
        - 5500: Mastercard test card prefix  
        - 3782: American Express test card prefix
        Note: Generated numbers have invalid Luhn checksums.
        """
        # Well-known test card prefixes by network
        test_prefixes = [
            "4111",  # Visa test
            "5500",  # Mastercard test
            "3782",  # American Express test
        ]
        prefix = random.choice(test_prefixes)
        
        # Generate remaining digits (without valid Luhn checksum)
        remaining = ''.join(random.choices(string.digits, k=12))
        card_number = prefix + remaining
        
        # Format as standard credit card
        return f"{card_number[:4]}-{card_number[4:8]}-{card_number[8:12]}-{card_number[12:16]}"

    def _generate_employee_id(self, context: dict[str, Any]) -> str:
        """Generate realistic employee ID."""
        format_hint = context.get("format_hint", "EMP-NNNNNN")
        
        if format_hint == "EMP-NNNNNN":
            return f"EMP-{random.randint(100000, 999999)}"
        elif format_hint == "LNNNNN":
            # Letter prefix + digits (common format)
            letter = random.choice(string.ascii_uppercase)
            return f"{letter}{random.randint(10000, 99999)}"
        else:
            # Department code + sequence
            depts = ["ENG", "FIN", "HR", "OPS", "MKT", "IT"]
            return f"{random.choice(depts)}{random.randint(1000, 9999)}"

    def _generate_mrn(self, context: dict[str, Any]) -> str:
        """Generate Medical Record Number (MRN)."""
        format_hint = context.get("format_hint", "MRN-NNNNNNNN")
        
        if format_hint == "MRN-NNNNNNNN":
            return f"MRN-{random.randint(10000000, 99999999)}"
        else:
            # Facility-based MRN
            facility_codes = ["HOSP", "CLIN", "LAB", "MED"]
            return f"{random.choice(facility_codes)}-{random.randint(1000000, 9999999)}"
