from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class AudienceType(str, Enum):
    """Target audience for generated content."""
    INTERNAL = "internal"  # Internal SOC/security team
    EXTERNAL = "external"  # External auditors, customers
    ATTACKER = "attacker"  # Content meant to deceive attackers
    DEVELOPER = "developer"  # Developer-facing content


class RealismLevel(str, Enum):
    """Level of realism in generated content."""
    LOW = "low"  # Obviously fake, for testing
    MEDIUM = "medium"  # Realistic but with some indicators
    HIGH = "high"  # Production-quality deception


class LogCategory(str, Enum):
    """Category of log to generate - controls structural format."""
    SYSTEM = "system"  # OS-level syslog, auth.log, kernel logs
    APPLICATION = "application"  # Application audit logs, JSON structured
    ACCESS = "access"  # Web access logs (Apache, Nginx)
    SECURITY = "security"  # Security event logs, SIEM format
    AUDIT = "audit"  # Business/compliance audit trails


class GenerateRequest(BaseModel):
    """Base request for content generation."""

    context: dict[str, Any] = Field(default_factory=dict, description="Generation context parameters")
    honeypot_id: Optional[str] = Field(None, description="Associated honeypot ID")
    industry: Optional[str] = Field(None, description="Industry context (healthcare, finance, tech, retail, etc.)")
    compliance: Optional[list[str]] = Field(None, description="Compliance standards (HIPAA, PCI-DSS, SOX, GDPR)")


class SourceCodeRequest(GenerateRequest):
    """Request for source code generation."""

    language: str = Field(..., description="Programming language (python, javascript, shell, go)")
    script_type: Optional[str] = Field(None, description="Type of script (webapp, cli, etc.)")
    purpose: Optional[str] = Field(None, description="Purpose description")


class ConfigRequest(GenerateRequest):
    """Request for configuration file generation."""

    config_type: str = Field(..., description="Config type (bashrc, ssh_config, env, nginx, docker_compose)")
    persona: Optional[str] = Field("developer", description="User persona")


class LogRequest(GenerateRequest):
    """Request for log file generation."""

    log_type: str = Field(..., description="Log type (auth, syslog, bash_history, apache_access, nginx_access, application)")
    duration_hours: int = Field(24, description="Duration in hours", ge=1, le=168)
    attack_activity: bool = Field(False, description="Include attack patterns")
    # New semantic intent fields
    log_category: LogCategory = Field(
        LogCategory.SYSTEM, 
        description="Category of log - controls structural format (system, application, access, security, audit)"
    )
    log_format: Optional[str] = Field(
        None, 
        description="Explicit log format (syslog, json, combined, clf, custom). If not specified, defaults based on log_category."
    )


class DocumentRequest(GenerateRequest):
    """Request for document generation."""

    doc_type: str = Field(..., description="Document type (notes, readme, todo, api_docs, runbook)")
    persona: Optional[str] = Field("developer", description="User persona")
    topic: Optional[str] = Field(None, description="Document topic")
    # New semantic intent fields
    audience: AudienceType = Field(
        AudienceType.INTERNAL, 
        description="Target audience for the document"
    )
    realism_level: RealismLevel = Field(
        RealismLevel.HIGH, 
        description="Level of realism for generated content"
    )
    hide_honeypot_concepts: bool = Field(
        True, 
        description="If True, generated content will not mention honeypots, deception, or fake data"
    )


class HoneytokenRequest(GenerateRequest):
    """Request for honeytoken generation."""

    token_type: str = Field(
        ...,
        description="Token type (aws_access_key, github_token, ssh_private_key, database_password, api_token, patient_id, ssn, credit_card)",
    )
    # New structured token parameters
    format_hint: Optional[str] = Field(
        None,
        description="Optional format hint for structured tokens (e.g., 'XXX-XX-XXXX' for SSN, 'YYYYMMDD-NNNN' for patient ID)"
    )


class PopulateRequest(BaseModel):
    """Request for honeypot population."""

    profile: str = Field(
        "developer_workstation",
        description="Population profile (developer_workstation, production_server, database_server, web_server)",
    )
    custom_files: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Additional custom files to include",
    )
    context: dict[str, Any] = Field(default_factory=dict, description="Additional context")
    industry: Optional[str] = Field(None, description="Industry context for content generation")


class HoneytokenCheckRequest(BaseModel):
    """Request to check if token is a honeytoken."""

    token_value: str = Field(..., description="Token value to check")
