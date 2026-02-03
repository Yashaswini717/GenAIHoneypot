from typing import Any


def _get_audience_instruction(audience: str) -> str:
    """Get instructions based on target audience."""
    audience_instructions = {
        "internal": "Write as internal documentation for security/IT team. Use technical jargon freely.",
        "external": "Write as documentation for external stakeholders, auditors, or customers. Be professional and clear.",
        "attacker": "Write as authentic developer/admin notes that would appear realistic to an attacker. Include 'hidden' credentials or sensitive info.",
        "developer": "Write as informal developer notes with shortcuts, abbreviations, and work-in-progress content.",
    }
    return audience_instructions.get(audience, audience_instructions["internal"])


def _get_realism_instruction(realism_level: str) -> str:
    """Get instructions based on realism level."""
    realism_instructions = {
        "low": "Content can be obviously simplified or templated for testing purposes.",
        "medium": "Content should be realistic but may have some placeholder values.",
        "high": "Content must be production-quality, indistinguishable from real documentation. Include authentic details, dates, and realistic content.",
    }
    return realism_instructions.get(realism_level, realism_instructions["high"])


def _get_honeypot_visibility_instruction(hide_honeypot_concepts: bool) -> str:
    """Get instructions about honeypot concept visibility."""
    if hide_honeypot_concepts:
        return "IMPORTANT: Do NOT mention honeypots, deception, fake data, or security traps. Generate content as if it's for a real production system."
    else:
        return "Content may reference security monitoring, detection, or honeypot concepts where appropriate."


def get_readme_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for README.md."""
    project_type = context.get("project_type", "web_application")
    tech_stack = context.get("tech_stack", "Python/Flask")
    audience = context.get("audience", "developer")
    realism_level = context.get("realism_level", "high")
    hide_honeypot = context.get("hide_honeypot_concepts", True)
    
    audience_inst = _get_audience_instruction(audience)
    realism_inst = _get_realism_instruction(realism_level)
    honeypot_inst = _get_honeypot_visibility_instruction(hide_honeypot)
    
    return f"""Generate a realistic README.md for a {project_type} using {tech_stack}.

{audience_inst}
{realism_inst}
{honeypot_inst}

Include:
- Project title and description
- Features list
- Prerequisites
- Installation instructions
- Configuration section
- Usage examples
- API documentation (if applicable)
- Testing instructions
- Deployment notes
- Troubleshooting section
- Contributing guidelines
- License information
- Some TODOs or known issues
- Badges (build, coverage, version)
Make it look like real project documentation with some incompleteness."""


def get_notes_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for developer notes."""
    persona = context.get("persona", "developer")
    topic = context.get("topic", "current project")
    audience = context.get("audience", "developer")
    realism_level = context.get("realism_level", "high")
    hide_honeypot = context.get("hide_honeypot_concepts", True)
    industry = context.get("industry", "technology")
    
    audience_inst = _get_audience_instruction(audience)
    realism_inst = _get_realism_instruction(realism_level)
    honeypot_inst = _get_honeypot_visibility_instruction(hide_honeypot)
    
    industry_context = f"Context: {industry} industry environment." if industry else ""
    
    return f"""Generate realistic developer notes for a {persona} working on {topic}.

{audience_inst}
{realism_inst}
{honeypot_inst}
{industry_context}

Include:
- Meeting notes
- Technical decisions and rationale
- Code snippets and examples
- Bug investigation notes
- Performance optimization ideas
- API endpoints documentation
- Database schema notes
- Deployment checklist
- Login credentials (as realistic-looking credentials)
- Quick commands and scripts
- Incomplete thoughts and TODOs
- Links to resources
- Timestamps and dates
Make it look like authentic working notes."""


def get_todo_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for TODO.md."""
    project_type = context.get("project_type", "web_application")
    audience = context.get("audience", "developer")
    realism_level = context.get("realism_level", "high")
    hide_honeypot = context.get("hide_honeypot_concepts", True)
    
    audience_inst = _get_audience_instruction(audience)
    realism_inst = _get_realism_instruction(realism_level)
    honeypot_inst = _get_honeypot_visibility_instruction(hide_honeypot)
    
    return f"""Generate a realistic TODO.md for a {project_type}.

{audience_inst}
{realism_inst}
{honeypot_inst}

Include:
- High priority tasks
- Medium priority tasks
- Low priority/nice-to-have
- Completed tasks (checked off)
- Bug fixes needed
- Feature requests
- Technical debt items
- Refactoring tasks
- Testing improvements
- Documentation updates
- Performance optimizations
- Security improvements
- Some tasks with deadlines
- Some tasks assigned to people
- Use markdown checkboxes
Make it look like real project management."""


def get_api_docs_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for API documentation."""
    api_type = context.get("api_type", "REST")
    audience = context.get("audience", "developer")
    realism_level = context.get("realism_level", "high")
    hide_honeypot = context.get("hide_honeypot_concepts", True)
    
    audience_inst = _get_audience_instruction(audience)
    realism_inst = _get_realism_instruction(realism_level)
    honeypot_inst = _get_honeypot_visibility_instruction(hide_honeypot)
    
    return f"""Generate realistic API documentation for a {api_type} API.

{audience_inst}
{realism_inst}
{honeypot_inst}

Include:
- Authentication section (API keys, OAuth)
- Base URLs (production, staging)
- Endpoint list with methods
- Request/response examples
- Error codes and messages
- Rate limiting information
- Versioning strategy
- Changelog
- Code examples in multiple languages
- Common use cases
- Webhook documentation
- Testing with curl examples
Make it comprehensive but realistic."""


def get_runbook_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for operations runbook."""
    service = context.get("service", "web application")
    audience = context.get("audience", "internal")
    realism_level = context.get("realism_level", "high")
    hide_honeypot = context.get("hide_honeypot_concepts", True)
    
    audience_inst = _get_audience_instruction(audience)
    realism_inst = _get_realism_instruction(realism_level)
    honeypot_inst = _get_honeypot_visibility_instruction(hide_honeypot)
    
    return f"""Generate a realistic operations runbook for {service}.

{audience_inst}
{realism_inst}
{honeypot_inst}

Include:
- Service overview
- Architecture diagram (described)
- Monitoring and alerts
- Common issues and solutions
- Deployment procedures
- Rollback procedures
- Database backup/restore
- Log locations and analysis
- Performance troubleshooting
- Incident response steps
- Contact information
- On-call procedures
- Configuration management
- Credentials location (use realistic paths)
Make it practical and detailed."""


def get_changelog_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for CHANGELOG.md."""
    project_name = context.get("project_name", "Application")
    versions = context.get("versions", 5)
    realism_level = context.get("realism_level", "high")
    hide_honeypot = context.get("hide_honeypot_concepts", True)
    
    realism_inst = _get_realism_instruction(realism_level)
    honeypot_inst = _get_honeypot_visibility_instruction(hide_honeypot)
    
    return f"""Generate a realistic CHANGELOG.md for {project_name} ({versions} recent versions).

{realism_inst}
{honeypot_inst}

Include:
- Version numbers (semantic versioning)
- Release dates
- Added features
- Changed functionality
- Deprecated items
- Removed features
- Fixed bugs
- Security patches
- Breaking changes
- Migration notes
Follow "Keep a Changelog" format.
Make it look like real project history."""


def get_architecture_doc_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for architecture documentation."""
    system_type = context.get("system_type", "microservices")
    audience = context.get("audience", "internal")
    realism_level = context.get("realism_level", "high")
    hide_honeypot = context.get("hide_honeypot_concepts", True)
    
    audience_inst = _get_audience_instruction(audience)
    realism_inst = _get_realism_instruction(realism_level)
    honeypot_inst = _get_honeypot_visibility_instruction(hide_honeypot)
    
    return f"""Generate realistic architecture documentation for a {system_type} system.

{audience_inst}
{realism_inst}
{honeypot_inst}

Include:
- System overview
- Components and their responsibilities
- Technology stack
- Data flow diagrams (described)
- API contracts
- Database schemas
- Infrastructure setup
- Scaling strategy
- Security considerations
- Monitoring and logging
- Deployment architecture
- Trade-offs and decisions
- Future improvements
Make it technical and detailed."""
