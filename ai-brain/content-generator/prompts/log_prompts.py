from typing import Any

# Hard constraints for system-layer logs (attacker-facing: auth.log, syslog, etc.)
_SYSTEM_LOG_CONSTRAINTS = """

IMPORTANT — Output rules:
- Output ONLY raw log lines, exactly as they would appear in the log file on disk.
- Start with the first log entry — no introductory text, no explanation.
- End with the last log entry — no trailing commentary or summary.
- Do NOT wrap the output in code fences (``` or ~~~).
- Do NOT include security analysis terms: threat_score, anomaly, correlation_id, severity, risk_level.
- Do NOT reference honeypots, deception, detection, SIEM, or SOC.
- Match the exact format of real OS/service logs (syslog, combined log format, etc.).
- Do NOT output JSON unless the target log type is explicitly JSON-formatted (e.g., application structured logs)."""

# Constraints for analysis-layer logs (defender-facing: SIEM, audit, security events)
_ANALYSIS_LOG_CONSTRAINTS = """

IMPORTANT — Output rules:
- Output ONLY the log entries in the specified structured format.
- Start with the first log entry — no introductory text.
- End with the last log entry — no trailing commentary.
- Do NOT wrap the output in code fences (``` or ~~~)."""


def get_auth_log_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for auth.log."""
    duration_hours = context.get("duration_hours", 24)
    attack_activity = context.get("attack_activity", False)
    
    attack_note = ""
    if attack_activity:
        attack_note = "\n- Include failed SSH login attempts from suspicious IPs\n- Add some brute force patterns\n- Include blocked connection attempts"
    
    return f"""Generate realistic auth.log entries spanning {duration_hours} hours.
Include:
- Successful SSH logins from legitimate IPs
- PAM authentication events
- Sudo command executions
- User session opening/closing
- Cron job executions
- System service authentications{attack_note}
- Realistic timestamps in syslog format
- Mix of successful and failed events
- Different usernames (admin, deploy, ubuntu, etc.)
- Realistic IP addresses (both internal and external)
Make it look like real server authentication logs.{_SYSTEM_LOG_CONSTRAINTS}"""


def get_syslog_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for syslog."""
    duration_hours = context.get("duration_hours", 24)
    services = context.get("services", ["cron", "systemd", "kernel"])
    
    return f"""Generate realistic syslog entries spanning {duration_hours} hours.
Include entries from services: {', '.join(services)}
Include:
- Kernel messages (device events, network)
- Systemd service start/stop/reload
- Cron job executions
- Network interface events
- Disk I/O events
- System startup/shutdown messages
- Package manager operations
- Realistic timestamps
- Proper syslog facility.priority levels (e.g., kern.warning, auth.info)
- Realistic facility tags
Make it look like real system logs.{_SYSTEM_LOG_CONSTRAINTS}"""


def get_bash_history_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for bash history."""
    persona = context.get("persona", "developer")
    num_commands = context.get("num_commands", 100)
    
    return f"""Generate realistic bash history for a {persona} ({num_commands} commands).
Include:
- Git operations (clone, commit, push, pull, branch)
- File operations (ls, cd, cp, mv, cat, grep)
- Package management (apt, yum, pip, npm)
- Docker commands
- SSH connections
- Database queries
- Text editing (vim, nano)
- System monitoring (ps, top, df, netstat)
- Build commands (make, npm run, python)
- Some typos and corrected commands
- Repeated common commands
- Commands with sensitive info (accidentally typed passwords, then deleted)
Make it look authentic with realistic patterns.{_SYSTEM_LOG_CONSTRAINTS}"""


def get_apache_access_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for Apache access log."""
    duration_hours = context.get("duration_hours", 24)
    site_type = context.get("site_type", "web_app")
    
    return f"""Generate realistic Apache access log for a {site_type} spanning {duration_hours} hours.
Include:
- GET/POST requests to various endpoints
- Static file requests (css, js, images)
- API endpoint calls
- Different user agents (browsers, bots, curl)
- Mix of status codes (200, 304, 404, 500)
- Realistic IP addresses
- Referrer headers
- Request sizes
- Response times
- Some bot traffic
- Some suspicious scanning attempts
Use Combined Log Format.{_SYSTEM_LOG_CONSTRAINTS}"""


def get_nginx_access_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for nginx access log."""
    duration_hours = context.get("duration_hours", 24)
    site_type = context.get("site_type", "api")
    
    return f"""Generate realistic nginx access log for a {site_type} spanning {duration_hours} hours.
Include:
- HTTP/HTTPS requests
- API endpoints with different methods
- WebSocket upgrade requests
- Static asset requests
- Health check endpoints
- Load balancer traffic
- Different status codes (200, 201, 400, 401, 404, 500, 502, 503)
- Realistic IP addresses
- User agents
- X-Request-ID header values when present in the request
- Upstream response times
- Some automated scanner traffic
Use nginx combined format with timing.{_SYSTEM_LOG_CONSTRAINTS}"""


def get_nginx_error_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for nginx error log."""
    duration_hours = context.get("duration_hours", 24)
    
    return f"""Generate realistic nginx error log spanning {duration_hours} hours.
Include:
- Upstream connection failures
- Timeout errors
- SSL handshake errors
- File not found errors
- Permission denied errors
- Client disconnects
- Rate limiting messages
- Memory/resource warnings
- Different error levels (error, warn, notice)
- Realistic timestamps
- Connection details
Make it look like real production errors.{_SYSTEM_LOG_CONSTRAINTS}"""


def get_application_log_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for application log."""
    app_type = context.get("app_type", "web_api")
    duration_hours = context.get("duration_hours", 24)
    industry = context.get("industry", "technology")
    log_format = context.get("log_format", "syslog")
    
    format_instruction = ""
    if log_format == "json":
        format_instruction = """
Format: JSON structured logs with one JSON object per line.
Example format:
{"timestamp":"2024-01-15T10:23:45.123Z","level":"INFO","service":"api","request_id":"abc-123","message":"Request processed","duration_ms":45}
"""
    elif log_format == "syslog":
        format_instruction = """
Format: Syslog-style with structured data.
Example format:
Jan 15 10:23:45 api-server-01 webapp[12345]: [INFO] [req:abc-123] Request processed in 45ms
"""
    
    industry_context = ""
    if industry:
        industry_context = f"\nGenerate logs relevant to {industry} industry operations."
    
    return f"""Generate realistic application log for a {app_type} spanning {duration_hours} hours.{industry_context}
{format_instruction}
Include:
- INFO level: Request handling, operation success
- WARN level: Deprecated API usage, slow queries
- ERROR level: Exceptions, failed operations
- DEBUG level: Detailed execution flow
- Request IDs for tracing
- Execution times
- Database query logs
- External API call logs
- User IDs and actions
- Stack traces for errors
Make it look like real application logging for a {industry} company.{_SYSTEM_LOG_CONSTRAINTS}"""


def get_audit_log_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for audit/compliance logs."""
    duration_hours = context.get("duration_hours", 24)
    industry = context.get("industry", "finance")
    compliance = context.get("compliance", [])
    
    compliance_context = ""
    if compliance:
        compliance_context = f"\nCompliance requirements: {', '.join(compliance)}"
    
    return f"""Generate realistic audit trail logs for a {industry} organization spanning {duration_hours} hours.{compliance_context}

Format: JSON structured audit logs with one record per line.
Example format:
{{"timestamp":"2024-01-15T10:23:45.123Z","event_type":"DATA_ACCESS","actor":"user:john.doe@example.com","action":"READ","resource":"patient_record:12345","outcome":"SUCCESS","client_ip":"10.0.1.50","session_id":"sess-abc123"}}

Include:
- User authentication events (login, logout, MFA)
- Data access events (read, write, delete)
- Administrative actions (user creation, permission changes)
- System configuration changes
- Export/download events for sensitive data
- Failed access attempts with reasons
- Actor identification (user, service account, system)
- Resource identifiers (what was accessed)
- Outcome status (success, failure, denied)
- Client metadata (IP, device, location)
Make these production-quality audit logs suitable for compliance review.{_ANALYSIS_LOG_CONSTRAINTS}"""


def get_security_event_log_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for security event logs (SIEM-style)."""
    duration_hours = context.get("duration_hours", 24)
    attack_activity = context.get("attack_activity", False)
    
    attack_note = ""
    if attack_activity:
        attack_note = """
- Include some security events indicating potential attacks:
  - Multiple failed login attempts from same source
  - Unusual access patterns
  - Privilege escalation attempts
  - Suspicious file access
"""
    
    return f"""Generate realistic security event logs (SIEM format) spanning {duration_hours} hours.

Format: CEF (Common Event Format) or JSON structured security events.
Example JSON format:
{{"timestamp":"2024-01-15T10:23:45.123Z","event_category":"authentication","event_type":"login_failure","severity":"medium","source_ip":"203.0.113.42","destination":"auth-server-01","user":"admin","reason":"invalid_password","count":3}}

Include:
- Authentication events (success, failure)
- Network connection events
- File access events
- Process execution events
- Privilege changes
- Anomaly detection events{attack_note}
- Event severity levels (low, medium, high, critical)
- Source and destination information
- Correlation IDs for related events
Make these look like real SIEM security events.{_ANALYSIS_LOG_CONSTRAINTS}"""


def get_database_log_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for database log."""
    db_type = context.get("db_type", "postgresql")
    
    # Provide explicit format example for PostgreSQL (the default and most common)
    # to prevent LLM from defaulting to JSON or inventing a format
    format_example = ""
    if db_type.lower() == "postgresql":
        format_example = """
Format: PostgreSQL default log format.
Example:
2024-01-15 10:23:45.123 UTC [12345] LOG:  statement: SELECT * FROM users WHERE id = 42
2024-01-15 10:23:45.456 UTC [12345] WARNING:  table "sessions" has no indexes
"""
    
    return f"""Generate realistic {db_type} log entries.{format_example}
Include:
- Connection events
- Query execution logs
- Slow query warnings
- Index usage warnings
- Lock wait timeouts
- Transaction commits/rollbacks
- Checkpoint operations
- Vacuum operations
- Authentication success/failure
- Configuration changes
- Error messages with SQL states
- Performance statistics
Make it production-realistic.{_SYSTEM_LOG_CONSTRAINTS}"""
