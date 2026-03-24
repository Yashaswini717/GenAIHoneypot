from typing import Any

# Hard constraint appended to all config prompts
_CONFIG_CONSTRAINTS = """

IMPORTANT — Output rules:
- Output ONLY the raw configuration file content, nothing else.
- Start with the first line of the config file (comment header, directive, or setting).
- Do NOT include any introductory text, explanation, or description before or after the content.
- Do NOT wrap the output in code fences (``` or ~~~).
- Comments should look like they were written by the admin who last edited the file.
- Do NOT mention honeypots, deception, monitoring, or security analysis."""


def get_bashrc_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for .bashrc file."""
    persona = context.get("persona", "developer")
    
    return f"""Generate a realistic .bashrc file for a {persona}.
Include:
- Shell prompt customization (PS1)
- Useful aliases (ls, grep, git shortcuts)
- PATH modifications
- History settings
- Auto-completion setup
- Environment variables
- Function definitions
- Tool-specific configurations (nvm, pyenv, etc.)
- Comments explaining sections
Make it look like a file evolved over time with accumulated customizations.{_CONFIG_CONSTRAINTS}"""


def get_ssh_config_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for SSH config."""
    persona = context.get("persona", "sysadmin")
    num_hosts = context.get("num_hosts", 5)
    
    return f"""Generate a realistic SSH config file for a {persona} managing {num_hosts} servers.
Include:
- Multiple Host entries with realistic names
- Different authentication methods (keys, passwords)
- Port forwarding configurations
- ProxyJump/ProxyCommand for bastion hosts
- ForwardAgent settings
- Compression options
- ServerAliveInterval settings
- IdentityFile paths
- User mappings
- Comments explaining each host's purpose{_CONFIG_CONSTRAINTS}"""


def get_env_file_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for .env file."""
    app_type = context.get("app_type", "web")
    environment = context.get("environment", "development")
    
    return f"""Generate a realistic .env file for a {app_type} application in {environment}.
Include:
- Database connection strings (with honeytokens)
- API keys and secrets (use fake but realistic format)
- Service URLs and endpoints
- Feature flags
- Port configurations
- Debug settings
- Third-party service credentials (AWS, Stripe, etc.)
- Comments for sections
- Mix of commented out and active variables
Make credentials look real but use honeytokens.{_CONFIG_CONSTRAINTS}"""


def get_nginx_conf_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for nginx.conf."""
    site_type = context.get("site_type", "web_app")
    
    return f"""Generate a realistic nginx configuration for {site_type}.
Include:
- Server blocks with realistic domain names
- Upstream configurations
- SSL/TLS settings
- Proxy headers
- Rate limiting
- Caching rules
- Gzip compression
- Security headers
- Access and error log paths
- Location blocks with proper routing
- WebSocket support if applicable
- Static file serving
Make it production-ready with some common misconfigurations.{_CONFIG_CONSTRAINTS}"""


def get_docker_compose_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for docker-compose.yml."""
    stack = context.get("stack", "web")
    
    return f"""Generate a realistic docker-compose.yml for a {stack} application stack.
Include:
- Multiple services (app, database, cache, etc.)
- Environment variables
- Volume mounts
- Port mappings
- Networks
- Health checks
- Restart policies
- Resource limits
- Dependencies between services
- Build contexts
- Realistic image versions
- Comments explaining services
Make it look like a real development/production setup.{_CONFIG_CONSTRAINTS}"""


def get_database_config_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for database configuration."""
    db_type = context.get("db_type", "postgresql")
    
    return f"""Generate a realistic {db_type} configuration file.
Include:
- Connection settings
- Pool configurations
- Memory settings
- Logging configuration
- Authentication settings
- Performance tuning parameters
- Replication settings
- Backup configurations
- Security settings
- Comments explaining each section
Make it production-ready with realistic values.{_CONFIG_CONSTRAINTS}"""


def get_apache_conf_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for Apache config."""
    site_type = context.get("site_type", "wordpress")
    
    return f"""Generate a realistic Apache virtual host configuration for {site_type}.
Include:
- VirtualHost directives
- DocumentRoot paths
- Directory permissions
- Rewrite rules
- SSL configuration
- Log files
- Custom error pages
- Module configurations
- Security headers
- Performance settings
Make it look like real production config.{_CONFIG_CONSTRAINTS}"""


def get_systemd_service_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for systemd service file."""
    service_name = context.get("service_name", "webapp")
    
    return f"""Generate a realistic systemd service file for {service_name}.
Include:
- [Unit] section with description
- [Service] section with proper type
- ExecStart command
- User and Group settings
- Environment variables
- Restart policies
- Resource limits
- Working directory
- [Install] section
- Security hardening options
Make it production-ready.{_CONFIG_CONSTRAINTS}"""
