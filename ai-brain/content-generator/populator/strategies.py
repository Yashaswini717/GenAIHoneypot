from typing import Any, Optional

from core.llm_client import LLMClient
from generators.config_files import ConfigGenerator
from generators.honeytokens import HoneytokenGenerator
from generators.source_code import SourceCodeGenerator
from generators.system_logs import SystemLogGenerator
from generators.user_documents import UserDocumentGenerator
from storage.honeytoken_store import HoneytokenStore
from storage.models import HoneytokenCreate

from .base import BasePopulator, PopulationResult
from .filesystem import FilesystemPopulator


class PopulationStrategy(BasePopulator):
    """Strategies for populating different honeypot types."""

    def __init__(
        self, 
        llm_client: LLMClient, 
        filesystem_populator: FilesystemPopulator,
        honeytoken_store: Optional[HoneytokenStore] = None,
    ):
        """Initialize strategy with generators."""
        self.llm_client = llm_client
        self.filesystem_populator = filesystem_populator
        self.honeytoken_store = honeytoken_store
        
        # Initialize generators
        self.source_code_gen = SourceCodeGenerator(llm_client)
        self.config_gen = ConfigGenerator(llm_client)
        self.log_gen = SystemLogGenerator(llm_client)
        self.doc_gen = UserDocumentGenerator(llm_client)
        self.token_gen = HoneytokenGenerator(llm_client)
        
        # Track embedded honeytokens during population
        self._embedded_tokens: list[dict[str, Any]] = []

    async def _generate_and_persist_honeytoken(
        self,
        token_type: str,
        honeypot_id: str,
        file_path: str,
    ) -> str:
        """Generate honeytoken, persist it, and return the value."""
        result = await self.token_gen.generate({"token_type": token_type})
        token_value = result.content
        
        if self.honeytoken_store:
            token_create = HoneytokenCreate(
                token_type=token_type,
                token_value=token_value,
                honeypot_id=honeypot_id,
                file_path=file_path,
                token_metadata={
                    "embedded_by": "population_strategy",
                },
            )
            stored = self.honeytoken_store.create_honeytoken(token_create)
            self._embedded_tokens.append({
                "token_id": stored.token_id,
                "token_type": token_type,
                "file_path": file_path,
            })
        
        return token_value

    async def populate(self, honeypot_id: str, context: dict[str, Any]) -> PopulationResult:
        """
        Populate using specified profile.

        Args:
            honeypot_id: Honeypot ID
            context: Must contain 'profile' key

        Returns:
            PopulationResult
        """
        # Reset embedded tokens tracking
        self._embedded_tokens = []
        
        profile = context.get("profile", "developer_workstation")
        
        strategies = {
            "developer_workstation": self._populate_developer,
            "production_server": self._populate_production,
            "database_server": self._populate_database,
            "web_server": self._populate_web_server,
        }
        
        strategy_func = strategies.get(profile, self._populate_developer)
        result = await strategy_func(honeypot_id, context)
        
        # Add embedded tokens info to result metadata
        if self._embedded_tokens:
            result.metadata["embedded_honeytokens"] = self._embedded_tokens
        
        return result

    async def _populate_developer(self, honeypot_id: str, context: dict[str, Any]) -> PopulationResult:
        """Populate developer workstation profile."""
        files = []
        
        # Source code
        for lang in ["python", "javascript"]:
            code = await self.source_code_gen.generate({
                "language": lang,
                "script_type": "webapp",
                "purpose": "API development",
            })
            files.append({
                "path": f"projects/app/src/main.{lang[:2]}",
                "content": code.content,
                "permissions": 0o644,
            })
        
        # Configuration files
        bashrc = await self.config_gen.generate({"config_type": "bashrc", "persona": "developer"})
        files.append({"path": ".bashrc", "content": bashrc.content, "permissions": 0o644})
        
        ssh_config = await self.config_gen.generate({"config_type": "ssh_config", "persona": "developer"})
        files.append({"path": ".ssh/config", "content": ssh_config.content, "permissions": 0o600})
        
        env = await self.config_gen.generate({"config_type": "env", "app_type": "web"})
        files.append({"path": "projects/app/.env", "content": env.content, "permissions": 0o600})
        
        # Documents
        notes = await self.doc_gen.generate({"doc_type": "notes", "persona": "developer"})
        files.append({"path": "Documents/dev-notes.txt", "content": notes.content, "permissions": 0o644})
        
        readme = await self.doc_gen.generate({"doc_type": "readme", "project_type": "web_api"})
        files.append({"path": "projects/app/README.md", "content": readme.content, "permissions": 0o644})
        
        # Bash history
        history = await self.log_gen.generate({"log_type": "bash_history", "persona": "developer"})
        files.append({"path": ".bash_history", "content": history.content, "permissions": 0o600})
        
        # Generate and embed honeytokens in credentials file
        aws_access_key_value = await self._generate_and_persist_honeytoken(
            "aws_access_key", honeypot_id, ".aws/credentials"
        )
        aws_secret_key_value = await self._generate_and_persist_honeytoken(
            "aws_secret_key", honeypot_id, ".aws/credentials"
        )
        github_token_value = await self._generate_and_persist_honeytoken(
            "github_token", honeypot_id, ".config/gh/hosts.yml"
        )
        
        # Create AWS credentials file with honeytokens
        aws_creds_content = f"""[default]
aws_access_key_id = {aws_access_key_value}
aws_secret_access_key = {aws_secret_key_value}
region = us-east-1
"""
        files.append({"path": ".aws/credentials", "content": aws_creds_content, "permissions": 0o600})
        
        # Create GitHub hosts config with honeytoken
        gh_hosts_content = f"""github.com:
    oauth_token: {github_token_value}
    user: developer
    git_protocol: ssh
"""
        files.append({"path": ".config/gh/hosts.yml", "content": gh_hosts_content, "permissions": 0o600})
        
        # Deploy files
        return await self.filesystem_populator.populate(honeypot_id, {"files": files})

    async def _populate_production(self, honeypot_id: str, context: dict[str, Any]) -> PopulationResult:
        """Populate production server profile."""
        files = []
        
        # Server configs
        nginx = await self.config_gen.generate({"config_type": "nginx", "site_type": "web_app"})
        files.append({"path": "etc/nginx/sites-available/app.conf", "content": nginx.content, "permissions": 0o644})
        
        docker_compose = await self.config_gen.generate({"config_type": "docker_compose", "stack": "web"})
        files.append({"path": "app/docker-compose.yml", "content": docker_compose.content, "permissions": 0o644})
        
        # System logs
        auth_log = await self.log_gen.generate({"log_type": "auth", "duration_hours": 48, "attack_activity": True})
        files.append({"path": "var/log/auth.log", "content": auth_log.content, "permissions": 0o640})
        
        syslog = await self.log_gen.generate({"log_type": "syslog", "duration_hours": 48})
        files.append({"path": "var/log/syslog", "content": syslog.content, "permissions": 0o640})
        
        nginx_access = await self.log_gen.generate({"log_type": "nginx_access", "duration_hours": 24})
        files.append({"path": "var/log/nginx/access.log", "content": nginx_access.content, "permissions": 0o640})
        
        # Deployment script
        deploy_script = await self.source_code_gen.generate({
            "language": "shell",
            "script_type": "deployment",
            "purpose": "application deployment",
        })
        files.append({"path": "scripts/deploy.sh", "content": deploy_script.content, "permissions": 0o755})
        
        # Generate and embed API token honeytoken
        api_token = await self._generate_and_persist_honeytoken(
            "api_token", honeypot_id, "app/.env.production"
        )
        jwt_secret = await self._generate_and_persist_honeytoken(
            "jwt_secret", honeypot_id, "app/.env.production"
        )
        
        # Create production env file with honeytokens
        env_prod_content = f"""# Production environment
NODE_ENV=production
API_TOKEN={api_token}
JWT_SECRET={jwt_secret}
DATABASE_URL=postgresql://app:prodpassword@db.internal:5432/app
REDIS_URL=redis://cache.internal:6379/0
"""
        files.append({"path": "app/.env.production", "content": env_prod_content, "permissions": 0o600})
        
        return await self.filesystem_populator.populate(honeypot_id, {"files": files})

    async def _populate_database(self, honeypot_id: str, context: dict[str, Any]) -> PopulationResult:
        """Populate database server profile."""
        files = []
        
        # Database scripts
        backup_script = await self.source_code_gen.generate({
            "language": "python",
            "script_type": "db_script",
            "purpose": "database backup",
        })
        files.append({"path": "scripts/backup_db.py", "content": backup_script.content, "permissions": 0o755})
        
        # Configuration
        env = await self.config_gen.generate({"config_type": "env", "app_type": "database"})
        files.append({"path": ".env", "content": env.content, "permissions": 0o600})
        
        # Logs
        auth_log = await self.log_gen.generate({"log_type": "auth", "duration_hours": 72})
        files.append({"path": "var/log/auth.log", "content": auth_log.content, "permissions": 0o640})
        
        # Generate and embed database password honeytoken
        db_password = await self._generate_and_persist_honeytoken(
            "database_password", honeypot_id, ".pgpass"
        )
        
        # Create .pgpass file with honeytoken
        pgpass_content = f"""# hostname:port:database:username:password
localhost:5432:*:postgres:{db_password}
db.internal:5432:production:app_user:{db_password}
"""
        files.append({"path": ".pgpass", "content": pgpass_content, "permissions": 0o600})
        
        return await self.filesystem_populator.populate(honeypot_id, {"files": files})

    async def _populate_web_server(self, honeypot_id: str, context: dict[str, Any]) -> PopulationResult:
        """Populate web server profile."""
        files = []
        
        # Web application code
        app_code = await self.source_code_gen.generate({
            "language": "python",
            "script_type": "webapp",
            "purpose": "web API",
        })
        files.append({"path": "app/main.py", "content": app_code.content, "permissions": 0o644})
        
        # Nginx config
        nginx = await self.config_gen.generate({"config_type": "nginx", "site_type": "api"})
        files.append({"path": "nginx.conf", "content": nginx.content, "permissions": 0o644})
        
        # Access logs
        apache_log = await self.log_gen.generate({"log_type": "apache_access", "duration_hours": 24})
        files.append({"path": "logs/access.log", "content": apache_log.content, "permissions": 0o644})
        
        # Generate and embed API key honeytoken
        api_key = await self._generate_and_persist_honeytoken(
            "api_token", honeypot_id, "app/config.py"
        )
        
        # Create config file with honeytoken
        config_content = f'''"""Application configuration."""

class Config:
    SECRET_KEY = "{api_key}"
    DATABASE_URL = "postgresql://localhost/app"
    DEBUG = False
'''
        files.append({"path": "app/config.py", "content": config_content, "permissions": 0o644})
        
        return await self.filesystem_populator.populate(honeypot_id, {"files": files})
