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
        # Steps that failed during the most recent build, for the caller to see
        self._failures: list[str] = []

    async def _gen(self, generator: Any, context: dict[str, Any], *, what: str) -> Optional[Any]:
        """Run one generation step, returning None instead of raising.

        A profile is six to ten sequential model calls and used to be
        all-or-nothing: any one of them raising aborted the whole build, the
        endpoint turned that into a 503, and the attacker got nothing generated
        at all. Against a provider where roughly one call in three stalls to
        its timeout, a complete profile almost never landed.

        One failed call should cost one file, not the profile. Callers check
        for None and skip that file; everything else still gets built.
        """
        try:
            return await generator.generate(context)
        except Exception as e:
            self._failures.append(what)
            self.logger.warning(
                "generation_step_failed", step=what, error=str(e), error_type=type(e).__name__
            )
            return None

    @property
    def failures(self) -> list[str]:
        """Steps that failed during the most recent build."""
        return list(self._failures)

    async def _generate_and_persist_honeytoken(
        self,
        token_type: str,
        honeypot_id: str,
        file_path: str,
    ) -> Optional[str]:
        """Generate honeytoken, persist it, and return the value.

        Returns None if generation failed. Callers must skip the file they were
        going to embed it in -- a credentials file containing the literal text
        "None" where a secret should be is worse than no credentials file.
        """
        result = await self._gen(
            self.token_gen, {"token_type": token_type}, what=f"honeytoken/{token_type}"
        )
        if result is None:
            return None
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
            # register_ rather than create_: two generated values can collide,
            # and a duplicate row makes check_honeytoken's scalar_one_or_none
            # raise, which would silently disable that value's tripwire.
            stored = self.honeytoken_store.register_honeytoken(token_create)
            self._embedded_tokens.append({
                "token_id": stored.token_id,
                "token_type": token_type,
                "token_value": token_value,
                "file_path": file_path,
            })
        
        return token_value

    async def build(self, honeypot_id: str, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate a profile's files without deciding where they go.

        Split out from `populate` because writing to this process's own disk is
        only one possible destination, and it turned out to be the wrong one.
        The honeypot's attacker containers are reachable through the session
        broker, not through a local path, so the caller that can reach them
        needs the file specs themselves rather than a count of files written
        somewhere it cannot see.

        `self._embedded_tokens` is populated as a side effect and is how a
        caller learns which honeytoken values ended up inside this content —
        without them, a generated credential could be used by an attacker with
        nothing watching for it.
        """
        self._embedded_tokens = []
        self._failures = []

        profile = context.get("profile", "developer_workstation")

        strategies = {
            "developer_workstation": self._build_developer,
            "production_server": self._build_production,
            "database_server": self._build_database,
            "web_server": self._build_web_server,
        }

        strategy_func = strategies.get(profile, self._build_developer)
        files = await strategy_func(honeypot_id, context)

        if self._failures:
            self.logger.warning(
                "build_completed_with_failures",
                profile=profile,
                files=len(files),
                failed_steps=len(self._failures),
                steps=self._failures,
            )
        return files

    @property
    def embedded_tokens(self) -> list[dict[str, Any]]:
        """Honeytokens embedded by the most recent `build` call."""
        return list(self._embedded_tokens)

    async def populate(self, honeypot_id: str, context: dict[str, Any]) -> PopulationResult:
        """
        Populate using specified profile, writing to the local filesystem.

        Args:
            honeypot_id: Honeypot ID
            context: Must contain 'profile' key

        Returns:
            PopulationResult
        """
        files = await self.build(honeypot_id, context)
        result = await self.filesystem_populator.populate(honeypot_id, {"files": files})

        # Add embedded tokens info to result metadata
        if self._embedded_tokens:
            result.metadata["embedded_honeytokens"] = self._embedded_tokens

        return result

    async def _build_developer(self, honeypot_id: str, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Populate developer workstation profile."""
        if context.get("action") == "serve_minimal_banner":
            return await self._build_developer_minimal(honeypot_id, context)

        files = []

        # Source code
        for lang in ["python", "javascript"]:
            code = await self._gen(self.source_code_gen, {
                "language": lang,
                "script_type": "webapp",
                "purpose": "API development",
            }, what=f"source/{lang}")
            if code:
                files.append({
                    "path": f"projects/app/src/main.{lang[:2]}",
                    "content": code.content,
                    "permissions": 0o644,
                })

        # Configuration files
        bashrc = await self._gen(self.config_gen, {"config_type": "bashrc", "persona": "developer"}, what="config/bashrc")
        if bashrc:
            files.append({"path": ".bashrc", "content": bashrc.content, "permissions": 0o644})

        ssh_config = await self._gen(self.config_gen, {"config_type": "ssh_config", "persona": "developer"}, what="config/ssh_config")
        if ssh_config:
            files.append({"path": ".ssh/config", "content": ssh_config.content, "permissions": 0o600})

        env = await self._gen(self.config_gen, {"config_type": "env", "app_type": "web"}, what="config/env")
        if env:
            files.append({"path": "projects/app/.env", "content": env.content, "permissions": 0o600})

        # Documents
        notes = await self._gen(self.doc_gen, {"doc_type": "notes", "persona": "developer"}, what="doc/notes")
        if notes:
            files.append({"path": "Documents/dev-notes.txt", "content": notes.content, "permissions": 0o644})

        readme = await self._gen(self.doc_gen, {"doc_type": "readme", "project_type": "web_api"}, what="doc/readme")
        if readme:
            files.append({"path": "projects/app/README.md", "content": readme.content, "permissions": 0o644})

        # Bash history
        history = await self._gen(self.log_gen, {"log_type": "bash_history", "persona": "developer"}, what="log/bash_history")
        if history:
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
        
        # Create AWS credentials file with honeytokens. Skipped entirely if
        # either value failed to generate -- a credentials file reading
        # "aws_secret_access_key = None" is a worse decoy than no file at all.
        if aws_access_key_value and aws_secret_key_value:
            aws_creds_content = f"""[default]
aws_access_key_id = {aws_access_key_value}
aws_secret_access_key = {aws_secret_key_value}
region = us-east-1
"""
            files.append({"path": ".aws/credentials", "content": aws_creds_content, "permissions": 0o600})

        # Create GitHub hosts config with honeytoken
        if github_token_value:
            gh_hosts_content = f"""github.com:
    oauth_token: {github_token_value}
    user: developer
    git_protocol: ssh
"""
            files.append({"path": ".config/gh/hosts.yml", "content": gh_hosts_content, "permissions": 0o600})

        return files

    async def _build_developer_minimal(self, honeypot_id: str, context: dict[str, Any]) -> list[dict[str, Any]]:
        """
        Minimal-footprint variant of the developer workstation profile.

        Deliberately a much smaller surface than `_build_developer` (3
        files instead of 7, one honeytoken pair instead of three) — the
        strategy this represents is giving a cautious attacker almost
        nothing to explore, rather than an elaborate environment inviting
        deeper poking around. Exists so `serve_minimal_banner` produces
        genuinely different deployed content from `populate_developer_workstation`,
        not just a different label pointing at the same files.
        """
        files = []

        code = await self._gen(self.source_code_gen, {
            "language": "python",
            "script_type": "cli",
            "purpose": "internal utility script",
        }, what="source/python")
        if code:
            files.append({"path": "scripts/util.py", "content": code.content, "permissions": 0o644})

        bashrc = await self._gen(self.config_gen, {"config_type": "bashrc", "persona": "developer"}, what="config/bashrc")
        if bashrc:
            files.append({"path": ".bashrc", "content": bashrc.content, "permissions": 0o644})

        aws_access_key_value = await self._generate_and_persist_honeytoken(
            "aws_access_key", honeypot_id, ".aws/credentials"
        )
        aws_secret_key_value = await self._generate_and_persist_honeytoken(
            "aws_secret_key", honeypot_id, ".aws/credentials"
        )
        if aws_access_key_value and aws_secret_key_value:
            aws_creds_content = f"""[default]
aws_access_key_id = {aws_access_key_value}
aws_secret_access_key = {aws_secret_key_value}
region = us-east-1
"""
            files.append({"path": ".aws/credentials", "content": aws_creds_content, "permissions": 0o600})

        return files

    async def _build_production(self, honeypot_id: str, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Populate production server profile."""
        files = []
        
        # Server configs
        nginx = await self._gen(self.config_gen, {"config_type": "nginx", "site_type": "web_app"}, what="config/nginx")
        if nginx:
            files.append({"path": "etc/nginx/sites-available/app.conf", "content": nginx.content, "permissions": 0o644})

        docker_compose = await self._gen(self.config_gen, {"config_type": "docker_compose", "stack": "web"}, what="config/docker_compose")
        if docker_compose:
            files.append({"path": "app/docker-compose.yml", "content": docker_compose.content, "permissions": 0o644})

        # System logs
        auth_log = await self._gen(self.log_gen, {"log_type": "auth", "duration_hours": 48, "attack_activity": True}, what="log/auth")
        if auth_log:
            files.append({"path": "var/log/auth.log", "content": auth_log.content, "permissions": 0o640})

        syslog = await self._gen(self.log_gen, {"log_type": "syslog", "duration_hours": 48}, what="log/syslog")
        if syslog:
            files.append({"path": "var/log/syslog", "content": syslog.content, "permissions": 0o640})

        nginx_access = await self._gen(self.log_gen, {"log_type": "nginx_access", "duration_hours": 24}, what="log/nginx_access")
        if nginx_access:
            files.append({"path": "var/log/nginx/access.log", "content": nginx_access.content, "permissions": 0o640})

        # Deployment script
        deploy_script = await self._gen(self.source_code_gen, {
            "language": "shell",
            "script_type": "deployment",
            "purpose": "application deployment",
        }, what="source/deploy")
        if deploy_script:
            files.append({"path": "scripts/deploy.sh", "content": deploy_script.content, "permissions": 0o755})

        # Generate and embed API token honeytoken
        api_token = await self._generate_and_persist_honeytoken(
            "api_token", honeypot_id, "app/.env.production"
        )
        jwt_secret = await self._generate_and_persist_honeytoken(
            "jwt_secret", honeypot_id, "app/.env.production"
        )
        
        # Create production env file with honeytokens
        if api_token and jwt_secret:
            env_prod_content = f"""# Production environment
NODE_ENV=production
API_TOKEN={api_token}
JWT_SECRET={jwt_secret}
DATABASE_URL=postgresql://app:prodpassword@db.internal:5432/app
REDIS_URL=redis://cache.internal:6379/0
"""
            files.append({"path": "app/.env.production", "content": env_prod_content, "permissions": 0o600})

        # simulate_cron_jobs specifically: add real persistence-mechanism
        # content (a crontab + the script it runs) that's otherwise absent
        # from this profile, so it's genuinely distinct from
        # populate_production_server rather than the same files under a
        # different action label.
        if context.get("action") == "simulate_cron_jobs":
            backup_script = await self._gen(self.source_code_gen, {
                "language": "shell",
                "script_type": "backup",
                "purpose": "nightly backup and log rotation",
            }, what="source/backup")
            if backup_script:
                files.append({"path": "opt/scripts/nightly_backup.sh", "content": backup_script.content, "permissions": 0o755})

            crontab_content = (
                "# /etc/crontab: system-wide crontab\n"
                "SHELL=/bin/bash\n"
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\n"
                "0 3 * * * root /opt/scripts/nightly_backup.sh >> /var/log/backup.log 2>&1\n"
                "*/15 * * * * root /opt/scripts/healthcheck.sh\n"
                "0 0 1 * * root /usr/bin/certbot renew --quiet\n"
            )
            files.append({"path": "etc/crontab", "content": crontab_content, "permissions": 0o644})

        return files

    async def _build_database(self, honeypot_id: str, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Populate database server profile."""
        files = []
        
        # Database scripts
        backup_script = await self._gen(self.source_code_gen, {
            "language": "python",
            "script_type": "db_script",
            "purpose": "database backup",
        }, what="source/db_backup")
        if backup_script:
            files.append({"path": "scripts/backup_db.py", "content": backup_script.content, "permissions": 0o755})

        # Configuration
        env = await self._gen(self.config_gen, {"config_type": "env", "app_type": "database"}, what="config/env")
        if env:
            files.append({"path": ".env", "content": env.content, "permissions": 0o600})

        # Logs
        auth_log = await self._gen(self.log_gen, {"log_type": "auth", "duration_hours": 72}, what="log/auth")
        if auth_log:
            files.append({"path": "var/log/auth.log", "content": auth_log.content, "permissions": 0o640})

        # Generate and embed database password honeytoken
        db_password = await self._generate_and_persist_honeytoken(
            "database_password", honeypot_id, ".pgpass"
        )
        
        # Create .pgpass file with honeytoken
        if db_password:
            pgpass_content = f"""# hostname:port:database:username:password
localhost:5432:*:postgres:{db_password}
db.internal:5432:production:app_user:{db_password}
"""
            files.append({"path": ".pgpass", "content": pgpass_content, "permissions": 0o600})

        # serve_fake_sensitive_files specifically: add an explicitly
        # "juicy" file that's otherwise absent from this profile, so it's
        # genuinely distinct from populate_database_server rather than
        # the same files under a different action label. Built entirely
        # from honeytoken-generated PII (SSA-reserved SSN ranges,
        # invalid-Luhn card numbers — see generators/honeytokens.py) so
        # every value in it is both realistic-looking and tracked.
        if context.get("action") == "serve_fake_sensitive_files":
            rows = ["customer_id,name,ssn,credit_card,email"]
            for i in range(5):
                ssn = await self._generate_and_persist_honeytoken(
                    "ssn", honeypot_id, "exports/customer_export.csv"
                )
                credit_card = await self._generate_and_persist_honeytoken(
                    "credit_card", honeypot_id, "exports/customer_export.csv"
                )
                # Skip the row rather than the file: a short export is
                # plausible, a column of "None" is not.
                if ssn and credit_card:
                    rows.append(f"{1000 + i},Customer {i + 1},{ssn},{credit_card},customer{i + 1}@example.com")
            if len(rows) > 1:
                files.append({
                    "path": "exports/customer_export.csv",
                    "content": "\n".join(rows) + "\n",
                    "permissions": 0o644,
                })

        return files

    async def _build_web_server(self, honeypot_id: str, context: dict[str, Any]) -> list[dict[str, Any]]:
        """Populate web server profile."""
        files = []
        
        # Web application code
        app_code = await self._gen(self.source_code_gen, {
            "language": "python",
            "script_type": "webapp",
            "purpose": "web API",
        }, what="source/webapp")
        if app_code:
            files.append({"path": "app/main.py", "content": app_code.content, "permissions": 0o644})

        # Nginx config
        nginx = await self._gen(self.config_gen, {"config_type": "nginx", "site_type": "api"}, what="config/nginx")
        if nginx:
            files.append({"path": "nginx.conf", "content": nginx.content, "permissions": 0o644})

        # Access logs
        apache_log = await self._gen(self.log_gen, {"log_type": "apache_access", "duration_hours": 24}, what="log/apache_access")
        if apache_log:
            files.append({"path": "logs/access.log", "content": apache_log.content, "permissions": 0o644})

        # Generate and embed API key honeytoken
        api_key = await self._generate_and_persist_honeytoken(
            "api_token", honeypot_id, "app/config.py"
        )
        
        # Create config file with honeytoken
        if api_key:
            config_content = f'''"""Application configuration."""

class Config:
    SECRET_KEY = "{api_key}"
    DATABASE_URL = "postgresql://localhost/app"
    DEBUG = False
'''
            files.append({"path": "app/config.py", "content": config_content, "permissions": 0o644})

        return files
