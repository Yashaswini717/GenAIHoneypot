from typing import Any

# Hard constraint appended to all source code prompts
_SOURCE_CODE_CONSTRAINTS = """

IMPORTANT — Output rules:
- Output ONLY the raw source code file, nothing else.
- Start with the first line of code (shebang, import, package declaration).
- Do NOT include any introductory text, explanation, or description before or after the code.
- Do NOT wrap the output in code fences (``` or ~~~).
- Comments in the code should reflect real developer concerns (TODOs, workarounds, technical debt), NOT documentation for a reader.
- Code must be syntactically valid and executable.
- Include realistic imperfections: inconsistent formatting, legacy patterns, commented-out code, shortcut workarounds."""


def get_python_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for Python code."""
    script_type = context.get("script_type", "general")
    purpose = context.get("purpose", "utility script")
    
    prompts = {
        "webapp": f"""Generate a realistic Python Flask web application for {purpose}.
Include:
- Flask routes with proper error handling
- Database connections (SQLAlchemy)
- Environment variable configuration
- Logging setup
- Authentication middleware
- API endpoints with validation
- Requirements comments at top
Make it look like production code with some technical debt.{_SOURCE_CODE_CONSTRAINTS}""",
        
        "db_script": f"""Generate a realistic Python database script for {purpose}.
Include:
- SQLAlchemy models or raw SQL queries
- Connection pooling and retry logic
- Transaction management
- Error handling and logging
- Configuration from environment variables
- Migration or data manipulation logic
- Comments explaining business logic{_SOURCE_CODE_CONSTRAINTS}""",
        
        "automation": f"""Generate a realistic Python automation script for {purpose}.
Include:
- Command-line argument parsing
- File I/O operations
- Error handling and retry logic
- Progress logging
- Configuration file reading
- Subprocess execution if needed
- Cron-ready with proper exit codes{_SOURCE_CODE_CONSTRAINTS}""",
        
        "data_processing": f"""Generate a realistic Python data processing script for {purpose}.
Include:
- Pandas/NumPy operations
- CSV/JSON file handling
- Data validation and cleaning
- Error handling for bad data
- Progress bars or logging
- Output file generation
- Command-line interface{_SOURCE_CODE_CONSTRAINTS}""",
    }
    
    return prompts.get(script_type, prompts["automation"])


def get_javascript_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for JavaScript code."""
    script_type = context.get("script_type", "general")
    purpose = context.get("purpose", "API client")
    
    prompts = {
        "api": f"""Generate a realistic Node.js API server for {purpose}.
Include:
- Express.js setup with middleware
- RESTful routes with validation
- Database connections (MongoDB/PostgreSQL)
- JWT authentication
- Error handling middleware
- Environment configuration
- CORS setup
- Logging with Winston or similar
Make it look like real production code.{_SOURCE_CODE_CONSTRAINTS}""",
        
        "frontend": f"""Generate a realistic React component for {purpose}.
Include:
- React hooks (useState, useEffect)
- Props with PropTypes or TypeScript
- Event handlers
- Conditional rendering
- API calls with fetch or axios
- Error boundaries
- Loading states
- CSS modules or styled-components{_SOURCE_CODE_CONSTRAINTS}""",
        
        "cli": f"""Generate a realistic Node.js CLI tool for {purpose}.
Include:
- Commander.js or Yargs for CLI parsing
- File system operations
- Async/await for I/O
- Colorful console output (chalk)
- Progress indicators
- Error handling
- Configuration file support{_SOURCE_CODE_CONSTRAINTS}""",
    }
    
    return prompts.get(script_type, prompts["api"])


def get_shell_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for shell scripts."""
    script_type = context.get("script_type", "general")
    purpose = context.get("purpose", "automation")
    
    prompts = {
        "backup": f"""Generate a realistic bash backup script for {purpose}.
Include:
- Shebang and script metadata
- Parameter validation
- Tar/rsync backup operations
- Log file creation
- Error checking after each command
- Cleanup of old backups
- Email notification on failure
- Lock file to prevent concurrent runs{_SOURCE_CODE_CONSTRAINTS}""",
        
        "deployment": f"""Generate a realistic bash deployment script for {purpose}.
Include:
- Git operations
- Docker/container commands
- Service restarts
- Health checks
- Rollback mechanism
- Logging with timestamps
- Environment checks
- Backup before deployment{_SOURCE_CODE_CONSTRAINTS}""",
        
        "monitoring": f"""Generate a realistic bash monitoring script for {purpose}.
Include:
- System resource checks (CPU, memory, disk)
- Process monitoring
- Service health checks
- Alert generation
- Log rotation
- Metric collection
- Notification on thresholds{_SOURCE_CODE_CONSTRAINTS}""",
    }
    
    return prompts.get(script_type, prompts["backup"])


def get_go_prompt(context: dict[str, Any]) -> str:
    """Generate prompt for Go code."""
    script_type = context.get("script_type", "general")
    purpose = context.get("purpose", "web service")
    
    prompts = {
        "server": f"""Generate a realistic Go HTTP server for {purpose}.
Include:
- net/http server setup
- Gorilla mux or chi router
- Middleware (logging, auth, CORS)
- Database connections (database/sql)
- Graceful shutdown
- Environment configuration
- Structured logging
- Health check endpoints
- Context usage
Make it idiomatic Go code.{_SOURCE_CODE_CONSTRAINTS}""",
        
        "cli": f"""Generate a realistic Go CLI application for {purpose}.
Include:
- Cobra or flag package for CLI
- Subcommands with flags
- Configuration via viper
- Error handling
- Logging with levels
- Concurrent operations with goroutines
- Progress reporting
- Exit codes{_SOURCE_CODE_CONSTRAINTS}""",
        
        "worker": f"""Generate a realistic Go background worker for {purpose}.
Include:
- Worker pool pattern
- Job queue processing
- Graceful shutdown
- Error handling and retries
- Metrics collection
- Context cancellation
- Database operations
- Structured logging{_SOURCE_CODE_CONSTRAINTS}""",
    }
    
    return prompts.get(script_type, prompts["server"])
