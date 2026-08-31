import asyncio
import sys

import uvicorn
from config.logging_config import setup_logging
from config.settings import settings


def run_api():
    """Run FastAPI application."""
    setup_logging()
    
    uvicorn.run(
        "api.main:app",
        host=settings.api_host,
        port=settings.api_port,
        workers=settings.api_workers,
        reload=settings.api_reload,
        log_config=None,  # Use our own logging
    )


def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == "api":
        run_api()
    else:
        print(f"{settings.app_name} v{settings.app_version}")
        print("\nUsage:")
        print("  python main.py api    - Run FastAPI server")
        print("\nFor API documentation, visit http://localhost:8000/docs after starting the server")


if __name__ == "__main__":
    main()
