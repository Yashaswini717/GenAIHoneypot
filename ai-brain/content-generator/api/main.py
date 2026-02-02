from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.middleware import RequestLoggingMiddleware, error_handler
from api.routes import generate, health, honeytokens, populate
from config.logging_config import setup_logging
from config.settings import settings
from core.exceptions import ContentGeneratorError


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    setup_logging()
    yield
    # Shutdown
    pass


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI-Powered Content Generator for Honeypot Systems",
    lifespan=lifespan,
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request logging middleware
app.add_middleware(RequestLoggingMiddleware)

# Exception handlers
app.add_exception_handler(ContentGeneratorError, error_handler)

# Include routers
app.include_router(health.router)
app.include_router(generate.router)
app.include_router(populate.router)
app.include_router(honeytokens.router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "name": settings.app_name,
        "version": settings.app_version,
        "status": "operational",
        "docs": "/docs",
    }
