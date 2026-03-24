import time
from typing import Callable

import structlog
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from core.exceptions import ContentGeneratorError, LLMError, ValidationError

logger = structlog.get_logger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all requests."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log request and response."""
        request_id = request.headers.get("X-Request-ID", "unknown")
        start_time = time.time()

        logger.info(
            "request_started",
            method=request.method,
            path=request.url.path,
            request_id=request_id,
        )

        try:
            response = await call_next(request)
            duration_ms = int((time.time() - start_time) * 1000)

            logger.info(
                "request_completed",
                method=request.method,
                path=request.url.path,
                status_code=response.status_code,
                duration_ms=duration_ms,
                request_id=request_id,
            )

            response.headers["X-Request-ID"] = request_id
            response.headers["X-Response-Time"] = str(duration_ms)
            return response

        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.error(
                "request_failed",
                method=request.method,
                path=request.url.path,
                error=str(e),
                duration_ms=duration_ms,
                request_id=request_id,
            )
            raise


async def error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle application errors."""
    if isinstance(exc, ContentGeneratorError):
        status_code = 500
        if isinstance(exc, LLMError):
            status_code = 503  # Service unavailable
        elif isinstance(exc, ValidationError):
            status_code = 422  # Unprocessable entity

        return JSONResponse(
            status_code=status_code,
            content={
                "error": exc.__class__.__name__,
                "message": exc.message,
                "details": exc.details,
            },
        )

    # Unexpected error
    logger.exception("unexpected_error", error=str(exc))
    return JSONResponse(
        status_code=500,
        content={
            "error": "InternalServerError",
            "message": "An unexpected error occurred",
        },
    )
