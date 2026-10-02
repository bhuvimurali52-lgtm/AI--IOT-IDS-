"""FastAPI application entry point for the IoT IDS service."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import router
from app.core.config import get_settings, validate_runtime_paths
from app.core.errors import sanitize_public_message
from app.core.logging_config import setup_logging

settings = get_settings()
setup_logging(log_level=settings.log_level, log_dir=settings.log_dir)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan hooks for startup and shutdown."""
    from app.database.models import init_db

    logger.info(
        "Starting %s v%s env=%s mode=%s",
        settings.app_name,
        settings.app_version,
        settings.app_env,
        settings.ids_mode,
    )
    for warning in validate_runtime_paths(settings):
        logger.warning("%s", warning)
    try:
        init_db(settings.database_path)
    except Exception:  # noqa: BLE001
        logger.exception("Database initialization failed")
        # Continue: /health stays alive; /ready reports database unavailable.
    yield
    logger.info("Shutting down %s", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "AI-Powered IoT Intrusion Detection API "
        "(Phase 8: production-oriented prototype hardening + Phase 7 evaluation)"
    ),
    lifespan=lifespan,
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
)

_cors_origins = settings.cors_origin_list()
if _cors_origins:
    logger.info(
        "CORS allow_origins=%s allow_credentials=%s",
        _cors_origins,
        False,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Accept", "Content-Type"],
    )

app.include_router(router)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    logger.warning("Validation error: %s", exc.errors())
    return JSONResponse(
        status_code=422,
        content={"detail": "Invalid request", "errors": exc.errors()},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(_request: Request, exc: HTTPException) -> JSONResponse:
    detail = exc.detail
    if isinstance(detail, str):
        detail = sanitize_public_message(detail, fallback="Request failed")
    return JSONResponse(status_code=exc.status_code, content={"detail": detail})


@app.exception_handler(Exception)
async def unhandled_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled API error: %s", type(exc).__name__)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )
