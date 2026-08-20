"""
Main FastAPI application.

Creates the application instance,
initializes the database,
and registers API routes.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import api_router
from app.core.config import PROJECT_NAME
from app.core.config import PROJECT_VERSION
from app.database.database import create_tables


@asynccontextmanager
async def lifespan(
    app: FastAPI,
):
    """
    Application lifespan handler.

    Creates database tables when the application starts.
    """

    create_tables()

    yield


app = FastAPI(
    title=PROJECT_NAME,
    version=PROJECT_VERSION,
    description=(
        "Phishing awareness and URL "
        "security analysis tool."
    ),
    lifespan=lifespan,
)


app.include_router(
    api_router,
    prefix="/api",
)


@app.get(
    "/",
    tags=["System"],
)
def root() -> dict[str, str]:
    """
    Root endpoint.
    """

    return {
        "name": PROJECT_NAME,
        "version": PROJECT_VERSION,
        "status": "running",
    }


@app.get(
    "/health",
    tags=["System"],
)
def health_check() -> dict[str, str]:
    """
    Health check endpoint.
    """

    return {
        "status": "ok",
    }