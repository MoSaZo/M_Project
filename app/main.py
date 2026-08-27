"""
Main FastAPI application.

Creates the application instance,
initializes the database,
serves the frontend,
and registers API routes.
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import api_router
from app.core.config import PROJECT_NAME
from app.core.config import PROJECT_VERSION
from app.database.database import create_tables


BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"


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


# ---------------------------
# API routes
# ---------------------------

app.include_router(
    api_router,
    prefix="/api",
)


# ---------------------------
# Frontend
# ---------------------------

app.mount(
    "/frontend",
    StaticFiles(directory=FRONTEND_DIR),
    name="frontend",
)


@app.get(
    "/",
    tags=["System"],
)
def root():
    """
    Serve the PhishGuard frontend.
    """

    return FileResponse(
        FRONTEND_DIR / "index.html",
    )


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