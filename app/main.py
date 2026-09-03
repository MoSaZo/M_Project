"""
Main FastAPI application.

Creates the application instance,
initializes the database,
starts the gateway DNS monitor,
serves the frontend,
and registers API routes.
"""

import threading
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import api_router
from app.core.config import PROJECT_NAME
from app.core.config import PROJECT_VERSION
from app.database.database import create_tables
from app.gateway.monitor import DNSMonitor


BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"


gateway_monitor: DNSMonitor | None = None
gateway_thread: threading.Thread | None = None


@asynccontextmanager
async def lifespan(
    app: FastAPI,
):
    """
    Application lifespan handler.

    Initializes the database and starts the gateway
    DNS monitor in a background thread.
    """

    global gateway_monitor
    global gateway_thread

    # ---------------------------
    # Database
    # ---------------------------

    create_tables()

    # ---------------------------
    # Gateway
    # ---------------------------

    gateway_monitor = DNSMonitor()

    gateway_thread = threading.Thread(
        target=gateway_monitor.start,
        name="phishguard-gateway",
        daemon=True,
    )

    gateway_thread.start()

    print("[System] Gateway monitor started.")

    try:
        yield

    finally:

        # ---------------------------
        # Stop Gateway
        # ---------------------------

        if gateway_monitor is not None:
            gateway_monitor.stop()

        if (
            gateway_thread is not None
            and gateway_thread.is_alive()
        ):
            gateway_thread.join(
                timeout=5,
            )

        print("[System] Gateway monitor stopped.")


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
