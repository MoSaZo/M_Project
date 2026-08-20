"""
Application API routes.
"""

from fastapi import APIRouter

from app.api.analyze import router as analyze_router
from app.api.history import router as history_router
from app.api.email import router as email_router


api_router = APIRouter()


api_router.include_router(
    analyze_router,
)

api_router.include_router(
    history_router,
)

api_router.include_router(
    email_router,
)