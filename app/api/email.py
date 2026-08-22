"""
Email API endpoints.

Provides endpoints for sending phishing awareness emails.
"""

from fastapi import APIRouter
from fastapi import HTTPException

from app.schemas.requests import AwarenessEmailRequest
from app.services.email_service import (
    send_awareness_email,
)


router = APIRouter(
    prefix="/email",
    tags=["Email"],
)


@router.post(
    "/send-awareness",
)
def send_awareness_email_endpoint(
    request: AwarenessEmailRequest,
) -> dict:
    """
    Send a phishing awareness email.
    """

    try:

        send_awareness_email(
            recipient=request.recipient,
            subject=request.subject,
            body=request.body,
        )

        return {
            "success": True,
            "message": (
                "Educational email sent successfully."
            ),
        }

    except Exception as exc:

        raise HTTPException(
            status_code=500,
            detail=str(exc),
        ) from exc