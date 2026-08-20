"""
Email service.

Handles educational phishing awareness emails.
"""

import smtplib
from email.message import EmailMessage

from app.core.config import SMTP_FROM
from app.core.config import SMTP_HOST
from app.core.config import SMTP_PASSWORD
from app.core.config import SMTP_PORT
from app.core.config import SMTP_USE_TLS
from app.core.config import SMTP_USERNAME


def send_awareness_email(
    recipient: str,
    subject: str,
    body: str,
) -> None:
    """
    Send an educational awareness email.

    Args:
        recipient:
            Destination email address.

        subject:
            Email subject.

        body:
            Plain-text email body.

    Raises:
        RuntimeError:
            If SMTP configuration is incomplete.
        smtplib.SMTPException:
            If SMTP communication fails.
    """

    if not SMTP_HOST:
        raise RuntimeError(
            "SMTP_HOST is not configured.",
        )

    if not SMTP_USERNAME:
        raise RuntimeError(
            "SMTP_USERNAME is not configured.",
        )

    if not SMTP_PASSWORD:
        raise RuntimeError(
            "SMTP_PASSWORD is not configured.",
        )

    if not SMTP_FROM:
        raise RuntimeError(
            "SMTP_FROM is not configured.",
        )

    message = EmailMessage()

    message["From"] = SMTP_FROM
    message["To"] = recipient
    message["Subject"] = subject

    message.set_content(body)

    with smtplib.SMTP(
        SMTP_HOST,
        SMTP_PORT,
        timeout=20,
    ) as server:

        if SMTP_USE_TLS:
            server.starttls()

        server.login(
            SMTP_USERNAME,
            SMTP_PASSWORD,
        )

        server.send_message(
            message,
        )