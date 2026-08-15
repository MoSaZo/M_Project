import os
import smtplib

from email.message import EmailMessage


def send_awareness_email(
    recipient: str,
    subject: str,
    body: str
) -> None:
    """
    Send an educational awareness email using SMTP.
    """

    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_username = os.getenv("SMTP_USERNAME")
    smtp_password = os.getenv("SMTP_PASSWORD")
    smtp_from = os.getenv("SMTP_FROM", smtp_username)
    smtp_use_tls = os.getenv(
        "SMTP_USE_TLS",
        "true"
    ).lower() == "true"

    if not smtp_host:
        raise RuntimeError("SMTP_HOST is not configured.")

    if not smtp_username:
        raise RuntimeError(
            "SMTP_USERNAME is not configured."
        )

    if not smtp_password:
        raise RuntimeError(
            "SMTP_PASSWORD is not configured."
        )

    if not smtp_from:
        raise RuntimeError(
            "SMTP_FROM is not configured."
        )

    message = EmailMessage()

    message["From"] = smtp_from
    message["To"] = recipient
    message["Subject"] = subject

    message.set_content(body)

    with smtplib.SMTP(
        smtp_host,
        smtp_port,
        timeout=20
    ) as server:

        if smtp_use_tls:
            server.starttls()

        server.login(
            smtp_username,
            smtp_password
        )

        server.send_message(message)
