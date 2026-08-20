"""
Application configuration.
"""

import os
from pathlib import Path
from dotenv import load_dotenv


BASE_DIR = Path(__file__).resolve().parent.parent.parent

load_dotenv(
    BASE_DIR / ".env"
)


DATABASE_URL = (
    "sqlite:///"
    + str(BASE_DIR / "phishing.db")
)


SMTP_HOST = os.getenv(
    "SMTP_HOST",
    "smtp.gmail.com",
)

SMTP_PORT = int(
    os.getenv(
        "SMTP_PORT",
        "587",
    )
)

SMTP_USERNAME = os.getenv(
    "SMTP_USERNAME",
    "",
)

SMTP_PASSWORD = os.getenv(
    "SMTP_PASSWORD",
    "",
)

SMTP_FROM = os.getenv(
    "SMTP_FROM",
    SMTP_USERNAME,
)

SMTP_USE_TLS = (
    os.getenv(
        "SMTP_USE_TLS",
        "true",
    ).lower()
    == "true"
)


PROJECT_NAME = "Phishing Awareness Tool"

PROJECT_VERSION = "1.0.0"