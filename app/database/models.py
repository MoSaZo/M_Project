"""
SQLAlchemy database models.

Contains persistent models used by the application.
"""

from datetime import datetime

from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from app.database.database import Base


class URLScan(Base):
    """
    Store the result of a URL security analysis.
    """

    __tablename__ = "url_scans"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    url: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    hostname: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    registered_domain: Mapped[str | None] = mapped_column(
        String(255),
        nullable=True,
    )

    subdomain: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    protocol: Mapped[str | None] = mapped_column(
        String(20),
        nullable=True,
    )

    subdomain_levels: Mapped[int | None] = mapped_column(
        Integer,
        nullable=True,
    )

    tld: Mapped[str | None] = mapped_column(
        String(50),
        nullable=True,
    )

    query_parameter_count: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    risk_level: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    risk_summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    reasons: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )