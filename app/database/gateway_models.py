"""
Database model for gateway DNS analysis events.
"""

from datetime import datetime

from sqlalchemy import Boolean
from sqlalchemy import DateTime
from sqlalchemy import Float
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column

from app.database.database import Base


class GatewayEvent(Base):
    """
    Persist a DNS observation and its analysis result.
    """

    __tablename__ = "gateway_events"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    timestamp: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False,
    )

    domain: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        index=True,
    )

    answer: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    record_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    source_ip: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    destination_ip: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    response: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
    )

    score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    prediction: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
    )