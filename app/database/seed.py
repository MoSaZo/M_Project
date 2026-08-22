"""
Database initialization utilities.
"""

from app.database import models  # noqa: F401
from app.database.database import Base
from app.database.database import engine


def init_database() -> None:
    """
    Create all database tables.
    """

    Base.metadata.create_all(
        bind=engine,
    )