"""
API dependencies.

Provides shared dependencies used by FastAPI routes.
"""

from collections.abc import Generator

from sqlalchemy.orm import Session

from app.database.database import get_db


def database_session() -> Generator[
    Session,
    None,
    None,
]:
    """
    Provide a database session to API endpoints.

    Yields:
        Active SQLAlchemy session.
    """

    yield from get_db()