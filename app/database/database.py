"""
Database configuration.

Provides the SQLAlchemy engine,
session factory, base model,
and database dependency.
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Session
from sqlalchemy.orm import sessionmaker

from app.core.config import DATABASE_URL


class Base(DeclarativeBase):
    """
    Base class for all SQLAlchemy models.
    """

    pass


connect_args: dict = {}

if DATABASE_URL.startswith("sqlite"):
    connect_args = {
        "check_same_thread": False,
    }


engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    future=True,
)


SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def get_db() -> Generator[
    Session,
    None,
    None,
]:
    """
    Yield a database session.

    The session is automatically closed
    after the request finishes.
    """

    db = SessionLocal()

    try:
        yield db

    finally:
        db.close()


def create_tables() -> None:
    """
    Create all database tables.
    """

    from app.database import models

    Base.metadata.create_all(
        bind=engine,
    )