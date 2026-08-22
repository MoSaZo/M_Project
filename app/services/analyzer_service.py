"""
Analyzer service.

Coordinates URL analysis and persistence.
"""

from typing import Any

from sqlalchemy.orm import Session

from app.analyzer.analyzer import analyze_url
from app.services.history_service import save_analysis


def analyze(
    url: str,
) -> dict[str, Any]:
    """
    Analyze a URL without saving it.
    """

    return analyze_url(url)


def analyze_and_save(
    db: Session,
    url: str,
) -> dict[str, Any]:
    """
    Analyze a URL and persist the result.

    Args:
        db:
            Active SQLAlchemy session.

        url:
            URL to analyze.

    Returns:
        Analysis report with database ID.
    """

    analysis = analyze_url(
        url,
    )

    scan = save_analysis(
        db,
        analysis,
    )

    return {
        **analysis,
        "id": scan.id,
    }