"""
History service.

Handles persistence and retrieval of URL analysis history.
"""

from typing import Any

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.database.models import URLScan


def save_analysis(
    db: Session,
    analysis: dict[str, Any],
) -> URLScan:
    """
    Save an analysis result to the database.

    Args:
        db:
            Active SQLAlchemy session.

        analysis:
            Result returned by the URL analyzer.

    Returns:
        Persisted URLScan model.
    """

    reasons = analysis.get(
        "reasons",
        [],
    )

    if isinstance(reasons, list):
        reasons_text = "\n".join(
            str(reason)
            for reason in reasons
        )
    else:
        reasons_text = str(
            reasons,
        )

    scan = URLScan(
        url=analysis["url"],
        hostname=analysis.get("hostname"),
        registered_domain=analysis.get(
            "registered_domain",
        ),
        subdomain=analysis.get("subdomain"),
        protocol=analysis.get("protocol"),
        subdomain_levels=analysis.get(
            "subdomain_levels",
        ),
        tld=analysis.get("suffix"),
        query_parameter_count=analysis.get(
            "query_parameter_count",
            0,
        ),
        risk_score=analysis["risk_score"],
        risk_level=analysis["risk_level"],
        risk_summary=analysis.get(
            "risk_summary",
        ),
        reasons=reasons_text,
    )

    db.add(scan)
    db.commit()
    db.refresh(scan)

    return scan


def get_analysis(
    db: Session,
    scan_id: int,
) -> URLScan | None:
    """
    Retrieve one analysis from history.

    Args:
        db:
            Active SQLAlchemy session.

        scan_id:
            Analysis identifier.

    Returns:
        URLScan instance or None.
    """

    return (
        db.query(URLScan)
        .filter(
            URLScan.id == scan_id,
        )
        .first()
    )


def get_history(
    db: Session,
    limit: int = 50,
) -> list[URLScan]:
    """
    Retrieve recent analysis history.

    Args:
        db:
            Active SQLAlchemy session.

        limit:
            Maximum number of records.

    Returns:
        List of URLScan records.
    """

    return (
        db.query(URLScan)
        .order_by(
            desc(URLScan.created_at),
        )
        .limit(limit)
        .all()
    )