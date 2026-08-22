"""
Formatting utilities.
"""

from typing import Any


def format_risk_score(
    score: int,
) -> str:
    """
    Format a risk score for display.
    """

    return f"{score}/100"


def format_reasons(
    reasons: list[str] | None,
) -> str:
    """
    Convert risk reasons into display text.
    """

    if not reasons:
        return "No suspicious indicators detected."

    return "\n".join(
        f"- {reason}"
        for reason in reasons
    )


def format_analysis_summary(
    analysis: dict[str, Any],
) -> str:
    """
    Build a short human-readable analysis summary.
    """

    score = analysis.get(
        "risk_score",
        0,
    )

    level = analysis.get(
        "risk_level",
        "Unknown",
    )

    url = analysis.get(
        "url",
        "",
    )

    return (
        f"URL: {url}\n"
        f"Risk Score: {format_risk_score(score)}\n"
        f"Risk Level: {level}"
    )