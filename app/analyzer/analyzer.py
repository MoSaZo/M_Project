"""
Main URL analyzer.

Coordinates URL parsing, indicator detection,
compound rules, risk calculation, and report building.
"""

from typing import Any

from app.analyzer.compound_rules import apply_compound_rules
from app.analyzer.indicators import collect_indicators
from app.analyzer.parser import parse_url
from app.analyzer.report_builder import build_report
from app.analyzer.risk_engine import calculate_risk


def analyze_url(url: str) -> dict[str, Any]:
    """
    Analyze a URL and build the final analysis report.

    Args:
        url:
            URL to analyze.

    Returns:
        Complete URL analysis report.
    """

    parsed = parse_url(url)

    indicators = collect_indicators(
        parsed,
    )

    indicators.extend(
        apply_compound_rules(
            parsed,
            indicators,
        )
    )

    risk = calculate_risk(
        indicators,
    )

    return build_report(
        parsed,
        risk,
    )