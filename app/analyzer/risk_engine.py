"""
Risk calculation engine.

Calculates the final phishing risk score,
severity levels, reasons, and overall risk level.
"""

from typing import Any


def get_severity(score: int) -> str:
    """
    Determine the severity level of a single indicator.
    """

    if score >= 15:
        return "High"

    if score >= 8:
        return "Medium"

    return "Low"


def calculate_risk(
    indicators: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Calculate the final phishing risk score.

    The total score is capped at 100.
    """

    risk_score = 0

    reasons: list[str] = []

    normalized_indicators: list[
        dict[str, Any]
    ] = []

    for indicator in indicators:
        score = indicator["score"]

        risk_score += score

        severity = indicator.get(
            "severity",
            get_severity(score),
        )

        normalized_indicators.append(
            {
                "score": score,
                "severity": severity,
                "reason": indicator["reason"],
            }
        )

        reasons.append(
            indicator["reason"],
        )

    risk_score = min(
        risk_score,
        100,
    )

    if risk_score < 20:
        risk_level = "Safe"
    elif risk_score < 50:
        risk_level = "Suspicious"
    else:
        risk_level = "High Risk"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "indicators": normalized_indicators,
    }