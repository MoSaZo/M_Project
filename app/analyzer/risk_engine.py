"""
Risk calculation engine.

Calculates the final phishing risk score,
severity levels, reasons, and overall risk level.

Rule-based risk scoring is kept independent from
the machine-learning prediction. The final risk level
can optionally take a high-confidence ML prediction
into account.
"""

from typing import Any


ML_SAFE_CONFIDENCE_THRESHOLD = 0.70
ML_HIGH_CONFIDENCE_THRESHOLD = 0.90


def get_severity(score: int) -> str:
    """
    Determine the severity level of a single indicator.
    """

    if score >= 15:
        return "High"

    if score >= 8:
        return "Medium"

    return "Low"


def calculate_final_risk_level(
    risk_score: int,
    ml_prediction: str | None = None,
    ml_probability: float | None = None,
) -> str:
    """
    Determine the final risk level from rule-based risk
    and optional machine-learning prediction.

    Rule-based thresholds remain the primary scoring system.

    A phishing prediction with probability >= 0.70 can
    raise a Safe result to Suspicious.

    A phishing prediction with probability >= 0.90 can
    raise a Suspicious result to High Risk.
    """

    if risk_score < 20:
        risk_level = "Safe"
    elif risk_score < 50:
        risk_level = "Suspicious"
    else:
        risk_level = "High Risk"

    if (
        ml_prediction == "phishing"
        and ml_probability is not None
    ):
        if (
            risk_level == "Safe"
            and ml_probability >= ML_SAFE_CONFIDENCE_THRESHOLD
        ):
            return "Suspicious"

        if (
            risk_level == "Suspicious"
            and ml_probability >= ML_HIGH_CONFIDENCE_THRESHOLD
        ):
            return "High Risk"

    return risk_level


def calculate_risk(
    indicators: list[dict[str, Any]],
    ml_prediction: str | None = None,
    ml_probability: float | None = None,
) -> dict[str, Any]:
    """
    Calculate the final phishing risk score and level.

    The rule-based score is capped at 100.

    Machine-learning output is optional so existing callers
    remain compatible.
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

    risk_level = calculate_final_risk_level(
        risk_score=risk_score,
        ml_prediction=ml_prediction,
        ml_probability=ml_probability,
    )

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons,
        "indicators": normalized_indicators,
    }