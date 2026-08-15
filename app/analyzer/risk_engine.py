def get_severity(score: int) -> str:
    """
    Determine the severity level of a single indicator.
    """

    if score >= 15:
        return "High"

    elif score >= 8:
        return "Medium"

    return "Low"


def calculate_risk(indicators: list[dict]) -> dict:
    """
    Calculate the final phishing risk score based on detected indicators.
    """

    risk_score = 0
    reasons = []
    normalized_indicators = []

    for indicator in indicators:

        score = indicator["score"]

        risk_score += score

        severity = indicator.get(
            "severity",
            get_severity(score)
        )

        normalized_indicator = {
            "score": score,
            "severity": severity,
            "reason": indicator["reason"]
        }

        normalized_indicators.append(
            normalized_indicator
        )

        reasons.append(
            indicator["reason"]
        )


    # Prevent score from exceeding 100

    risk_score = min(
        risk_score,
        100
    )


    # Determine overall risk level

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
        "indicators": normalized_indicators
    }