def calculate_risk(indicators: list[dict]) -> dict:
    """
    Calculate the final phishing risk score based on detected indicators.
    """

    risk_score = 0
    reasons = []

    for indicator in indicators:
        risk_score += indicator["score"]
        reasons.append(indicator["reason"])

    # Prevent score from exceeding 100
    risk_score = min(risk_score, 100)

    # Determine risk level
    if risk_score < 20:
        risk_level = "Safe"
    elif risk_score < 50:
        risk_level = "Suspicious"
    else:
        risk_level = "High Risk"

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "reasons": reasons
    }