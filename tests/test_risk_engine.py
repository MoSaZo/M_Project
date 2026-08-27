from app.analyzer.risk_engine import calculate_risk


def test_score_0_is_safe():
    result = calculate_risk([])

    assert result["risk_score"] == 0
    assert result["risk_level"] == "Safe"


def test_score_19_is_safe():
    indicators = [
        {
            "score": 19,
            "reason": "test",
        }
    ]

    result = calculate_risk(indicators)

    assert result["risk_score"] == 19
    assert result["risk_level"] == "Safe"


def test_score_20_is_suspicious():
    indicators = [
        {
            "score": 20,
            "reason": "test",
        }
    ]

    result = calculate_risk(indicators)

    assert result["risk_score"] == 20
    assert result["risk_level"] == "Suspicious"


def test_score_49_is_suspicious():
    indicators = [
        {
            "score": 49,
            "reason": "test",
        }
    ]

    result = calculate_risk(indicators)

    assert result["risk_score"] == 49
    assert result["risk_level"] == "Suspicious"


def test_score_50_is_high_risk():
    indicators = [
        {
            "score": 50,
            "reason": "test",
        }
    ]

    result = calculate_risk(indicators)

    assert result["risk_score"] == 50
    assert result["risk_level"] == "High Risk"


def test_high_confidence_ml_raises_safe_to_suspicious():
    result = calculate_risk(
        [],
        ml_prediction="phishing",
        ml_probability=0.90,
    )

    assert result["risk_score"] == 0
    assert result["risk_level"] == "Suspicious"


def test_high_confidence_ml_raises_suspicious_to_high_risk():
    indicators = [
        {
            "score": 20,
            "reason": "test",
        }
    ]

    result = calculate_risk(
        indicators,
        ml_prediction="phishing",
        ml_probability=0.90,
    )

    assert result["risk_score"] == 20
    assert result["risk_level"] == "High Risk"


def test_ml_below_threshold_does_not_raise_risk():
    indicators = [
        {
            "score": 20,
            "reason": "test",
        }
    ]

    result = calculate_risk(
        indicators,
        ml_prediction="phishing",
        ml_probability=0.89,
    )

    assert result["risk_score"] == 20
    assert result["risk_level"] == "Suspicious"


def test_legitimate_ml_does_not_lower_rule_based_risk():
    indicators = [
        {
            "score": 50,
            "reason": "test",
        }
    ]

    result = calculate_risk(
        indicators,
        ml_prediction="legitimate",
        ml_probability=0.99,
    )

    assert result["risk_score"] == 50
    assert result["risk_level"] == "High Risk"


def test_risk_score_is_capped_at_100():
    indicators = [
        {
            "score": 80,
            "reason": "test 1",
        },
        {
            "score": 50,
            "reason": "test 2",
        },
    ]

    result = calculate_risk(indicators)

    assert result["risk_score"] == 100
    assert result["risk_level"] == "High Risk"