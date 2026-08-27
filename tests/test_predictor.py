from models.predictor import predict_url


def test_prediction_structure():
    result = predict_url(
        "https://www.google.com"
    )

    assert "prediction" in result
    assert "probability" in result


def test_legitimate_prediction():
    result = predict_url(
        "https://www.google.com"
    )

    assert result["prediction"] == "legitimate"


def test_phishing_prediction():
    result = predict_url(
        "http://login-secure.example.com/account/verify?id=123"
    )

    assert result["prediction"] == "phishing"


def test_probability_range():
    result = predict_url(
        "https://www.google.com"
    )

    assert 0.0 <= result["probability"] <= 1.0


def test_probability_type():
    result = predict_url(
        "https://www.google.com"
    )

    assert isinstance(
        result["probability"],
        float,
    )


def test_https_probability():
    result = predict_url(
        "https://github.com"
    )

    assert result["probability"] < 0.5


def test_suspicious_probability():
    result = predict_url(
        "http://verify-login-account.example.com/update"
    )

    assert result["probability"] > 0.5