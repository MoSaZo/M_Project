"""
Behavioral validation for the phishing URL model.
"""

from models.predictor import predict_url


TEST_CASES = [
    # Known legitimate domains.
    (
        "LEGITIMATE",
        "https://www.google.com",
    ),
    (
        "LEGITIMATE",
        "https://github.com",
    ),
    (
        "LEGITIMATE",
        "https://www.microsoft.com",
    ),
    (
        "LEGITIMATE",
        "https://openai.com",
    ),
    (
        "LEGITIMATE",
        "https://www.apple.com",
    ),
    (
        "LEGITIMATE",
        "https://www.amazon.com",
    ),
    (
        "LEGITIMATE",
        "https://www.facebook.com",
    ),
    (
        "LEGITIMATE",
        "https://www.youtube.com",
    ),
    (
        "LEGITIMATE",
        "https://www.linkedin.com",
    ),
    (
        "LEGITIMATE",
        "https://stackoverflow.com",
    ),

    # Suspicious URLs.
    (
        "PHISHING",
        "http://login-secure.example.com/account/verify?id=123",
    ),
    (
        "PHISHING",
        "http://verify-login-account.example.com/update",
    ),
    (
        "PHISHING",
        "http://paypal-login-security.example.com/verify",
    ),
    (
        "PHISHING",
        "http://account-security.example.com/login",
    ),
    (
        "PHISHING",
        "http://secure-login.example.com/account/password",
    ),
    (
        "PHISHING",
        "http://192.168.1.100/login/verify",
    ),
    (
        "PHISHING",
        "http://example.com/login?redirect=https://evil.example",
    ),
    (
        "PHISHING",
        "http://verify-account.example.com/update?token=123456",
    ),
]


def main() -> None:
    """Run behavioral validation."""

    print("=" * 72)
    print("PHISHING URL MODEL - BEHAVIORAL VALIDATION")
    print("=" * 72)

    results = []

    for expected, url in TEST_CASES:
        result = predict_url(url)

        prediction = result["prediction"]
        probability = result["probability"]

        passed = (
            (
                expected == "LEGITIMATE"
                and prediction == "legitimate"
            )
            or (
                expected == "PHISHING"
                and prediction == "phishing"
            )
        )

        results.append(passed)

        status = "PASS" if passed else "FAIL"

        print()
        print(f"[{status}]")
        print(f"Expected : {expected}")
        print(f"Predicted: {prediction}")
        print(f"Probability: {probability:.4f}")
        print(f"URL      : {url}")

    passed_count = sum(results)
    total_count = len(results)

    accuracy = (
        passed_count / total_count
        if total_count
        else 0.0
    )

    print()
    print("=" * 72)
    print("VALIDATION SUMMARY")
    print("=" * 72)
    print(
        f"Passed: {passed_count}/{total_count}"
    )
    print(
        f"Behavioral accuracy: {accuracy:.2%}"
    )

    if passed_count == total_count:
        print("RESULT: PASS")
    else:
        print("RESULT: REVIEW REQUIRED")


if __name__ == "__main__":
    main()