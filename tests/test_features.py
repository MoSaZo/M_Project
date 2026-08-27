from models.features import FEATURE_NAMES
from models.features import extract_url_features


def test_returns_expected_keys():
    features = extract_url_features(
        "https://www.google.com"
    )

    assert set(features.keys()) == set(
        FEATURE_NAMES
    )


def test_feature_count():
    features = extract_url_features(
        "https://www.google.com"
    )

    assert len(features) == len(
        FEATURE_NAMES
    )


def test_https_feature():
    features = extract_url_features(
        "https://www.google.com"
    )

    assert features["is_https"] == 1.0


def test_http_feature():
    features = extract_url_features(
        "http://www.google.com"
    )

    assert features["is_https"] == 0.0


def test_ip_address_detection():
    features = extract_url_features(
        "http://192.168.1.1/login"
    )

    assert features["is_ip_address"] == 1.0


def test_at_symbol_detection():
    features = extract_url_features(
        "http://user@example.com"
    )

    assert features["has_at_symbol"] == 1.0


def test_keyword_count():
    features = extract_url_features(
        "http://login.example.com/account/verify"
    )

    assert features["suspicious_keyword_count"] >= 3


def test_query_parameter_count():
    features = extract_url_features(
        "https://example.com?a=1&b=2"
    )

    assert features["query_parameter_count"] == 2.0


def test_query_key_count():
    features = extract_url_features(
        "https://example.com?a=1&a=2&b=3"
    )

    assert features["query_key_count"] == 2.0


def test_redirect_parameter():
    features = extract_url_features(
        "https://example.com?redirect=https://evil.com"
    )

    assert features["redirect_parameter_count"] == 1.0


def test_double_encoding():
    features = extract_url_features(
        "https://example.com/%2520"
    )

    assert features["double_encoding_count"] == 1.0


def test_punycode_detection():
    features = extract_url_features(
        "https://xn--pple-43d.com"
    )

    assert features["has_punycode"] == 1.0


def test_path_features():
    features = extract_url_features(
        "https://example.com/account/login/verify123"
    )

    assert features["path_segment_count"] == 3.0
    assert features["path_digit_count"] >= 3.0


def test_domain_features():
    features = extract_url_features(
        "https://secure-login.example.com"
    )

    assert features["domain_length"] == 7.0
    assert features["tld_length"] == 3.0
    assert features["subdomain_length"] == 12.0
    assert features["domain_hyphen_count"] == 0.0
    assert features["hostname_hyphen_ratio"] > 0.0


def test_feature_types():
    features = extract_url_features(
        "https://www.google.com"
    )

    for name in FEATURE_NAMES:
        assert name in features
        assert isinstance(
            features[name],
            float,
        )
