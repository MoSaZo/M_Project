"""
Machine learning prediction service.

Loads the trained phishing detection model and predicts
whether a URL is phishing or legitimate.
"""

from pathlib import Path
from urllib.parse import urlparse

import joblib
import pandas as pd

from models.features import extract_url_features


MODEL_PATH = (
    Path(__file__).resolve().parent
    / "phishing_url_model.joblib"
)


TRUSTED_DOMAINS = {
    "google.com",
    "github.com",
    "microsoft.com",
    "openai.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "youtube.com",
    "linkedin.com",
    "stackoverflow.com",
    "yahoo.com",
    "yahoodns.net",
    "deepseek.com",
    "volces.com",
}


_model_bundle = joblib.load(MODEL_PATH)

_model = _model_bundle["model"]
_feature_names = _model_bundle["features"]


def _get_registered_domain(
    url: str,
) -> str:
    """
    Extract the normalized hostname.

    This helper intentionally keeps the logic simple.
    Trusted-domain matching is performed against exact
    hostnames and their subdomains.
    """

    value = url.strip()

    if not value.startswith(
        ("http://", "https://")
    ):
        value = "http://" + value

    parsed = urlparse(value)

    hostname = (
        parsed.hostname or ""
    ).lower().rstrip(".")

    return hostname


def _is_trusted_domain(
    hostname: str,
) -> bool:
    """
    Return True when the hostname belongs to a
    configured trusted domain.

    Examples:

        github.com
        www.github.com

    are trusted.

    A deceptive hostname such as:

        github.com.evil.com

    is NOT trusted.
    """

    for domain in TRUSTED_DOMAINS:
        if hostname == domain:
            return True

        if hostname.endswith(
            "." + domain
        ):
            return True

    return False


def predict_url(
    url: str,
) -> dict[str, float | str]:
    """
    Predict whether a URL is phishing.

    Args:
        url:
            URL to classify.

    Returns:
        Dictionary containing prediction and phishing
        probability.
    """

    features = extract_url_features(
        url,
    )

    dataframe = pd.DataFrame(
        [
            [
                features[name]
                for name in _feature_names
            ]
        ],
        columns=_feature_names,
    )

    prediction = _model.predict(
        dataframe,
    )[0]

    probability = float(
        _model.predict_proba(
            dataframe,
        )[0][1]
    )

    hostname = _get_registered_domain(
        url,
    )

    if _is_trusted_domain(hostname):
        prediction = 0
        probability = 0.0

    return {
        "prediction": (
            "phishing"
            if prediction == 1
            else "legitimate"
        ),
        "probability": round(
            probability,
            4,
        ),
    }