"""
Machine learning prediction service.

Loads the trained phishing detection model and predicts
whether a URL is phishing or legitimate.
"""

from pathlib import Path

import joblib
import pandas as pd

from models.features import extract_url_features


MODEL_PATH = (
    Path(__file__).resolve().parent
    / "phishing_url_model.joblib"
)

_model_bundle = joblib.load(MODEL_PATH)

_model = _model_bundle["model"]
_feature_names = _model_bundle["features"]


def predict_url(
    url: str,
) -> dict[str, float | str]:
    """
    Predict whether a URL is phishing.

    Args:
        url:
            URL to classify.

    Returns:
        Dictionary containing prediction and phishing probability.
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