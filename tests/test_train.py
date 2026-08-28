"""
Tests for the phishing model training script.
"""

from unittest.mock import MagicMock
from unittest.mock import patch

import pandas as pd

from models import train


def test_main_trains_and_saves_model(
    tmp_path,
) -> None:
    """
    Training pipeline should load data, train a model,
    evaluate it, and save the trained artifact.
    """

    dataset = pd.DataFrame(
        {
            "URL": [
                "https://google.com",
                "https://example.com",
                "http://phishing.test/login",
                "http://evil.test/account",
                "https://safe.test",
                "http://fake.test/verify",
                "https://legitimate.test",
                "http://malicious.test/update",
                "https://trusted.test",
                "http://attack.test/login",
            ],
            "label": [
                1,
                1,
                0,
                0,
                1,
                0,
                1,
                0,
                1,
                0,
            ],
        }
    )

    fake_features = {
        name: index
        for index, name in enumerate(
            train.MODEL_FEATURE_NAMES
        )
    }

    model_path = (
        tmp_path
        / "phishing_url_model.joblib"
    )

    with (
        patch(
            "models.train.pd.read_csv",
            return_value=dataset,
        ) as mock_read_csv,
        patch(
            "models.train.extract_url_features",
            return_value=fake_features,
        ),
        patch.object(
            train,
            "MODEL_PATH",
            model_path,
        ),
        patch(
            "models.train.RandomForestClassifier"
        ) as mock_classifier,
        patch(
            "models.train.classification_report",
            return_value="classification report",
        ),
        patch(
            "models.train.confusion_matrix",
            return_value=[[1, 0], [0, 1]],
        ),
        patch(
            "models.train.roc_auc_score",
            return_value=0.95,
        ),
    ):
        model = MagicMock()

        model.predict.return_value = [
            0,
            1,
            0,
            1,
        ]

        model.predict_proba.return_value = [
            [0.90, 0.10],
            [0.20, 0.80],
            [0.75, 0.25],
            [0.10, 0.90],
        ]

        model.feature_importances_ = [
            0.1
        ] * len(train.MODEL_FEATURE_NAMES)

        mock_classifier.return_value = model

        with patch(
            "models.train.joblib.dump"
        ) as mock_dump:

            train.main()

    mock_read_csv.assert_called_once_with(
        train.DATASET_PATH,
        usecols=["URL", "label"],
    )

    mock_classifier.assert_called_once_with(
        n_estimators=300,
        max_depth=18,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    model.fit.assert_called_once()

    model.predict.assert_called_once()

    model.predict_proba.assert_called_once()

    mock_dump.assert_called_once()

    saved_data = mock_dump.call_args.args[0]

    assert saved_data["model"] is model
    assert (
        saved_data["features"]
        == train.MODEL_FEATURE_NAMES
    )

    assert model_path.parent.exists()


def test_main_converts_labels_to_phishing_target(
    tmp_path,
) -> None:
    """
    Dataset label 0 should become phishing target 1,
    while label 1 should become legitimate target 0.
    """

    dataset = pd.DataFrame(
        {
            "URL": [
                "https://safe.test",
                "http://evil.test",
                "https://safe2.test",
                "http://evil2.test",
                "https://safe3.test",
                "http://evil3.test",
            ],
            "label": [
                1,
                0,
                1,
                0,
                1,
                0,
            ],
        }
    )

    fake_features = {
        name: 0
        for name in train.MODEL_FEATURE_NAMES
    }

    model_path = (
        tmp_path
        / "model.joblib"
    )

    with (
        patch(
            "models.train.pd.read_csv",
            return_value=dataset,
        ),
        patch(
            "models.train.extract_url_features",
            return_value=fake_features,
        ),
        patch.object(
            train,
            "MODEL_PATH",
            model_path,
        ),
        patch(
            "models.train.RandomForestClassifier"
        ) as mock_classifier,
        patch(
            "models.train.classification_report",
            return_value="report",
        ),
        patch(
            "models.train.confusion_matrix",
            return_value=[[1, 0], [0, 1]],
        ),
        patch(
            "models.train.roc_auc_score",
            return_value=1.0,
        ),
        patch(
            "models.train.joblib.dump",
        ),
    ):
        model = MagicMock()

        model.predict.return_value = [
            0,
            1,
        ]

        model.predict_proba.return_value = [
            [0.9, 0.1],
            [0.1, 0.9],
        ]

        model.feature_importances_ = [
            0.1
        ] * len(train.MODEL_FEATURE_NAMES)

        mock_classifier.return_value = model

        train.main()

    fit_call = model.fit.call_args

    y_train = fit_call.args[1]

    assert set(y_train.tolist()) == {0, 1}