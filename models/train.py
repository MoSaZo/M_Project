"""
Train a baseline phishing URL classification model.
"""

from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from models.features import FEATURE_NAMES
from models.features import extract_url_features


DATASET_PATH = Path(
    "evaluation/PhiUSIIL_Phishing_URL_Dataset.csv",
)

MODEL_PATH = Path(
    "models/phishing_url_model.joblib",
)


def main() -> None:
    """
    Train and save the phishing URL classifier.
    """

    print("Loading dataset...")

    df = pd.read_csv(
        DATASET_PATH,
        usecols=["URL", "label"],
    )

    print(f"Rows: {len(df):,}")

    # PhiUSIIL:
    # 1 = legitimate
    # 0 = phishing
    #
    # Our target:
    # 1 = phishing
    # 0 = legitimate
    df["target"] = (
        df["label"] == 0
    ).astype(int)

    print("\nClass distribution:")
    print(
        df["target"].value_counts(
            normalize=False,
        )
    )

    print("\nExtracting URL features...")

    feature_rows = [
        extract_url_features(url)
        for url in df["URL"]
    ]

    X = pd.DataFrame(
        feature_rows,
        columns=FEATURE_NAMES,
    )

    y = df["target"]

    print(
        f"Feature matrix: {X.shape[0]:,} "
        f"rows x {X.shape[1]} features"
    )

    print("\nSplitting dataset...")

    X_train, X_test, y_train, y_test = (
        train_test_split(
            X,
            y,
            test_size=0.20,
            random_state=42,
            stratify=y,
        )
    )

    print(
        f"Train: {len(X_train):,} "
        f"Test: {len(X_test):,}"
    )

    print("\nTraining Random Forest...")

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=16,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )

    model.fit(
        X_train,
        y_train,
    )

    print("\nEvaluating...")

    predictions = model.predict(X_test)

    probabilities = model.predict_proba(
        X_test,
    )[:, 1]

    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=[
                "legitimate",
                "phishing",
            ],
            digits=4,
        )
    )

    print("Confusion matrix:")
    print(
        confusion_matrix(
            y_test,
            predictions,
        )
    )

    print("\nROC-AUC:")
    print(
        f"{roc_auc_score(y_test, probabilities):.4f}"
    )

    print("\nFeature importance:")

    importance = pd.Series(
        model.feature_importances_,
        index=FEATURE_NAMES,
    ).sort_values(
        ascending=False,
    )

    print(
        importance.to_string()
    )

    MODEL_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        {
            "model": model,
            "features": FEATURE_NAMES,
        },
        MODEL_PATH,
    )

    print(
        f"\nModel saved to: {MODEL_PATH}"
    )


if __name__ == "__main__":
    main()