"""
Train a phishing URL classification model.
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

from models.features import MODEL_FEATURE_NAMES
from models.features import extract_url_features


DATASET_PATH = Path(
    "evaluation/PhiUSIIL_Phishing_URL_Dataset.csv"
)

MODEL_PATH = Path(
    "models/phishing_url_model.joblib"
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
    # label 1 = legitimate
    # label 0 = phishing
    #
    # Our target:
    # 0 = legitimate
    # 1 = phishing
    df["target"] = (
        df["label"] == 0
    ).astype(int)

    print("\nClass distribution:")
    print(
        df["target"].value_counts()
    )

    print("\nExtracting URL features...")

    feature_rows = [
        extract_url_features(url)
        for url in df["URL"]
    ]

    X = pd.DataFrame(
        feature_rows,
        columns=MODEL_FEATURE_NAMES,
    )

    y = df["target"]

    print(
        f"Feature matrix: "
        f"{X.shape[0]:,} rows x "
        f"{X.shape[1]} features"
    )

    print("\nSplitting dataset...")

    (
        X_train,
        X_test,
        y_train,
        y_test,
    ) = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y,
    )

    print(
        f"Train: {len(X_train):,}"
    )

    print(
        f"Test: {len(X_test):,}"
    )

    print("\nTraining Random Forest...")

    model = RandomForestClassifier(
        n_estimators=300,
        max_depth=18,
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

    predictions = model.predict(
        X_test
    )

    probabilities = (
        model.predict_proba(
            X_test
        )[:, 1]
    )

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

    roc_auc = roc_auc_score(
        y_test,
        probabilities,
    )

    print(
        f"{roc_auc:.4f}"
    )

    print("\nFeature importance:")

    importance = pd.Series(
        model.feature_importances_,
        index=MODEL_FEATURE_NAMES,
    ).sort_values(
        ascending=False
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
            "features": MODEL_FEATURE_NAMES,
        },
        MODEL_PATH,
    )

    print(
        f"\nModel saved to: "
        f"{MODEL_PATH}"
    )


if __name__ == "__main__":
    main()