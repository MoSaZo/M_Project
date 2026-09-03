"""
Evaluate the current URL analyzer against a PhiUSIIL sample.

Dataset labels:
    1 = legitimate
    0 = phishing

This script does not modify the production analyzer or model.

It also simulates alternative ML confidence thresholds
without changing the production risk engine.
"""

import sys
import time
from collections import Counter
from pathlib import Path


# Add the project root to Python's import path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


import pandas as pd

from app.analyzer.analyzer import analyze_url
from models import predictor


# Use a single worker during evaluation.
#
# The production model configuration is not changed.
# This only affects the predictor object inside this
# evaluation process and avoids repeatedly creating
# large joblib thread pools for single-URL predictions.
if predictor._model is not None:
    predictor._model.n_jobs = 1


DATASET_PATH = (
    PROJECT_ROOT
    / "evaluation"
    / "PhiUSIIL_sample_10000.csv"
)

SIMULATED_THRESHOLDS = (
    0.70,
    0.75,
    0.80,
    0.85,
    0.90,
)


def expected_prediction(label: int) -> str:
    """
    Convert the PhiUSIIL label to the analyzer prediction.
    """

    return (
        "legitimate"
        if label == 1
        else "phishing"
    )


def analyzer_prediction(report: dict) -> str:
    """
    Convert the final risk level into a binary prediction.
    """

    if report["risk_level"] == "Safe":
        return "legitimate"

    return "phishing"


def simulated_prediction(
    report: dict,
    ml_threshold: float,
) -> str:
    """
    Simulate a more sensitive ML/rule combination.

    This does NOT change the production risk engine.

    Existing non-safe rule results remain phishing.
    A Safe result becomes phishing only when:
        ML prediction = phishing
        AND ML probability >= threshold
    """

    if report["risk_level"] != "Safe":
        return "phishing"

    ml_prediction = report.get(
        "ml_prediction"
    )

    ml_probability = report.get(
        "ml_probability"
    )

    if (
        ml_prediction == "phishing"
        and ml_probability is not None
        and ml_probability >= ml_threshold
    ):
        return "phishing"

    return "legitimate"


def probability_bucket(
    probability: float | None,
) -> str:
    """
    Group ML probability into useful analysis ranges.
    """

    if probability is None:
        return "unknown"

    if probability < 0.50:
        return "0.00-0.49"

    if probability < 0.60:
        return "0.50-0.59"

    if probability < 0.70:
        return "0.60-0.69"

    if probability < 0.80:
        return "0.70-0.79"

    if probability < 0.90:
        return "0.80-0.89"

    return "0.90-1.00"


def calculate_metrics(
    results: list[dict],
    prediction_key: str,
) -> dict[str, float | int]:
    """
    Calculate binary classification metrics.
    """

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    for result in results:
        expected = result["expected"]
        predicted = result[prediction_key]

        if (
            expected == "phishing"
            and predicted == "phishing"
        ):
            true_positive += 1

        elif (
            expected == "legitimate"
            and predicted == "legitimate"
        ):
            true_negative += 1

        elif (
            expected == "legitimate"
            and predicted == "phishing"
        ):
            false_positive += 1

        elif (
            expected == "phishing"
            and predicted == "legitimate"
        ):
            false_negative += 1

    total = (
        true_positive
        + true_negative
        + false_positive
        + false_negative
    )

    accuracy = (
        (true_positive + true_negative)
        / total
        if total
        else 0.0
    )

    precision = (
        true_positive
        / (true_positive + false_positive)
        if true_positive + false_positive
        else 0.0
    )

    recall = (
        true_positive
        / (true_positive + false_negative)
        if true_positive + false_negative
        else 0.0
    )

    f1 = (
        2 * precision * recall
        / (precision + recall)
        if precision + recall
        else 0.0
    )

    false_positive_rate = (
        false_positive
        / (false_positive + true_negative)
        if false_positive + true_negative
        else 0.0
    )

    false_negative_rate = (
        false_negative
        / (false_negative + true_positive)
        if false_negative + true_positive
        else 0.0
    )

    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "false_positive_rate": (
            false_positive_rate
        ),
        "false_negative_rate": (
            false_negative_rate
        ),
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
    }


def print_metrics(
    title: str,
    metrics: dict[str, float | int],
) -> None:
    """
    Print a metric block.
    """

    print()
    print(title)
    print("-" * 70)

    print(
        f"Accuracy            : "
        f"{metrics['accuracy']:.4f}"
    )
    print(
        f"Precision           : "
        f"{metrics['precision']:.4f}"
    )
    print(
        f"Recall              : "
        f"{metrics['recall']:.4f}"
    )
    print(
        f"F1                  : "
        f"{metrics['f1']:.4f}"
    )
    print(
        f"False Positive Rate : "
        f"{metrics['false_positive_rate']:.4f}"
    )
    print(
        f"False Negative Rate : "
        f"{metrics['false_negative_rate']:.4f}"
    )

    print()
    print(
        f"TP={metrics['true_positive']} | "
        f"TN={metrics['true_negative']} | "
        f"FP={metrics['false_positive']} | "
        f"FN={metrics['false_negative']}"
    )


def print_counter(
    title: str,
    counter: Counter,
) -> None:
    """
    Print a counter in descending frequency order.
    """

    print()
    print(title)
    print("-" * 70)

    if not counter:
        print("None")
        return

    for key, value in counter.most_common():
        print(
            f"{value:>5} | {key}"
        )


def main() -> None:
    """
    Run the evaluation and threshold simulation.
    """

    # Use 1,000 rows for the initial evaluation.
    # The full 10,000-row evaluation will be run later.
    df = pd.read_csv(
        DATASET_PATH
    ).head(10000)

    total = len(df)

    results = []

    errors = []

    false_negative_details = []

    processing_errors = 0

    start_time = time.perf_counter()

    print(
        "=" * 70,
        flush=True,
    )
    print(
        "PhiUSIIL Evaluation",
        flush=True,
    )
    print(
        "=" * 70,
        flush=True,
    )
    print(
        f"Dataset size: {total}",
        flush=True,
    )
    print(
        "Starting analysis...",
        flush=True,
    )
    print(
        flush=True,
    )

    for position, (index, row) in enumerate(
        df.iterrows(),
        start=1,
    ):
        url = str(row["URL"])
        label = int(row["label"])

        expected = expected_prediction(
            label
        )

        try:
            report = analyze_url(url)

            predicted = analyzer_prediction(
                report
            )

            result = {
                "index": index,
                "url": url,
                "expected": expected,
                "predicted": predicted,
                "risk_score": report[
                    "risk_score"
                ],
                "risk_level": report[
                    "risk_level"
                ],
                "ml_prediction": report.get(
                    "ml_prediction"
                ),
                "ml_probability": report.get(
                    "ml_probability"
                ),
            }

            for threshold in SIMULATED_THRESHOLDS:
                result[
                    f"sim_{threshold:.2f}"
                ] = simulated_prediction(
                    report,
                    threshold,
                )

            results.append(result)

            if predicted != expected:
                errors.append(result)

                if (
                    expected == "phishing"
                    and predicted == "legitimate"
                ):
                    indicators = report.get(
                        "indicators",
                        [],
                    )

                    false_negative_details.append(
                        {
                            **result,
                            "indicators": indicators,
                        }
                    )

        except Exception as exc:
            processing_errors += 1

            print(
                f"[ERROR] Row {index}: {exc}",
                flush=True,
            )

        if (
            position == 1
            or position % 100 == 0
            or position == total
        ):
            elapsed = (
                time.perf_counter()
                - start_time
            )

            rate = (
                position / elapsed
                if elapsed > 0
                else 0.0
            )

            remaining = (
                (total - position) / rate
                if rate > 0
                else 0.0
            )

            print(
                f"[PROGRESS] "
                f"{position}/{total} "
                f"({position / total:.1%}) | "
                f"{rate:.1f} URLs/s | "
                f"ETA {remaining:.0f}s",
                flush=True,
            )

    processed = len(results)

    current_metrics = calculate_metrics(
        results,
        "predicted",
    )

    elapsed = (
        time.perf_counter()
        - start_time
    )

    print()
    print(
        "=" * 70
    )
    print(
        "Current Production Logic"
    )
    print(
        "=" * 70
    )

    print(
        f"Dataset size        : {total}"
    )
    print(
        f"Processed           : {processed}"
    )
    print(
        f"Processing errors   : "
        f"{processing_errors}"
    )
    print(
        f"Collected errors    : "
        f"{len(errors)}"
    )

    print_metrics(
        "Current Metrics",
        current_metrics,
    )

    # --------------------------------------------------------------
    # Threshold simulation
    # --------------------------------------------------------------

    print()
    print(
        "=" * 70
    )
    print(
        "Simulated ML Confidence Thresholds"
    )
    print(
        "=" * 70
    )

    print(
        "These results are hypothetical only."
    )
    print(
        "Production risk_engine.py is NOT changed."
    )

    print()
    print(
        "Threshold | Accuracy | Precision | "
        "Recall | F1 | FPR | FNR | FP | FN"
    )
    print(
        "-" * 70
    )

    simulation_metrics = {}

    for threshold in SIMULATED_THRESHOLDS:
        key = f"sim_{threshold:.2f}"

        metrics = calculate_metrics(
            results,
            key,
        )

        simulation_metrics[
            threshold
        ] = metrics

        print(
            f"{threshold:>9.2f} | "
            f"{metrics['accuracy']:.4f} | "
            f"{metrics['precision']:.4f} | "
            f"{metrics['recall']:.4f} | "
            f"{metrics['f1']:.4f} | "
            f"{metrics['false_positive_rate']:.4f} | "
            f"{metrics['false_negative_rate']:.4f} | "
            f"{metrics['false_positive']:>2} | "
            f"{metrics['false_negative']:>3}"
        )

    # --------------------------------------------------------------
    # Effect of each threshold
    # --------------------------------------------------------------

    print()
    print(
        "Threshold Effect vs Current Logic"
    )
    print(
        "-" * 70
    )

    for threshold in SIMULATED_THRESHOLDS:
        current = current_metrics
        simulated = simulation_metrics[
            threshold
        ]

        recall_change = (
            simulated["recall"]
            - current["recall"]
        )

        fpr_change = (
            simulated["false_positive_rate"]
            - current["false_positive_rate"]
        )

        fn_change = (
            simulated["false_negative"]
            - current["false_negative"]
        )

        fp_change = (
            simulated["false_positive"]
            - current["false_positive"]
        )

        print(
            f"Threshold {threshold:.2f} | "
            f"Recall {recall_change:+.4f} | "
            f"FPR {fpr_change:+.4f} | "
            f"FN {fn_change:+d} | "
            f"FP {fp_change:+d}"
        )

    # --------------------------------------------------------------
    # False-negative population
    # --------------------------------------------------------------

    if false_negative_details:
        print()
        print(
            "=" * 70
        )
        print(
            "False Negative Population"
        )
        print(
            "=" * 70
        )

        risk_scores = Counter(
            detail["risk_score"]
            for detail in false_negative_details
        )

        ml_predictions = Counter(
            detail["ml_prediction"]
            for detail in false_negative_details
        )

        probability_buckets = Counter(
            probability_bucket(
                detail["ml_probability"]
            )
            for detail in false_negative_details
        )

        indicator_reasons = Counter()

        for detail in false_negative_details:
            for indicator in detail[
                "indicators"
            ]:
                indicator_reasons.update(
                    [indicator["reason"]]
                )

        print_counter(
            "False-negative rule scores",
            risk_scores,
        )

        print_counter(
            "False-negative ML predictions",
            ml_predictions,
        )

        print_counter(
            "False-negative ML probability buckets",
            probability_buckets,
        )

        print_counter(
            "Indicator reasons found in false negatives",
            indicator_reasons,
        )

    print()
    print(
        f"Evaluation time     : "
        f"{elapsed:.2f}s"
    )


if __name__ == "__main__":
    main()