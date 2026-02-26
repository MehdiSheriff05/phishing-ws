import argparse
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score


def evaluate(csv_path: Path) -> None:
    """
    CSV format expected:
    y_true,y_pred
    1,0
    0,0
    ...
    """
    df = pd.read_csv(csv_path)

    y_true = df["y_true"]
    y_pred = df["y_pred"]

    print("Accuracy:", round(accuracy_score(y_true, y_pred), 4))
    print("Precision:", round(precision_score(y_true, y_pred, zero_division=0), 4))
    print("Recall:", round(recall_score(y_true, y_pred, zero_division=0), 4))
    print("F1:", round(f1_score(y_true, y_pred, zero_division=0), 4))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prototype evaluation scaffold")
    parser.add_argument("--csv", required=True, help="Path to CSV with y_true,y_pred")
    args = parser.parse_args()
    evaluate(Path(args.csv))
