from __future__ import annotations

import json
from pathlib import Path

import joblib
import kagglehub
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split


ARTIFACTS_DIR = Path(__file__).resolve().parent / "artifacts"
VECTORIZER_PATH = ARTIFACTS_DIR / "vectorizer.joblib"
CLASSIFIER_PATH = ARTIFACTS_DIR / "classifier.joblib"
METRICS_PATH = ARTIFACTS_DIR / "metrics.json"
CONFUSION_PATH = ARTIFACTS_DIR / "confusion_matrix.csv"
DATASET_REF = "naserabdullahalam/phishing-email-dataset"
FEEDBACK_TRAINING_PATH = ARTIFACTS_DIR / "feedback" / "training_feedback.csv"

TEXT_CANDIDATES = ["text", "email_text", "body", "message", "content", "Email Text"]
LABEL_CANDIDATES = ["label", "target", "class", "is_phishing", "Label"]


def _normalize_label(value) -> int:
    if pd.isna(value):
        return 0
    if isinstance(value, (int, np.integer, float, np.floating)):
        return int(value > 0)
    value_str = str(value).strip().lower()
    if value_str in {"1", "phishing", "spam", "malicious", "true", "yes"}:
        return 1
    return 0


def _find_column(columns: list[str], candidates: list[str]) -> str:
    lower_map = {c.lower(): c for c in columns}
    for name in candidates:
        if name.lower() in lower_map:
            return lower_map[name.lower()]
    raise ValueError(f"Could not find expected column. Available: {columns}")


def _load_dataset_frame() -> pd.DataFrame:
    dataset_path = Path(kagglehub.dataset_download(DATASET_REF))

    files = list(dataset_path.rglob("*.csv")) + list(dataset_path.rglob("*.parquet"))
    if not files:
        raise FileNotFoundError(f"No CSV/Parquet files found in {dataset_path}")

    frame = None
    for file in files:
        try:
            if file.suffix.lower() == ".csv":
                candidate = pd.read_csv(file)
            else:
                candidate = pd.read_parquet(file)
            if len(candidate.columns) >= 2 and len(candidate) > 100:
                frame = candidate
                break
        except Exception:
            continue

    if frame is None:
        raise RuntimeError("Unable to parse a usable dataset file")

    return frame


def main() -> None:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    df = _load_dataset_frame()
    text_col = _find_column(df.columns.tolist(), TEXT_CANDIDATES)
    label_col = _find_column(df.columns.tolist(), LABEL_CANDIDATES)

    df = df[[text_col, label_col]].dropna().copy()
    df[text_col] = df[text_col].astype(str).str.strip()
    df = df[df[text_col] != ""]
    df["y"] = df[label_col].apply(_normalize_label)
    df = df[[text_col, "y"]].rename(columns={text_col: "text"})

    feedback_examples = 0
    if FEEDBACK_TRAINING_PATH.exists():
        feedback_df = pd.read_csv(FEEDBACK_TRAINING_PATH)
        if {"text", "label"}.issubset(set(feedback_df.columns)):
            feedback_df = feedback_df[["text", "label"]].dropna().copy()
            feedback_df["text"] = feedback_df["text"].astype(str).str.strip()
            feedback_df = feedback_df[feedback_df["text"] != ""]
            feedback_df["y"] = feedback_df["label"].apply(_normalize_label)
            feedback_df = feedback_df[["text", "y"]]
            feedback_examples = int(len(feedback_df))
            if feedback_examples > 0:
                df = pd.concat([df, feedback_df], ignore_index=True)

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"],
        df["y"],
        test_size=0.2,
        random_state=42,
        stratify=df["y"],
    )

    vectorizer = TfidfVectorizer(
        max_features=30000,
        ngram_range=(1, 2),
        lowercase=True,
        strip_accents="unicode",
        min_df=2,
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    classifier = LogisticRegression(max_iter=2000, class_weight="balanced")
    classifier.fit(X_train_vec, y_train)

    y_pred = classifier.predict(X_test_vec)
    y_proba = classifier.predict_proba(X_test_vec)[:, 1]

    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    pr_auc = float(average_precision_score(y_test, y_proba))
    cm = confusion_matrix(y_test, y_pred)

    metrics = {
        "dataset": DATASET_REF,
        "num_samples": int(len(df)),
        "feedback_examples_used": feedback_examples,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "pr_auc": pr_auc,
        "confusion_matrix": cm.tolist(),
    }

    joblib.dump(vectorizer, VECTORIZER_PATH)
    joblib.dump(classifier, CLASSIFIER_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    cm_frame = pd.DataFrame(cm, index=["actual_0", "actual_1"], columns=["pred_0", "pred_1"])
    cm_frame.to_csv(CONFUSION_PATH, index=True)

    print("Training complete.")
    print(json.dumps(metrics, indent=2))
    print(f"Saved vectorizer: {VECTORIZER_PATH}")
    print(f"Saved classifier: {CLASSIFIER_PATH}")
    print(f"Saved metrics: {METRICS_PATH}")
    print(f"Saved confusion matrix: {CONFUSION_PATH}")


if __name__ == "__main__":
    main()
