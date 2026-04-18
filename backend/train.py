from __future__ import annotations

import argparse
import json
from html import unescape
from html.parser import HTMLParser
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
TEST_DATA_DIR = Path(__file__).resolve().parents[1] / "test_data"

# The dataset has changed column names across files, so these candidate names make loading flexible.
TEXT_CANDIDATES = ["text", "email_text", "body", "message", "content", "Email Text"]
LABEL_CANDIDATES = ["label", "target", "class", "is_phishing", "Label"]


# This parser extracts only paragraph text from HTML test emails for train/test overlap removal.
class ParagraphTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._paragraph_depth = 0
        self._parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # Test email bodies place content in paragraph tags, so paragraph depth controls extraction.
        if tag == "p":
            self._paragraph_depth += 1

    def handle_endtag(self, tag: str) -> None:
        # Ending a paragraph stops recording text until another paragraph begins.
        if tag == "p" and self._paragraph_depth > 0:
            self._paragraph_depth -= 1

    def handle_data(self, data: str) -> None:
        # Ignore layout text outside paragraphs so only actual email body text is compared.
        if self._paragraph_depth <= 0:
            return
        clean = " ".join((data or "").split()).strip()
        if clean:
            self._parts.append(clean)

    def extracted_text(self) -> str:
        # Joining paragraphs gives one normalized string that can be compared to dataset rows.
        return " ".join(self._parts).strip()


def _normalize_label(value) -> int:
    # Numeric labels are treated as phishing when they are greater than zero.
    if pd.isna(value):
        return 0
    if isinstance(value, (int, np.integer, float, np.floating)):
        return int(value > 0)
    # String labels are mapped into the same binary classes used by scikit-learn.
    value_str = str(value).strip().lower()
    if value_str in {"1", "phishing", "spam", "malicious", "true", "yes"}:
        return 1
    return 0


def _normalize_text_content(value: str) -> str:
    # Text normalization removes HTML entities and repeated whitespace before vectorization.
    return " ".join(unescape(str(value or "")).split()).strip()


def _find_column(columns: list[str], candidates: list[str]) -> str:
    # Column lookup is case-insensitive so different dataset file versions can be parsed.
    lower_map = {c.lower(): c for c in columns}
    for name in candidates:
        if name.lower() in lower_map:
            return lower_map[name.lower()]
    raise ValueError(f"Could not find expected column. Available: {columns}")


def _load_dataset_frame() -> pd.DataFrame:
    # kagglehub downloads the dataset, but local cache fallback keeps training usable offline.
    files: list[Path] = []
    try:
        dataset_path = Path(kagglehub.dataset_download(DATASET_REF))
        files = list(dataset_path.rglob("*.csv")) + list(dataset_path.rglob("*.parquet"))
    except Exception:
        # If downloading fails, search the user's existing kagglehub cache for dataset files.
        cache_root = Path.home() / ".cache" / "kagglehub"
        files = list(cache_root.rglob("*.csv")) + list(cache_root.rglob("*.parquet"))

    if not files:
        raise FileNotFoundError("No CSV/Parquet files found from download or local cache")

    usable_frames: list[pd.DataFrame] = []
    for file in files:
        try:
            # The loader accepts both CSV and Parquet because Kaggle datasets vary by release.
            if file.suffix.lower() == ".csv":
                candidate = pd.read_csv(file)
            else:
                candidate = pd.read_parquet(file)
            # Tiny files or files without text/label columns are skipped as metadata files.
            if len(candidate.columns) < 2 or len(candidate) <= 100:
                continue
            text_col = _find_column(candidate.columns.tolist(), TEXT_CANDIDATES)
            label_col = _find_column(candidate.columns.tolist(), LABEL_CANDIDATES)
            usable_frames.append(
                candidate[[text_col, label_col]].rename(columns={text_col: "text", label_col: "label"})
            )
        except Exception:
            continue

    if not usable_frames:
        raise RuntimeError("Unable to parse any usable dataset files")

    return pd.concat(usable_frames, ignore_index=True)


def _extract_test_email_texts(test_data_dir: Path) -> set[str]:
    # Test emails are collected so training can exclude them and avoid evaluation leakage.
    texts: set[str] = set()
    if not test_data_dir.exists():
        return texts

    for path in sorted(test_data_dir.glob("*/*.html")):
        # Folder indexes are navigation pages, not email examples.
        if path.name == "index.html":
            continue
        parser = ParagraphTextParser()
        parser.feed(path.read_text(encoding="utf-8"))
        extracted = _normalize_text_content(parser.extracted_text())
        if extracted:
            texts.add(extracted)
    return texts


def _load_feedback_frame() -> tuple[pd.DataFrame, int]:
    # Feedback examples are optional and only used when --include-feedback is provided.
    if not FEEDBACK_TRAINING_PATH.exists():
        return pd.DataFrame(columns=["text", "y"]), 0

    feedback_df = pd.read_csv(FEEDBACK_TRAINING_PATH)
    if not {"text", "label"}.issubset(set(feedback_df.columns)):
        return pd.DataFrame(columns=["text", "y"]), 0

    # Feedback is normalized into the same "text" and "y" columns as the Kaggle data.
    feedback_df = feedback_df[["text", "label"]].dropna().copy()
    feedback_df["text"] = feedback_df["text"].astype(str).map(_normalize_text_content)
    feedback_df = feedback_df[feedback_df["text"] != ""]
    feedback_df["y"] = feedback_df["label"].apply(_normalize_label)
    feedback_df = feedback_df[["text", "y"]]
    return feedback_df, int(len(feedback_df))


def _build_synthetic_non_phishing_messages(count: int) -> list[str]:
    # Synthetic benign messages are only a fallback if a dataset lacks enough legitimate emails.
    templates = [
        "Hi team, the project check-in is at {time} in room {room}. Please review the notes before joining.",
        "Reminder: your library book return date is {date}. You can renew online if needed.",
        "Your package is out for delivery today between {time}. Track status on the courier portal.",
        "Weekly course update: assignment {num} is due on {date}. Reach out if you need clarification.",
        "Meeting notes from today's stand-up are attached. Please confirm your action items by {time}.",
        "Payroll update: your payslip for {month} is now available in the employee portal.",
        "Your appointment with student services is confirmed for {date} at {time}.",
        "Campus network maintenance is scheduled on {date}. Brief downtime may occur after {time}.",
        "Thank you for registering. Your event ticket and seat details are available in your dashboard.",
        "Team lunch is planned for {date}. Please select your menu choice by end of day.",
        "Your course registration has been approved. Check the portal for timetable details on {date}.",
        "This is a reminder that your utility bill payment was received successfully on {date}.",
    ]
    messages: list[str] = []
    for i in range(count):
        # Template variation prevents every synthetic message from being identical.
        template = templates[i % len(templates)]
        message = template.format(
            time=f"{8 + (i % 10)}:{(i * 11) % 60:02d}",
            room=f"C-{100 + (i % 80)}",
            date=f"2026-{1 + ((i // 28) % 12):02d}-{1 + (i % 28):02d}",
            num=1 + (i % 12),
            month=[
                "January",
                "February",
                "March",
                "April",
                "May",
                "June",
                "July",
                "August",
                "September",
                "October",
                "November",
                "December",
            ][i % 12],
        )
        messages.append(message)
    return messages


def _prepare_base_frame() -> pd.DataFrame:
    # Base preparation turns the raw dataset into the clean two-column training frame.
    df = _load_dataset_frame()
    df = df[["text", "label"]].dropna().copy()
    df["text"] = df["text"].astype(str).map(_normalize_text_content)
    df = df[df["text"] != ""]
    df["y"] = df["label"].apply(_normalize_label)
    df = df[["text", "y"]]
    return df


def _sample_balanced_frame(df: pd.DataFrame, samples_per_class: int, seed: int) -> pd.DataFrame:
    # Balanced sampling gives the model equal exposure to phishing and legitimate emails.
    phishing_df = df[df["y"] == 1]
    legitimate_df = df[df["y"] == 0]

    # Training should fail loudly if one class does not contain enough real examples.
    if len(phishing_df) < samples_per_class:
        raise ValueError(
            f"Not enough phishing examples after exclusions: found={len(phishing_df)}, required={samples_per_class}"
        )
    if len(legitimate_df) < samples_per_class:
        raise ValueError(
            f"Not enough non-phishing examples after exclusions: found={len(legitimate_df)}, required={samples_per_class}"
        )

    # Random state makes dissertation results repeatable.
    phishing_sample = phishing_df.sample(n=samples_per_class, random_state=seed)
    legitimate_sample = legitimate_df.sample(n=samples_per_class, random_state=seed)
    return pd.concat([phishing_sample, legitimate_sample], ignore_index=True).sample(
        frac=1.0, random_state=seed
    )


def main() -> None:
    # Command-line flags let the same script support normal training and controlled experiments.
    parser = argparse.ArgumentParser(
        description="Train the phishing model on a balanced dataset while excluding test_data emails."
    )
    parser.add_argument("--samples-per-class", type=int, default=900, help="Training examples per class.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for balanced sampling.")
    parser.add_argument(
        "--include-feedback",
        action="store_true",
        help="Include saved feedback examples from backend/artifacts/feedback/training_feedback.csv.",
    )
    parser.add_argument(
        "--allow-test-overlap",
        action="store_true",
        help="Do not exclude emails whose text appears in test_data. Not recommended for evaluation.",
    )
    parser.add_argument(
        "--allow-synthetic-non-phishing",
        action="store_true",
        help="If the source dataset lacks enough non-phishing emails, generate benign training messages to fill the gap.",
    )
    args = parser.parse_args()

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)

    # Load and clean the full source dataset before any sampling occurs.
    df = _prepare_base_frame()
    original_count = int(len(df))

    excluded_test_examples = 0
    if not args.allow_test_overlap:
        # Excluding test_data prevents the model from seeing evaluation examples during training.
        test_texts = _extract_test_email_texts(TEST_DATA_DIR)
        if test_texts:
            before = len(df)
            df = df[~df["text"].isin(test_texts)].copy()
            excluded_test_examples = before - len(df)

    # Duplicate texts are removed so repeated emails do not overweight the classifier.
    df = df.drop_duplicates(subset=["text", "y"]).reset_index(drop=True)
    deduped_count = int(len(df))

    synthetic_non_phishing_used = 0
    non_phishing_count = int((df["y"] == 0).sum())
    if non_phishing_count < args.samples_per_class:
        if not args.allow_synthetic_non_phishing:
            # The preferred approach is real benign data, not synthetic examples.
            raise ValueError(
                "Not enough non-phishing examples after exclusions: "
                f"found={non_phishing_count}, required={args.samples_per_class}. "
                "Re-run with --allow-synthetic-non-phishing to generate separate benign training emails."
            )
        missing = args.samples_per_class - non_phishing_count
        # Synthetic messages are clearly tracked in metrics for transparency.
        synthetic_messages = _build_synthetic_non_phishing_messages(missing)
        synthetic_df = pd.DataFrame({"text": synthetic_messages, "y": 0})
        df = pd.concat([df, synthetic_df], ignore_index=True)
        df = df.drop_duplicates(subset=["text", "y"]).reset_index(drop=True)
        synthetic_non_phishing_used = int((df["y"] == 0).sum() - non_phishing_count)

    # The final base training set is exactly balanced before optional feedback is added.
    sampled_df = _sample_balanced_frame(df, samples_per_class=args.samples_per_class, seed=args.seed)
    sampled_base_count = int(len(sampled_df))

    feedback_examples_used = 0
    if args.include_feedback:
        # Feedback can adapt the model later, but this run intentionally did not use it.
        feedback_df, feedback_count = _load_feedback_frame()
        if feedback_count > 0:
            feedback_examples_used = feedback_count
            sampled_df = pd.concat([sampled_df, feedback_df], ignore_index=True)
            sampled_df = sampled_df.drop_duplicates(subset=["text", "y"]).reset_index(drop=True)

    # Stratification keeps the 80/20 split balanced in both train and validation data.
    X_train, X_test, y_train, y_test = train_test_split(
        sampled_df["text"],
        sampled_df["y"],
        test_size=0.2,
        random_state=args.seed,
        stratify=sampled_df["y"],
    )

    # TF-IDF turns email text into weighted word and two-word phrase features.
    vectorizer = TfidfVectorizer(
        max_features=30000,
        ngram_range=(1, 2),
        lowercase=True,
        strip_accents="unicode",
        min_df=2,
    )

    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    # Logistic Regression is explainable, fast, and outputs probabilities for the extension.
    classifier = LogisticRegression(max_iter=2000, class_weight="balanced")
    classifier.fit(X_train_vec, y_train)

    # Validation metrics show how well the trained model performs on unseen split data.
    y_pred = classifier.predict(X_test_vec)
    y_proba = classifier.predict_proba(X_test_vec)[:, 1]

    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    pr_auc = float(average_precision_score(y_test, y_proba))
    cm = confusion_matrix(y_test, y_pred)

    # Metrics are saved so dissertation screenshots can cite the exact training run.
    metrics = {
        "dataset": DATASET_REF,
        "samples_per_class": int(args.samples_per_class),
        "random_seed": int(args.seed),
        "include_feedback": bool(args.include_feedback),
        "excluded_test_data_overlap": not args.allow_test_overlap,
        "allow_synthetic_non_phishing": bool(args.allow_synthetic_non_phishing),
        "original_dataset_rows": original_count,
        "excluded_test_examples": excluded_test_examples,
        "deduped_dataset_rows": deduped_count,
        "synthetic_non_phishing_used": synthetic_non_phishing_used,
        "sampled_base_rows": sampled_base_count,
        "feedback_examples_used": feedback_examples_used,
        "num_samples": int(len(sampled_df)),
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "pr_auc": pr_auc,
        "confusion_matrix": cm.tolist(),
    }

    # These artifacts are what the FastAPI backend loads when it starts.
    joblib.dump(vectorizer, VECTORIZER_PATH)
    joblib.dump(classifier, CLASSIFIER_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    # The confusion matrix CSV is easier to inspect than JSON for many readers.
    cm_frame = pd.DataFrame(cm, index=["actual_0", "actual_1"], columns=["pred_0", "pred_1"])
    cm_frame.to_csv(CONFUSION_PATH, index=True)

    # Console output confirms artifact locations after training completes.
    print("Training complete.")
    print(json.dumps(metrics, indent=2))
    print(f"Saved vectorizer: {VECTORIZER_PATH}")
    print(f"Saved classifier: {CLASSIFIER_PATH}")
    print(f"Saved metrics: {METRICS_PATH}")
    print(f"Saved confusion matrix: {CONFUSION_PATH}")


if __name__ == "__main__":
    main()
