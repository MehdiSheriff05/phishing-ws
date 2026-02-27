import argparse
import json
import re
from pathlib import Path

import pandas as pd
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

SUSPICIOUS_WORDS = ["urgent", "verify", "login", "reset", "invoice", "password", "suspended"]


def _normalize_text(value) -> str:
    if value is None:
        return ""
    return str(value).strip()


def load_email_csv(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    required = {"subject", "body_text", "label"}
    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    for col in ["sender_email", "urls", "attachments"]:
        if col not in df.columns:
            df[col] = ""

    df["label"] = df["label"].astype(int)
    df["text"] = (
        df["subject"].map(_normalize_text) + " " + df["body_text"].map(_normalize_text)
    ).str.strip()
    return df


def hand_features(df: pd.DataFrame):
    def one_row(row):
        text = f"{row['subject']} {row['body_text']}".lower()
        urls = _normalize_text(row["urls"]).lower()
        sender = _normalize_text(row["sender_email"]).lower()
        keyword_hits = sum(1 for w in SUSPICIOUS_WORDS if w in text)
        has_ip_url = 1 if re.search(r"https?://\d+\.\d+\.\d+\.\d+", urls) else 0
        url_count = urls.count("http")
        has_free_sender = 1 if any(d in sender for d in ["gmail.com", "yahoo.com", "outlook.com"]) else 0
        return [keyword_hits, has_ip_url, url_count, has_free_sender]

    return pd.DataFrame([one_row(r) for _, r in df.iterrows()], columns=[
        "keyword_hits",
        "has_ip_url",
        "url_count",
        "has_free_sender",
    ])


def main() -> None:
    parser = argparse.ArgumentParser(description="Train classical ML baseline on email CSV")
    parser.add_argument("--csv", required=True)
    parser.add_argument("--output", default="models/checkpoints/email-ml-metrics.json")
    args = parser.parse_args()

    df = load_email_csv(Path(args.csv))
    train_df, val_df = train_test_split(df, test_size=0.2, random_state=42, stratify=df["label"])

    tfidf = TfidfVectorizer(max_features=12000, ngram_range=(1, 2))
    x_train_text = tfidf.fit_transform(train_df["text"])
    x_val_text = tfidf.transform(val_df["text"])

    x_train_hand = hand_features(train_df)
    x_val_hand = hand_features(val_df)

    x_train = hstack([x_train_text, x_train_hand.values])
    x_val = hstack([x_val_text, x_val_hand.values])

    clf = LogisticRegression(max_iter=1000, class_weight="balanced")
    clf.fit(x_train, train_df["label"])

    y_pred = clf.predict(x_val)
    metrics = {
        "accuracy": accuracy_score(val_df["label"], y_pred),
        "precision": precision_score(val_df["label"], y_pred, zero_division=0),
        "recall": recall_score(val_df["label"], y_pred, zero_division=0),
        "f1": f1_score(val_df["label"], y_pred, zero_division=0),
    }

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(json.dumps(metrics, indent=2))
    print(f"Saved metrics to: {out_path}")


if __name__ == "__main__":
    main()
