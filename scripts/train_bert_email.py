import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

import pandas as pd
import torch
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from torch.utils.data import DataLoader, Dataset
from transformers import AutoModelForSequenceClassification, AutoTokenizer


@dataclass
class TrainConfig:
    csv_path: Path
    model_name: str
    output_dir: Path
    text_max_len: int
    batch_size: int
    epochs: int
    lr: float
    weight_decay: float


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

    for col in ["sender_email", "sender_name", "subject", "body_text", "urls", "attachments"]:
        if col not in df.columns:
            df[col] = ""

    df["label"] = df["label"].astype(int)
    df["text"] = (
        "[SENDER] "
        + df["sender_email"].map(_normalize_text)
        + " [SUBJECT] "
        + df["subject"].map(_normalize_text)
        + " [BODY] "
        + df["body_text"].map(_normalize_text)
        + " [URLS] "
        + df["urls"].map(_normalize_text)
        + " [ATTACHMENTS] "
        + df["attachments"].map(_normalize_text)
    )
    return df[["text", "label"]]


class EmailDataset(Dataset):
    def __init__(self, texts: List[str], labels: List[int], tokenizer, max_len: int):
        self.texts = texts
        self.labels = labels
        self.tokenizer = tokenizer
        self.max_len = max_len

    def __len__(self):
        return len(self.texts)

    def __getitem__(self, idx: int):
        enc = self.tokenizer(
            self.texts[idx],
            truncation=True,
            padding="max_length",
            max_length=self.max_len,
            return_tensors="pt",
        )
        return {
            "input_ids": enc["input_ids"].squeeze(0),
            "attention_mask": enc["attention_mask"].squeeze(0),
            "labels": torch.tensor(self.labels[idx], dtype=torch.long),
        }


def evaluate(model, loader, device) -> Dict[str, float]:
    model.eval()
    y_true, y_pred = [], []
    with torch.no_grad():
        for batch in loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            logits = model(input_ids=input_ids, attention_mask=attention_mask).logits
            preds = torch.argmax(logits, dim=-1)

            y_true.extend(labels.cpu().tolist())
            y_pred.extend(preds.cpu().tolist())

    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
    }


def train(cfg: TrainConfig) -> None:
    df = load_email_csv(cfg.csv_path)

    train_df, val_df = train_test_split(
        df,
        test_size=0.2,
        random_state=42,
        stratify=df["label"],
    )

    tokenizer = AutoTokenizer.from_pretrained(cfg.model_name)
    model = AutoModelForSequenceClassification.from_pretrained(cfg.model_name, num_labels=2)

    device = "cuda" if torch.cuda.is_available() else "cpu"
    model.to(device)

    train_ds = EmailDataset(train_df["text"].tolist(), train_df["label"].tolist(), tokenizer, cfg.text_max_len)
    val_ds = EmailDataset(val_df["text"].tolist(), val_df["label"].tolist(), tokenizer, cfg.text_max_len)

    train_loader = DataLoader(train_ds, batch_size=cfg.batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=cfg.batch_size)

    optimizer = torch.optim.AdamW(model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)

    history = []
    for epoch in range(cfg.epochs):
        model.train()
        total_loss = 0.0

        for batch in train_loader:
            optimizer.zero_grad()

            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["labels"].to(device)

            out = model(input_ids=input_ids, attention_mask=attention_mask, labels=labels)
            loss = out.loss
            loss.backward()
            optimizer.step()
            total_loss += float(loss.item())

        metrics = evaluate(model, val_loader, device)
        epoch_data = {
            "epoch": epoch + 1,
            "train_loss": total_loss / max(1, len(train_loader)),
            **metrics,
        }
        history.append(epoch_data)
        print(
            f"epoch={epoch_data['epoch']} loss={epoch_data['train_loss']:.4f} "
            f"acc={epoch_data['accuracy']:.4f} prec={epoch_data['precision']:.4f} "
            f"rec={epoch_data['recall']:.4f} f1={epoch_data['f1']:.4f}"
        )

    cfg.output_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(cfg.output_dir)
    tokenizer.save_pretrained(cfg.output_dir)

    metrics_path = cfg.output_dir / "metrics.json"
    metrics_path.write_text(json.dumps(history, indent=2), encoding="utf-8")
    print(f"Saved model to: {cfg.output_dir}")
    print(f"Saved metrics to: {metrics_path}")


def parse_args() -> TrainConfig:
    parser = argparse.ArgumentParser(description="Fine-tune BERT on phishing email CSV")
    parser.add_argument("--csv", required=True, help="Path to email CSV with subject,body_text,label")
    parser.add_argument("--model-name", default="distilbert-base-uncased")
    parser.add_argument("--output-dir", default="models/checkpoints/email-bert")
    parser.add_argument("--max-len", type=int, default=256)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--epochs", type=int, default=2)
    parser.add_argument("--lr", type=float, default=2e-5)
    parser.add_argument("--weight-decay", type=float, default=0.01)
    args = parser.parse_args()

    return TrainConfig(
        csv_path=Path(args.csv),
        model_name=args.model_name,
        output_dir=Path(args.output_dir),
        text_max_len=args.max_len,
        batch_size=args.batch_size,
        epochs=args.epochs,
        lr=args.lr,
        weight_decay=args.weight_decay,
    )


if __name__ == "__main__":
    train(parse_args())
