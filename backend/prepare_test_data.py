from __future__ import annotations

import argparse
import html
from pathlib import Path

import kagglehub
import numpy as np
import pandas as pd


DATASET_REF = "naserabdullahalam/phishing-email-dataset"

# Candidate column names make the script robust to small dataset schema differences.
TEXT_CANDIDATES = ["text", "email_text", "body", "message", "content", "Email Text"]
LABEL_CANDIDATES = ["label", "target", "class", "is_phishing", "Label", "type"]


def _normalize_label(value) -> int:
    # Unknown labels return -1 so they can be filtered out before sampling.
    if pd.isna(value):
        return -1
    if isinstance(value, (int, np.integer, float, np.floating)):
        return int(value > 0)
    # Dataset labels may be words instead of numbers, so normalize both formats.
    value_str = str(value).strip().lower()
    if value_str in {"1", "phishing", "spam", "malicious", "true", "yes"}:
        return 1
    if value_str in {"0", "legitimate", "ham", "safe", "false", "no", "normal"}:
        return 0
    return -1


def _find_column(columns: list[str], candidates: list[str]) -> str:
    # Case-insensitive lookup avoids failures caused by "Label" versus "label".
    lower_map = {c.lower(): c for c in columns}
    for name in candidates:
        if name.lower() in lower_map:
            return lower_map[name.lower()]
    raise ValueError(f"Could not find expected column. Available: {columns}")


def _pick_usable_file(files: list[Path]) -> Path:
    # The Kaggle folder may contain multiple files; this finds the first usable data table.
    for file in files:
        try:
            if file.suffix.lower() == ".csv":
                candidate = pd.read_csv(file, nrows=200)
            else:
                candidate = pd.read_parquet(file).head(200)
            if len(candidate.columns) >= 2:
                return file
        except Exception:
            continue
    raise RuntimeError("Unable to parse a usable dataset file")


def _load_dataset_frame(dataset_file: str | None = None) -> pd.DataFrame:
    # A provided dataset file is useful when the user already downloaded data locally.
    files: list[Path] = []

    if dataset_file:
        path = Path(dataset_file).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Dataset file not found: {path}")
        files = [path]
    else:
        try:
            # Otherwise kagglehub downloads or locates the configured phishing email dataset.
            dataset_path = Path(kagglehub.dataset_download(DATASET_REF))
            files = list(dataset_path.rglob("*.csv")) + list(dataset_path.rglob("*.parquet"))
        except Exception:
            # Fallback to local kagglehub cache if download fails.
            cache_root = Path.home() / ".cache" / "kagglehub"
            files = list(cache_root.rglob("*.csv")) + list(cache_root.rglob("*.parquet"))

    if not files:
        raise FileNotFoundError("No CSV/Parquet files found from download or local cache")

    chosen = _pick_usable_file(files)

    # Read the chosen dataset fully after the lightweight usability check above.
    frame = None
    for file in [chosen]:
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


def _email_html(title: str, sender: str, body: str) -> str:
    # Each email is wrapped in a simple HTML page so it can be opened in a browser.
    body_html = "<br/>".join(html.escape(line) for line in body.splitlines())
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #f3f5f8; margin: 0; padding: 24px; }}
    .email {{ max-width: 840px; margin: 0 auto; background: #fff; border: 1px solid #ddd; border-radius: 8px; }}
    .head {{ padding: 14px 18px; border-bottom: 1px solid #eee; background: #f8fafc; }}
    .body {{ padding: 18px; line-height: 1.55; color: #222; white-space: normal; }}
    .meta {{ color: #4b5563; font-size: 13px; }}
  </style>
</head>
<body>
  <div class="email">
    <div class="head">
      <div><strong>From:</strong> {html.escape(sender)}</div>
      <div><strong>Subject:</strong> {html.escape(title)}</div>
    </div>
    <div class="body">
      <div class="meta">Test email page for extension scanning.</div>
      <hr/>
      <p>{body_html}</p>
    </div>
  </div>
</body>
</html>
"""


def _build_synthetic_non_phishing_messages(count: int) -> list[str]:
    # Synthetic benign emails are a fallback when the dataset lacks enough non-phishing samples.
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
    ]
    messages: list[str] = []
    for i in range(count):
        # Vary time, room, date, and month so the synthetic messages are not duplicates.
        t = templates[i % len(templates)]
        msg = t.format(
            time=f"{9 + (i % 8)}:{(i * 7) % 60:02d}",
            room=f"B-{100 + (i % 50)}",
            date=f"2026-04-{1 + (i % 28):02d}",
            num=1 + (i % 8),
            month=["January", "February", "March", "April", "May", "June"][i % 6],
        )
        messages.append(msg)
    return messages


def _write_folder_index(folder: Path, title: str) -> None:
    # Folder indexes let a non-technical tester click through emails in a browser.
    pages = sorted([p for p in folder.glob("*.html") if p.name != "index.html"])
    links = "\n".join([f'<li><a href="./{p.name}">{p.stem}</a></li>' for p in pages])
    content = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>{html.escape(title)}</title>
</head>
<body>
  <h1>{html.escape(title)}</h1>
  <ul>
    {links}
  </ul>
</body>
</html>
"""
    (folder / "index.html").write_text(content, encoding="utf-8")


def main() -> None:
    # This script creates the browser-friendly test set and a blank evaluation CSV template.
    parser = argparse.ArgumentParser(description="Prepare GUI test dataset pages and logging CSV.")
    parser.add_argument("--per-class", type=int, default=100, help="Emails per class for test data.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for sampling.")
    parser.add_argument(
        "--out-dir",
        default=str(Path(__file__).resolve().parents[1] / "test_data"),
        help="Output directory for generated test pages.",
    )
    parser.add_argument(
        "--dataset-file",
        default="",
        help="Optional path to a local CSV/Parquet file to use instead of downloading.",
    )
    parser.add_argument(
        "--allow-synthetic-non-phishing",
        action="store_true",
        help="If non-phishing class is missing, create non-phishing pages from benign templates.",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    phishing_dir = out_dir / "phishing"
    non_phishing_dir = out_dir / "non_phishing"
    phishing_dir.mkdir(parents=True, exist_ok=True)
    non_phishing_dir.mkdir(parents=True, exist_ok=True)

    # Load the source dataset and identify which columns contain text and labels.
    df = _load_dataset_frame(dataset_file=args.dataset_file or None)
    text_col = _find_column(df.columns.tolist(), TEXT_CANDIDATES)
    label_col = _find_column(df.columns.tolist(), LABEL_CANDIDATES)

    # Clean rows with missing text or unclear labels before taking samples.
    clean = df[[text_col, label_col]].dropna().copy()
    clean[text_col] = clean[text_col].astype(str).str.strip()
    clean = clean[clean[text_col] != ""]
    clean["actual_label"] = clean[label_col].apply(_normalize_label)
    clean = clean[clean["actual_label"].isin([0, 1])].copy()

    phishing_rows = clean[clean["actual_label"] == 1]
    non_phishing_rows = clean[clean["actual_label"] == 0]

    # The test set must include enough real phishing examples to support evaluation.
    if len(phishing_rows) < args.per_class:
        raise ValueError(
            f"Not enough phishing rows. Found phishing={len(phishing_rows)}, required={args.per_class}"
        )

    # Sampling with a seed keeps the generated test set repeatable.
    phishing_sample = phishing_rows.sample(n=args.per_class, random_state=args.seed).reset_index(drop=True)
    non_phishing_sample = non_phishing_rows.sample(
        n=min(args.per_class, len(non_phishing_rows)),
        random_state=args.seed,
    ).reset_index(drop=True)

    # Remove old generated pages before writing a fresh test set.
    for old in phishing_dir.glob("*.html"):
        old.unlink()
    for old in non_phishing_dir.glob("*.html"):
        old.unlink()

    records: list[dict[str, str | int | float]] = []

    for i, row in phishing_sample.iterrows():
        # Phishing examples are written into the phishing folder with matching CSV labels.
        email_id = f"phishing_{i + 1:03d}"
        rel_path = f"phishing/{email_id}.html"
        body = str(row[text_col])
        (phishing_dir / f"{email_id}.html").write_text(
            _email_html("Account security update", "alerts@example-mail.com", body),
            encoding="utf-8",
        )
        records.append(
            {
                "email_id": email_id,
                "relative_path": rel_path,
                "actual_label": 1,
                "pretraining_probability": "",
                "posttraining_probability": "",
                "pretraining_label": "",
                "posttraining_label": "",
                "pretraining_description": "",
                "posttraining_description": "",
                "notes": "",
            }
        )

    for i, row in non_phishing_sample.iterrows():
        # Non-phishing examples are written separately so folder names provide ground truth.
        email_id = f"non_phishing_{i + 1:03d}"
        rel_path = f"non_phishing/{email_id}.html"
        body = str(row[text_col])
        (non_phishing_dir / f"{email_id}.html").write_text(
            _email_html("Weekly project update", "team@university.edu", body),
            encoding="utf-8",
        )
        records.append(
            {
                "email_id": email_id,
                "relative_path": rel_path,
                "actual_label": 0,
                "pretraining_probability": "",
                "posttraining_probability": "",
                "pretraining_label": "",
                "posttraining_label": "",
                "pretraining_description": "",
                "posttraining_description": "",
                "notes": "",
            }
        )

    if len(non_phishing_sample) < args.per_class:
        # Synthetic benign messages are only used when explicitly allowed by the user.
        if not args.allow_synthetic_non_phishing:
            raise ValueError(
                "Non-phishing rows are missing. Re-run with --allow-synthetic-non-phishing "
                "or provide a dataset that contains non-phishing examples."
            )
        missing = args.per_class - len(non_phishing_sample)
        synthetic_messages = _build_synthetic_non_phishing_messages(missing)
        start = len(non_phishing_sample)
        for i, body in enumerate(synthetic_messages, start=1):
            # Synthetic rows are marked in notes so they remain transparent in the CSV.
            email_id = f"non_phishing_{start + i:03d}"
            rel_path = f"non_phishing/{email_id}.html"
            (non_phishing_dir / f"{email_id}.html").write_text(
                _email_html("General update", "noreply@university.edu", body),
                encoding="utf-8",
            )
            records.append(
                {
                    "email_id": email_id,
                    "relative_path": rel_path,
                    "actual_label": 0,
                    "pretraining_probability": "",
                    "posttraining_probability": "",
                    "pretraining_label": "",
                    "posttraining_label": "",
                    "pretraining_description": "",
                    "posttraining_description": "",
                    "notes": "synthetic_non_phishing",
                }
            )

    _write_folder_index(phishing_dir, "Phishing Test Emails")
    _write_folder_index(non_phishing_dir, "Non-Phishing Test Emails")

    # The root index lets testers choose phishing or non-phishing folders from one page.
    root_index = """<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Test Data</title>
</head>
<body>
  <h1>Test Data</h1>
  <ul>
    <li><a href="./phishing/">Phishing (100)</a></li>
    <li><a href="./non_phishing/">Non-Phishing (100)</a></li>
  </ul>
</body>
</html>
"""
    (out_dir / "index.html").write_text(root_index, encoding="utf-8")

    # The CSV starts blank so later pretraining and post-training scripts can fill results.
    log_df = pd.DataFrame(records).sort_values(by=["actual_label", "email_id"], ascending=[False, True])
    log_df.to_csv(out_dir / "evaluation_log_template.csv", index=False)

    # Console output confirms what was generated for the tester.
    print(f"Saved pages to: {out_dir}")
    final_phishing_count = len(list(phishing_dir.glob("*.html"))) - 1
    final_non_phishing_count = len(list(non_phishing_dir.glob("*.html"))) - 1
    print(f"Phishing pages: {final_phishing_count}")
    print(f"Non-phishing pages: {final_non_phishing_count}")
    print(f"Log template: {out_dir / 'evaluation_log_template.csv'}")


if __name__ == "__main__":
    main()
