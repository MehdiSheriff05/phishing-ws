import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.url_checks import analyze_urls

IN_PATH = Path("data/processed/github_url_testset.csv")
OUT_PATH = Path("data/processed/github_eval_predictions.csv")
THRESHOLD = 40.0


def main() -> None:
    if not IN_PATH.exists():
        raise FileNotFoundError(f"Missing input: {IN_PATH}")

    rows = []
    with IN_PATH.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row["url"]
            y_true = int(row["y_true"])
            score = analyze_urls([url])["score"]
            y_pred = 1 if score >= THRESHOLD else 0
            rows.append((url, y_true, y_pred, score))

    with OUT_PATH.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "y_true", "y_pred", "url_score"])
        writer.writerows(rows)

    print(f"Wrote {OUT_PATH} with {len(rows)} rows")


if __name__ == "__main__":
    main()
