import csv
import random
from pathlib import Path

RANDOM_SEED = 42
PHISH_SAMPLE_SIZE = 2000
BENIGN_SAMPLE_SIZE = 2000

RAW_PHISH = Path("data/raw/phishing_links_active.txt")
OUT_DATASET = Path("data/processed/github_url_testset.csv")
OUT_EVAL_TEMPLATE = Path("data/processed/github_eval_template.csv")

SAFE_DOMAINS = [
    "google.com",
    "youtube.com",
    "wikipedia.org",
    "github.com",
    "python.org",
    "apple.com",
    "microsoft.com",
    "amazon.com",
    "nytimes.com",
    "cnn.com",
    "openai.com",
    "mozilla.org",
    "stackoverflow.com",
    "cloudflare.com",
    "linkedin.com",
    "reddit.com",
    "bbc.com",
    "mit.edu",
    "stanford.edu",
    "who.int",
]
SAFE_PATHS = [
    "",
    "/",
    "/about",
    "/help",
    "/docs",
    "/blog",
    "/privacy",
    "/security",
    "/products",
    "/contact",
]


def normalize_url(line: str) -> str:
    return line.strip()


def build_benign_urls(n: int) -> list[str]:
    urls: list[str] = []
    idx = 0
    while len(urls) < n:
        domain = SAFE_DOMAINS[idx % len(SAFE_DOMAINS)]
        path = SAFE_PATHS[(idx // len(SAFE_DOMAINS)) % len(SAFE_PATHS)]
        proto = "https" if idx % 5 else "http"
        urls.append(f"{proto}://www.{domain}{path}")
        idx += 1
    return urls


def main() -> None:
    if not RAW_PHISH.exists():
        raise FileNotFoundError(f"Missing raw phishing dataset: {RAW_PHISH}")

    random.seed(RANDOM_SEED)

    phishing_urls = []
    with RAW_PHISH.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            url = normalize_url(line)
            if not url:
                continue
            phishing_urls.append(url)

    phishing_urls = sorted(set(phishing_urls))
    random.shuffle(phishing_urls)
    phishing_sample = phishing_urls[:PHISH_SAMPLE_SIZE]

    benign_sample = build_benign_urls(BENIGN_SAMPLE_SIZE)

    rows = [(u, 1) for u in phishing_sample] + [(u, 0) for u in benign_sample]
    random.shuffle(rows)

    OUT_DATASET.parent.mkdir(parents=True, exist_ok=True)
    with OUT_DATASET.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "y_true"])
        writer.writerows(rows)

    with OUT_EVAL_TEMPLATE.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "y_true", "y_pred"])
        for url, y_true in rows:
            writer.writerow([url, y_true, ""])  # Fill y_pred after running your model/rules.

    print(f"Wrote {OUT_DATASET} with {len(rows)} rows")
    print(f"Wrote {OUT_EVAL_TEMPLATE} template for evaluation")


if __name__ == "__main__":
    main()
