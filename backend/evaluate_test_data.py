from __future__ import annotations

import argparse
import csv
import json
from html.parser import HTMLParser
from pathlib import Path
from urllib import error, request


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_DATA_DIR = PROJECT_ROOT / "test_data"
DEFAULT_EVALUATION_CSV = TEST_DATA_DIR / "evaluation_log_template.csv"


# These columns are filled by this script when it runs before and after model training.
RESULT_COLUMNS = (
    "pretraining_probability",
    "pretraining_label",
    "pretraining_description",
    "posttraining_probability",
    "posttraining_label",
    "posttraining_description",
)


class EmailPageParser(HTMLParser):
    # Collect visible text and links from generated HTML email pages for API testing.
    def __init__(self) -> None:
        super().__init__()
        self._ignore_depth = 0
        self._current_href: str | None = None
        self._text_chunks: list[str] = []
        self._link_chunks: list[dict[str, str]] = []
        self._link_text_parts: list[str] = []

    # Ignore non-email content such as scripts and begin recording link text when needed.
    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        # attrs_map lets the parser read href values from anchor tags.
        attrs_map = dict(attrs)
        if tag in {"script", "style", "noscript"}:
            self._ignore_depth += 1
            return
        if tag == "a":
            # Link text is collected between <a> and </a> so the backend sees anchor context.
            self._current_href = (attrs_map.get("href") or "").strip()
            self._link_text_parts = []

    # Finish a link record once the closing anchor tag is reached.
    def handle_endtag(self, tag: str) -> None:
        # Leaving script/style/noscript sections allows normal email text to be recorded again.
        if tag in {"script", "style", "noscript"} and self._ignore_depth > 0:
            self._ignore_depth -= 1
            return
        if tag == "a":
            # Each link record mirrors the format sent by the Chrome extension.
            href = (self._current_href or "").strip()
            text = " ".join(self._link_text_parts).strip()
            if href:
                self._link_chunks.append({"text": text[:300], "href": href})
            self._current_href = None
            self._link_text_parts = []

    # Store readable text chunks and duplicate link text into the current link record.
    def handle_data(self, data: str) -> None:
        # Ignored sections should not affect phishing predictions.
        if self._ignore_depth > 0:
            return
        clean = " ".join((data or "").split()).strip()
        if not clean:
            return
        # All visible text is collected, while link text is also attached to the current URL.
        self._text_chunks.append(clean)
        if self._current_href is not None:
            self._link_text_parts.append(clean)

    # Return the same payload shape used by the Chrome extension.
    def extract(self) -> dict[str, object]:
        # Limit text length to match the extension and keep API requests fast.
        visible_text = " ".join(self._text_chunks).strip()[:20000]
        return {"visible_text": visible_text, "links": self._link_chunks[:200]}


def build_description(label: str, flags: list[str]) -> str:
    # Descriptions give the CSV a readable reason for the predicted label.
    clean_flags = [str(flag).strip() for flag in flags if str(flag).strip()]
    if clean_flags:
        description = " | ".join(clean_flags[:3])[:500]
        return normalize_description(description)
    if label == "phishing":
        return "Marked phishing without specific flags returned."
    return "Marked legitimate with no warning flags."


def normalize_description(description: str) -> str:
    # Normalization makes CSV wording clearer for dissertation readers.
    replacements = [
        ("Model files not loaded; using simple rule score only.", "Pretraining heuristic-only scan; no trained model was used."),
        ("Risky words found:", "Heuristic keyword match:"),
        ("Money-transfer or inheritance language found", "Heuristic pattern match: money-transfer / inheritance wording"),
        ("Pressure language found", "Heuristic pattern match: urgency / pressure wording"),
        ("Advance-fee scam wording pattern found", "Heuristic pattern match: advance-fee scam wording"),
        ("Multiple contact email addresses found in message", "Heuristic pattern match: multiple contact email addresses in the message"),
    ]
    normalized = description
    for old, new in replacements:
        # Replacing backend phrases avoids implying ML was used during pretraining.
        normalized = normalized.replace(old, new)
    return normalized


def load_evaluation_rows(csv_path: Path) -> tuple[list[dict[str, str]], list[str]]:
    # The CSV is loaded as dictionaries so columns can be addressed by name.
    with csv_path.open("r", newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
        fieldnames = list(rows[0].keys()) if rows else []
    if not fieldnames:
        raise RuntimeError(f"Evaluation CSV is empty: {csv_path}")
    # Add result columns if the selected CSV is an older template.
    for column in RESULT_COLUMNS:
        if column not in fieldnames:
            fieldnames.append(column)
    for row in rows:
        for column in fieldnames:
            row.setdefault(column, "")
    return rows, fieldnames


def write_evaluation_rows(csv_path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> None:
    # Rewriting the whole file keeps the CSV simple and avoids partial-row corruption.
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def reset_evaluation_results(csv_path: Path) -> None:
    # Resetting clears old results so a fresh pre/post run uses the same template.
    rows, fieldnames = load_evaluation_rows(csv_path)
    for row in rows:
        for column in RESULT_COLUMNS:
            row[column] = ""
    write_evaluation_rows(csv_path, rows, fieldnames)


def log_prediction_to_csv(
    *,
    csv_path: Path,
    relative_path: str,
    phase: str,
    prediction: dict[str, object],
) -> None:
    # The relative path connects each API result back to the correct CSV row.
    rows, fieldnames = load_evaluation_rows(csv_path)
    row_by_path = {row.get("relative_path", ""): row for row in rows}
    if relative_path not in row_by_path:
        raise RuntimeError(f"No evaluation row found for {relative_path}")

    # The phase is either pretraining or posttraining based on /health model_loaded.
    row = row_by_path[relative_path]
    row[f"{phase}_probability"] = f"{float(prediction['probability_phishing']):.6f}"
    row[f"{phase}_label"] = str(prediction["label"])
    row[f"{phase}_description"] = build_description(
        str(prediction["label"]),
        list(prediction.get("flags", [])),
    )
    write_evaluation_rows(csv_path, rows, fieldnames)


def parse_email_page(path: Path) -> dict[str, object]:
    # HTML parsing lets evaluation test the same page files used by the browser extension.
    parser = EmailPageParser()
    parser.feed(path.read_text(encoding="utf-8"))
    return parser.extract()


def post_json(api_base_url: str, route: str, payload: dict[str, object]) -> dict[str, object]:
    # The standard library keeps this script lightweight with no extra HTTP dependency.
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        f"{api_base_url.rstrip('/')}{route}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        # Every email page is sent to /predict just like the extension would do.
        with request.urlopen(req, timeout=15) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{route} failed with HTTP {exc.code}: {details}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Could not reach backend at {api_base_url}: {exc.reason}") from exc


def get_json(api_base_url: str, route: str) -> dict[str, object]:
    # /health tells the script whether this run should fill pretraining or posttraining columns.
    req = request.Request(f"{api_base_url.rstrip('/')}{route}", method="GET")
    try:
        with request.urlopen(req, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{route} failed with HTTP {exc.code}: {details}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Could not reach backend at {api_base_url}: {exc.reason}") from exc


def iter_test_pages(root: Path) -> list[tuple[str, Path]]:
    # The test set is split into known phishing and known non-phishing folders.
    pages: list[tuple[str, Path]] = []
    for folder_name in ("phishing", "non_phishing"):
        folder = root / folder_name
        for path in sorted(folder.glob("*.html")):
            # Index pages are navigation helpers, not examples to evaluate.
            if path.name == "index.html":
                continue
            relative_path = path.relative_to(root).as_posix()
            pages.append((relative_path, path))
    return pages


def summarize(results: list[dict[str, object]]) -> dict[str, int]:
    # Summary counts make the console output easy to quote in the dissertation.
    summary = {
        "total": len(results),
        "correct": 0,
        "actual_phishing": 0,
        "actual_legitimate": 0,
        "predicted_phishing": 0,
        "predicted_legitimate": 0,
    }
    for item in results:
        # Actual labels come from folder names, while predicted labels come from the API.
        actual = int(item["actual_label"])
        predicted = str(item["predicted_label"])
        expected_label = "phishing" if actual == 1 else "legitimate"
        if actual == 1:
            summary["actual_phishing"] += 1
        else:
            summary["actual_legitimate"] += 1
        if predicted == "phishing":
            summary["predicted_phishing"] += 1
        else:
            summary["predicted_legitimate"] += 1
        if predicted == expected_label:
            summary["correct"] += 1
    return summary


def main() -> None:
    # CLI options let the same script evaluate any running backend and any compatible CSV.
    parser = argparse.ArgumentParser(description="Run API evaluation across all test_data email pages.")
    parser.add_argument("--api-base-url", default="http://127.0.0.1:8000", help="Backend API base URL.")
    parser.add_argument(
        "--test-data-dir",
        default=str(TEST_DATA_DIR),
        help="Directory containing phishing/ and non_phishing/ HTML test pages.",
    )
    parser.add_argument(
        "--evaluation-csv",
        default=str(DEFAULT_EVALUATION_CSV),
        help="CSV file to update with pretraining/posttraining results.",
    )
    parser.add_argument(
        "--reset-results",
        action="store_true",
        help="Clear existing pretraining/posttraining columns in the selected CSV before evaluating.",
    )
    args = parser.parse_args()

    api_base_url = args.api_base_url.strip().rstrip("/")
    test_data_dir = Path(args.test_data_dir).expanduser().resolve()
    evaluation_csv = Path(args.evaluation_csv).expanduser().resolve()
    pages = iter_test_pages(test_data_dir)
    if not pages:
        raise SystemExit(f"No HTML test pages found under {test_data_dir}")
    # Reset is normally used before the pretraining pass.
    if args.reset_results:
        reset_evaluation_results(evaluation_csv)

    # The backend declares whether model artifacts are loaded.
    health = get_json(api_base_url, "/health")
    phase = "posttraining" if bool(health.get("model_loaded")) else "pretraining"
    print(f"Connected to {api_base_url} | phase={phase} | pages={len(pages)} | csv={evaluation_csv}")

    results: list[dict[str, object]] = []

    for relative_path, path in pages:
        # The directory name is the ground-truth label for this test page.
        actual_label = 1 if relative_path.startswith("phishing/") else 0
        payload = parse_email_page(path)
        prediction = post_json(api_base_url, "/predict", payload)
        # Each prediction is written immediately so partial runs still preserve progress.
        log_prediction_to_csv(
            csv_path=evaluation_csv,
            relative_path=relative_path,
            phase=phase,
            prediction=prediction,
        )

        # Store a compact in-memory result for accuracy calculation after the loop.
        results.append(
            {
                "relative_path": relative_path,
                "actual_label": actual_label,
                "predicted_label": prediction["label"],
                "probability_phishing": prediction["probability_phishing"],
            }
        )
        print(
            f"{relative_path}: actual={actual_label} "
            f"predicted={prediction['label']} p={float(prediction['probability_phishing']):.4f}"
        )

    # Final summary gives the key metrics without requiring spreadsheet formulas.
    summary = summarize(results)
    accuracy = summary["correct"] / summary["total"] if summary["total"] else 0.0
    print("")
    print("Summary")
    print(f"Total pages: {summary['total']}")
    print(f"Correct predictions: {summary['correct']}")
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Actual phishing: {summary['actual_phishing']}")
    print(f"Actual legitimate: {summary['actual_legitimate']}")
    print(f"Predicted phishing: {summary['predicted_phishing']}")
    print(f"Predicted legitimate: {summary['predicted_legitimate']}")
    print(f"CSV updated: {evaluation_csv}")


if __name__ == "__main__":
    main()
