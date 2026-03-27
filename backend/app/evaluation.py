from __future__ import annotations

import csv
from pathlib import Path
from threading import Lock


PROJECT_ROOT = Path(__file__).resolve().parents[2]
TEST_DATA_DIR = PROJECT_ROOT / "test_data"
EVALUATION_LOG_PATH = TEST_DATA_DIR / "evaluation_log_template.csv"


class EvaluationLogStore:
    REQUIRED_FIELDS = [
        "email_id",
        "relative_path",
        "actual_label",
        "pretraining_probability",
        "posttraining_probability",
        "pretraining_label",
        "posttraining_label",
        "pretraining_description",
        "posttraining_description",
        "notes",
    ]

    def __init__(self) -> None:
        self._lock = Lock()

    def log_prediction(
        self,
        *,
        relative_path: str,
        label: str,
        probability_phishing: float,
        flags: list[str],
        model_loaded: bool,
    ) -> dict[str, object]:
        csv_path = EVALUATION_LOG_PATH
        if not csv_path.exists():
            raise FileNotFoundError(f"Evaluation CSV not found: {csv_path}")

        normalized_path = self._normalize_relative_path(relative_path)
        phase_prefix = "posttraining" if model_loaded else "pretraining"

        with self._lock:
            with csv_path.open("r", newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
                fieldnames = list(rows[0].keys()) if rows else []

            if not fieldnames:
                raise ValueError("Evaluation CSV is empty or missing headers")

            fieldnames = self._ensure_required_fields(fieldnames)
            for row in rows:
                for fieldname in fieldnames:
                    row.setdefault(fieldname, "")

            updated = False
            for row in rows:
                row_path = self._normalize_relative_path(row.get("relative_path", ""))
                if row_path != normalized_path:
                    continue
                row[f"{phase_prefix}_probability"] = f"{float(probability_phishing):.6f}"
                row[f"{phase_prefix}_label"] = label
                row[f"{phase_prefix}_description"] = self._build_description(label, flags)
                updated = True
                break

            if not updated:
                raise ValueError(f"No evaluation row found for relative_path={normalized_path}")

            with csv_path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(rows)

        return {
            "saved": True,
            "phase": phase_prefix,
            "relative_path": normalized_path,
            "csv_path": str(csv_path),
        }

    @staticmethod
    def _build_description(label: str, flags: list[str]) -> str:
        clean_flags = [str(flag).strip() for flag in flags if str(flag).strip()]
        if clean_flags:
            return " | ".join(clean_flags[:3])[:500]
        if label == "phishing":
            return "Flagged as phishing without specific flags returned."
        return "Marked legitimate with no warning flags."

    @classmethod
    def _ensure_required_fields(cls, fieldnames: list[str]) -> list[str]:
        merged = list(fieldnames)
        for required in cls.REQUIRED_FIELDS:
            if required not in merged:
                merged.append(required)
        return merged

    @staticmethod
    def _normalize_relative_path(relative_path: str) -> str:
        normalized = str(relative_path or "").strip().replace("\\", "/").lstrip("./")
        if not normalized:
            raise ValueError("relative_path is required")
        return normalized
