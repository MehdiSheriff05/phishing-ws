from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from .reputation import extract_domain


ARTIFACTS_DIR = Path(__file__).resolve().parents[1] / "artifacts"
FEEDBACK_DIR = ARTIFACTS_DIR / "feedback"
PREFERENCES_PATH = FEEDBACK_DIR / "user_preferences.json"
FEEDBACK_EVENTS_PATH = FEEDBACK_DIR / "feedback_events.jsonl"
TRAINING_FEEDBACK_PATH = FEEDBACK_DIR / "training_feedback.csv"


class FeedbackStore:
    def __init__(self) -> None:
        self._lock = Lock()
        FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
        self._ensure_files()

    def _ensure_files(self) -> None:
        if not PREFERENCES_PATH.exists():
            PREFERENCES_PATH.write_text(
                json.dumps({"allowlist": [], "blocklist": []}, indent=2),
                encoding="utf-8",
            )
        if not TRAINING_FEEDBACK_PATH.exists():
            with TRAINING_FEEDBACK_PATH.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["text", "label", "source", "timestamp"])
                writer.writeheader()
        FEEDBACK_EVENTS_PATH.touch(exist_ok=True)

    def _load_preferences(self) -> dict[str, set[str]]:
        try:
            data = json.loads(PREFERENCES_PATH.read_text(encoding="utf-8"))
        except Exception:
            data = {"allowlist": [], "blocklist": []}
        allowlist = {extract_domain(item) for item in data.get("allowlist", []) if item}
        blocklist = {extract_domain(item) for item in data.get("blocklist", []) if item}
        allowlist.discard("")
        blocklist.discard("")
        return {"allowlist": allowlist, "blocklist": blocklist}

    def _save_preferences(self, allowlist: set[str], blocklist: set[str]) -> None:
        payload = {"allowlist": sorted(allowlist), "blocklist": sorted(blocklist)}
        PREFERENCES_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def get_preferences(self) -> dict[str, list[str]]:
        with self._lock:
            prefs = self._load_preferences()
            return {"allowlist": sorted(prefs["allowlist"]), "blocklist": sorted(prefs["blocklist"])}

    def set_blocked(self, domain_or_url: str) -> str:
        domain = extract_domain(domain_or_url)
        if not domain:
            raise ValueError("Invalid domain/url for blocklist")
        with self._lock:
            prefs = self._load_preferences()
            prefs["blocklist"].add(domain)
            prefs["allowlist"].discard(domain)
            self._save_preferences(prefs["allowlist"], prefs["blocklist"])
        return domain

    def set_allowed(self, domain_or_url: str) -> str:
        domain = extract_domain(domain_or_url)
        if not domain:
            raise ValueError("Invalid domain/url for allowlist")
        with self._lock:
            prefs = self._load_preferences()
            prefs["allowlist"].add(domain)
            prefs["blocklist"].discard(domain)
            self._save_preferences(prefs["allowlist"], prefs["blocklist"])
        return domain

    def remove_blocked(self, domain_or_url: str) -> str:
        domain = extract_domain(domain_or_url)
        if not domain:
            raise ValueError("Invalid domain/url for unblock")
        with self._lock:
            prefs = self._load_preferences()
            prefs["blocklist"].discard(domain)
            self._save_preferences(prefs["allowlist"], prefs["blocklist"])
        return domain

    def remove_allowed(self, domain_or_url: str) -> str:
        domain = extract_domain(domain_or_url)
        if not domain:
            raise ValueError("Invalid domain/url for remove-allow")
        with self._lock:
            prefs = self._load_preferences()
            prefs["allowlist"].discard(domain)
            self._save_preferences(prefs["allowlist"], prefs["blocklist"])
        return domain

    def is_blocked(self, domain: str) -> bool:
        prefs = self._load_preferences()
        domain = extract_domain(domain)
        return self._matches(domain, prefs["blocklist"])

    def is_allowed(self, domain: str) -> bool:
        prefs = self._load_preferences()
        domain = extract_domain(domain)
        return self._matches(domain, prefs["allowlist"])

    @staticmethod
    def _matches(domain: str, domain_set: set[str]) -> bool:
        if not domain:
            return False
        if domain in domain_set:
            return True
        parts = domain.split(".")
        for idx in range(1, len(parts)):
            if ".".join(parts[idx:]) in domain_set:
                return True
        return False

    @staticmethod
    def _build_feedback_text(visible_text: str, links: list[dict[str, str]]) -> str:
        link_parts = [f"{item.get('text', '')} {item.get('href', '')}".strip() for item in links]
        return f"{visible_text.strip()} {' '.join(link_parts)}".strip()

    def record_feedback(
        self,
        visible_text: str,
        links: list[dict[str, str]],
        user_label: int,
        source: str = "extension",
    ) -> dict[str, object]:
        if user_label not in (0, 1):
            raise ValueError("user_label must be 0 or 1")

        full_text = self._build_feedback_text(visible_text, links)
        if not full_text:
            raise ValueError("Feedback requires visible text or links")

        timestamp = datetime.now(timezone.utc).isoformat()
        event = {
            "timestamp": timestamp,
            "label": user_label,
            "source": source,
            "visible_text": visible_text,
            "links": links,
        }

        with self._lock:
            with FEEDBACK_EVENTS_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=True) + "\n")

            with TRAINING_FEEDBACK_PATH.open("a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["text", "label", "source", "timestamp"])
                writer.writerow(
                    {
                        "text": full_text,
                        "label": int(user_label),
                        "source": source,
                        "timestamp": timestamp,
                    }
                )

        return {"saved": True, "label": user_label, "timestamp": timestamp}

    def stats(self) -> dict[str, object]:
        prefs = self.get_preferences()
        rows = 0
        with TRAINING_FEEDBACK_PATH.open("r", encoding="utf-8") as f:
            rows = max(0, sum(1 for _ in f) - 1)
        return {
            "allowlist_count": len(prefs["allowlist"]),
            "blocklist_count": len(prefs["blocklist"]),
            "feedback_examples": rows,
            "preferences_path": str(PREFERENCES_PATH),
            "training_feedback_path": str(TRAINING_FEEDBACK_PATH),
            "events_path": str(FEEDBACK_EVENTS_PATH),
        }
