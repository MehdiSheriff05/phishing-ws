from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from .reputation import extract_domain


# Feedback data is stored locally under artifacts so it is separate from source code.
ARTIFACTS_DIR = Path(__file__).resolve().parents[1] / "artifacts"
FEEDBACK_DIR = ARTIFACTS_DIR / "feedback"
PREFERENCES_PATH = FEEDBACK_DIR / "user_preferences.json"
FEEDBACK_EVENTS_PATH = FEEDBACK_DIR / "feedback_events.jsonl"
TRAINING_FEEDBACK_PATH = FEEDBACK_DIR / "training_feedback.csv"


# FeedbackStore owns allowlist/blocklist state and optional user-labelled training examples.
class FeedbackStore:
    def __init__(self) -> None:
        # A lock prevents preference files from being read while another request writes them.
        self._lock = Lock()
        FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
        self._ensure_files()

    def _ensure_files(self) -> None:
        # The preferences file starts empty so the app behaves normally on first run.
        if not PREFERENCES_PATH.exists():
            PREFERENCES_PATH.write_text(
                json.dumps({"allowlist": [], "blocklist": []}, indent=2),
                encoding="utf-8",
            )
        # The feedback CSV is kept for future retraining, even though report buttons were removed.
        if not TRAINING_FEEDBACK_PATH.exists():
            with TRAINING_FEEDBACK_PATH.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["text", "label", "source", "timestamp"])
                writer.writeheader()
        # JSONL events are append-only, which makes feedback history easy to inspect later.
        FEEDBACK_EVENTS_PATH.touch(exist_ok=True)

    def _load_preferences(self) -> dict[str, set[str]]:
        # If the JSON is damaged, recover with empty lists rather than crashing the API.
        try:
            data = json.loads(PREFERENCES_PATH.read_text(encoding="utf-8"))
        except Exception:
            data = {"allowlist": [], "blocklist": []}
        # Domains are normalized so "https://www.example.com/path" becomes "example.com".
        allowlist = {extract_domain(item) for item in data.get("allowlist", []) if item}
        blocklist = {extract_domain(item) for item in data.get("blocklist", []) if item}
        allowlist.discard("")
        blocklist.discard("")
        return {"allowlist": allowlist, "blocklist": blocklist}

    def _save_preferences(self, allowlist: set[str], blocklist: set[str]) -> None:
        # Sorting the lists keeps diffs stable and makes the JSON easier to read.
        payload = {"allowlist": sorted(allowlist), "blocklist": sorted(blocklist)}
        PREFERENCES_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def get_preferences(self) -> dict[str, list[str]]:
        # Public responses use lists because JSON does not have a set type.
        with self._lock:
            prefs = self._load_preferences()
            return {"allowlist": sorted(prefs["allowlist"]), "blocklist": sorted(prefs["blocklist"])}

    def set_blocked(self, domain_or_url: str) -> str:
        # Blocking a domain means the backend will force a warning if that domain appears.
        domain = extract_domain(domain_or_url)
        if not domain:
            raise ValueError("Invalid domain/url for blocklist")
        with self._lock:
            prefs = self._load_preferences()
            # A domain cannot be both trusted and blocked, so remove it from allowlist.
            prefs["blocklist"].add(domain)
            prefs["allowlist"].discard(domain)
            self._save_preferences(prefs["allowlist"], prefs["blocklist"])
        return domain

    def set_allowed(self, domain_or_url: str) -> str:
        # Allowlisting reduces risk only when the content does not still look dangerous.
        domain = extract_domain(domain_or_url)
        if not domain:
            raise ValueError("Invalid domain/url for allowlist")
        with self._lock:
            prefs = self._load_preferences()
            # A domain cannot be both allowed and blocked at the same time.
            prefs["allowlist"].add(domain)
            prefs["blocklist"].discard(domain)
            self._save_preferences(prefs["allowlist"], prefs["blocklist"])
        return domain

    def remove_blocked(self, domain_or_url: str) -> str:
        # Removing from blocklist returns the domain to the normal ML and heuristic path.
        domain = extract_domain(domain_or_url)
        if not domain:
            raise ValueError("Invalid domain/url for unblock")
        with self._lock:
            prefs = self._load_preferences()
            prefs["blocklist"].discard(domain)
            self._save_preferences(prefs["allowlist"], prefs["blocklist"])
        return domain

    def remove_allowed(self, domain_or_url: str) -> str:
        # Removing from allowlist prevents clean-page trust from being forced for the domain.
        domain = extract_domain(domain_or_url)
        if not domain:
            raise ValueError("Invalid domain/url for remove-allow")
        with self._lock:
            prefs = self._load_preferences()
            prefs["allowlist"].discard(domain)
            self._save_preferences(prefs["allowlist"], prefs["blocklist"])
        return domain

    def is_blocked(self, domain: str) -> bool:
        # This helper is called during prediction for every link domain on the page.
        prefs = self._load_preferences()
        domain = extract_domain(domain)
        return self._matches(domain, prefs["blocklist"])

    def is_allowed(self, domain: str) -> bool:
        # Allowlist checks also support subdomains through the shared _matches helper.
        prefs = self._load_preferences()
        domain = extract_domain(domain)
        return self._matches(domain, prefs["allowlist"])

    @staticmethod
    def _matches(domain: str, domain_set: set[str]) -> bool:
        # Match exact domains first, then check parent domains such as mail.google.com -> google.com.
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
        # Training examples combine visible body text with link labels and URLs.
        link_parts = [f"{item.get('text', '')} {item.get('href', '')}".strip() for item in links]
        return f"{visible_text.strip()} {' '.join(link_parts)}".strip()

    def record_feedback(
        self,
        visible_text: str,
        links: list[dict[str, str]],
        user_label: int,
        source: str = "extension",
    ) -> dict[str, object]:
        # User labels must stay binary so future training can reuse the CSV directly.
        if user_label not in (0, 1):
            raise ValueError("user_label must be 0 or 1")

        # Empty feedback would train the model on noise, so require real text or links.
        full_text = self._build_feedback_text(visible_text, links)
        if not full_text:
            raise ValueError("Feedback requires visible text or links")

        # UTC timestamps make feedback records comparable across machines and time zones.
        timestamp = datetime.now(timezone.utc).isoformat()
        event = {
            "timestamp": timestamp,
            "label": user_label,
            "source": source,
            "visible_text": visible_text,
            "links": links,
        }

        with self._lock:
            # JSONL preserves the full event for audit/debugging.
            with FEEDBACK_EVENTS_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=True) + "\n")

            # CSV keeps only the compact fields needed for optional future retraining.
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
        # Stats are useful in demos to prove where user preferences and feedback are stored.
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
