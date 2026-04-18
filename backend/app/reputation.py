from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen


# Reputation files provide local allow/flag lists that work even without internet access.
ARTIFACTS_DIR = Path(__file__).resolve().parents[1] / "artifacts"
REPUTATION_DIR = ARTIFACTS_DIR / "reputation"
TRUSTED_DOMAINS_PATH = REPUTATION_DIR / "trusted_domains.txt"
FLAGGED_DOMAINS_PATH = REPUTATION_DIR / "flagged_domains.txt"

# These defaults prevent common trusted domains from being over-flagged during demos.
DEFAULT_TRUSTED_DOMAINS = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "paypal.com",
}


# Normalize a URL or plain domain into the hostname used for reputation matching.
def extract_domain(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.netloc:
        return parsed.netloc.lower().replace("www.", "")
    # Allow plain domains without http/https.
    return parsed.path.lower().replace("www.", "").split("/")[0]


# DomainReputationService combines local files and optional Google Safe Browsing checks.
class DomainReputationService:
    def __init__(self) -> None:
        # The Google API key is optional; without it the app still uses local reputation files.
        self.safe_browsing_api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
        self.trusted_domains: set[str] = set()
        self.flagged_domains: set[str] = set()
        self.reload_lists()

    def reload_lists(self) -> None:
        # Reloading lets a presenter update reputation files without restarting FastAPI.
        REPUTATION_DIR.mkdir(parents=True, exist_ok=True)

        self.trusted_domains = self._load_domain_file(TRUSTED_DOMAINS_PATH) or set(
            DEFAULT_TRUSTED_DOMAINS
        )
        # Flagged domains are optional, so an empty file simply means no local block signals.
        self.flagged_domains = self._load_domain_file(FLAGGED_DOMAINS_PATH)

    @staticmethod
    def _load_domain_file(path: Path) -> set[str]:
        # Missing files are treated as empty lists to keep first-run setup simple.
        if not path.exists():
            return set()
        domains: set[str] = set()
        # Each line can be a bare domain or URL; comments and blank lines are ignored.
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip().lower()
            if not line or line.startswith("#"):
                continue
            domain = extract_domain(line)
            if domain:
                domains.add(domain)
        return domains

    @staticmethod
    def _domain_matches(domain: str, domain_set: set[str]) -> bool:
        # Exact matches catch example.com and parent checks catch login.example.com.
        if domain in domain_set:
            return True
        # Also match subdomains.
        parts = domain.split(".")
        for idx in range(1, len(parts)):
            candidate = ".".join(parts[idx:])
            if candidate in domain_set:
                return True
        return False

    def is_trusted_domain(self, domain: str) -> bool:
        # Trusted domains reduce noisy link warnings in heuristic detection.
        return self._domain_matches(domain, self.trusted_domains)

    def is_flagged_domain(self, domain: str) -> bool:
        # Flagged domains create strong warning evidence during prediction.
        return self._domain_matches(domain, self.flagged_domains)

    def _query_google_safe_browsing(self, url: str) -> bool:
        # External reputation is optional so the project can still run locally without credentials.
        if not self.safe_browsing_api_key:
            return False

        # The request follows Google Safe Browsing's threatMatches format.
        request_payload = {
            "client": {"clientId": "undergrad-phishing-detector", "clientVersion": "1.0.0"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        endpoint = (
            "https://safebrowsing.googleapis.com/v4/threatMatches:find"
            f"?key={self.safe_browsing_api_key}"
        )
        body = json.dumps(request_payload).encode("utf-8")
        req = Request(endpoint, data=body, headers={"Content-Type": "application/json"}, method="POST")

        try:
            # A response with matches means Google considers the URL suspicious.
            with urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode("utf-8") or "{}")
                return bool(data.get("matches"))
        except Exception:
            # If API call fails, keep app running.
            return False

    def check_url(self, url: str) -> dict[str, object]:
        # This method produces the human-readable reputation result used by flags and API routes.
        domain = extract_domain(url)
        if not domain:
            return {
                "url": url,
                "domain": "",
                "is_trusted": False,
                "is_flagged": False,
                "risk": "unknown",
                "sources": [],
            }

        # Sources explain why the system trusted or flagged the domain.
        sources: list[str] = []
        is_trusted = self.is_trusted_domain(domain)
        is_flagged = self.is_flagged_domain(domain)

        if is_trusted:
            sources.append("trusted_local")
        if is_flagged:
            sources.append("flagged_local")

        if self.safe_browsing_api_key and self._query_google_safe_browsing(url):
            is_flagged = True
            sources.append("google_safe_browsing")

        # Risk levels keep the output simple for popup display and dissertation screenshots.
        if is_flagged:
            risk = "high"
        elif is_trusted:
            risk = "low"
        else:
            risk = "unknown"

        return {
            "url": url,
            "domain": domain,
            "is_trusted": is_trusted,
            "is_flagged": is_flagged,
            "risk": risk,
            "sources": sources,
        }

    def check_urls(self, urls: list[str]) -> list[dict[str, object]]:
        # Batch checking lets one email scan evaluate every link it contains.
        return [self.check_url(url) for url in urls]

    def flags_for_links(self, links: list[dict[str, str]]) -> list[str]:
        # Convert reputation results into explanation flags shown to the user.
        flags: list[str] = []
        seen_flagged_domains: set[str] = set()

        for link in links:
            # Empty href values are ignored because they cannot be reputation checked.
            href = (link.get("href") or "").strip()
            if not href:
                continue
            result = self.check_url(href)
            domain = str(result["domain"])

            # Only report each bad domain once to avoid cluttering the popup.
            if result["is_flagged"] and domain not in seen_flagged_domains:
                seen_flagged_domains.add(domain)
                source_text = ", ".join(result["sources"]) or "domain_check"
                flags.append(f"Known bad domain: {domain} ({source_text})")

            # The @ symbol in URLs can hide the true destination from users.
            if not result["is_trusted"] and "@" in href:
                flags.append("Link contains '@' symbol in URL")

            # HTTP links are weaker evidence unless the domain is already trusted.
            if not result["is_trusted"] and href.startswith("http://"):
                flags.append("At least one non-trusted link uses insecure HTTP")

        # Preserve order while removing duplicates so explanations stay concise.
        return list(dict.fromkeys(flags))[:10]

    def status(self) -> dict[str, object]:
        # Status helps demos show whether local lists and Safe Browsing are active.
        return {
            "trusted_domains_count": len(self.trusted_domains),
            "flagged_domains_count": len(self.flagged_domains),
            "safe_browsing_enabled": bool(self.safe_browsing_api_key),
            "trusted_domains_path": str(TRUSTED_DOMAINS_PATH),
            "flagged_domains_path": str(FLAGGED_DOMAINS_PATH),
        }
