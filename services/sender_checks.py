import re
from typing import Dict, List, Optional


TRUSTED_BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "bank": None,
}


FREE_EMAIL_DOMAINS = {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "proton.me"}


def _extract_domain(email: str) -> str:
    if "@" not in email:
        return ""
    return email.split("@")[-1].lower().strip()


def analyze_sender(sender_email: str, sender_name: Optional[str]) -> Dict:
    reasons: List[str] = []
    score = 0.0

    domain = _extract_domain(sender_email)
    if not domain:
        return {"score": 100.0, "reasons": ["Invalid sender email format"], "domain": ""}

    if re.search(r"\d{3,}", domain):
        score += 8
        reasons.append("Sender domain contains unusual numeric pattern")

    if domain in FREE_EMAIL_DOMAINS:
        score += 6
        reasons.append("Sender uses a free email provider")

    if sender_name:
        lower_name = sender_name.lower()
        for brand, expected_domain in TRUSTED_BRANDS.items():
            if brand in lower_name and expected_domain and expected_domain not in domain:
                score += 25
                reasons.append(
                    f"Sender name references {brand.title()} but email domain is {domain}"
                )

    normalized = min(100.0, score)
    return {
        "score": round(normalized, 2),
        "reasons": reasons,
        "domain": domain,
    }
