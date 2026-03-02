from __future__ import annotations

from .reputation import DomainReputationService, extract_domain

PHISHING_KEYWORDS = {
    "verify",
    "urgent",
    "suspend",
    "suspended",
    "password",
    "login",
    "bank",
    "security",
    "confirm",
    "reset",
    "winner",
    "prize",
}

def detect_flags(
    visible_text: str,
    links: list[dict[str, str]],
    reputation_service: DomainReputationService,
) -> list[str]:
    flags: list[str] = []
    text_lower = visible_text.lower()

    found_keywords = sorted([kw for kw in PHISHING_KEYWORDS if kw in text_lower])
    if found_keywords:
        flags.append(f"Risky words found: {', '.join(found_keywords[:5])}")

    if len(links) > 20:
        flags.append("High number of links found in message")

    for link in links:
        href = (link.get("href") or "").strip()
        anchor_text = (link.get("text") or "").strip()
        if not href:
            continue

        domain = extract_domain(href)
        if "@" in href:
            flags.append("Link contains '@' symbol in URL")

        if href.startswith("http://"):
            flags.append("At least one link uses insecure HTTP")

        if any(t in anchor_text.lower() for t in ["click here", "verify", "login"]):
            if domain and not reputation_service.is_trusted_domain(domain):
                flags.append(f"Action link goes to untrusted site: {domain}")

        if len(domain) > 40 or domain.count("-") >= 3:
            flags.append(f"Domain looks unusual: {domain}")

    flags.extend(reputation_service.flags_for_links(links))

    # Deduplicate while preserving order
    deduped = list(dict.fromkeys(flags))
    return deduped[:10]
