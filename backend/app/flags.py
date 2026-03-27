from __future__ import annotations

import html
import re
import unicodedata

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
    "beneficiary",
    "inheritance",
    "transaction",
    "transfer",
    "fund",
    "investment",
    "royalties",
    "next of kin",
    "confidential",
    "assist",
    "lottery",
    "million",
    "usd",
    "bank details",
    "wire",
}

MONEY_SCAM_TERMS = {
    "million",
    "usd",
    "fund",
    "transfer",
    "beneficiary",
    "inheritance",
    "royalties",
    "investment",
}

PRESSURE_TERMS = {
    "urgent",
    "immediately",
    "without delay",
    "act now",
    "timely response",
    "confidential",
}

ADVANCE_FEE_MARKERS = {
    "dear sir",
    "dear madam",
    "dear friend",
    "next of kin",
    "beneficiary",
    "attorney",
    "confidential",
    "business proposition",
    "foreigner",
    "transfer the fund",
    "share in the ratio",
}

LEGACY_FOOTER_MARKERS = {
    "community di yahoo mail",
    "trucchi, novita, consigli",
    "la tua opinione",
    "dearriba me paga por navegar",
    "vos tambien podes ganar",
    "gana $$$ navegando",
    "entra a www.dearriba.com",
    "check-out go.com",
    "go get your free go e-mail account",
    "mail.go.com",
}


def _normalize_text(value: str) -> str:
    decoded = html.unescape(value or "")
    lowered = decoded.lower()
    # Remove accents so "novità" and "novita" match the same rule.
    no_accents = "".join(
        ch for ch in unicodedata.normalize("NFKD", lowered) if not unicodedata.combining(ch)
    )
    return " ".join(no_accents.split())


def detect_flags(
    visible_text: str,
    links: list[dict[str, str]],
    reputation_service: DomainReputationService,
) -> list[str]:
    flags: list[str] = []
    text_lower = _normalize_text(visible_text)

    found_keywords = sorted([kw for kw in PHISHING_KEYWORDS if kw in text_lower])
    if found_keywords:
        flags.append(f"Risky words found: {', '.join(found_keywords[:5])}")

    money_hits = sum(1 for term in MONEY_SCAM_TERMS if term in text_lower)
    if money_hits >= 2:
        flags.append("Money-transfer or inheritance language found")

    pressure_hits = sum(1 for term in PRESSURE_TERMS if term in text_lower)
    if pressure_hits >= 2:
        flags.append("Pressure language found")

    advance_fee_hits = sum(1 for term in ADVANCE_FEE_MARKERS if term in text_lower)
    if advance_fee_hits >= 2 and money_hits >= 1:
        flags.append("Advance-fee scam wording pattern found")

    # Spot large amount claims common in scam pitches.
    money_amount_patterns = [
        r"(usd|us\\$|\\$)\\s?\\d{1,3}(?:,\\d{3})+",
        r"\\b\\d+(?:\\.\\d+)?\\s+(million|billion)\\b",
    ]
    amount_hits = 0
    for pattern in money_amount_patterns:
        amount_hits += len(re.findall(pattern, text_lower))
    if amount_hits >= 1:
        flags.append("Large money amount claim found")

    # Scam messages often include explicit split percentages.
    if re.search(r"\\b\\d{1,2}%\\s+for\\s+(me|you|us)\\b", text_lower):
        flags.append("Profit sharing percentage pattern found")

    if any(marker in text_lower for marker in LEGACY_FOOTER_MARKERS):
        flags.append("Known suspicious legacy footer marker found")

    # Common pattern in scam emails: asks to reply to multiple external addresses.
    email_hits = re.findall(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", text_lower)
    unique_emails = sorted(set(email_hits))
    if len(unique_emails) >= 2:
        flags.append("Multiple contact email addresses found in message")

    if "send your responses to" in text_lower or "reply to" in text_lower:
        flags.append("Message asks for direct reply to external email address")

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
