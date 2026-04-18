from __future__ import annotations

import html
import re
import unicodedata

from .reputation import DomainReputationService, extract_domain

# These words are suspicious in phishing contexts, but the code still checks patterns around them.
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

# Money scam terms help detect inheritance, beneficiary, and transfer-style phishing emails.
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

# Pressure terms capture urgency wording, which is common in phishing social engineering.
PRESSURE_TERMS = {
    "urgent",
    "immediately",
    "without delay",
    "act now",
    "timely response",
    "confidential",
}

# These phrases are common in advance-fee scam emails and are stronger when money terms also appear.
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

# Legacy footer markers catch old spam/phishing samples that include known suspicious email footers.
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


# Normalize email text before rule checks so the rules compare consistent lowercase text.
def _normalize_text(value: str) -> str:
    decoded = html.unescape(value or "")
    lowered = decoded.lower()
    # Remove accents so "novità" and "novita" match the same rule.
    no_accents = "".join(
        ch for ch in unicodedata.normalize("NFKD", lowered) if not unicodedata.combining(ch)
    )
    return " ".join(no_accents.split())


# Match keywords as complete words or phrases so short terms do not fire inside unrelated words.
def _contains_keyword(text: str, keyword: str) -> bool:
    # Phrases can be searched directly because spaces make accidental matches unlikely.
    if " " in keyword:
        return keyword in text
    # Single words use word boundaries so "bank" does not match "embankment".
    return bool(re.search(rf"\b{re.escape(keyword)}\b", text))


# Collect phishing keywords conservatively so a single generic word does not over-explain a safe page.
def _find_risky_keywords(text: str) -> list[str]:
    # Sort the matches so the same email produces stable, repeatable explanations.
    found = sorted([kw for kw in PHISHING_KEYWORDS if _contains_keyword(text, kw)])
    generic_terms = {"bank", "security", "confirm", "transaction"}
    # A single generic business word is not enough evidence to call an email suspicious.
    if len(found) == 1 and found[0] in generic_terms:
        return []
    return found


# Run the human-readable heuristic checks that support both pretraining and trained predictions.
def detect_flags(
    visible_text: str,
    links: list[dict[str, str]],
    reputation_service: DomainReputationService,
) -> list[str]:
    flags: list[str] = []
    text_lower = _normalize_text(visible_text)

    # Keyword flags explain suspicious wording, but are not enough by themselves to prove phishing.
    found_keywords = _find_risky_keywords(text_lower)
    if found_keywords:
        flags.append(f"Risky words found: {', '.join(found_keywords[:5])}")

    # Multiple money terms together are stronger evidence than one isolated financial word.
    money_hits = sum(1 for term in MONEY_SCAM_TERMS if term in text_lower)
    if money_hits >= 2:
        flags.append("Money-transfer or inheritance language found")

    # Pressure wording matters most when multiple urgency terms appear together.
    pressure_hits = sum(1 for term in PRESSURE_TERMS if term in text_lower)
    if pressure_hits >= 2:
        flags.append("Pressure language found")

    # Advance-fee wording must appear with money language to avoid flagging harmless formal emails.
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
    # One large money claim is enough to explain why the message deserves attention.
    if amount_hits >= 1:
        flags.append("Large money amount claim found")

    # Scam messages often include explicit split percentages.
    if re.search(r"\\b\\d{1,2}%\\s+for\\s+(me|you|us)\\b", text_lower):
        flags.append("Profit sharing percentage pattern found")

    # Known legacy footers give explainable evidence for older dataset examples.
    if any(marker in text_lower for marker in LEGACY_FOOTER_MARKERS):
        flags.append("Known suspicious legacy footer marker found")

    # Common pattern in scam emails: asks to reply to multiple external addresses.
    email_hits = re.findall(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}", text_lower)
    unique_emails = sorted(set(email_hits))
    # Multiple contact addresses can indicate the sender is steering replies outside normal systems.
    if len(unique_emails) >= 2:
        flags.append("Multiple contact email addresses found in message")

    if "send your responses to" in text_lower or "reply to" in text_lower:
        flags.append("Message asks for direct reply to external email address")

    # Large link counts are noisy but still useful as one weak warning signal.
    if len(links) > 20:
        flags.append("High number of links found in message")

    for link in links:
        # Link evidence is checked separately because phishing often hides danger in URLs.
        href = (link.get("href") or "").strip()
        anchor_text = (link.get("text") or "").strip()
        if not href:
            continue

        # Link checks use the normalized domain so trusted domains avoid noisy link warnings.
        domain = extract_domain(href)
        if "@" in href:
            flags.append("Link contains '@' symbol in URL")

        # Non-trusted HTTP links are flagged because credentials should not be sent over plain HTTP.
        if href.startswith("http://") and domain and not reputation_service.is_trusted_domain(domain):
            flags.append("At least one link uses insecure HTTP")

        if any(t in anchor_text.lower() for t in ["click here", "verify", "login"]):
            # Suspicious call-to-action text matters more when it points to an untrusted domain.
            if domain and not reputation_service.is_trusted_domain(domain):
                flags.append(f"Action link goes to untrusted site: {domain}")

        if len(domain) > 40 or domain.count("-") >= 3:
            flags.append(f"Domain looks unusual: {domain}")

    # Reputation service adds local flagged-domain and optional Safe Browsing evidence.
    flags.extend(reputation_service.flags_for_links(links))

    # Deduplicate while preserving order
    deduped = list(dict.fromkeys(flags))
    return deduped[:10]
