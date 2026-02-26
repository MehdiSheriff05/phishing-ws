import ipaddress
import os
import re
from functools import lru_cache
from typing import Dict, List
from urllib.parse import urlparse


SUSPICIOUS_KEYWORDS = {
    "verify",
    "urgent",
    "login",
    "reset",
    "invoice",
    "password",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd"}
UNCOMMON_TLDS = {"top", "xyz", "click", "work", "gq", "ml", "cf", "tk", "zip"}
DEFAULT_MALICIOUS_DOMAINS = {
    "example-phish.com",
    "secure-login-alert.net",
    "account-verify-now.top",
}
DEFAULT_MALICIOUS_IPS = {"45.10.120.7", "185.234.218.12", "91.219.236.221"}


def _looks_like_ip(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _iter_parent_domains(hostname: str):
    parts = hostname.split(".")
    if len(parts) < 2:
        return
    for index in range(len(parts) - 1):
        yield ".".join(parts[index:])


def _parse_feed_values(raw: str) -> set:
    if not raw:
        return set()
    return {item.strip().lower() for item in re.split(r"[,\s]+", raw) if item.strip()}


@lru_cache(maxsize=1)
def _load_reputation_feeds():
    domain_feed = _parse_feed_values(os.getenv("PHISH_DOMAIN_REPUTATION_FEED", ""))
    ip_feed = _parse_feed_values(os.getenv("PHISH_IP_REPUTATION_FEED", ""))

    if not domain_feed:
        domain_feed = DEFAULT_MALICIOUS_DOMAINS.copy()
    if not ip_feed:
        ip_feed = DEFAULT_MALICIOUS_IPS.copy()
    return domain_feed, ip_feed


def analyze_urls(urls: List[str]) -> Dict:
    malicious_domains, malicious_ips = _load_reputation_feeds()
    reasons: List[str] = []
    score = 0.0

    for url in urls:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path_and_query = f"{parsed.path} {parsed.query}".lower()

        if not hostname:
            score += 5
            reasons.append(f"Malformed URL detected: {url}")
            continue

        host_is_ip = _looks_like_ip(hostname)
        if host_is_ip:
            if hostname in malicious_ips:
                score += 35
                reasons.append(f"IP reputation feed flagged URL host: {hostname}")
        else:
            matched_domain = next((d for d in _iter_parent_domains(hostname) if d in malicious_domains), None)
            if matched_domain:
                score += 35
                reasons.append(f"Domain reputation feed flagged URL host: {matched_domain}")

        if host_is_ip:
            score += 20
            reasons.append(f"URL uses an IP address instead of a domain: {hostname}")

        subdomain_count = max(0, len(hostname.split(".")) - 2)
        if subdomain_count >= 3:
            score += 12
            reasons.append(f"URL has excessive subdomains: {hostname}")

        if "xn--" in hostname:
            score += 18
            reasons.append(f"Possible punycode domain detected: {hostname}")

        if hostname in SHORTENERS:
            score += 14
            reasons.append(f"Shortened URL service used: {hostname}")

        if any(k in path_and_query or k in hostname for k in SUSPICIOUS_KEYWORDS):
            score += 8
            reasons.append(f"Suspicious keyword found in URL: {url}")

        tld = hostname.split(".")[-1] if "." in hostname else ""
        if tld in UNCOMMON_TLDS:
            score += 10
            reasons.append(f"Uncommon TLD found in URL: .{tld}")

        if len(url) > 120:
            score += 7
            reasons.append("Very long URL detected")

    normalized = min(100.0, score)
    return {
        "score": round(normalized, 2),
        "reasons": reasons,
        "count": len(urls),
    }
