import re
from typing import List


WHITESPACE_RE = re.compile(r"\s+")


def clean_text(text: str, max_chars: int = 20000) -> str:
    normalized = WHITESPACE_RE.sub(" ", text or "").strip()
    return normalized[:max_chars]


def dedupe_urls(urls: List[str]) -> List[str]:
    seen = set()
    out = []
    for url in urls:
        u = (url or "").strip()
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out
