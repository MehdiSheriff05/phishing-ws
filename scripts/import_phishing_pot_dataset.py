import argparse
import csv
import random
import re
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Iterable, List

RNG = random.Random(42)
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")


@dataclass
class EmailRow:
    sender_email: str
    sender_name: str
    subject: str
    body_text: str
    urls: str
    attachments: str
    label: int


def _strip_html(value: str) -> str:
    return TAG_RE.sub(" ", value or "").replace("\n", " ").strip()


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", (value or "").strip())


def _extract_sender(header_value: str) -> tuple[str, str]:
    if not header_value:
        return "", ""
    email_match = re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", header_value, re.I)
    sender_email = email_match.group(0).lower() if email_match else ""
    sender_name = header_value.replace(sender_email, "").replace("<>", "").strip('" <>')
    return sender_email, sender_name


def _collect_parts(msg) -> tuple[str, str, list[str], list[str]]:
    text_parts: List[str] = []
    html_parts: List[str] = []
    urls: List[str] = []
    attachments: List[str] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = (part.get_content_disposition() or "").lower()

            filename = part.get_filename()
            if disposition == "attachment" or filename:
                if filename:
                    attachments.append(filename)

            if content_type in {"text/plain", "text/html"}:
                try:
                    payload = part.get_content()
                except Exception:
                    payload = ""
                if isinstance(payload, bytes):
                    payload = payload.decode("utf-8", errors="ignore")
                payload = str(payload)
                urls.extend(URL_RE.findall(payload))
                if content_type == "text/plain":
                    text_parts.append(payload)
                else:
                    html_parts.append(payload)
    else:
        try:
            payload = msg.get_content()
        except Exception:
            payload = ""
        if isinstance(payload, bytes):
            payload = payload.decode("utf-8", errors="ignore")
        payload = str(payload)
        urls.extend(URL_RE.findall(payload))
        if msg.get_content_type() == "text/html":
            html_parts.append(payload)
        else:
            text_parts.append(payload)

    plain = _normalize(" ".join(text_parts))
    html = _normalize(_strip_html(" ".join(html_parts)))
    return plain, html, urls, attachments


def parse_eml(path: Path) -> EmailRow:
    with path.open("rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    sender_email, sender_name = _extract_sender(str(msg.get("From", "")))
    subject = _normalize(str(msg.get("Subject", "")))
    plain, html, urls, attachments = _collect_parts(msg)
    body_text = plain if plain else html
    if not body_text:
        body_text = "(empty body)"

    return EmailRow(
        sender_email=sender_email,
        sender_name=sender_name,
        subject=subject,
        body_text=body_text,
        urls=";".join(sorted(set(urls))[:20]),
        attachments=";".join(sorted(set(attachments))[:10]),
        label=1,
    )


def phishing_rows(eml_dir: Path, limit: int | None = None) -> List[EmailRow]:
    eml_files = sorted(eml_dir.glob("*.eml"))
    if limit:
        eml_files = eml_files[:limit]

    rows = []
    for p in eml_files:
        try:
            rows.append(parse_eml(p))
        except Exception:
            continue
    return rows


def benign_rows(count: int) -> List[EmailRow]:
    senders = [
        ("noreply@github.com", "GitHub"),
        ("newsletter@python.org", "Python"),
        ("updates@openai.com", "OpenAI"),
        ("info@university.edu", "University Office"),
        ("news@nytimes.com", "NYTimes"),
    ]
    subjects = [
        "Weekly newsletter",
        "Your account activity summary",
        "Meeting reminder",
        "Project update",
        "Security best practices",
    ]
    bodies = [
        "Here is your weekly update and upcoming events.",
        "We have updated documentation for your account settings.",
        "Reminder: your scheduled meeting is tomorrow at 10 AM.",
        "This message contains product release notes and changelog.",
        "Learn how to keep your account safe with these tips.",
    ]
    safe_urls = [
        "https://github.com/security",
        "https://www.python.org",
        "https://openai.com",
        "https://www.nytimes.com",
        "https://www.mozilla.org",
    ]

    out: List[EmailRow] = []
    for _ in range(count):
        sender_email, sender_name = RNG.choice(senders)
        out.append(
            EmailRow(
                sender_email=sender_email,
                sender_name=sender_name,
                subject=RNG.choice(subjects),
                body_text=RNG.choice(bodies),
                urls=RNG.choice(safe_urls),
                attachments="",
                label=0,
            )
        )
    return out


def write_rows(rows: Iterable[EmailRow], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["sender_email", "sender_name", "subject", "body_text", "urls", "attachments", "label"])
        for r in rows:
            writer.writerow([
                r.sender_email,
                r.sender_name,
                r.subject,
                r.body_text,
                r.urls,
                r.attachments,
                r.label,
            ])


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert phishing_pot .eml samples to training CSV")
    parser.add_argument("--eml-dir", default="/tmp/phishing_pot/email")
    parser.add_argument("--out", default="data/processed/phishing_pot_email_training.csv")
    parser.add_argument("--limit", type=int, default=3000)
    parser.add_argument("--benign-ratio", type=float, default=1.0)
    args = parser.parse_args()

    phish = phishing_rows(Path(args.eml_dir), args.limit)
    benign_count = int(len(phish) * max(0.0, args.benign_ratio))
    benign = benign_rows(benign_count)

    all_rows = phish + benign
    RNG.shuffle(all_rows)
    write_rows(all_rows, Path(args.out))

    print(f"phishing rows: {len(phish)}")
    print(f"benign rows: {len(benign)}")
    print(f"total rows: {len(all_rows)}")
    print(f"wrote: {args.out}")


if __name__ == "__main__":
    main()
