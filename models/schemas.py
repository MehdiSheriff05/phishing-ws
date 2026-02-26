from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class Attachment:
    filename: str
    extension: str
    size_kb: float
    mime_type: str


@dataclass
class EmailPayload:
    sender_email: str
    sender_name: Optional[str]
    subject: str
    body_text: str
    urls: List[str] = field(default_factory=list)
    attachments: List[Attachment] = field(default_factory=list)
    page_source: Optional[str] = None


REQUIRED_FIELDS = ["sender_email", "subject", "body_text", "urls", "attachments"]


def validate_payload(raw: Dict[str, Any]) -> Tuple[Optional[EmailPayload], List[str]]:
    errors: List[str] = []

    if not isinstance(raw, dict):
        return None, ["Payload must be a JSON object"]

    for field in REQUIRED_FIELDS:
        if field not in raw:
            errors.append(f"Missing required field: {field}")

    if errors:
        return None, errors

    sender_email = raw.get("sender_email", "")
    sender_name = raw.get("sender_name")
    subject = raw.get("subject", "")
    body_text = raw.get("body_text", "")
    urls = raw.get("urls", [])
    attachments = raw.get("attachments", [])
    page_source = raw.get("page_source")

    if not isinstance(sender_email, str) or not sender_email.strip():
        errors.append("sender_email must be a non-empty string")
    if sender_name is not None and not isinstance(sender_name, str):
        errors.append("sender_name must be a string when provided")
    if not isinstance(subject, str):
        errors.append("subject must be a string")
    if not isinstance(body_text, str):
        errors.append("body_text must be a string")
    if not isinstance(urls, list) or not all(isinstance(u, str) for u in urls):
        errors.append("urls must be a list of strings")

    parsed_attachments: List[Attachment] = []
    if not isinstance(attachments, list):
        errors.append("attachments must be a list")
    else:
        for i, item in enumerate(attachments):
            if not isinstance(item, dict):
                errors.append(f"attachments[{i}] must be an object")
                continue

            filename = item.get("filename")
            extension = item.get("extension")
            size_kb = item.get("size_kb")
            mime_type = item.get("mime_type")

            if not isinstance(filename, str):
                errors.append(f"attachments[{i}].filename must be a string")
            if not isinstance(extension, str):
                errors.append(f"attachments[{i}].extension must be a string")
            if not isinstance(size_kb, (int, float)):
                errors.append(f"attachments[{i}].size_kb must be numeric")
            if not isinstance(mime_type, str):
                errors.append(f"attachments[{i}].mime_type must be a string")

            if (
                isinstance(filename, str)
                and isinstance(extension, str)
                and isinstance(size_kb, (int, float))
                and isinstance(mime_type, str)
            ):
                parsed_attachments.append(
                    Attachment(
                        filename=filename,
                        extension=extension.lower().strip("."),
                        size_kb=float(size_kb),
                        mime_type=mime_type,
                    )
                )

    if errors:
        return None, errors

    return (
        EmailPayload(
            sender_email=sender_email.strip(),
            sender_name=sender_name.strip() if isinstance(sender_name, str) else None,
            subject=subject,
            body_text=body_text,
            urls=urls,
            attachments=parsed_attachments,
            page_source=page_source if isinstance(page_source, str) else None,
        ),
        [],
    )
