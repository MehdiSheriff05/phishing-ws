from typing import Dict, List

from models.schemas import Attachment


EXECUTABLE_EXTS = {
    "exe",
    "scr",
    "bat",
    "cmd",
    "js",
    "vbs",
    "ps1",
    "msi",
    "com",
}
MACRO_EXTS = {"docm", "xlsm", "pptm"}
ARCHIVE_EXTS = {"zip", "rar", "7z", "iso"}


def analyze_attachments(attachments: List[Attachment]) -> Dict:
    # TODO: Add sandbox-based dynamic attachment analysis.
    score = 0.0
    reasons: List[str] = []

    for att in attachments:
        ext = att.extension.lower().strip(".")
        filename_lower = att.filename.lower()

        if ext in EXECUTABLE_EXTS:
            score += 30
            reasons.append(f"Executable-like attachment detected: {att.filename}")

        if ext in MACRO_EXTS:
            score += 18
            reasons.append(f"Macro-enabled document detected: {att.filename}")

        if ext in ARCHIVE_EXTS:
            score += 12
            reasons.append(f"Archive attachment detected: {att.filename}")

        parts = filename_lower.split(".")
        if len(parts) >= 3 and parts[-1] in EXECUTABLE_EXTS:
            score += 25
            reasons.append(f"Double extension pattern detected: {att.filename}")

    normalized = min(100.0, score)
    return {"score": round(normalized, 2), "reasons": reasons, "count": len(attachments)}
