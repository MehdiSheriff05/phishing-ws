from models.schemas import Attachment
from services.attachment_checks import analyze_attachments


def test_executable_attachment_high_risk():
    attachments = [
        Attachment(
            filename="invoice.pdf.exe",
            extension="exe",
            size_kb=123,
            mime_type="application/octet-stream",
        )
    ]
    result = analyze_attachments(attachments)
    assert result["score"] >= 30
    assert any("Executable-like" in reason for reason in result["reasons"])


def test_empty_attachments_safe():
    result = analyze_attachments([])
    assert result["score"] == 0
