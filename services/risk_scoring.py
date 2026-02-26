from typing import Dict, List


WEIGHTS = {
    "text": 0.4,
    "url": 0.25,
    "sender": 0.2,
    "attachment": 0.15,
}


def _risk_label(score: float) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _recommended_action(level: str) -> str:
    if level == "high":
        return "Do not click links or open attachments. Verify sender through a trusted channel."
    if level == "medium":
        return "Proceed with caution and verify key details before taking action."
    return "No major phishing signals detected, but remain cautious."


def combine_scores(text_result: Dict, url_result: Dict, sender_result: Dict, attachment_result: Dict) -> Dict:
    weighted = (
        text_result.get("score", 0.0) * WEIGHTS["text"]
        + url_result.get("score", 0.0) * WEIGHTS["url"]
        + sender_result.get("score", 0.0) * WEIGHTS["sender"]
        + attachment_result.get("score", 0.0) * WEIGHTS["attachment"]
    )

    final_score = round(min(100.0, weighted), 2)
    level = _risk_label(final_score)

    reasons: List[str] = (
        text_result.get("reasons", [])
        + url_result.get("reasons", [])
        + sender_result.get("reasons", [])
        + attachment_result.get("reasons", [])
    )

    if not reasons:
        reasons = ["No high-confidence phishing indicators were triggered"]

    return {
        "risk_score": final_score,
        "risk_level": level,
        "reasons": reasons[:8],
        "indicators": {
            "text": text_result.get("score", 0.0),
            "url": url_result.get("score", 0.0),
            "sender": sender_result.get("score", 0.0),
            "attachment": attachment_result.get("score", 0.0),
        },
        "recommended_action": _recommended_action(level),
    }
