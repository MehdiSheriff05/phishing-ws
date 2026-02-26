from flask import Blueprint, jsonify, request

from config import config
from models.schemas import validate_payload
from services.attachment_checks import analyze_attachments
from services.model_inference import PhishingTextClassifier, TextInferenceConfig
from services.preprocess import clean_text, dedupe_urls
from services.risk_scoring import combine_scores
from services.sender_checks import analyze_sender
from services.url_checks import analyze_urls
from utils.logger import setup_logger


analyze_bp = Blueprint("analyze", __name__)
logger = setup_logger("phish_guard.analyze")
classifier = PhishingTextClassifier(
    TextInferenceConfig(
        model_name=config.MODEL_NAME,
        aggregation="mean",
        enable_transformer=config.ENABLE_TRANSFORMER,
    )
)


@analyze_bp.route("/analyze-email", methods=["POST"])
def analyze_email():
    payload = request.get_json(silent=True)
    email_obj, errors = validate_payload(payload)
    if errors:
        return jsonify({"error": "Validation error", "details": errors}), 400

    cleaned_subject = clean_text(email_obj.subject, max_chars=300)
    cleaned_body = clean_text(email_obj.body_text, max_chars=config.MAX_TEXT_CHARS)
    deduped_urls = dedupe_urls(email_obj.urls)

    text_result = classifier.score(cleaned_subject, cleaned_body)
    url_result = analyze_urls(deduped_urls)
    sender_result = analyze_sender(email_obj.sender_email, email_obj.sender_name)
    attachment_result = analyze_attachments(email_obj.attachments)

    response = combine_scores(text_result, url_result, sender_result, attachment_result)

    logger.info(
        "analyzed email sender=%s risk_score=%s risk_level=%s",
        email_obj.sender_email,
        response["risk_score"],
        response["risk_level"],
    )

    return jsonify(response), 200
