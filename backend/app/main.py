from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .evaluation import EvaluationLogStore
from .feedback import FeedbackStore
from .flags import detect_flags
from .model_io import load_artifacts
from .reputation import DomainReputationService, extract_domain
from .schemas import (
    DomainPreferenceRequest,
    EmailFeedbackRequest,
    EvaluationLogRequest,
    EvaluationLogResponse,
    FeedbackStatsResponse,
    PreferenceStateResponse,
    PredictRequest,
    PredictResponse,
    ReputationCheckRequest,
    ReputationCheckResponse,
)

app = FastAPI(title="Phishing Detection API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

vectorizer = None
classifier = None
model_loaded = False
reputation_service = None
feedback_store = None
evaluation_log_store = None


@app.on_event("startup")
def startup_event() -> None:
    global vectorizer, classifier, model_loaded, reputation_service, feedback_store, evaluation_log_store
    reputation_service = DomainReputationService()
    feedback_store = FeedbackStore()
    evaluation_log_store = EvaluationLogStore()
    try:
        vectorizer, classifier = load_artifacts()
        model_loaded = True
    except FileNotFoundError:
        # Before training, keep API running with simple rule score.
        model_loaded = False


@app.get("/health")
def health() -> dict[str, str | bool]:
    return {"status": "ok", "model_loaded": model_loaded}


@app.get("/preferences", response_model=PreferenceStateResponse)
def get_preferences() -> PreferenceStateResponse:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    prefs = feedback_store.get_preferences()
    return PreferenceStateResponse(**prefs)


@app.get("/feedback/stats", response_model=FeedbackStatsResponse)
def feedback_stats() -> FeedbackStatsResponse:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    return FeedbackStatsResponse(**feedback_store.stats())


@app.post("/preferences/block", response_model=PreferenceStateResponse)
def preferences_block(payload: DomainPreferenceRequest) -> PreferenceStateResponse:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    try:
        feedback_store.set_blocked(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PreferenceStateResponse(**feedback_store.get_preferences())


@app.post("/preferences/allow", response_model=PreferenceStateResponse)
def preferences_allow(payload: DomainPreferenceRequest) -> PreferenceStateResponse:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    try:
        feedback_store.set_allowed(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PreferenceStateResponse(**feedback_store.get_preferences())


@app.post("/preferences/unblock", response_model=PreferenceStateResponse)
def preferences_unblock(payload: DomainPreferenceRequest) -> PreferenceStateResponse:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    try:
        feedback_store.remove_blocked(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PreferenceStateResponse(**feedback_store.get_preferences())


@app.post("/preferences/unallow", response_model=PreferenceStateResponse)
def preferences_unallow(payload: DomainPreferenceRequest) -> PreferenceStateResponse:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    try:
        feedback_store.remove_allowed(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PreferenceStateResponse(**feedback_store.get_preferences())


@app.post("/feedback/report-spam")
def report_spam(payload: EmailFeedbackRequest) -> dict[str, object]:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    try:
        return feedback_store.record_feedback(
            visible_text=payload.visible_text,
            links=[{"text": item.text, "href": item.href} for item in payload.links],
            user_label=1,
            source=payload.source,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/feedback/report-not-spam")
def report_not_spam(payload: EmailFeedbackRequest) -> dict[str, object]:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    try:
        return feedback_store.record_feedback(
            visible_text=payload.visible_text,
            links=[{"text": item.text, "href": item.href} for item in payload.links],
            user_label=0,
            source=payload.source,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/evaluation/log", response_model=EvaluationLogResponse)
def evaluation_log(payload: EvaluationLogRequest) -> EvaluationLogResponse:
    if evaluation_log_store is None:
        raise HTTPException(status_code=500, detail="Evaluation log store is not ready")
    try:
        result = evaluation_log_store.log_prediction(
            relative_path=payload.relative_path,
            label=payload.label,
            probability_phishing=payload.probability_phishing,
            flags=payload.flags,
            model_loaded=model_loaded,
        )
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return EvaluationLogResponse(**result)


@app.get("/reputation/status")
def reputation_status() -> dict[str, object]:
    if reputation_service is None:
        raise HTTPException(status_code=500, detail="Domain check service is not ready")
    return reputation_service.status()


@app.post("/reputation/reload")
def reputation_reload() -> dict[str, object]:
    if reputation_service is None:
        raise HTTPException(status_code=500, detail="Domain check service is not ready")
    reputation_service.reload_lists()
    return {"status": "reloaded", **reputation_service.status()}


@app.post("/reputation/check", response_model=ReputationCheckResponse)
def reputation_check(payload: ReputationCheckRequest) -> ReputationCheckResponse:
    if reputation_service is None:
        raise HTTPException(status_code=500, detail="Domain check service is not ready")
    results = reputation_service.check_urls(payload.urls)
    return ReputationCheckResponse(results=results)


@app.post("/predict", response_model=PredictResponse)
def predict(payload: PredictRequest) -> PredictResponse:
    if reputation_service is None:
        raise HTTPException(status_code=500, detail="Domain check service is not ready")
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")

    link_parts = [f"{item.text} {item.href}" for item in payload.links]
    full_text = f"{payload.visible_text} {' '.join(link_parts)}".strip()
    if not full_text:
        raise HTTPException(status_code=400, detail="No text content available for prediction")

    flags = detect_flags(
        visible_text=payload.visible_text,
        links=[{"text": item.text, "href": item.href} for item in payload.links],
        reputation_service=reputation_service,
    )
    link_domains = [extract_domain(item.href) for item in payload.links if item.href]
    blocked_domains = sorted({d for d in link_domains if d and feedback_store.is_blocked(d)})
    allowed_domains = sorted({d for d in link_domains if d and feedback_store.is_allowed(d)})

    if vectorizer is None or classifier is None or not model_loaded:
        # In pre-training mode, treat each independent rule hit as a stronger signal.
        simple_score = min(0.95, 0.25 * len(flags))
        proba = simple_score
        label = "phishing" if proba >= 0.5 else "legitimate"

        if blocked_domains:
            proba = max(proba, 0.95)
            label = "phishing"
            flags.insert(0, f"User blocklist match: {', '.join(blocked_domains[:3])}")
        elif allowed_domains:
            proba = min(proba, 0.15)
            label = "legitimate"
            flags.insert(0, f"User allowlist match: {', '.join(allowed_domains[:3])}")

        fallback_flags = [
            "Model files not loaded; using simple rule score only.",
            *flags,
        ]
        return PredictResponse(
            label=label,
            probability_phishing=round(float(proba), 6),
            flags=fallback_flags[:10],
        )

    features = vectorizer.transform([full_text])
    proba = float(classifier.predict_proba(features)[0][1])
    label = "phishing" if proba >= 0.5 else "legitimate"
    if blocked_domains:
        proba = max(proba, 0.98)
        label = "phishing"
        flags.insert(0, f"User blocklist match: {', '.join(blocked_domains[:3])}")
    elif allowed_domains:
        proba = min(proba, 0.10)
        label = "legitimate"
        flags.insert(0, f"User allowlist match: {', '.join(allowed_domains[:3])}")

    return PredictResponse(
        label=label,
        probability_phishing=round(proba, 6),
        flags=flags,
    )
