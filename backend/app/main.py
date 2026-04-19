from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .evaluation import EvaluationLogStore
from .feedback import FeedbackStore
from .flags import detect_flags
from .model_io import load_artifacts
from .reputation import DomainReputationService, extract_domain
from .schemas import (
    DomainPreferenceRequest,
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

# CORS is open for local development so the unpacked Chrome extension can call the API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# The model threshold is deliberately above 0.50 because earlier tests showed too many false positives.
MODEL_PHISHING_THRESHOLD = 0.60

# The heuristic threshold keeps the pretraining baseline explainable without overreacting to one weak flag.
HEURISTIC_PHISHING_THRESHOLD = 0.50

# These markers indicate rule evidence that should still warn users even for allowlisted domains.
STRONG_HEURISTIC_MARKERS = (
    "blocklist",
    "known bad domain",
    "money-transfer",
    "inheritance",
    "advance-fee",
    "pressure language",
    "external email",
    "multiple contact email",
    "insecure http",
    "untrusted site",
    "@' symbol",
)

vectorizer = None
classifier = None
model_loaded = False
model_disabled_by_env = False
reputation_service = None
feedback_store = None
evaluation_log_store = None


# Treat common truthy strings as "disable the trained model for this run."
def is_model_disabled_by_env() -> bool:
    return os.getenv("PHISHING_DISABLE_MODEL", "").strip().lower() in {"1", "true", "yes", "on"}


# Initialize shared services once when FastAPI starts so each request can reuse them safely.
@app.on_event("startup")
def startup_event() -> None:
    # These globals behave like simple singletons for the running FastAPI process.
    global vectorizer, classifier, model_loaded, model_disabled_by_env, reputation_service, feedback_store, evaluation_log_store
    reputation_service = DomainReputationService()
    feedback_store = FeedbackStore()
    evaluation_log_store = EvaluationLogStore()

    # This switch lets demos compare heuristic-only and trained-model behavior without deleting artifacts.
    model_disabled_by_env = is_model_disabled_by_env()
    if model_disabled_by_env:
        vectorizer = None
        classifier = None
        model_loaded = False
        return

    try:
        # If artifacts exist, predictions use the trained ML model.
        vectorizer, classifier = load_artifacts()
        model_loaded = True
    except FileNotFoundError:
        # Before training, keep API running with simple rule score.
        model_loaded = False


# Return basic runtime status for scripts and the extension before running predictions.
@app.get("/health")
def health() -> dict[str, str | bool]:
    return {"status": "ok", "model_loaded": model_loaded, "model_disabled_by_env": model_disabled_by_env}


# Return the current allowlist and blocklist so the UI can explain user-specific behavior.
@app.get("/preferences", response_model=PreferenceStateResponse)
def get_preferences() -> PreferenceStateResponse:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    prefs = feedback_store.get_preferences()
    return PreferenceStateResponse(**prefs)


# Expose feedback counts and storage paths for debugging and project demonstrations.
@app.get("/feedback/stats", response_model=FeedbackStatsResponse)
def feedback_stats() -> FeedbackStatsResponse:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    return FeedbackStatsResponse(**feedback_store.stats())


# Add a domain to the blocklist; blocked domains always force a phishing warning.
@app.post("/preferences/block", response_model=PreferenceStateResponse)
def preferences_block(payload: DomainPreferenceRequest) -> PreferenceStateResponse:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    try:
        # The store normalizes URLs into domains before saving them.
        feedback_store.set_blocked(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PreferenceStateResponse(**feedback_store.get_preferences())


# Add a domain to the allowlist; allowlisting reduces risk only when content is otherwise clean.
@app.post("/preferences/allow", response_model=PreferenceStateResponse)
def preferences_allow(payload: DomainPreferenceRequest) -> PreferenceStateResponse:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    try:
        # Allowlisting is not absolute trust; risky content can still trigger a warning later.
        feedback_store.set_allowed(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PreferenceStateResponse(**feedback_store.get_preferences())


# Remove a domain from the blocklist when the user no longer wants forced warnings.
@app.post("/preferences/unblock", response_model=PreferenceStateResponse)
def preferences_unblock(payload: DomainPreferenceRequest) -> PreferenceStateResponse:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    try:
        feedback_store.remove_blocked(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PreferenceStateResponse(**feedback_store.get_preferences())


# Remove a domain from the allowlist so future scans use the normal risk decision path again.
@app.post("/preferences/unallow", response_model=PreferenceStateResponse)
def preferences_unallow(payload: DomainPreferenceRequest) -> PreferenceStateResponse:
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")
    try:
        feedback_store.remove_allowed(payload.domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return PreferenceStateResponse(**feedback_store.get_preferences())


# Log evaluation results from the standalone test script into the CSV used for the dissertation.
@app.post("/evaluation/log", response_model=EvaluationLogResponse)
def evaluation_log(payload: EvaluationLogRequest) -> EvaluationLogResponse:
    if evaluation_log_store is None:
        raise HTTPException(status_code=500, detail="Evaluation log store is not ready")
    try:
        # model_loaded determines whether the CSV writes pretraining or post-training columns.
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


# Show which local and optional external reputation sources are active.
@app.get("/reputation/status")
def reputation_status() -> dict[str, object]:
    if reputation_service is None:
        raise HTTPException(status_code=500, detail="Domain check service is not ready")
    return reputation_service.status()


# Reload domain reputation files without restarting the backend during a demo.
@app.post("/reputation/reload")
def reputation_reload() -> dict[str, object]:
    if reputation_service is None:
        raise HTTPException(status_code=500, detail="Domain check service is not ready")
    reputation_service.reload_lists()
    return {"status": "reloaded", **reputation_service.status()}


# Check arbitrary URLs against local reputation lists and optional Google Safe Browsing.
@app.post("/reputation/check", response_model=ReputationCheckResponse)
def reputation_check(payload: ReputationCheckRequest) -> ReputationCheckResponse:
    if reputation_service is None:
        raise HTTPException(status_code=500, detail="Domain check service is not ready")
    results = reputation_service.check_urls(payload.urls)
    return ReputationCheckResponse(results=results)


# Count strong rule evidence so allowlisted pages can still warn when the content looks suspicious.
def has_strong_heuristic_evidence(flags: list[str]) -> bool:
    # Join flags into one string so each marker can be checked with a simple substring test.
    joined_flags = " | ".join(flags).lower()
    return any(marker in joined_flags for marker in STRONG_HEURISTIC_MARKERS)


# Apply blocklist and allowlist policy after the base score has been computed.
def apply_user_domain_policy(
    *,
    proba: float,
    label: str,
    flags: list[str],
    blocked_domains: list[str],
    allowed_domains: list[str],
) -> tuple[float, str, list[str]]:
    # Blocklist is the strongest user policy: it always warns and raises the score.
    if blocked_domains:
        flags.insert(0, f"User blocklist warning: {', '.join(blocked_domains[:3])}")
        return max(proba, 0.98), "phishing", flags

    # Allowlisted domains still warn if the model or strong rules say the page looks dangerous.
    if allowed_domains and (proba >= MODEL_PHISHING_THRESHOLD or has_strong_heuristic_evidence(flags)):
        flags.insert(0, f"Allowlist caution: {', '.join(allowed_domains[:3])} is allowed, but this page still looks risky")
        return max(proba, MODEL_PHISHING_THRESHOLD), "phishing", flags

    # Clean allowlisted pages are trusted to reduce false positives for known safe domains.
    if allowed_domains:
        flags.insert(0, f"User allowlist match: {', '.join(allowed_domains[:3])}")
        return min(proba, 0.10), "legitimate", flags

    return proba, label, flags


# Predict phishing risk for text and links extracted by the extension or evaluation script.
@app.post("/predict", response_model=PredictResponse)
def predict(payload: PredictRequest) -> PredictResponse:
    if reputation_service is None:
        raise HTTPException(status_code=500, detail="Domain check service is not ready")
    if feedback_store is None:
        raise HTTPException(status_code=500, detail="Feedback store is not ready")

    # Link text and URLs are merged with visible text because phishing clues can appear in either place.
    link_parts = [f"{item.text} {item.href}" for item in payload.links]
    full_text = f"{payload.visible_text} {' '.join(link_parts)}".strip()
    if not full_text:
        raise HTTPException(status_code=400, detail="No text content available for prediction")

    # Rule flags provide human-readable explanations even when the ML model supplies the score.
    flags = detect_flags(
        visible_text=payload.visible_text,
        links=[{"text": item.text, "href": item.href} for item in payload.links],
        reputation_service=reputation_service,
    )
    # Preferences are applied only to domains that actually appear in the scanned links.
    link_domains = [extract_domain(item.href) for item in payload.links if item.href]
    blocked_domains = sorted({d for d in link_domains if d and feedback_store.is_blocked(d)})
    allowed_domains = sorted({d for d in link_domains if d and feedback_store.is_allowed(d)})

    if vectorizer is None or classifier is None or not model_loaded:
        # Pretraining is intentionally a lightweight baseline, so rule hits explain risk but do not over-score.
        simple_score = min(0.45, 0.15 * len(flags))
        proba = simple_score
        label = "phishing" if proba >= HEURISTIC_PHISHING_THRESHOLD else "legitimate"

        # User domain policy still works before training, which helps extension demos.
        proba, label, flags = apply_user_domain_policy(
            proba=proba,
            label=label,
            flags=flags,
            blocked_domains=blocked_domains,
            allowed_domains=allowed_domains,
        )

        # The first flag makes the CSV and popup clear that this was not an ML prediction.
        fallback_flags = [
            "Model files not loaded; using simple rule score only.",
            *flags,
        ]
        return PredictResponse(
            label=label,
            probability_phishing=round(float(proba), 6),
            flags=fallback_flags[:10],
        )

    # The vectorizer converts raw email text into the same numeric features used during training.
    features = vectorizer.transform([full_text])
    proba = float(classifier.predict_proba(features)[0][1])
    label = "phishing" if proba >= MODEL_PHISHING_THRESHOLD else "legitimate"

    # After ML scoring, domain policy can still override based on user allowlist/blocklist choices.
    proba, label, flags = apply_user_domain_policy(
        proba=proba,
        label=label,
        flags=flags,
        blocked_domains=blocked_domains,
        allowed_domains=allowed_domains,
    )

    return PredictResponse(
        label=label,
        probability_phishing=round(proba, 6),
        flags=flags,
    )
