from __future__ import annotations

from pydantic import BaseModel, Field


# A link contains both the text shown to the user and the real destination URL.
class LinkItem(BaseModel):
    text: str = ""
    href: str = ""


# This is the request body sent from the Chrome extension to the /predict endpoint.
class PredictRequest(BaseModel):
    visible_text: str = Field(default="", min_length=1)
    links: list[LinkItem] = Field(default_factory=list)


# This is the main response the extension displays in the popup and notifications.
class PredictResponse(BaseModel):
    label: str
    probability_phishing: float
    flags: list[str]


# Evaluation logging uses this shape when a script records a prediction into the CSV.
class EvaluationLogRequest(BaseModel):
    relative_path: str = Field(min_length=1)
    label: str = Field(min_length=1)
    probability_phishing: float
    flags: list[str] = Field(default_factory=list)


# The response confirms which CSV row and phase were updated.
class EvaluationLogResponse(BaseModel):
    saved: bool
    phase: str
    relative_path: str
    csv_path: str


# Reputation checks can test a batch of URLs without running a full email prediction.
class ReputationCheckRequest(BaseModel):
    urls: list[str] = Field(default_factory=list, min_length=1)


# Each URL reputation result explains whether the link was trusted, flagged, or unknown.
class UrlReputationResult(BaseModel):
    url: str
    domain: str
    is_trusted: bool
    is_flagged: bool
    risk: str
    sources: list[str]


# The reputation endpoint returns one result per URL that was supplied.
class ReputationCheckResponse(BaseModel):
    results: list[UrlReputationResult]


# Allowlist and blocklist operations only need one domain or URL from the user.
class DomainPreferenceRequest(BaseModel):
    domain: str = Field(min_length=1)


# The extension can show or debug the current domain preference state with this response.
class PreferenceStateResponse(BaseModel):
    allowlist: list[str]
    blocklist: list[str]


# Feedback stats support demos by showing where preferences and feedback files are stored.
class FeedbackStatsResponse(BaseModel):
    allowlist_count: int
    blocklist_count: int
    feedback_examples: int
    preferences_path: str
    training_feedback_path: str
    events_path: str
