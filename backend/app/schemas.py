from __future__ import annotations

from pydantic import BaseModel, Field


class LinkItem(BaseModel):
    text: str = ""
    href: str = ""


class PredictRequest(BaseModel):
    visible_text: str = Field(default="", min_length=1)
    links: list[LinkItem] = Field(default_factory=list)


class PredictResponse(BaseModel):
    label: str
    probability_phishing: float
    flags: list[str]


class ReputationCheckRequest(BaseModel):
    urls: list[str] = Field(default_factory=list, min_length=1)


class UrlReputationResult(BaseModel):
    url: str
    domain: str
    is_trusted: bool
    is_flagged: bool
    risk: str
    sources: list[str]


class ReputationCheckResponse(BaseModel):
    results: list[UrlReputationResult]


class DomainPreferenceRequest(BaseModel):
    domain: str = Field(min_length=1)


class EmailFeedbackRequest(BaseModel):
    visible_text: str = ""
    links: list[LinkItem] = Field(default_factory=list)
    source: str = "extension"


class PreferenceStateResponse(BaseModel):
    allowlist: list[str]
    blocklist: list[str]


class FeedbackStatsResponse(BaseModel):
    allowlist_count: int
    blocklist_count: int
    feedback_examples: int
    preferences_path: str
    training_feedback_path: str
    events_path: str
