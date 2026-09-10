from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


class ShapFactor(BaseModel):
    feature: str
    value: float | int | str
    impact: float
    direction: str


class ScanResponse(BaseModel):
    url: str
    original_url: str
    normalized_url: str
    expanded_url: str
    redirect_chain: list[str]
    final_destination: str
    evasion_techniques: list[str]
    hostname: str
    result: str
    is_phishing: bool
    threat_level: str
    risk_score: int
    confidence: float
    model_probability: float
    model_threshold: float
    contextual_signals: list[str]
    threat_feed_matched: bool
    threat_feed_status: str
    threat_feed_source: str
    indicators: list[str]
    shap_factors: list[ShapFactor]
    features: dict[str, Any]


class ScanHistoryItem(BaseModel):
    id: int
    url: str
    hostname: str
    result: str
    is_phishing: bool
    risk_score: int
    confidence: float
    indicators: list[str]
    created_at: datetime


class DashboardStats(BaseModel):
    total_scans: int
    phishing_detected: int
    safe_detected: int
    average_risk_score: float
    recent_scans: list[ScanHistoryItem]
    risk_buckets: dict[str, int]
    model_metrics: dict[str, Any]
