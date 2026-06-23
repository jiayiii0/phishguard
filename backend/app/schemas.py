from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class ScanRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)


class ShapFactor(BaseModel):
    feature: str
    value: float | int | str
    impact: float
    direction: str


class ScanResponse(BaseModel):
    url: str
    hostname: str
    result: str
    is_phishing: bool
    risk_score: int
    confidence: float
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
