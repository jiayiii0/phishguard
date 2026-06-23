from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from .config import get_settings
from .database import get_db
from .models import ScanRecord
from .schemas import DashboardStats, ScanHistoryItem, ScanRequest, ScanResponse
from .services.predictor import PhishGuardPredictor


router = APIRouter()
_predictor: PhishGuardPredictor | None = None


def get_predictor() -> PhishGuardPredictor:
    global _predictor
    if _predictor is None:
        _predictor = PhishGuardPredictor()
    return _predictor


def model_metrics() -> dict:
    settings = get_settings()
    metrics_path = Path(settings.model_dir) / "metrics.json"
    if metrics_path.exists():
        import json

        return json.loads(metrics_path.read_text(encoding="utf-8"))
    return {}


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "engine": "XGBoost"}


@router.post("/scan", response_model=ScanResponse)
def scan_url(payload: ScanRequest, db: Session = Depends(get_db)) -> dict:
    try:
        result = get_predictor().predict(payload.url)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    record = ScanRecord(
        url=result["url"],
        hostname=result["hostname"],
        result=result["result"],
        is_phishing=result["is_phishing"],
        risk_score=result["risk_score"],
        confidence=result["confidence"],
        indicators=result["indicators"],
        shap_factors=result["shap_factors"],
        features=result["features"],
    )
    db.add(record)
    db.commit()
    return result


@router.get("/history", response_model=list[ScanHistoryItem])
def history(db: Session = Depends(get_db), limit: int = 20) -> list[ScanRecord]:
    return db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(min(limit, 100)).all()


@router.get("/dashboard", response_model=DashboardStats)
def dashboard(db: Session = Depends(get_db)) -> dict:
    total = db.query(func.count(ScanRecord.id)).scalar() or 0
    phishing = db.query(func.count(ScanRecord.id)).filter(ScanRecord.is_phishing.is_(True)).scalar() or 0
    safe = db.query(func.count(ScanRecord.id)).filter(ScanRecord.is_phishing.is_(False)).scalar() or 0
    avg_risk = db.query(func.avg(ScanRecord.risk_score)).scalar() or 0
    recent = db.query(ScanRecord).order_by(ScanRecord.created_at.desc()).limit(8).all()
    low = db.query(func.count(ScanRecord.id)).filter(ScanRecord.risk_score < 35).scalar() or 0
    medium = db.query(func.count(ScanRecord.id)).filter(ScanRecord.risk_score.between(35, 69)).scalar() or 0
    high = db.query(func.count(ScanRecord.id)).filter(ScanRecord.risk_score >= 70).scalar() or 0
    return {
        "total_scans": total,
        "phishing_detected": phishing,
        "safe_detected": safe,
        "average_risk_score": round(float(avg_risk), 2),
        "recent_scans": recent,
        "risk_buckets": {"low": low, "medium": medium, "high": high},
        "model_metrics": model_metrics(),
    }
