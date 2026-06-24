from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from ..config import get_settings
from .features import explain_indicators, extract_features, hostname_from_url, normalize_url


def threat_level(score: int, is_phishing: bool) -> str:
    if is_phishing and score >= 85:
        return "Phishing"
    if score >= 70:
        return "High Risk"
    if score >= 45:
        return "Suspicious"
    if score >= 20:
        return "Low Risk"
    return "Safe"


class PhishGuardPredictor:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.model = None
        self.scaler = None
        self.feature_columns: list[str] = []
        self.metrics: dict[str, Any] = {}
        self.explainer = None
        self._load()

    def _load(self) -> None:
        model_dir = Path(self.settings.model_dir)
        model_path = model_dir / "xgboost_model.joblib"
        scaler_path = model_dir / "scaler.joblib"
        columns_path = model_dir / "feature_columns.joblib"
        metrics_path = model_dir / "metrics.json"

        if not model_path.exists() or not scaler_path.exists() or not columns_path.exists():
            raise FileNotFoundError(
                "XGBoost artifacts are missing. Run `python -m backend.ml.train --demo` first."
            )

        self.model = joblib.load(model_path)
        self.scaler = joblib.load(scaler_path)
        self.feature_columns = joblib.load(columns_path)
        self.metrics = json.loads(metrics_path.read_text(encoding="utf-8")) if metrics_path.exists() else {}

        if not self.settings.enable_shap:
            self.explainer = None
            return
        try:
            import shap

            self.explainer = shap.TreeExplainer(self.model)
        except Exception:
            self.explainer = None

    def reload(self) -> None:
        self._load()

    def _vectorize(self, features: dict[str, Any]) -> tuple[pd.DataFrame, np.ndarray]:
        frame = pd.DataFrame([features]).reindex(columns=self.feature_columns, fill_value=0)
        return frame, self.scaler.transform(frame)

    def _shap_factors(self, frame: pd.DataFrame, scaled: np.ndarray, features: dict[str, Any]) -> list[dict[str, Any]]:
        if self.explainer is None:
            heuristic = []
            for key in ("is_shortened_url", "brand_impersonation", "has_punycode", "has_suspicious_tld", "has_https"):
                if key in features:
                    impact = float(features[key]) if key != "has_https" else float(1 - int(features[key]))
                    heuristic.append({
                        "feature": key,
                        "value": features[key],
                        "impact": round(impact, 4),
                        "direction": "raises risk" if impact > 0 else "lowers risk",
                    })
            return heuristic[:6]

        try:
            values = self.explainer.shap_values(scaled)
            if isinstance(values, list):
                values = values[-1]
            row_values = np.asarray(values)[0]
            ordered = sorted(
                zip(self.feature_columns, row_values),
                key=lambda item: abs(float(item[1])),
                reverse=True,
            )[:8]
            return [
                {
                    "feature": name,
                    "value": features.get(name, 0),
                    "impact": round(float(impact), 5),
                    "direction": "raises risk" if float(impact) > 0 else "lowers risk",
                }
                for name, impact in ordered
            ]
        except Exception:
            self.explainer = None
            return self._shap_factors(frame, scaled, features)

    def predict(self, url: str) -> dict[str, Any]:
        normalized = normalize_url(url)
        features = extract_features(normalized, include_network=self.settings.enable_network_intel)
        frame, scaled = self._vectorize(features)

        probability = self.model.predict_proba(scaled)[0]
        phishing_probability = float(probability[1])
        model_threshold = float(self.metrics.get("selected_threshold", 0.5))
        indicators = explain_indicators(features)
        indicator_weight = 0.0
        high_value_flags = [
            "is_shortened_url",
            "brand_impersonation",
            "has_punycode",
            "typosquatting_similarity",
            "has_suspicious_tld",
            "has_encoded_chars",
            "has_ip",
        ]
        indicator_weight += sum(float(features.get(flag, 0)) for flag in high_value_flags) * 0.14
        indicator_weight += min(float(features.get("suspicious_word_count", 0)) * 0.08, 0.24)
        if int(features.get("has_https", 1)) == 0:
            indicator_weight += 0.08
        indicator_probability = min(indicator_weight, 0.96)
        combined_probability = max(phishing_probability, indicator_probability)
        is_phishing = combined_probability >= model_threshold
        confidence = combined_probability if is_phishing else max(float(probability[0]), 1 - combined_probability)
        risk_score = int(round(combined_probability * 100))

        if is_phishing and not indicators:
            indicators = ["The XGBoost model detected a suspicious URL pattern"]

        return {
            "url": normalized,
            "hostname": hostname_from_url(normalized),
            "result": "Phishing" if is_phishing else "Safe",
            "is_phishing": bool(is_phishing),
            "threat_level": threat_level(risk_score, bool(is_phishing)),
            "risk_score": risk_score,
            "confidence": round(confidence * 100, 2),
            "indicators": indicators,
            "shap_factors": self._shap_factors(frame, scaled, features),
            "features": features,
        }


predictor = PhishGuardPredictor
