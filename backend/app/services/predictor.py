from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd

from ..config import get_settings
from .features import explain_indicators, extract_features, hostname_from_url, preprocess_url
from .threat_feed import lookup_threat_feed


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


def contextual_risk_adjustment(
    combined_probability: float,
    features: dict[str, Any],
    threat_feed_matched: bool,
) -> tuple[float, list[str]]:
    """Reduce URL-only false positives on reputable platforms without whitelisting them."""
    signals: list[str] = []
    if int(features.get("known_platform_domain", 0)) == 1:
        signals.append("Known platform domain detected")
    if int(features.get("brand_matches_registered_domain", 0)) == 1:
        signals.append("Brand appears on its own registered domain")
    if int(features.get("embedded_same_registered_domain_count", 0)) > 0:
        signals.append("Embedded URL stays within the same registered domain")

    if threat_feed_matched:
        return combined_probability, signals

    severe_flags = [
        "has_ip",
        "has_punycode",
        "homoglyph_detected",
        "has_suspicious_tld",
        "brand_impersonation",
        "credential_terms_on_unrelated_domain",
        "final_domain_differs",
        "has_at_symbol_abuse",
        "embedded_external_url_count",
        "redirect_loop_detected",
    ]
    has_severe_signal = any(float(features.get(flag, 0)) > 0 for flag in severe_flags)
    clean_known_platform = (
        int(features.get("known_platform_domain", 0)) == 1
        and int(features.get("brand_matches_registered_domain", 0)) == 1
        and int(features.get("has_https", 0)) == 1
        and not has_severe_signal
    )

    if not clean_known_platform:
        return combined_probability, signals

    length_only_or_same_domain_flow = (
        int(features.get("suspicious_word_count", 0)) <= 4
        and float(features.get("obfuscation_score", 0)) <= 0.25
        and int(features.get("embedded_external_url_count", 0)) == 0
    )
    if length_only_or_same_domain_flow and combined_probability > 0.22:
        signals.append("Risk reduced because the URL is a clean known-platform flow, not a brand-mismatched domain")
        return 0.22, signals
    return combined_probability, signals


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
            for key in (
                "is_shortened_url",
                "final_domain_differs",
                "homoglyph_detected",
                "punycode_detected",
                "brand_impersonation",
                "obfuscation_score",
                "has_suspicious_tld",
                "has_https",
            ):
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
        preprocessed = preprocess_url(
            url,
            expand_shorteners=self.settings.enable_shortener_expansion,
            timeout=float(self.settings.url_resolve_timeout_seconds),
            max_redirects=5,
        )
        normalized = preprocessed.analysis_url
        features = extract_features(
            normalized,
            include_network=self.settings.enable_network_intel,
            preprocessed=preprocessed,
        )
        hostname = hostname_from_url(normalized)
        threat_feed = {"matched": False, "source": "", "match_type": ""}
        if self.settings.enable_threat_feed_lookup:
            threat_feed = lookup_threat_feed(
                preprocessed.expanded_url,
                hostname,
                timeout=float(self.settings.url_resolve_timeout_seconds),
            )
        feed_match_type = str(threat_feed.get("match_type") or "").lower()
        threat_feed_matched = bool(threat_feed.get("matched"))
        feed_url_match = threat_feed_matched and feed_match_type == "url"
        feed_domain_match = threat_feed_matched and feed_match_type == "domain"
        domain_match_on_known_platform = feed_domain_match and int(features.get("known_platform_domain", 0)) == 1
        authoritative_threat_feed_match = threat_feed_matched and not domain_match_on_known_platform
        features["known_threat_feed_match"] = int(threat_feed_matched)
        features["known_threat_feed_url_match"] = int(feed_url_match)
        features["known_threat_feed_domain_match"] = int(feed_domain_match)
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
            "homoglyph_detected",
            "final_domain_differs",
            "has_at_symbol_abuse",
            "url_encoding_detected",
        ]
        indicator_weight += sum(float(features.get(flag, 0)) for flag in high_value_flags) * 0.14
        indicator_weight += min(float(features.get("suspicious_word_count", 0)) * 0.08, 0.24)
        indicator_weight += min(float(features.get("obfuscation_score", 0)) * 0.3, 0.18)
        if int(features.get("has_https", 1)) == 0:
            indicator_weight += 0.08
        indicator_probability = min(indicator_weight, 0.96)
        combined_probability = max(phishing_probability, indicator_probability)
        if authoritative_threat_feed_match:
            combined_probability = max(combined_probability, 0.98)
            source = str(threat_feed.get("source") or "public threat feed")
            match_type = "URL" if feed_url_match else "domain"
            feed_indicator = f"Known phishing feed match: {source} {match_type}"
            if feed_indicator not in indicators:
                indicators.insert(0, feed_indicator)
        combined_probability, contextual_signals = contextual_risk_adjustment(
            combined_probability,
            features,
            authoritative_threat_feed_match,
        )
        is_phishing = combined_probability >= model_threshold
        confidence = combined_probability if is_phishing else max(float(probability[0]), 1 - combined_probability)
        risk_score = int(round(combined_probability * 100))

        if is_phishing and not indicators:
            indicators = ["The XGBoost model detected a suspicious URL pattern"]

        return {
            "url": preprocessed.original_url,
            "original_url": preprocessed.original_url,
            "normalized_url": preprocessed.normalized_url,
            "expanded_url": preprocessed.expanded_url,
            "redirect_chain": preprocessed.redirect_chain,
            "final_destination": preprocessed.final_destination_domain,
            "evasion_techniques": (
                ["threat_feed_match", *preprocessed.evasion_techniques]
                if authoritative_threat_feed_match
                else preprocessed.evasion_techniques
            ),
            "hostname": hostname,
            "result": "Phishing" if is_phishing else "Safe",
            "is_phishing": bool(is_phishing),
            "threat_level": threat_level(risk_score, bool(is_phishing)),
            "risk_score": risk_score,
            "confidence": round(confidence * 100, 2),
            "model_probability": round(phishing_probability * 100, 2),
            "model_threshold": round(model_threshold, 4),
            "contextual_signals": contextual_signals,
            "threat_feed_matched": bool(threat_feed.get("matched")),
            "threat_feed_status": str(threat_feed.get("status") or "disabled"),
            "threat_feed_source": str(threat_feed.get("source") or ""),
            "indicators": indicators,
            "shap_factors": self._shap_factors(frame, scaled, features),
            "features": features,
        }


predictor = PhishGuardPredictor
