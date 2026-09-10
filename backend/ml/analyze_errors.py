from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from backend.app.services.features import extract_features
from backend.app.services.predictor import PhishGuardPredictor
from backend.ml.train import real_dataset, split_by_hostname


ARTIFACT_DIR = Path(__file__).resolve().parent / "artifacts"
HARD_LEGITIMATE_CASES = [
    "https://docs.google.com/forms/u/1/d/e/1FAIpQLSfmkF4oiWVWs_Kiu-5igwc_1iLbbF9itc0DpkLmT4OQTlWXcQ/formResponse",
    "https://accounts.google.com/signin/v2/identifier?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&flowName=GlifWebSignIn",
    "https://github.com/login?return_to=%2Fsettings%2Fsecurity",
    "https://www.paypal.com/my/signin?returnUri=%2Fmyaccount%2Fsummary",
    "https://support.microsoft.com/en-us/account-billing/reset-a-forgotten-microsoft-account-password-eff4f067-5042-c1a3-fe72-b04d60556c37",
]
HARD_SUSPICIOUS_CASES = [
    "http://google-login-security.example.com/account/verify",
    "http://paypal.com@malicious-login.example/verify",
    "http://xn--paypa1-login.com/verify",
    "http://192.0.2.10/paypal/verify-account",
    "http://microsoft-security-check.xyz/signin",
    "http://secure-login-maybank2u.top/account",
]


def _mean_features(frame: pd.DataFrame, columns: list[str]) -> dict[str, float]:
    if frame.empty:
        return {column: 0.0 for column in columns}
    return {column: round(float(frame[column].mean()), 4) for column in columns}


def _sample_errors(data: pd.DataFrame, mask: pd.Series, limit: int = 10) -> list[dict[str, Any]]:
    rows = data.loc[mask, ["url", "label"]].head(limit)
    return rows.to_dict(orient="records")


def main() -> None:
    metrics = json.loads((ARTIFACT_DIR / "metrics.json").read_text(encoding="utf-8"))
    threshold = float(metrics["selected_threshold"])
    model = joblib.load(ARTIFACT_DIR / "xgboost_model.joblib")
    scaler = joblib.load(ARTIFACT_DIR / "scaler.joblib")
    feature_columns = joblib.load(ARTIFACT_DIR / "feature_columns.joblib")

    data, _, _ = real_dataset(balance=True, return_report=True)
    features = pd.DataFrame([extract_features(url, include_network=False) for url in data["url"]])
    features = features.reindex(columns=feature_columns, fill_value=0)
    labels = data["label"].astype(int)
    _, _, test_index, _ = split_by_hostname(data, test_size=0.15, validation_size=0.15, random_state=42)

    x_test = features.loc[test_index]
    y_test = labels.loc[test_index]
    probabilities = model.predict_proba(scaler.transform(x_test))[:, 1]
    predictions = (probabilities >= threshold).astype(int)
    test_data = data.loc[test_index].copy()
    test_data["prediction"] = predictions
    test_data["probability"] = probabilities

    false_positive_mask = (test_data["label"] == 0) & (test_data["prediction"] == 1)
    false_negative_mask = (test_data["label"] == 1) & (test_data["prediction"] == 0)
    true_positive_mask = (test_data["label"] == 1) & (test_data["prediction"] == 1)
    true_negative_mask = (test_data["label"] == 0) & (test_data["prediction"] == 0)

    focus_columns = [
        "url_length",
        "path_length",
        "query_length",
        "count_slash",
        "count_digits",
        "special_char_ratio",
        "suspicious_word_count",
        "subdomain_count",
        "has_https",
        "has_suspicious_tld",
        "brand_impersonation",
        "known_platform_domain",
        "brand_matches_registered_domain",
    ]
    indexed_features = features.loc[test_index].reset_index(drop=True)
    reset_data = test_data.reset_index(drop=True)

    predictor = PhishGuardPredictor()
    hard_legitimate = [predictor.predict(url) for url in HARD_LEGITIMATE_CASES]
    hard_suspicious = [predictor.predict(url) for url in HARD_SUSPICIOUS_CASES]

    report = {
        "threshold": threshold,
        "final_test_size": int(len(test_data)),
        "false_positive_count": int(false_positive_mask.sum()),
        "false_negative_count": int(false_negative_mask.sum()),
        "true_positive_count": int(true_positive_mask.sum()),
        "true_negative_count": int(true_negative_mask.sum()),
        "false_positive_feature_means": _mean_features(indexed_features.loc[false_positive_mask.to_numpy()], focus_columns),
        "false_negative_feature_means": _mean_features(indexed_features.loc[false_negative_mask.to_numpy()], focus_columns),
        "true_positive_feature_means": _mean_features(indexed_features.loc[true_positive_mask.to_numpy()], focus_columns),
        "true_negative_feature_means": _mean_features(indexed_features.loc[true_negative_mask.to_numpy()], focus_columns),
        "false_positive_samples": _sample_errors(reset_data, false_positive_mask.reset_index(drop=True)),
        "false_negative_samples": _sample_errors(reset_data, false_negative_mask.reset_index(drop=True)),
        "hard_legitimate_summary": {
            "tested": len(hard_legitimate),
            "correctly_classified": sum(1 for result in hard_legitimate if not result["is_phishing"]),
            "falsely_flagged": sum(1 for result in hard_legitimate if result["is_phishing"]),
            "results": [
                {
                    "url": result["url"],
                    "result": result["result"],
                    "threat_level": result["threat_level"],
                    "risk_score": result["risk_score"],
                    "model_probability": result["model_probability"],
                }
                for result in hard_legitimate
            ],
        },
        "hard_suspicious_summary": {
            "tested": len(hard_suspicious),
            "detected": sum(1 for result in hard_suspicious if result["is_phishing"]),
            "missed": sum(1 for result in hard_suspicious if not result["is_phishing"]),
            "results": [
                {
                    "url": result["url"],
                    "result": result["result"],
                    "threat_level": result["threat_level"],
                    "risk_score": result["risk_score"],
                    "model_probability": result["model_probability"],
                }
                for result in hard_suspicious
            ],
        },
    }
    output_path = ARTIFACT_DIR / "error_analysis.json"
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
