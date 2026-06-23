from __future__ import annotations

import argparse
import bz2
import gzip
import io
import json
import os
import time
from pathlib import Path
from zipfile import ZipFile

import joblib
import numpy as np
import pandas as pd
import requests
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import RandomizedSearchCV, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from backend.app.services.features import extract_features
ML_DIR = Path(__file__).resolve().parent
DATA_DIR = ML_DIR / "data"
ARTIFACT_DIR = ML_DIR / "artifacts"
DATA_DIR.mkdir(parents=True, exist_ok=True)
ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

PHISHTANK_URL = "http://data.phishtank.com/data/online-valid.csv"
PHISHTANK_COMPRESSED_URL = "http://data.phishtank.com/data/online-valid.csv.bz2"
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"
UMBRELLA_TOP_1M_URL = "http://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip"
MAJESTIC_MILLION_URL = "https://downloads.majestic.com/majestic_million.csv"
PHISHING_DATABASE_ACTIVE_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt"
PHISHING_DATABASE_ACTIVE_NOW_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE-NOW.txt"
REAL_SOURCE_FILES = [
    (DATA_DIR / "phishtank_urls.csv", 1, "PhishTank"),
    (DATA_DIR / "phishing_database_urls.csv", 1, "Phishing.Database"),
    (DATA_DIR / "openphish_urls.csv", 1, "OpenPhish"),
    (DATA_DIR / "uci_phishing_urls.csv", None, "UCI Phishing Websites Dataset"),
    (DATA_DIR / "kaggle_phishing_urls.csv", None, "Kaggle phishing URL datasets"),
    (DATA_DIR / "legitimate_urls.csv", 0, "Legitimate URL dataset"),
]
PHISHTANK_COLUMNS = {"phish_id", "url", "phish_detail_url", "submission_time", "verified", "verification_time", "online", "target"}

DEMO_PHISHING = [
    "http://login-secure-account-verification.com",
    "http://192.168.1.10/paypal/verify-account",
    "http://bit.ly/paypal-login-alert",
    "http://tinyurl.com/bank-secure-update",
    "http://xn--paypa1-login.com/verify",
    "http://microsoft-security-check.xyz/signin",
    "http://google.account.verify.click/session",
    "http://secure-login-maybank2u.top/account",
    "http://paypal.com@malicious-login.example/verify",
    "http://example.com/%2Flogin%3Dsecure%40verify",
    "http://appleid.support-unlock-account.cyou/login",
    "http://bank-update-security-alert.com/login",
] * 60

DEMO_LEGITIMATE = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.utar.edu.my",
    "https://www.maybank2u.com.my",
    "https://www.wikipedia.org",
    "https://www.microsoft.com/security",
    "https://www.apple.com",
    "https://www.github.com",
    "https://www.linkedin.com",
    "https://www.cimb.com.my",
    "https://www.paypal.com",
    "https://support.google.com/accounts",
] * 60

LEGITIMATE_SEED_DOMAINS = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.amazon.com",
    "https://www.wikipedia.org",
    "https://www.github.com",
    "https://www.linkedin.com",
    "https://www.paypal.com",
    "https://www.netflix.com",
    "https://www.cloudflare.com",
    "https://www.mozilla.org",
    "https://www.python.org",
    "https://www.fastapi.tiangolo.com",
    "https://www.postgresql.org",
    "https://www.kaggle.com",
    "https://archive.ics.uci.edu",
    "https://www.maybank2u.com.my",
    "https://www.cimb.com.my",
    "https://www.publicbank.com.my",
    "https://www.shopee.com.my",
    "https://www.lazada.com.my",
    "https://www.touchngo.com.my",
    "https://www.mybsn.com.my",
    "https://www.bankislam.com",
]


def save_url_frame(urls: list[str], label: int, output: Path) -> pd.DataFrame:
    frame = pd.DataFrame({"url": urls}).dropna().drop_duplicates()
    frame["label"] = label
    frame.to_csv(output, index=False)
    return frame


def download_phishtank() -> None:
    app_key = os.getenv("PHISHTANK_APP_KEY", "").strip()
    url = (
        f"http://data.phishtank.com/data/{app_key}/online-valid.csv.bz2"
        if app_key
        else PHISHTANK_COMPRESSED_URL
    )
    response = requests.get(url, headers={"User-Agent": "phishtank/phishguard-xgboost"}, timeout=120)
    response.raise_for_status()
    raw_path = DATA_DIR / ("phishtank_online_valid.csv.bz2" if url.endswith(".bz2") else "phishtank_online_valid.csv")
    raw_path.write_bytes(response.content)
    import_phishtank_file(raw_path)


def import_phishtank_file(path: Path) -> pd.DataFrame:
    if not path.exists():
        raise FileNotFoundError(f"PhishTank file not found: {path}")
    suffixes = "".join(path.suffixes).lower()
    if suffixes.endswith(".csv.bz2"):
        raw = pd.read_csv(io.BytesIO(bz2.decompress(path.read_bytes())))
    elif suffixes.endswith(".csv.gz"):
        raw = pd.read_csv(io.BytesIO(gzip.decompress(path.read_bytes())))
    else:
        raw = pd.read_csv(path)
    if "url" not in raw.columns:
        raise ValueError("PhishTank file did not contain a url column.")
    if "verified" in raw.columns:
        raw = raw[raw["verified"].astype(str).str.lower().eq("yes")]
    if "online" in raw.columns:
        raw = raw[raw["online"].astype(str).str.lower().eq("yes")]
    return save_url_frame(raw["url"].astype(str).tolist(), 1, DATA_DIR / "phishtank_urls.csv")


def download_openphish() -> None:
    response = requests.get(OPENPHISH_FEED_URL, timeout=60)
    response.raise_for_status()
    urls = [line.strip() for line in response.text.splitlines() if line.strip().startswith(("http://", "https://"))]
    save_url_frame(urls, 1, DATA_DIR / "openphish_urls.csv")


def download_phishing_database(active_now: bool = False) -> pd.DataFrame:
    url = PHISHING_DATABASE_ACTIVE_NOW_URL if active_now else PHISHING_DATABASE_ACTIVE_URL
    response = requests.get(url, headers={"User-Agent": "PhishGuard-XGBoost"}, timeout=180)
    response.raise_for_status()
    urls = []
    for line in response.text.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        if cleaned.startswith(("http://", "https://")):
            urls.append(cleaned)
    return save_url_frame(urls, 1, DATA_DIR / "phishing_database_urls.csv")


def build_legitimate_seed() -> None:
    urls = []
    paths = [
        "",
        "/",
        "/about",
        "/contact",
        "/support",
        "/security",
        "/privacy",
        "/help",
        "/news",
        "/products",
        "/login",
        "/account",
    ]
    for domain in LEGITIMATE_SEED_DOMAINS:
        for path in paths:
            urls.append(domain.rstrip("/") + path)
    save_url_frame(urls, 0, DATA_DIR / "legitimate_urls.csv")


def download_umbrella_legitimate(limit: int = 50000) -> None:
    try:
        response = requests.get(UMBRELLA_TOP_1M_URL, timeout=120)
        response.raise_for_status()
        with ZipFile(io.BytesIO(response.content)) as archive:
            csv_name = archive.namelist()[0]
            raw = pd.read_csv(archive.open(csv_name), header=None, names=["rank", "domain"])
    except Exception:
        response = requests.get(MAJESTIC_MILLION_URL, timeout=120)
        response.raise_for_status()
        raw = pd.read_csv(io.StringIO(response.text))
        domain_column = "Domain" if "Domain" in raw.columns else raw.columns[-1]
        raw = raw.rename(columns={domain_column: "domain"})
    raw = raw.dropna().head(limit)
    urls = ["https://" + str(domain).strip().lower().rstrip("/") for domain in raw["domain"] if "." in str(domain)]
    save_url_frame(urls, 0, DATA_DIR / "legitimate_urls.csv")


def load_csv_if_exists(path: Path, label: int | None = None) -> pd.DataFrame:
    if not path.exists():
        return pd.DataFrame(columns=["url", "label"])
    frame = pd.read_csv(path)
    if "url" not in frame.columns:
        raise ValueError(f"{path} must contain a url column.")
    if "label" not in frame.columns:
        if label is None:
            raise ValueError(f"{path} must contain a label column.")
        frame["label"] = label
    return frame[["url", "label"]].dropna()


def demo_dataset() -> pd.DataFrame:
    phishing_urls = []
    legitimate_urls = []
    for index in range(1, 61):
        for url in DEMO_PHISHING[:12]:
            suffix = f"/session/{index}?verify=account&token={1000 + index}"
            phishing_urls.append(url.rstrip("/") + suffix)
        for url in DEMO_LEGITIMATE[:12]:
            suffix = f"/page/{index}" if index % 2 == 0 else f"?ref={index}"
            legitimate_urls.append(url.rstrip("/") + suffix)
    phishing = pd.DataFrame({"url": phishing_urls, "label": 1})
    legitimate = pd.DataFrame({"url": legitimate_urls, "label": 0})
    return pd.concat([phishing, legitimate], ignore_index=True)


def real_dataset(balance: bool = False) -> tuple[pd.DataFrame, list[str]]:
    frames = []
    sources_used = []
    for path, label, source_name in REAL_SOURCE_FILES:
        loaded = load_csv_if_exists(path, label)
        if not loaded.empty:
            frames.append(loaded)
            sources_used.append(f"{source_name}: {len(loaded)} rows from {path.name}")
    if not frames:
        raise FileNotFoundError(
            "No training data found. Add CSV files under backend/ml/data or run with --demo."
        )
    frame = pd.concat(frames, ignore_index=True).dropna().drop_duplicates("url")
    if frame.empty:
        raise FileNotFoundError(
            "No training data found. Add CSV files under backend/ml/data or run with --demo."
        )
    counts = frame["label"].astype(int).value_counts()
    if set(counts.index) != {0, 1}:
        raise ValueError("Training requires both labels: 0 legitimate and 1 phishing.")
    if balance:
        smallest = int(counts.min())
        frame = pd.concat(
            [group.sample(n=smallest, random_state=42) for _, group in frame.groupby("label")],
            ignore_index=True,
        )
    return frame.sample(frac=1, random_state=42).reset_index(drop=True), sources_used


def train(demo: bool = False, tune: bool = False, balance: bool = False, cv_folds: int = 3) -> dict:
    if demo:
        data = demo_dataset()
        sources_used = ["Synthetic local demo dataset: 1440 generated URLs"]
    else:
        data, sources_used = real_dataset(balance=balance)
    data = data.dropna().drop_duplicates("url")
    data["label"] = data["label"].astype(int)

    features = pd.DataFrame([extract_features(url, include_network=False) for url in data["url"]])
    labels = data["label"]
    feature_columns = list(features.columns)

    x_train, x_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, random_state=42, stratify=labels
    )
    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)

    label_counts = labels.value_counts().to_dict()
    negative = max(int(label_counts.get(0, 1)), 1)
    positive = max(int(label_counts.get(1, 1)), 1)
    scale_pos_weight = negative / positive

    model = XGBClassifier(
        n_estimators=120,
        max_depth=4,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="logloss",
        random_state=42,
        n_jobs=1,
        scale_pos_weight=scale_pos_weight,
        verbosity=0,
    )

    training_started = time.perf_counter()
    best_params = None
    if tune:
        search = RandomizedSearchCV(
            estimator=model,
            param_distributions={
                "n_estimators": [120, 180, 240, 320],
                "max_depth": [3, 4, 5, 6],
                "learning_rate": [0.03, 0.05, 0.08, 0.12],
                "subsample": [0.75, 0.85, 0.95, 1.0],
                "colsample_bytree": [0.75, 0.85, 0.95, 1.0],
                "min_child_weight": [1, 3, 5],
            },
            n_iter=12,
            scoring="f1",
            cv=min(cv_folds, 5),
            random_state=42,
            n_jobs=1,
        )
        search.fit(x_train_scaled, y_train)
        model = search.best_estimator_
        best_params = search.best_params_
    else:
        model.fit(x_train_scaled, y_train)
    training_seconds = round(time.perf_counter() - training_started, 4)
    prediction_started = time.perf_counter()
    probabilities = model.predict_proba(x_test_scaled)[:, 1]
    prediction_ms_per_url = round(((time.perf_counter() - prediction_started) / max(len(x_test_scaled), 1)) * 1000, 4)
    cv_scores = cross_val_score(model, scaler.transform(features), labels, cv=cv_folds, scoring="f1")

    threshold_candidates = np.arange(0.20, 0.81, 0.01)
    threshold_scores = []
    for threshold in threshold_candidates:
        candidate_predictions = (probabilities >= threshold).astype(int)
        threshold_scores.append({
            "threshold": round(float(threshold), 2),
            "precision": float(precision_score(y_test, candidate_predictions, zero_division=0)),
            "recall": float(recall_score(y_test, candidate_predictions, zero_division=0)),
            "f1": float(f1_score(y_test, candidate_predictions, zero_division=0)),
        })
    high_recall_scores = [score for score in threshold_scores if score["recall"] >= 0.95]
    selected = max(high_recall_scores or threshold_scores, key=lambda score: (score["f1"], score["precision"]))
    selected_threshold = float(selected["threshold"])
    predictions = (probabilities >= selected_threshold).astype(int)

    metrics = {
        "algorithm": "XGBoost",
        "training_sources": sources_used,
        "mode": "demo" if demo else "real",
        "dataset_size": int(len(data)),
        "class_distribution": {str(k): int(v) for k, v in labels.value_counts().to_dict().items()},
        "balanced_training": bool(balance),
        "feature_count": int(len(feature_columns)),
        "train_test_split": "80:20 stratified",
        "cross_validation_folds": int(cv_folds),
        "hyperparameter_tuning": "RandomizedSearchCV" if tune else "fixed baseline parameters",
        "best_params": best_params or model.get_params(),
        "selected_threshold": selected_threshold,
        "threshold_selection": "best F1 with recall >= 0.95 when available",
        "training_seconds": training_seconds,
        "prediction_ms_per_url": prediction_ms_per_url,
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y_test, predictions, zero_division=0)), 4),
        "cv_f1_mean": round(float(cv_scores.mean()), 4),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "classification_report": classification_report(y_test, predictions, zero_division=0),
    }

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, ARTIFACT_DIR / "xgboost_model.joblib")
    joblib.dump(scaler, ARTIFACT_DIR / "scaler.joblib")
    joblib.dump(feature_columns, ARTIFACT_DIR / "feature_columns.joblib")
    (ARTIFACT_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", action="store_true", help="Train a local demo model.")
    parser.add_argument("--download-phishtank", action="store_true", help="Download PhishTank feed.")
    parser.add_argument("--phishtank-file", type=Path, help="Import an existing PhishTank CSV/CSV.GZ/CSV.BZ2 file.")
    parser.add_argument("--download-openphish", action="store_true", help="Download OpenPhish feed.")
    parser.add_argument("--download-phishing-database", action="store_true", help="Download Phishing.Database active phishing URLs.")
    parser.add_argument("--phishing-database-active-now", action="store_true", help="Use Phishing.Database ACTIVE-NOW feed instead of ACTIVE feed.")
    parser.add_argument("--build-legitimate-seed", action="store_true", help="Build a curated legitimate URL seed CSV.")
    parser.add_argument("--download-umbrella-legitimate", action="store_true", help="Download Cisco Umbrella top domains as legitimate URLs.")
    parser.add_argument("--legitimate-limit", type=int, default=50000, help="Maximum legitimate URLs to keep from downloaded top domains.")
    parser.add_argument("--balance", action="store_true", help="Downsample classes to equal size. Off by default to use as much data as possible.")
    parser.add_argument("--tune", action="store_true", help="Run RandomizedSearchCV hyperparameter tuning for XGBoost.")
    parser.add_argument("--cv-folds", type=int, default=3, help="Number of cross-validation folds.")
    parser.add_argument("--download-only", action="store_true", help="Download/build datasets without training.")
    args = parser.parse_args()

    if args.download_phishtank:
        try:
            download_phishtank()
        except Exception as exc:
            print(f"PhishTank download skipped: {exc}")
    if args.phishtank_file:
        imported = import_phishtank_file(args.phishtank_file)
        print(f"Imported PhishTank URLs: {len(imported)}")
    if args.download_openphish:
        try:
            download_openphish()
        except Exception as exc:
            print(f"OpenPhish download skipped: {exc}")
    if args.download_phishing_database:
        try:
            imported = download_phishing_database(active_now=args.phishing_database_active_now)
            print(f"Downloaded Phishing.Database URLs: {len(imported)}")
        except Exception as exc:
            print(f"Phishing.Database download skipped: {exc}")
    if args.download_umbrella_legitimate:
        try:
            download_umbrella_legitimate(args.legitimate_limit)
        except Exception as exc:
            print(f"Legitimate domain download skipped: {exc}")
    if args.build_legitimate_seed:
        build_legitimate_seed()
    if args.download_only:
        return
    metrics = train(demo=args.demo, tune=args.tune, balance=args.balance, cv_folds=args.cv_folds)
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
