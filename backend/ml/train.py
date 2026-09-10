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
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import RandomizedSearchCV, cross_val_score, train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from backend.app.services.features import extract_features, hostname_from_url, normalize_url
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
    (DATA_DIR / "legitimate_hard_negatives.csv", 0, "Legitimate hard-negative URL set"),
    (DATA_DIR / "broad_legitimate_hard_negatives.csv", 0, "Broad legitimate hard-negative URL set"),
    (DATA_DIR / "targeted_hard_negatives.csv", 0, "Targeted external hard-negative URL set"),
    (DATA_DIR / "targeted_missed_phishing.csv", 1, "Targeted missed phishing URL set"),
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


def clean_labeled_dataset(frame: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, int]]:
    report = {
        "raw_rows": int(len(frame)),
        "missing_rows_removed": 0,
        "malformed_rows_removed": 0,
        "exact_duplicate_urls_removed": 0,
        "normalized_duplicate_urls_removed": 0,
        "conflicting_normalized_urls_removed": 0,
    }
    frame = frame.dropna(subset=["url", "label"]).copy()
    report["missing_rows_removed"] = report["raw_rows"] - int(len(frame))
    frame["url"] = frame["url"].astype(str).str.strip()
    frame["label"] = frame["label"].astype(int)
    before_exact = len(frame)
    frame = frame.drop_duplicates("url")
    report["exact_duplicate_urls_removed"] = before_exact - int(len(frame))

    frame["normalized_url"] = frame["url"].map(normalize_url)
    frame["hostname"] = frame["normalized_url"].map(hostname_from_url)
    before_malformed = len(frame)
    frame = frame[frame["hostname"].astype(bool)].copy()
    report["malformed_rows_removed"] = before_malformed - int(len(frame))

    label_counts = frame.groupby("normalized_url")["label"].nunique()
    conflicting_urls = set(label_counts[label_counts > 1].index)
    if conflicting_urls:
        frame = frame[~frame["normalized_url"].isin(conflicting_urls)].copy()
    report["conflicting_normalized_urls_removed"] = len(conflicting_urls)

    before_normalized = len(frame)
    frame = frame.drop_duplicates("normalized_url")
    report["normalized_duplicate_urls_removed"] = before_normalized - int(len(frame))
    frame["url"] = frame["normalized_url"]
    return frame[["url", "label", "hostname"]].reset_index(drop=True), report


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


def real_dataset(balance: bool = False, return_report: bool = False) -> tuple[pd.DataFrame, list[str]] | tuple[pd.DataFrame, list[str], dict[str, int]]:
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
    frame = pd.concat(frames, ignore_index=True)
    if frame.empty:
        raise FileNotFoundError(
            "No training data found. Add CSV files under backend/ml/data or run with --demo."
        )
    frame, cleaning_report = clean_labeled_dataset(frame)
    counts = frame["label"].astype(int).value_counts()
    if set(counts.index) != {0, 1}:
        raise ValueError("Training requires both labels: 0 legitimate and 1 phishing.")
    cleaning_report["rows_after_cleaning"] = int(len(frame))
    cleaning_report["legitimate_rows_after_cleaning"] = int(counts.get(0, 0))
    cleaning_report["phishing_rows_after_cleaning"] = int(counts.get(1, 0))
    if balance:
        smallest = int(counts.min())
        frame = pd.concat(
            [group.sample(n=smallest, random_state=42) for _, group in frame.groupby("label")],
            ignore_index=True,
        )
    frame = frame.sample(frac=1, random_state=42).reset_index(drop=True)
    cleaning_report["rows_after_balancing"] = int(len(frame))
    cleaning_report["legitimate_rows_after_balancing"] = int((frame["label"].astype(int) == 0).sum())
    cleaning_report["phishing_rows_after_balancing"] = int((frame["label"].astype(int) == 1).sum())
    if return_report:
        return frame, sources_used, cleaning_report
    return frame, sources_used


def split_by_hostname(
    data: pd.DataFrame,
    test_size: float = 0.15,
    validation_size: float = 0.15,
    random_state: int = 42,
) -> tuple[pd.Index, pd.Index, pd.Index, dict[str, int | str]]:
    group_labels = data.groupby("hostname")["label"].agg(lambda values: int(values.mode().iloc[0]))
    stratify = group_labels if group_labels.value_counts().min() >= 2 else None
    train_val_groups, test_groups = train_test_split(
        group_labels.index,
        test_size=test_size,
        random_state=random_state,
        stratify=stratify,
    )
    remaining_labels = group_labels.loc[train_val_groups]
    validation_fraction = validation_size / (1 - test_size)
    remaining_stratify = remaining_labels if remaining_labels.value_counts().min() >= 2 else None
    train_groups, validation_groups = train_test_split(
        remaining_labels.index,
        test_size=validation_fraction,
        random_state=random_state,
        stratify=remaining_stratify,
    )

    train_mask = data["hostname"].isin(train_groups)
    validation_mask = data["hostname"].isin(validation_groups)
    test_mask = data["hostname"].isin(test_groups)
    split_report = {
        "method": "hostname-grouped split with stratified group labels",
        "random_seed": random_state,
        "train_size": int(train_mask.sum()),
        "validation_size": int(validation_mask.sum()),
        "final_test_size": int(test_mask.sum()),
        "train_hosts": int(len(train_groups)),
        "validation_hosts": int(len(validation_groups)),
        "final_test_hosts": int(len(test_groups)),
        "train_validation_host_overlap": int(len(set(train_groups) & set(validation_groups))),
        "train_test_host_overlap": int(len(set(train_groups) & set(test_groups))),
        "validation_test_host_overlap": int(len(set(validation_groups) & set(test_groups))),
    }
    return data.index[train_mask], data.index[validation_mask], data.index[test_mask], split_report


def threshold_metrics(y_true, probabilities, threshold: float) -> dict[str, float | int | list[list[int]]]:
    predictions = (probabilities >= threshold).astype(int)
    matrix = confusion_matrix(y_true, predictions).tolist()
    tn, fp = matrix[0]
    fn, tp = matrix[1]
    return {
        "threshold": round(float(threshold), 2),
        "accuracy": round(float(accuracy_score(y_true, predictions)), 6),
        "precision": round(float(precision_score(y_true, predictions, zero_division=0)), 6),
        "recall": round(float(recall_score(y_true, predictions, zero_division=0)), 6),
        "f1": round(float(f1_score(y_true, predictions, zero_division=0)), 6),
        "false_positive_rate": round(float(fp / max(fp + tn, 1)), 6),
        "false_negative_rate": round(float(fn / max(fn + tp, 1)), 6),
        "confusion_matrix": matrix,
    }



def select_threshold(validation_thresholds: list[dict[str, float | int | list[list[int]]]]) -> dict[str, float | int | list[list[int]]]:
    strong_recall_low_fp = [
        score
        for score in validation_thresholds
        if float(score["recall"]) >= 0.92 and float(score["false_positive_rate"]) <= 0.03
    ]
    if strong_recall_low_fp:
        return max(
            strong_recall_low_fp,
            key=lambda score: (float(score["precision"]), float(score["recall"]), float(score["f1"])),
        )

    high_recall = [score for score in validation_thresholds if float(score["recall"]) >= 0.93]
    return max(
        high_recall or validation_thresholds,
        key=lambda score: (float(score["f1"]), float(score["precision"]), -float(score["false_positive_rate"])),
    )

def train(demo: bool = False, tune: bool = False, balance: bool = False, cv_folds: int = 3) -> dict:
    if demo:
        data = demo_dataset()
        sources_used = ["Synthetic local demo dataset: 1440 generated URLs"]
        data, cleaning_report = clean_labeled_dataset(data)
    else:
        data, sources_used, cleaning_report = real_dataset(balance=balance, return_report=True)

    features = pd.DataFrame([extract_features(url, include_network=False) for url in data["url"]])
    labels = data["label"].astype(int)
    feature_columns = list(features.columns)

    train_index, validation_index, test_index, split_report = split_by_hostname(
        data,
        test_size=0.15,
        validation_size=0.15,
        random_state=42,
    )
    x_train = features.loc[train_index]
    y_train = labels.loc[train_index]
    x_validation = features.loc[validation_index]
    y_validation = labels.loc[validation_index]
    x_test = features.loc[test_index]
    y_test = labels.loc[test_index]

    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_validation_scaled = scaler.transform(x_validation)
    x_test_scaled = scaler.transform(x_test)

    train_label_counts = y_train.value_counts().to_dict()
    label_counts = labels.value_counts().to_dict()
    training_negative = max(int(train_label_counts.get(0, 1)), 1)
    training_positive = max(int(train_label_counts.get(1, 1)), 1)
    scale_pos_weight = training_negative / training_positive
    negative = max(int(label_counts.get(0, 1)), 1)
    positive = max(int(label_counts.get(1, 1)), 1)

    model = XGBClassifier(
        n_estimators=240,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.9,
        colsample_bytree=0.9,
        min_child_weight=3,
        gamma=0.1,
        reg_alpha=0.05,
        reg_lambda=1.2,
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
                "gamma": [0, 0.05, 0.1, 0.2],
                "reg_alpha": [0, 0.05, 0.1],
                "reg_lambda": [0.8, 1.0, 1.2, 1.5],
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

    validation_probabilities = model.predict_proba(x_validation_scaled)[:, 1]
    threshold_candidates = np.arange(0.20, 0.81, 0.01)
    validation_thresholds = [
        threshold_metrics(y_validation, validation_probabilities, threshold)
        for threshold in threshold_candidates
    ]
    selected = select_threshold(validation_thresholds)
    selected_threshold = float(selected["threshold"])

    prediction_started = time.perf_counter()
    probabilities = model.predict_proba(x_test_scaled)[:, 1]
    prediction_ms_per_url = round(((time.perf_counter() - prediction_started) / max(len(x_test_scaled), 1)) * 1000, 4)
    predictions = (probabilities >= selected_threshold).astype(int)
    cv_scores = cross_val_score(model, x_train_scaled, y_train, cv=cv_folds, scoring="f1")
    test_matrix = confusion_matrix(y_test, predictions).tolist()
    tn, fp = test_matrix[0]
    fn, tp = test_matrix[1]
    try:
        roc_auc = float(roc_auc_score(y_test, probabilities))
    except ValueError:
        roc_auc = 0.0
    try:
        pr_auc = float(average_precision_score(y_test, probabilities))
    except ValueError:
        pr_auc = 0.0

    feature_importance = sorted(
        [
            {"feature": name, "importance": round(float(importance), 6)}
            for name, importance in zip(feature_columns, model.feature_importances_)
        ],
        key=lambda item: item["importance"],
        reverse=True,
    )

    metrics = {
        "algorithm": "XGBoost",
        "training_sources": sources_used,
        "mode": "demo" if demo else "real",
        "dataset_size": int(len(data)),
        "class_distribution": {str(k): int(v) for k, v in labels.value_counts().to_dict().items()},
        "balanced_training": bool(balance),
        "feature_count": int(len(feature_columns)),
        "data_cleaning": cleaning_report,
        "split": split_report,
        "train_validation_test_split": "hostname-grouped 70:15:15",
        "cross_validation_folds": int(cv_folds),
        "hyperparameter_tuning": "RandomizedSearchCV" if tune else "fixed baseline parameters",
        "best_params": best_params or model.get_params(),
        "selected_threshold": selected_threshold,
        "threshold_selection": (
            "selected on validation data before final testing; preferred recall >= 0.92 "
            "with false-positive rate <= 0.03 and strongest precision, otherwise best validation F1 under a high-recall constraint"
        ),
        "validation_thresholds": validation_thresholds,
        "validation_metrics_at_selected_threshold": selected,
        "final_test_metrics": threshold_metrics(y_test, probabilities, selected_threshold),
        "feature_importance": feature_importance[:15],
        "training_seconds": training_seconds,
        "prediction_ms_per_url": prediction_ms_per_url,
        "accuracy": round(float(accuracy_score(y_test, predictions)), 6),
        "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 6),
        "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 6),
        "f1_score": round(float(f1_score(y_test, predictions, zero_division=0)), 6),
        "false_positive_rate": round(float(fp / max(fp + tn, 1)), 6),
        "false_negative_rate": round(float(fn / max(fn + tp, 1)), 6),
        "roc_auc": round(roc_auc, 6),
        "pr_auc": round(pr_auc, 6),
        "cv_f1_mean": round(float(cv_scores.mean()), 4),
        "confusion_matrix": test_matrix,
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
