from backend.app.services.features import extract_features
from backend.ml.train import build_legitimate_seed, real_dataset


def test_shortened_suspicious_url_features():
    features = extract_features("http://bit.ly/paypal-login-alert")
    assert features["is_shortened_url"] == 1
    assert features["suspicious_word_count"] >= 1
    assert features["has_https"] == 0


def test_safe_url_features():
    features = extract_features("https://www.google.com")
    assert features["has_https"] == 1
    assert features["has_ip"] == 0


def test_real_dataset_balancing_keeps_labels():
    build_legitimate_seed()
    data, sources = real_dataset(balance=True)

    assert {"url", "label"}.issubset(data.columns)
    assert set(data["label"].astype(int).unique()) == {0, 1}
    assert data["label"].value_counts().nunique() == 1
    assert sources


def test_real_dataset_default_keeps_all_available_rows():
    build_legitimate_seed()
    data, sources = real_dataset()

    assert {"url", "label"}.issubset(data.columns)
    assert len(data) >= 600
    assert set(data["label"].astype(int).unique()) == {0, 1}
    assert sources
