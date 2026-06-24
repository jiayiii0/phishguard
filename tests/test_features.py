from backend.app.services.features import extract_features
from backend.ml import train as train_module


def test_shortened_suspicious_url_features():
    features = extract_features("http://bit.ly/paypal-login-alert")
    assert features["is_shortened_url"] == 1
    assert features["suspicious_word_count"] >= 1
    assert features["has_https"] == 0


def test_safe_url_features():
    features = extract_features("https://www.google.com")
    assert features["has_https"] == 1
    assert features["has_ip"] == 0


def configure_test_dataset(tmp_path, monkeypatch):
    phishing = tmp_path / "phishing_database_urls.csv"
    legitimate = tmp_path / "legitimate_urls.csv"
    phishing.write_text(
        "url,label\n"
        "http://login-secure-example.test,1\n"
        "http://verify-account-example.test,1\n"
        "http://bank-alert-example.test,1\n",
        encoding="utf-8",
    )
    legitimate.write_text(
        "url,label\n"
        "https://www.google.com,0\n"
        "https://www.microsoft.com,0\n"
        "https://www.apple.com,0\n"
        "https://www.wikipedia.org,0\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        train_module,
        "REAL_SOURCE_FILES",
        [
            (phishing, 1, "Phishing.Database"),
            (legitimate, 0, "Legitimate URL dataset"),
        ],
    )


def test_real_dataset_balancing_keeps_labels(tmp_path, monkeypatch):
    configure_test_dataset(tmp_path, monkeypatch)
    data, sources = train_module.real_dataset(balance=True)

    assert {"url", "label"}.issubset(data.columns)
    assert set(data["label"].astype(int).unique()) == {0, 1}
    assert data["label"].value_counts().nunique() == 1
    assert sources


def test_real_dataset_default_keeps_all_available_rows(tmp_path, monkeypatch):
    configure_test_dataset(tmp_path, monkeypatch)
    data, sources = train_module.real_dataset()

    assert {"url", "label"}.issubset(data.columns)
    assert len(data) == 7
    assert set(data["label"].astype(int).unique()) == {0, 1}
    assert sources
