from backend.app.services.features import extract_features, preprocess_url
from backend.ml import train as train_module


class FakeResponse:
    def __init__(self, status_code=302, location=None):
        self.status_code = status_code
        self.headers = {}
        if location:
            self.headers["Location"] = location


class FakeSession:
    def __init__(self, redirects):
        self.redirects = redirects
        self.calls = []

    def head(self, url, allow_redirects=False, timeout=2.0, headers=None):
        self.calls.append(url)
        return self.redirects.get(url, FakeResponse(status_code=200))

    def get(self, url, allow_redirects=False, timeout=2.0, headers=None):
        self.calls.append(url)
        return self.redirects.get(url, FakeResponse(status_code=200))


def test_shortened_suspicious_url_features():
    features = extract_features("http://bit.ly/paypal-login-alert")
    assert features["is_shortened_url"] == 1
    assert features["suspicious_word_count"] >= 1
    assert features["has_https"] == 0


def test_safe_url_features():
    features = extract_features("https://www.google.com")
    assert features["has_https"] == 1
    assert features["has_ip"] == 0


def test_preprocess_decodes_and_canonicalizes_url():
    result = preprocess_url("HTTPS://Example.COM//%70%61%79%70%61%6c#section")

    assert result.original_url == "HTTPS://Example.COM//%70%61%79%70%61%6c#section"
    assert result.normalized_url == "https://example.com/paypal"
    assert result.analysis_url == "https://example.com/paypal"
    assert result.encoded_characters_detected is True


def test_modern_evasion_features_detect_obfuscation_and_brand_signals():
    features = extract_features("http://paypal.com@xn--paypa1-login.com/%68%74%74%70%73%3A%2F%2Fevil.test///verify")

    assert features["has_at_symbol_abuse"] == 1
    assert features["punycode_detected"] == 1
    assert features["url_encoding_detected"] == 1
    assert features["embedded_url_count"] >= 1
    assert features["brand_impersonation_score"] > 0
    assert features["obfuscation_score"] > 0


def test_unicode_homoglyph_features_match_known_brand():
    features = extract_features("http://раураl.com/login")

    assert features["unicode_char_count"] > 0
    assert features["homoglyph_detected"] == 1
    assert features["domain_similarity_score"] >= 0.8


def test_shortener_expansion_records_redirect_chain():
    session = FakeSession({
        "http://bit.ly/paypal-login-alert": FakeResponse(302, "https://login-paypal-alert.example/verify"),
        "https://login-paypal-alert.example/verify": FakeResponse(200),
    })

    result = preprocess_url("http://bit.ly/paypal-login-alert", expand_shorteners=True, session=session)

    assert result.expanded_url == "https://login-paypal-alert.example/verify"
    assert result.redirect_count == 1
    assert result.redirect_chain == [
        "http://bit.ly/paypal-login-alert",
        "https://login-paypal-alert.example/verify",
    ]
    assert result.final_destination_domain == "login-paypal-alert.example"
    assert result.final_domain_differs is True


def test_shortener_expansion_blocks_private_redirect_target():
    session = FakeSession({
        "http://bit.ly/private-login": FakeResponse(302, "http://127.0.0.1/admin"),
    })

    result = preprocess_url("http://bit.ly/private-login", expand_shorteners=True, session=session)

    assert result.expanded_url == "http://bit.ly/private-login"
    assert result.redirect_count == 0
    assert result.security_blocked is True
    assert "blocked_private_redirect" in result.evasion_techniques


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
