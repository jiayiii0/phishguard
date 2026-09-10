import os
import tempfile
from pathlib import Path

test_database = Path(tempfile.gettempdir()) / "phishguard_test.db"
os.environ["DATABASE_URL"] = f"sqlite:///{test_database.as_posix()}"

from fastapi.testclient import TestClient

from backend.app.main import app


def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["engine"] == "XGBoost"


def test_scan_endpoint_returns_xgboost_prediction():
    client = TestClient(app)
    response = client.post("/api/v1/scan", json={"url": "http://bit.ly/paypal-login-alert"})
    body = response.json()

    assert response.status_code == 200
    assert body["is_phishing"] is True
    assert body["result"] == "Phishing"
    assert body["threat_level"] in {"Safe", "Low Risk", "Suspicious", "High Risk", "Phishing"}
    assert 0 <= body["risk_score"] <= 100
    assert body["confidence"] > 0
    assert body["indicators"]
    assert body["shap_factors"]
    assert "is_shortened_url" in body["features"]
    assert body["original_url"] == "http://bit.ly/paypal-login-alert"
    assert body["normalized_url"].startswith("http://bit.ly/")
    assert "expanded_url" in body
    assert "redirect_chain" in body
    assert "final_destination" in body
    assert "shortened_url" in body["evasion_techniques"]


def test_scan_endpoint_decodes_obfuscated_url():
    client = TestClient(app)
    response = client.post("/api/v1/scan", json={"url": "https://example.com/%70%61%79%70%61%6c#fragment"})
    body = response.json()

    assert response.status_code == 200
    assert body["normalized_url"] == "https://example.com/paypal"
    assert body["features"]["url_encoding_detected"] == 1
    assert "percent_encoding" in body["evasion_techniques"]


def test_scan_endpoint_uses_threat_feed_match_for_clean_looking_phishing_url(monkeypatch):
    from backend.app.services import predictor as predictor_module

    monkeypatch.setattr(
        predictor_module,
        "lookup_threat_feed",
        lambda url, hostname, timeout=2.0: {
            "matched": True,
            "source": "Phishing.Database",
            "match_type": "url",
        },
        raising=False,
    )

    client = TestClient(app)
    response = client.post("/api/v1/scan", json={"url": "https://www.boutique-dofus.fr"})
    body = response.json()

    assert response.status_code == 200
    assert body["is_phishing"] is True
    assert body["result"] == "Phishing"
    assert body["risk_score"] >= 95
    assert "Known phishing feed match: Phishing.Database URL" in body["indicators"]
    assert body["features"]["known_threat_feed_match"] == 1
    assert body["threat_feed_matched"] is True



def test_domain_only_threat_feed_match_on_known_platform_does_not_force_phishing(monkeypatch):
    from backend.app.services import predictor as predictor_module

    monkeypatch.setattr(
        predictor_module,
        "lookup_threat_feed",
        lambda url, hostname, timeout=2.0: {
            "matched": True,
            "source": "Phishing.Database",
            "match_type": "domain",
        },
        raising=False,
    )

    client = TestClient(app)
    response = client.post(
        "/api/v1/scan",
        json={"url": "https://www.amazon.com/s?k=laptop&utm_campaign=security"},
    )
    body = response.json()

    assert response.status_code == 200
    assert body["features"]["known_platform_domain"] == 1
    assert body["features"]["known_threat_feed_domain_match"] == 1
    assert body["features"]["known_threat_feed_url_match"] == 0
    assert body["is_phishing"] is False
    assert body["risk_score"] < 45
    assert "threat_feed_match" not in body["evasion_techniques"]
def test_dashboard_endpoint_returns_scan_statistics():
    client = TestClient(app)
    client.post("/api/v1/scan", json={"url": "https://www.google.com"})
    response = client.get("/api/v1/dashboard")
    body = response.json()

    assert response.status_code == 200
    assert body["total_scans"] >= 1
    assert "risk_buckets" in body
    assert body["model_metrics"]["algorithm"] == "XGBoost"


def test_scan_blocks_local_urls():
    client = TestClient(app)
    response = client.post("/api/v1/scan", json={"url": "http://127.0.0.1:8000"})
    assert response.status_code == 400


def test_scan_rejects_malformed_urls_with_spaces():
    client = TestClient(app)
    response = client.post("/api/v1/scan", json={"url": "not a url"})
    assert response.status_code == 400


def test_clear_history_endpoint():
    client = TestClient(app)
    client.post("/api/v1/scan", json={"url": "https://www.google.com"})
    response = client.delete("/api/v1/history")

    assert response.status_code == 200
    assert "deleted" in response.json()


def test_long_google_forms_url_is_not_flagged_by_length_alone():
    client = TestClient(app)
    response = client.post(
        "/api/v1/scan",
        json={
            "url": "https://docs.google.com/forms/u/1/d/e/1FAIpQLSfmkF4oiWVWs_Kiu-5igwc_1iLbbF9itc0DpkLmT4OQTlWXcQ/formResponse"
        },
    )
    body = response.json()

    assert response.status_code == 200
    assert body["is_phishing"] is False
    assert body["risk_score"] < 45
    assert body["threat_level"] in {"Safe", "Low Risk"}


def test_long_google_account_url_is_not_flagged_when_domain_context_is_clean():
    client = TestClient(app)
    response = client.post(
        "/api/v1/scan",
        json={
            "url": "https://accounts.google.com/signin/v2/identifier?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2F&flowName=GlifWebSignIn"
        },
    )
    body = response.json()

    assert response.status_code == 200
    assert body["is_phishing"] is False
    assert body["risk_score"] < 45
    assert body["threat_level"] in {"Safe", "Low Risk"}


def test_fake_google_login_domain_remains_phishing():
    client = TestClient(app)
    response = client.post(
        "/api/v1/scan",
        json={"url": "http://google-login-security.example.com/account/verify"},
    )
    body = response.json()

    assert response.status_code == 200
    assert body["is_phishing"] is True
    assert body["risk_score"] >= 70
