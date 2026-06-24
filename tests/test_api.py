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


def test_clear_history_endpoint():
    client = TestClient(app)
    client.post("/api/v1/scan", json={"url": "https://www.google.com"})
    response = client.delete("/api/v1/history")

    assert response.status_code == 200
    assert "deleted" in response.json()
