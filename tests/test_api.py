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
