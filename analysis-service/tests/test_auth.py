from fastapi.testclient import TestClient

from app.main import app


def test_all_scan_modes_reject_direct_unauthenticated_access():
    client = TestClient(app)
    for path in ["/analyze/", "/api/v1/files/scan", "/api/v1/files/scan-batch", "/api/v1/commits/analyze", "/api/v1/language/detect"]:
        response = client.post(path, json={})
        assert response.status_code == 401
        assert response.json()["detail"] == "Authenticated gateway access required."


def test_wrong_token_rejected_and_missing_configuration_fails_closed(monkeypatch):
    client = TestClient(app)
    assert client.post("/api/v1/files/scan", headers={"X-Analysis-Token": "wrong"}, json={}).status_code == 401
    monkeypatch.delenv("ANALYSIS_SERVICE_TOKEN")
    assert client.post("/api/v1/files/scan", json={}).status_code == 503
    assert client.get("/health/").status_code == 200
