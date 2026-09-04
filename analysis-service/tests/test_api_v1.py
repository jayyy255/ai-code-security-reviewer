import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "scanner-service"
    assert "modes" in data

def test_v1_file_scan_paste():
    payload = {
        "code": "import os\nos.system('ping ' + target)",
        "language": "python",
        "file_name": "network.py",
        "ephemeral": True
    }
    response = client.post("/api/v1/files/scan", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "analysis_id" in data
    assert data["scan_type"] == "paste"
    assert len(data["findings"]) > 0
    assert data["privacy_metadata"]["ephemeral_scan"] is True
    assert data["malware_status"] is not None
    assert data["malware_status"]["status"] in ("unavailable", "clean", "failed", "infected")

def test_v1_file_scan_batch():
    payload = {
        "files": [
            {
                "filename": "server.js",
                "content": "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';"
            },
            {
                "filename": "util.py",
                "content": "import os\nprint('safe')"
            }
        ],
        "ephemeral": False
    }
    response = client.post("/api/v1/files/scan-batch", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scan_type"] == "upload"
    assert len(data["files_analyzed"]) == 2
    assert len(data["findings"]) > 0

def test_v1_empty_code_rejection():
    payload = {
        "code": "   ",
        "language": "python"
    }
    response = client.post("/api/v1/files/scan", json=payload)
    assert response.status_code == 422 # Pydantic validation error
