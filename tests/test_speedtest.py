import pytest
from fastapi.testclient import TestClient
from app.main import app  # Import FastAPI app

client = TestClient(app)

def test_speedtest():
    response = client.get("/speedtest/")
    assert response.status_code == 200
    data = response.json()

    # Update the assertion to match the actual response keys
    assert "download_speed_mbps" in data
    assert "upload_speed_mbps" in data
    assert isinstance(data["download_speed_mbps"], (int, float))
    assert isinstance(data["upload_speed_mbps"], (int, float))

