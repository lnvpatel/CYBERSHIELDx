import pytest

def test_check_safe_url(client):
    """Test checking a safe URL."""
    response = client.post("/phishing/check?url=https://example.com")
    
    data = response.json()

    assert response.status_code == 200
    data = response.json()
    assert data["is_phishing"]["is_phishing"] is False  # ✅ Safe URL

def test_check_phishing_url(client):
    """Test checking a known phishing URL."""
    response = client.post("/phishing/check?url=http://fake-bank-login.com")
    
    data = response.json()

    assert response.status_code == 200
    data = response.json()
    assert data["is_phishing"]["is_phishing"] is True  # 🛑 Suspicious URL


