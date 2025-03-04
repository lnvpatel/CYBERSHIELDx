import pytest

def test_ip_safe(client):
    """Test checking a safe IP."""
    response = client.get("/ip-detection/check?ip=8.8.8.8")  # Google's Public DNS

    assert response.status_code == 200
    assert response.json()["is_suspicious"] is False  # ✅ Safe IP
    assert response.json()["is_vpn"] is False  # ✅ Not a VPN

def test_ip_suspicious(client):
    """Test checking a known suspicious IP."""
    response = client.get("/ip-detection/check?ip=194.34.233.199")  # Example of a flagged IP

    assert response.status_code == 200
    assert response.json()["is_suspicious"] is True  # 🛑 Malicious IP
    assert response.json()["is_vpn"] is True  # 🛑 VPN detected
