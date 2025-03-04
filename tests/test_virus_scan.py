import pytest

def test_virus_scan_clean(client):
    """Test virus scanning a clean file."""
    test_file_content = b"Regular text file content"

    response = client.post("/virus-scan/scan", files={"file": ("clean.txt", test_file_content, "text/plain")})

    assert response.status_code == 200
    assert response.json()["status"] == "clean"

def test_virus_scan_infected(client):
    """Test virus scanning an infected file (simulated)."""
    test_file_content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    response = client.post("/virus-scan/scan", files={"file": ("infected.txt", test_file_content, "text/plain")})

    assert response.status_code == 200
    assert response.json()["status"] == "infected"
