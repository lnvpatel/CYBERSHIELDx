import pytest

def test_file_scan_clean(client):
    """Test scanning a clean file."""
    test_file_content = b"Hello, this is a clean file"
    
    response = client.post("/file-scan/upload/", files={"file": ("clean.txt", test_file_content, "text/plain")})
    
    assert response.status_code == 200
    assert response.json()["status"] == "clean"

def test_file_scan_infected(client):
    """Test scanning an infected file (simulated)."""
    test_file_content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    response = client.post("/file-scan/upload/", files={"file": ("virus.txt", test_file_content, "text/plain")})
    
    assert response.status_code == 200
    assert response.json()["status"] == "infected"
