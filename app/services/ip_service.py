import requests

# Example blacklisted IPs (Replace with a proper list or database)
BLACKLISTED_IPS = {
    "192.168.1.1": "Known malicious IP",
    "203.0.113.5": "Suspicious activity detected",
    "45.33.32.156": "Flagged as malicious",
    "194.34.233.199":"suspicous"
}

def get_geoip_data(ip_address: str) -> dict:
    """
    Fetch GeoIP details for a given IP address using ip-api.com.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()

        if data.get("status") == "fail":
            return {"error": "Invalid IP or lookup failed"}

        return {
            "country": data.get("country"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
        }
    except Exception:
        return {"error": "GeoIP service unavailable"}

def detect_vpn_proxy(ip_address: str) -> dict:
    """
    Detect if an IP is using a VPN or Proxy using ip-api.com.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=proxy,hosting,mobile")
        data = response.json()

        return {
            "vpn": data.get("proxy", False),
            "hosting_service": data.get("hosting", False),
            "mobile_network": data.get("mobile", False)
        }
    except Exception:
        return {"error": "VPN/Proxy detection service unavailable"}

def analyze_ip(ip_address: str) -> dict:
    """
    Check if an IP is suspicious, fetch GeoIP details, and detect VPN/Proxy usage.
    """
    is_suspicious = ip_address in BLACKLISTED_IPS
    details = BLACKLISTED_IPS.get(ip_address, "No known threats")

    geoip_data = get_geoip_data(ip_address)
    vpn_proxy_data = detect_vpn_proxy(ip_address)

    return {
        "suspicious": is_suspicious,
        "details": details,
        "geoip": geoip_data,
        "vpn_proxy": vpn_proxy_data
    }
