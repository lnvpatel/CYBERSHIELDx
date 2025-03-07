from fastapi import APIRouter, HTTPException, Query
from pydantic import IPvAnyAddress
from app.services import ip_service

router = APIRouter(prefix="", tags=["IP Detection"])

@router.get("/check")
def check_ip(ip: IPvAnyAddress = Query(..., description="IP address to check")):
    """
    Check if an IP is suspicious, fetch GeoIP details, and detect VPN/Proxy usage.
    """
    try:
        report = ip_service.analyze_ip(str(ip))

        return {
            "ip": str(ip),
            "is_suspicious": report["suspicious"],  # Match test key
            "is_vpn": report["vpn_proxy"]["vpn"],  # Match test key
            "geoip": report["geoip"],
        }

    except ValueError as ve:
        raise HTTPException(status_code=400, detail=f"Invalid IP address: {ve}")
    except Exception:
        raise HTTPException(status_code=500, detail="Internal server error")
