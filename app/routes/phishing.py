from fastapi import APIRouter, HTTPException, Query
from app.services.phishing_service import detect_phishing

router = APIRouter(prefix="", tags=["Phishing Detection"])

@router.post("/check")
def check_phishing(url: str = Query(..., title="URL", description="URL to check for phishing")):
    """
    Check if a given URL is a phishing attempt.
    """
    try:
        is_phishing = detect_phishing(url)
        return {"url": url, "is_phishing": is_phishing}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error detecting phishing: {str(e)}")
