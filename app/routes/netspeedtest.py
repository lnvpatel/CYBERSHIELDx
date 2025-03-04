from fastapi import APIRouter
from app.services.speed_service import get_internet_speed

router = APIRouter(prefix="", tags=["Internet Speed Test"])

@router.get("/")
async def internet_speed_test():
    """Route to test internet speed."""
    return get_internet_speed()
