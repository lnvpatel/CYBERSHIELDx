print(f"Loading authentication.py from: {__file__}")
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.db import get_db
from app.schemas import UserCreate, UserResponse
from app.services.auth_service import AuthService
from app.security import verify_email_token
import traceback
import logging

router = APIRouter(prefix="/auth", tags=["Authentication"])
logger = logging.getLogger(__name__)

@router.post("/signup", response_model=UserResponse)
async def register_user(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    try:
        new_user = await AuthService.register_user(db, user_data)
        logger.info(f"Signup successful for user: {new_user.email}")
        return new_user
    except Exception as e:
        await db.rollback()
        logger.exception(f"Signup failed: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/verify-email")
async def verify_email(token: str, db: AsyncSession = Depends(get_db)):
    """Verifies user email using token"""
    try:
        logger.info(f"Verifying email with token: {token}")
        email = verify_email_token(token)
        if not email:
            logger.warning(f"Invalid or expired token: {token}")
            raise HTTPException(status_code=400, detail="Invalid or expired token")
        result = await AuthService.verify_email(db, token)
        logger.info(f"Verification successful for email: {email}")
        return result
    except HTTPException as e:
        logger.error(f"HTTPException during verification: {e}")
        raise e
    except Exception as e:
        logger.exception(f"Unexpected error during verification: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/login")
async def login_user(username: str, password: str, db: AsyncSession = Depends(get_db)):
    """Logs in a user (only if email is verified)"""
    try:
        result = await AuthService.authenticate_user(db, username, password)
        logger.info(f"Login successful for user: {username}")
        return result
    except HTTPException as e:
        logger.error(f"HTTPException during login: {e}")
        raise e
    except Exception as e:
        logger.exception(f"Unexpected error during login: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/logout")
async def logout_user(token: str, db: AsyncSession = Depends(get_db)):
    """Logs out a user by revoking their token"""
    try:
        result = await AuthService.logout_user(db, token)
        logger.info("Logout successful")
        return result
    except HTTPException as e:
        logger.error(f"HTTPException during logout: {e}")
        raise e
    except Exception as e:
        logger.exception(f"Unexpected error during logout: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")