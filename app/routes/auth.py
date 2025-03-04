from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.db import get_db
from app.schemas import UserCreate, UserResponse
from app.services.auth_service import AuthService
from app.security import verify_email_token

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/signup", response_model=UserResponse)
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """Registers a new user (email verification required)"""
    return AuthService.register_user(db, user_data)

@router.post("/verify-email")
def verify_email(token: str, db: Session = Depends(get_db)):
    """Verifies user email using token"""
    email = verify_email_token(token)
    if not email:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    return AuthService.verify_email(db, email)

@router.post("/login")
def login_user(username: str, password: str, db: Session = Depends(get_db)):
    """Logs in a user (only if email is verified)"""
    return AuthService.authenticate_user(db, username, password)

@router.post("/logout")
def logout_user(token: str):
    """Logs out a user by revoking their token"""
    return AuthService.logout_user(token)
