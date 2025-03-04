from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from fastapi import HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.config import settings
from app.db import get_db
from app.models import User, UserRole  # ✅ Ensure UserRole is imported
from passlib.context import CryptContext
import logging

# ✅ Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ✅ OAuth2 authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# ✅ Password hashing context (For secure password storage)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ✅ JWT Token Management

def create_access_token(user: User, expires_delta: Optional[timedelta] = None) -> str:
    """Create an access token with token versioning."""
    to_encode = {
        "sub": user.username,
        "token_version": user.token_version,  # Include token version
        "exp": datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)),
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_refresh_token(user: User, expires_delta: Optional[timedelta] = None) -> str:
    """Create a refresh token with token versioning."""
    to_encode = {
        "sub": user.username,
        "token_version": user.token_version,  # Include token version
        "exp": datetime.now(timezone.utc) + (expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)),
    }
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

# ✅ Email Verification Token

def create_email_verification_token(email: str) -> str:
    """Generate a token for email verification."""
    expire = datetime.now(timezone.utc) + timedelta(hours=24)
    to_encode = {"sub": email, "exp": expire}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def verify_email_token(token: str) -> Optional[str]:
    """Verify the email verification token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

# ✅ Token Verification

def verify_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Verify and decode a JWT token with token versioning."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        token_version: int = payload.get("token_version", 0)

        if not username:
            raise HTTPException(status_code=401, detail="Invalid token: Missing username")

        user = db.query(User).filter(User.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        # ✅ Check token version
        if user.token_version != token_version:
            raise HTTPException(status_code=401, detail="Token has been revoked. Please log in again.")

        return {"user": user, "role": user.role}
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


# ✅ Check if user is admin
def is_admin(user_data: Dict[str, Any] = Depends(verify_token)) -> bool:
    """Check if the user has admin privileges."""
    if user_data.get("role") != UserRole.ADMIN:
        logger.warning(f"Unauthorized access attempt by user: {user_data.get('user').username}")
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return True

# ✅ Password Hashing & Verification
def get_password_hash(password: str) -> str:
    """Hash a password securely using bcrypt."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against its hashed counterpart."""
    return pwd_context.verify(plain_password, hashed_password)

# ✅ Get Current User from Token
def get_current_user(user_data: Dict[str, Any] = Depends(verify_token)) -> User:
    """Retrieve the current user based on the JWT token."""
    user = user_data.get("user")
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    return user
