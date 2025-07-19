# app/core/security.py

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel # For TokenPayload
import uuid # For generating JTI
from fastapi.concurrency import run_in_threadpool # For async synchronous operations

from app.config import settings
from app.core.exceptions import APIException # Ensure APIException is correctly defined here
from fastapi import status # For HTTP status codes in exceptions


# Initialize logger for this module
logger = logging.getLogger(__name__)

# =========================
# Password Hashing
# =========================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

async def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies a plain password against a hashed password asynchronously by running
    the synchronous verification operation in a separate thread to avoid blocking the event loop.
    """
    return await run_in_threadpool(pwd_context.verify, plain_password, hashed_password)

async def get_password_hash(password: str) -> str:
    """
    Hashes a password asynchronously by running the synchronous hashing operation
    in a separate thread to avoid blocking the event loop.
    """
    return await run_in_threadpool(pwd_context.hash, password)

# =========================
# JWT Token Management
# =========================

class TokenPayload(BaseModel):
    """Pydantic model for JWT token payload."""
    sub: str # Subject (usually user ID)
    username: Optional[str] = None # Optional, for convenience
    jti: Optional[str] = None # JWT ID for refresh tokens and session tracking
    exp: Optional[datetime] = None # Expiration time (datetime object, converted from timestamp)
    type: Optional[str] = None # Token type (e.g., "access", "refresh", "email_verification", "password_reset", "mfa_challenge", "mfa_status_change")
    session_jti: Optional[str] = None # For MFA challenge tokens, to link to session


async def create_token(data: dict, expires_delta: Optional[timedelta] = None, token_type: str = "access") -> str:
    """
    Creates a JWT token with a given payload, expiration delta, and type.
    If expires_delta is not provided, it uses default durations from settings.
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        # Default expiration based on token type if not provided
        if token_type == "access":
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        elif token_type == "refresh":
            # This branch for refresh tokens should ideally only be hit if expires_delta is explicitly None.
            # In practice, refresh tokens usually have expires_delta passed from login/refresh logic.
            expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        elif token_type == "email_verification":
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.OTP_EXPIRATION_MINUTES)
        elif token_type == "password_reset":
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.OTP_EXPIRATION_MINUTES)
        elif token_type == "mfa_challenge":
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.MFA_CHALLENGE_TOKEN_EXPIRE_MINUTES)
        elif token_type == "mfa_status_change":
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.MFA_EMAIL_TOKEN_EXPIRE_MINUTES)
        else:
            # Fallback for any unhandled token types, or if no specific expiry is set
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES) 

    to_encode.update({"exp": expire.timestamp(), "type": token_type}) # Store timestamp for JWT
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Creates an access token."""
    return await create_token(data, expires_delta, token_type="access")

async def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a refresh token.
    A unique JWT ID (JTI) is automatically generated and added to the payload.
    """
    jti = str(uuid.uuid4()) # Generate a random UUID for JTI
    data.update({"jti": jti})
    return await create_token(data, expires_delta, token_type="refresh")

async def create_email_verification_token(user_id: str, expires_delta: Optional[timedelta] = None) -> str:
    """Creates an email verification token."""
    data = {"sub": user_id}
    return await create_token(data, expires_delta, token_type="email_verification")

async def create_password_reset_token(user_id: str, expires_delta: Optional[timedelta] = None) -> str:
    """Creates a password reset token."""
    data = {"sub": user_id}
    return await create_token(data, expires_delta, token_type="password_reset")

async def create_mfa_challenge_token(user_id: str, session_jti: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Creates a temporary token to signify an ongoing MFA challenge.
    This token links the user and the specific session needing MFA verification.
    """
    data = {"sub": user_id, "session_jti": session_jti}
    return await create_token(data, expires_delta, token_type="mfa_challenge")

async def create_mfa_status_change_token(user_id: str, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generates a JWT token for confirming MFA status changes (enable/disable).
    """
    data = {"sub": user_id}
    return await create_token(data, expires_delta, token_type="mfa_status_change")


async def decode_token(token: str) -> TokenPayload:
    """
    Decodes a JWT token, validates it, and returns its payload as a TokenPayload object.
    Raises APIException for invalid or expired tokens.
    """
    try:
        # Decode the token without verifying expiration here, as TokenPayload
        # will validate `exp` and we might want to handle expired tokens specifically.
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM], options={"verify_exp": True})
        
        # Convert 'exp' timestamp back to datetime object for Pydantic validation
        if 'exp' in payload and isinstance(payload['exp'], (int, float)):
            payload['exp'] = datetime.fromtimestamp(payload['exp'], tz=timezone.utc)
        
        # Validate payload structure with Pydantic model
        token_data = TokenPayload(**payload)
        return token_data
    except JWTError as e:
        logger.warning(f"JWTError during token decoding: {e}")
        raise APIException(status_code=status.HTTP_401_UNAUTHORIZED, message="Invalid or expired token.", name="invalid_token")
    except Exception as e:
        logger.error(f"Unexpected error during token decoding: {e.__class__.__name__}: {e}", exc_info=True)
        raise APIException(status_code=status.HTTP_401_UNAUTHORIZED, message=f"Token decoding error: {e}", name="token_decode_error")