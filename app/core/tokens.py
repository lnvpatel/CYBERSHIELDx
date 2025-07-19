# app/core/tokens.py

import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from app.config import settings
from app.core.security import create_access_token
from typing import Tuple
from jose import jwt
from uuid import uuid4

# =========================
# Token Generator Utilities
# =========================

def generate_token(length: int = 32) -> str:
    """
    Generates a secure random token using secrets.token_urlsafe.
    This is a fast, CPU-bound operation.
    """
    return secrets.token_urlsafe(length)

def generate_email_verification_token(user_email: str) -> tuple[str, datetime]:
    """
    Creates a deterministic email verification token based on email, random salt, and timestamp.
    Uses timezone-aware datetime for consistency.
    This is a fast, CPU-bound operation.
    """
    salt = secrets.token_hex(16)
    # Use timezone-aware datetime for consistency
    raw = f"{user_email}{salt}{datetime.now(timezone.utc).timestamp()}"
    token = hashlib.sha256(raw.encode()).hexdigest()
    # Use timezone-aware datetime for consistency and configure expiry via settings
    expiry = datetime.now(timezone.utc) + timedelta(minutes=settings.EMAIL_VERIFICATION_TIMEOUT) # Assuming you add this to settings
    return token, expiry

def generate_password_reset_token(user_email: str) -> tuple[str, datetime]:
    """
    Creates a secure password reset token.
    Uses timezone-aware datetime for consistency.
    This is a fast, CPU-bound operation.
    """
    salt = secrets.token_hex(16)
    # Use timezone-aware datetime for consistency
    raw = f"reset-{user_email}-{salt}-{datetime.now(timezone.utc).timestamp()}"
    token = hashlib.sha256(raw.encode()).hexdigest()
    # Use timezone-aware datetime for consistency
    expiry = datetime.now(timezone.utc) + timedelta(minutes=settings.PASSWORD_RESET_TIMEOUT)
    return token, expiry
