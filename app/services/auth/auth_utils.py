# app/services/auth_utils.py

import logging
import re
from datetime import datetime, timezone, timedelta
from typing import Optional, Sequence

# Ensure Path is imported if not already
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

# Import necessary models and exceptions
from app.infrastructure.database.models import PasswordHistory, User # Import User model
from app.core.security import verify_password
from app.config import settings
from app.core.exceptions import unauthorized, forbidden # Import exceptions
from app.services.activity_service import log_user_activity # Import log_user_activity

logger = logging.getLogger(__name__)

# Calculate BASE_DIR for the project root consistently
# auth_utils.py is at app/services/auth_utils.py, so it needs 3 .parent calls to reach the root
BASE_DIR = Path(__file__).resolve().parent.parent.parent
UPLOADS_DIR = BASE_DIR / "uploads"

# Ensure the uploads directory exists
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
logger.info(f"Ensured uploads directory exists at: {UPLOADS_DIR}")

# Define PASSWORD_REGEX for validation
PASSWORD_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:'\",.<>\/?`~]).{8,}$"

# Define max allowed photo size (e.g., 5MB)
MAX_PHOTO_SIZE_BYTES = 5 * 1024 * 1024 # 5 MB

def is_token_expired(expiry: Optional[datetime]) -> bool:
    """
    Checks if a given token expiry datetime is in the past.
    Ensures both datetimes are timezone-aware (UTC) for proper comparison.
    """
    if expiry is None:
        return True

    now_utc = datetime.now(timezone.utc)

    if expiry.tzinfo is None:
        expiry_aware = expiry.replace(tzinfo=timezone.utc)
    else:
        expiry_aware = expiry.astimezone(timezone.utc)

    return expiry_aware < now_utc

async def is_valid_password_for_history(new_password: str, password_history: Sequence[PasswordHistory]) -> bool:
    """
    Checks if the new password has been used recently (e.g., in the last N passwords).
    This function expects an asynchronous context to await verify_password.
    """
    recent_passwords = password_history[:settings.PASSWORD_HISTORY_COUNT]
    
    for record in recent_passwords:
        if await verify_password(new_password, record.hashed_password):
            return False # Password found in history
    return True

async def handle_failed_login_attempts(
    db: AsyncSession,
    user: User,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> None:
    """
    Handles failed login attempts for a user, including incrementing attempts,
    locking the account if thresholds are met, and logging the activity.
    Raises appropriate exceptions if the account becomes locked or credentials are invalid.
    """
    user.login_attempts += 1
    now_utc = datetime.now(timezone.utc)

    if user.login_attempts >= settings.account_lockout_attempts:
        user.account_locked = True
        user.locked_until = now_utc + timedelta(minutes=settings.account_lockout_duration_minutes)
        logger.warning(f"Account for {user.username} locked due to too many failed attempts.")
        db.add(user)
        await db.commit()
        await log_user_activity(
            db, user.id, "account_locked",
            f"Account locked after {user.login_attempts} failed login attempts.",
            ip_address, user_agent
        )
        raise forbidden(
            message=f"Too many failed login attempts. Account locked for {settings.account_lockout_duration_minutes} minutes."
        )
    
    db.add(user)
    await db.commit()
    logger.warning(f"Login failed: Incorrect password for {user.username}. Attempts: {user.login_attempts}/{settings.account_lockout_attempts}")
    await log_user_activity(
        db, user.id, "login_failed", "Incorrect password", ip_address, user_agent
    )
    raise unauthorized(message="Invalid credentials")