# app/services/auth_password_service.py

import logging
import re
from datetime import datetime, timezone # <-- ADDED THIS LINE
from typing import Optional

from fastapi import BackgroundTasks

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.schemas.auth import ForgotPasswordStartRequest, ForgotPasswordConfirmRequest, ResetPasswordRequest
from app.infrastructure.database.models import User, PasswordHistory
from app.core.security import get_password_hash
from app.core.exceptions import bad_request, unauthorized, not_found # <-- Ensure not_found is here too if used
from app.core.tokens import generate_password_reset_token
from app.core.email_utils import send_email, build_password_reset_context
from app.config import settings
from app.services.activity_service import log_user_activity
from app.services.auth.auth_utils import is_token_expired, is_valid_password_for_history, PASSWORD_REGEX


logger = logging.getLogger(__name__)


async def forgot_password_start(db: AsyncSession, username_or_email: str, background_tasks: BackgroundTasks, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> dict:
    """
    Initiates the forgot password process.
    """
    logger.debug(f"Forgot password start requested for: {username_or_email}")
    user_query = select(User).filter(
        (User.username == username_or_email) | (User.email == username_or_email)
    )
    user_result = await db.execute(user_query)
    user: Optional[User] = user_result.scalar_one_or_none()

    if not user:
        logger.warning(f"Forgot password start failed: User not found for {username_or_email}")
        # Return a generic message to prevent user enumeration
        return {"detail": "If an account with that email/username exists, a password reset link will be sent."}
    
    reset_token, reset_expiry = generate_password_reset_token(user.email)
    user.password_reset_token = reset_token
    user.password_reset_expires = reset_expiry
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    reset_context = build_password_reset_context(user.username, reset_token)
    background_tasks.add_task(
        send_email,
        to_email=user.email,
        subject=f"Password Reset - {settings.APP_NAME}",
        template_name="password_reset",
        context=reset_context
    )
    logger.info(f"Password reset email sending for {user.email} offloaded to background task.")
    
    await log_user_activity(
        db,
        user_id=user.id,
        activity_type="password_reset_initiated",
        details="Password reset link sent to email",
        ip_address=ip_address,
        user_agent=user_agent
    )

    return {"detail": "If an account with that email/username exists, a password reset link will be sent."}


async def confirm_user_email_for_reset(db: AsyncSession, username: str, email: str, background_tasks: BackgroundTasks, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> dict:
    """
    Confirms the user's email and username for password reset.
    """
    logger.debug(f"Confirming email for reset for username: {username}, email: {email}")
    user_query = select(User).filter(
        (User.username == username) & (User.email == email)
    )
    user_result = await db.execute(user_query)
    user: Optional[User] = user_result.scalar_one_or_none()

    if not user:
        logger.warning(f"Password reset confirmation failed: User not found for {username}/{email}")
        raise bad_request("Invalid username or email provided.")

    return await forgot_password_start(db, user.email, background_tasks, ip_address=ip_address, user_agent=user_agent)


async def reset_password(db: AsyncSession, token: str, new_password: str, confirm_password: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> dict:
    """
    Resets the user's password using a valid reset token.
    """
    logger.debug(f"Reset password attempt with token: {token[:10]}...")
    user_query = select(User).filter(User.password_reset_token == token)
    user_result = await db.execute(user_query)
    user: Optional[User] = user_result.scalar_one_or_none()

    if not user:
        logger.warning(f"Password reset failed: Invalid or expired token {token[:10]}...")
        raise unauthorized("Invalid or expired password reset token.")

    if is_token_expired(user.password_reset_expires):
        logger.warning(f"Password reset failed: Token expired for user {user.username}")
        user.password_reset_token = None
        user.password_reset_expires = None
        await db.commit()
        await db.refresh(user)
        await log_user_activity(
            db,
            user_id=user.id,
            activity_type="password_reset_failed",
            details="Password reset token expired",
            ip_address=ip_address,
            user_agent=user_agent
        )
        raise unauthorized("Password reset token has expired. Please request a new one.")

    if new_password != confirm_password:
        logger.warning("Password reset failed: New passwords do not match.")
        await log_user_activity(
            db,
            user_id=user.id,
            activity_type="password_reset_failed",
            details="New passwords do not match",
            ip_address=ip_address,
            user_agent=user_agent
        )
        raise bad_request("New passwords do not match.")

    if not re.fullmatch(PASSWORD_REGEX, new_password):
        logger.warning(f"Password reset failed for {user.username}: New password does not meet complexity requirements.")
        await log_user_activity(
            db,
            user_id=user.id,
            activity_type="password_reset_failed",
            details="New password does not meet complexity requirements.",
            ip_address=ip_address,
            user_agent=user_agent
        )
        raise bad_request(
            "New password must be at least 8 characters long and include "
            "at least one uppercase letter, one lowercase letter, one number, "
            "and one special character."
        )

    password_history_query = select(PasswordHistory).filter(PasswordHistory.user_id == user.id).order_by(PasswordHistory.changed_at.desc())
    password_history_result = await db.execute(password_history_query)
    password_history = password_history_result.scalars().all()

    if not await is_valid_password_for_history(new_password, password_history):
        logger.warning(f"Password reset failed: Password previously used for user {user.username}.")
        await log_user_activity(
            db,
            user_id=user.id,
            activity_type="password_reset_failed",
            details=f"New password is one of the last {settings.PASSWORD_HISTORY_COUNT} passwords",
            ip_address=ip_address,
            user_agent=user_agent
        )
        raise bad_request(f"New password cannot be one of the last {settings.PASSWORD_HISTORY_COUNT} passwords.")

    user.hashed_password = await get_password_hash(new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    password_history_entry = PasswordHistory(
        user_id=user.id,
        hashed_password=user.hashed_password,
        changed_at=datetime.now(timezone.utc)
    )
    db.add(password_history_entry)
    await db.commit()
    logger.info(f"Password successfully reset for user: {user.username}.")
    
    await log_user_activity(
        db,
        user_id=user.id,
        activity_type="password_reset_successful",
        details="Password reset via token",
        ip_address=ip_address,
        user_agent=user_agent
    )
    return {"detail": "Password reset successfully."}