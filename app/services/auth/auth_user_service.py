# app/services/auth_user_service.py

import logging
import re
import io
from PIL import Image
from typing import Optional, cast
from datetime import datetime, timezone 
from fastapi import UploadFile, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.schemas.user import UserCreate, UserResponse
from app.infrastructure.database.models import User, PasswordHistory
from app.core.security import get_password_hash
from app.core.exceptions import bad_request, unauthorized, conflict, server_error, APIException, forbidden, not_found # <-- ADDED 'not_found'
from app.core.tokens import generate_email_verification_token
from app.core.email_utils import send_email, build_email_verification_context
from app.config import settings
from app.services.activity_service import log_user_activity
from app.services.admin_service import get_registration_settings
from app.services.auth.auth_utils import is_token_expired, PASSWORD_REGEX, MAX_PHOTO_SIZE_BYTES
from app.tasks.background_tasks import process_user_photo_background

logger = logging.getLogger(__name__)


async def register_user(
    db: AsyncSession,
    data: UserCreate,
    background_tasks: BackgroundTasks,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    photo: Optional[UploadFile] = None
) -> UserResponse:
    """
    Registers a new user asynchronously, including optional photo upload and optimization.
    Image processing and email sending are offloaded to background tasks.
    """
    try:
        logger.debug(f"Attempting to register user: {data.username}")

        registration_settings = await get_registration_settings()
        if not registration_settings.is_registration_enabled:
            logger.warning(f"User registration attempted while disabled for username: {data.username}")
            raise forbidden("New user registration is currently disabled by the administrator.")

        existing_user_query = select(User).filter(
            (User.username == data.username) | 
            (User.email == data.email) | 
            (User.mobile_number == data.mobile_number)
        )
        existing_user_result = await db.execute(existing_user_query)
        if existing_user_result.scalar_one_or_none():
            logger.warning(f"Registration conflict: Username, email, or mobile number already exists for {data.username}/{data.email}")
            raise conflict("Username, email, or mobile number already registered.")

        if not re.fullmatch(PASSWORD_REGEX, data.password):
            logger.warning(f"User registration failed for {data.username}: Password does not meet complexity requirements.")
            raise bad_request(
                "Password must be at least 8 characters long and include "
                "at least one uppercase letter, one lowercase letter, one number, "
                "and one special character."
            )

        hashed_password = await get_password_hash(data.password)

        user = User(
            first_name=data.first_name,
            last_name=data.last_name,
            username=data.username,
            email=data.email,
            mobile_number=data.mobile_number,
            dob=data.dob,
            hashed_password=hashed_password,
            photo_url=None,
            is_active=True,
            is_verified=False,
            is_admin=False
        )

        verification_token, verification_token_expires = generate_email_verification_token(user.email)
        user.verification_token = verification_token
        user.verification_token_expires = verification_token_expires

        db.add(user)
        await db.commit()
        await db.refresh(user)

        logger.info(f"User {user.username} registered with ID: {user.id}")

        if photo and photo.filename:
            first_chunk = await photo.read(MAX_PHOTO_SIZE_BYTES + 1)
            if len(first_chunk) > MAX_PHOTO_SIZE_BYTES:
                logger.warning(f"Uploaded photo exceeds max size for user {user.username}. Size: {len(first_chunk)} bytes")
                raise bad_request(f"Profile photo exceeds the maximum allowed size of {MAX_PHOTO_SIZE_BYTES / (1024 * 1024):.1f} MB.")
            
            await photo.seek(0)
            image_bytes = await photo.read()

            original_file_extension = cast(str, photo.filename).split('.')[-1].lower()
            if original_file_extension not in ["jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff"]:
                logger.warning(f"Invalid original photo format uploaded during registration by {user.username}: {photo.filename}")
                raise bad_request("Invalid image file format. Only JPG, PNG, GIF, WEBP, BMP, TIFF are allowed for upload.")
            
            background_tasks.add_task(
                process_user_photo_background,
                user_id=user.id,
                image_bytes=image_bytes,
                original_file_extension=original_file_extension,
                current_photo_url=None
            )
            logger.info(f"Image processing for user {user.id} offloaded to background task.")

        await log_user_activity(
            db,
            user_id=user.id,
            activity_type="user_registration",
            details=f"User {user.username} registered.",
            ip_address=ip_address,
            user_agent=user_agent
        )

        password_history_entry = PasswordHistory(
            user_id=user.id,
            hashed_password=hashed_password,
            changed_at=datetime.now(timezone.utc)
        )
        db.add(password_history_entry)
        await db.commit()

        if settings.REQUIRE_EMAIL_VERIFICATION:
            verification_context = build_email_verification_context(user.username, verification_token)
            background_tasks.add_task(
                send_email,
                to_email=user.email,
                subject=f"Verify Your Account - {settings.APP_NAME}",
                template_name="verification",
                context=verification_context
            )
            logger.info(f"Verification email sending for {user.email} offloaded to background task.")

        return UserResponse.model_validate(user)

    except APIException as e:
        await db.rollback()
        logger.error(f"Transaction rolled back due to APIException during user registration: {e.message}")
        raise

    except Exception as e:
        await db.rollback()
        logger.error(f"Unexpected error during user registration for {data.username}: {e}", exc_info=True)
        raise server_error("An unexpected error occurred during user registration.")


async def verify_email_token(db: AsyncSession, token: str, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> UserResponse:
    """
    Verifies a user's email using a provided token.
    """
    logger.debug(f"Verifying email token: {token[:10]}...")
    
    user_query = select(User).filter(User.verification_token == token)
    user_result = await db.execute(user_query)
    user: Optional[User] = user_result.scalar_one_or_none()

    if not user:
        logger.warning(f"Email verification failed: Invalid or expired token {token[:10]}...")
        raise unauthorized("Invalid or expired verification token")

    if user.is_verified:
        logger.info(f"User {user.username} already verified.")
        return UserResponse.model_validate(user)

    if is_token_expired(user.verification_token_expires):
        logger.warning(f"Email verification failed: Token expired for user {user.username}")
        user.verification_token = None
        user.verification_token_expires = None
        await db.commit()
        await db.refresh(user)
        await log_user_activity(
            db,
            user_id=user.id,
            activity_type="email_verification_token_expired",
            details="Email verification token expired",
            ip_address=ip_address,
            user_agent=user_agent
        )
        raise unauthorized("Verification token has expired. Please request a new one.")

    user.is_verified = True
    user.verification_token = None
    user.verification_token_expires = None
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)
    logger.info(f"User {user.username} email verified successfully.")
    
    await log_user_activity(
        db,
        user_id=user.id,
        activity_type="email_verified",
        details="User email verified successfully",
        ip_address=ip_address,
        user_agent=user_agent
    )
    return UserResponse.model_validate(user)


async def resend_verification_email(db: AsyncSession, email: str, background_tasks: BackgroundTasks, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> dict:
    """
    Resends the email verification link to a user.
    """
    logger.debug(f"Resend verification email requested for: {email}")
    user_query = select(User).filter(User.email == email)
    user_result = await db.execute(user_query)
    user: Optional[User] = user_result.scalar_one_or_none()

    if not user:
        logger.warning(f"Resend verification failed: User not found for email {email}")
        raise not_found("User not found.") # <-- FIXED THIS LINE

    if user.is_verified:
        logger.info(f"Resend verification skipped: User {user.username} already verified.")
        raise bad_request("Email is already verified.")

    new_token, new_expiry = generate_email_verification_token(user.email)
    user.verification_token = new_token
    user.verification_token_expires = new_expiry
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    verification_context = build_email_verification_context(user.username, new_token)
    background_tasks.add_task(
        send_email,
        to_email=user.email,
        subject=f"Verify Your Account - {settings.APP_NAME}",
        template_name="verification",
        context=verification_context
    )
    logger.info(f"New verification email sending for {user.email} offloaded to background task.")
    
    await log_user_activity(
        db,
        user_id=user.id,
        activity_type="email_verification_resent",
        details="Email verification link resent",
        ip_address=ip_address,
        user_agent=user_agent
    )

    return {"detail": "Verification email sent. Please check your inbox."}