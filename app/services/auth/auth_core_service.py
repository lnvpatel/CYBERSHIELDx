import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal
from jose import JWTError

from fastapi import HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.schemas.auth import LoginRequest, TokenResponse
from app.schemas.mfa import MFALoginVerifyRequest
from app.infrastructure.database.models import User, UserSession, BlacklistedToken
from app.core.security import (
    verify_password, create_access_token, create_refresh_token, decode_token, TokenPayload,
    create_mfa_challenge_token
)
from app.core.exceptions import unauthorized, forbidden, APIException, bad_request
from app.config import settings
from app.services.activity_service import log_user_activity
from app.services.auth.auth_utils import is_token_expired, handle_failed_login_attempts
from app.services.session_service import create_user_session # Make sure this function accepts is_trusted_initial
from app.services.mfa_service import MfaService


logger = logging.getLogger(__name__)


async def login_user(
    db: AsyncSession,
    data: LoginRequest,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    background_tasks: BackgroundTasks = BackgroundTasks()
) -> TokenResponse:
    """
    Authenticates a user and returns access and refresh tokens, or initiates MFA/New Device verification.
    """
    logger.debug(f"Attempting login for: {data.username_or_email}")
    logger.debug(f"LoginRequest received: username_or_email='{data.username_or_email}', remember_me={data.remember_me}, device_id='{data.device_id}'")


    user_query = select(User).filter(
        (User.username == data.username_or_email) |
        (User.email == data.username_or_email) |
        (User.mobile_number == data.username_or_email)
    )
    user = (await db.execute(user_query)).scalar_one_or_none()

    if not user:
        logger.warning(f"Login failed: User not found for {data.username_or_email}")
        raise unauthorized(message="Invalid credentials")

    now_utc = datetime.now(timezone.utc)
    logger.debug(f"User found: {user.username} (ID: {user.id}). MFA Enabled: {user.is_mfa_enabled}")

    if user.account_locked:
        if user.locked_until and user.locked_until > now_utc:
            remaining_time = user.locked_until - now_utc
            minutes_remaining = int(remaining_time.total_seconds() // 60) + 1
            logger.warning(f"Account for {user.username} is locked until {user.locked_until}. Remaining: {remaining_time}")
            raise forbidden(message=f"Account is locked. Please try again in {minutes_remaining} minutes.")
        else:
            logger.info(f"Account for {user.username} was locked but lockout period has expired. Resetting.")
            user.login_attempts = 0
            user.account_locked = False
            user.locked_until = None
            db.add(user)
            await db.commit()
            await db.refresh(user)

    if not await verify_password(data.password, user.hashed_password):
        await handle_failed_login_attempts(db, user, ip_address, user_agent)

    # Reset login attempts on successful password verification
    user.login_attempts = 0
    user.account_locked = False
    user.locked_until = None
    db.add(user)

    if not user.is_active:
        logger.warning(f"Login failed: Inactive user {user.username}")
        await log_user_activity(db, user.id, "login_failed", "Account inactive", ip_address, user_agent)
        raise unauthorized(message="Account is inactive")

    if settings.REQUIRE_EMAIL_VERIFICATION and not user.is_verified:
        logger.warning(f"Login failed: Unverified email for user {user.username}")
        await log_user_activity(db, user.id, "login_failed", "Email unverified", ip_address, user_agent)
        raise unauthorized(message="Please verify your email to log in.")

    user.last_login = now_utc
    await db.commit()
    await db.refresh(user)

    refresh_token_expires_delta = timedelta(
        days=settings.REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS if data.remember_me else settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    logger.info(f"User {user.username} logging in. Refresh token expiry: {refresh_token_expires_delta.days} days (Remember Me: {data.remember_me}).")

    refresh_token = await create_refresh_token(
        {"sub": str(user.id), "username": user.username},
        expires_delta=refresh_token_expires_delta
    )
    refresh_token_payload: TokenPayload = await decode_token(refresh_token)
    session_jti = refresh_token_payload.jti

    if not session_jti or refresh_token_payload.exp is None:
        logger.error("Failed to generate JTI or 'exp' for refresh token during login.")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not create session identifier.")

# --- START OF MODIFICATION for device trust ---
    is_device_already_trusted = False
    logger.debug(f"Checking for device trust. User MFA enabled: {user.is_mfa_enabled}, Device ID provided: {data.device_id is not None}.")

    if user.is_mfa_enabled and data.device_id:
        # CRITICAL CHANGE HERE: REMOVE UserSession.is_active == True from filter
        # AND ADD .limit(1) TO ENSURE ONLY ONE RESULT
        existing_trusted_session_query = select(UserSession).filter(
            UserSession.user_id == user.id,
            UserSession.device_id == data.device_id,
            UserSession.is_trusted == True,  # We only care if it was previously marked as trusted
            UserSession.expires_at > now_utc # And that its trusted status hasn't expired
        ).order_by(UserSession.last_accessed_at.desc()).limit(1) # <--- YOU MUST ADD THIS .limit(1)

        existing_trusted_session = (await db.execute(existing_trusted_session_query)).scalar_one_or_none()
        if existing_trusted_session:
            is_device_already_trusted = True
            logger.info(f"User {user.username} logging in from previously trusted device ID: {data.device_id}. Existing trusted session found (ID: {existing_trusted_session.id}).")
            # You might want to update existing_trusted_session.last_accessed_at here if you reuse sessions
            # For simplicity, we are creating a new session later, so no update needed on the old record.
        else:
            logger.info(f"User {user.username} logging in from device ID: {data.device_id}. NO existing trusted session found for this device or it's expired.")
    elif user.is_mfa_enabled and not data.device_id:
        logger.info(f"User {user.username} has MFA enabled but no device ID provided. Device cannot be recognized as trusted for MFA bypass.")
    else: # User does not have MFA enabled
        logger.debug(f"User {user.username} does NOT have MFA enabled. Device trust status is not relevant for MFA bypass.")

    # Determine initial active and trusted state for the NEW session being created
    # If MFA is NOT enabled OR if MFA IS enabled AND the device is already trusted,
    # then the new session is active and trusted from the start.
    initial_session_active_state = not user.is_mfa_enabled or is_device_already_trusted
    initial_session_trusted_state = initial_session_active_state # Trusted state mirrors active state at this point

    logger.debug(f"Initial session states calculated: is_active_initial={initial_session_active_state}, is_trusted_initial={initial_session_trusted_state}.")

    session: UserSession = await create_user_session(
        db=db,
        user=user,
        jti=session_jti,
        expires_at=refresh_token_payload.exp,
        ip_address=ip_address,
        user_agent=user_agent,
        remember_me=data.remember_me,
        device_id=data.device_id,
        is_active_initial=initial_session_active_state,
        is_trusted_initial=initial_session_trusted_state
    )
    logger.debug(f"New UserSession created (ID: {session.id}). Database values: session.is_active={session.is_active}, session.is_trusted={session.is_trusted}.")
    # --- END OF DEVICE TRUST LOGIC ---


    mfa_service = MfaService(db, background_tasks)
    mfa_type_required = None

    # --- CRITICAL MFA CHALLENGE DECISION POINT ---
    logger.debug(f"Deciding MFA challenge: user.is_mfa_enabled={user.is_mfa_enabled}, session.is_trusted={session.is_trusted}.")

    # If user has MFA enabled AND the current session (which reflects device trust for bypass) is NOT marked as trusted
    if user.is_mfa_enabled and not session.is_trusted:
        mfa_type_required = await mfa_service.handle_login_mfa_challenge(user, session)
        logger.info(f"MFA challenge WILL be initiated for user {user.username}. Type required: {mfa_type_required}")
    else:
        logger.info(f"MFA challenge WILL NOT be initiated for user {user.username} (MFA disabled or device recognized as trusted).")


    if mfa_type_required:
        mfa_challenge_token = await create_mfa_challenge_token(
            user_id=str(user.id),
            session_jti=session.jti,
            expires_delta=timedelta(minutes=settings.MFA_CHALLENGE_TOKEN_EXPIRE_MINUTES)
        )
        logger.info(f"Login for {user.username} requires MFA ({mfa_type_required}). Challenge token issued for session JTI: {session.jti}.")
        await log_user_activity(
            db, user.id, "login_mfa_challenge_initiated",
            f"MFA challenge issued for login (Type: {mfa_type_required}). Session JTI: {session.jti}",
            ip_address, user_agent
        )
        return TokenResponse(
            access_token=None,
            refresh_token=None,
            token_type=None,
            mfa_required=True,
            mfa_challenge_token=mfa_challenge_token,
            mfa_method_required=mfa_type_required,
            is_device_trusted=session.is_trusted, # This will be False, as MFA is required for this device
            message=f"Verification required. Please provide the {mfa_type_required.upper()} code."
        )
    else:
        # No MFA required (either MFA not enabled, or device was trusted for bypass).
        # Ensure the current session is explicitly marked as active and trusted in the database.
        # This covers cases where MFA is NOT enabled, or MFA IS enabled but device is trusted.
        if not session.is_active or not session.is_trusted:
            session.is_active = True
            session.is_trusted = True
            session.last_accessed_at = now_utc
            session.updated_at = now_utc
            db.add(session)
            await db.commit()
            await db.refresh(session)
            logger.info(f"Session {session.id} activated and ensured trusted as no MFA challenge was required.")
        else:
            logger.info(f"Session {session.id} already active and trusted. Proceeding with login.")


        access_token_data = {"sub": str(user.id), "username": user.username, "session_jti": session.jti}
        access_token = await create_access_token(access_token_data)

        await log_user_activity(
            db, user.id, "login_successful",
            f"User logged in (Remember Me: {data.remember_me}, Trusted Device: {session.is_trusted}).",
            ip_address, user_agent
        )
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            mfa_required=False, # MFA is NOT required
            mfa_challenge_token=None,
            mfa_method_required=None,
            is_device_trusted=session.is_trusted, # Reflect the actual trust status from the session
            message="Login successful"
        )

async def verify_mfa_login_challenge(
    db: AsyncSession,
    data: MFALoginVerifyRequest,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> TokenResponse:
    """
    Verifies the OTP/TOTP code for a pending MFA login challenge and issues final access/refresh tokens.
    """
    logger.debug(f"Attempting MFA login challenge verification for token: {data.mfa_challenge_token[:10]}...")

    try:
        mfa_challenge_payload: TokenPayload = await decode_token(data.mfa_challenge_token)
        user_id_str = mfa_challenge_payload.sub
        session_jti = mfa_challenge_payload.session_jti

        if mfa_challenge_payload.type != "mfa_challenge":
            logger.warning(f"Invalid challenge token type: {mfa_challenge_payload.type}")
            raise unauthorized(message="Invalid MFA challenge token.")

        if is_token_expired(mfa_challenge_payload.exp):
            logger.warning("MFA challenge token has expired.")
            raise unauthorized(message="MFA challenge token has expired. Please try logging in again.")

        if not user_id_str or not session_jti:
            logger.warning("MFA challenge token missing user_id or session_jti.")
            raise unauthorized(message="Invalid MFA challenge token.")

        user_id = int(user_id_str)

    except APIException as e:
        logger.warning(f"MFA challenge token decoding/validation failed: {e.message}")
        raise unauthorized(message="Invalid or expired verification token.")
    except JWTError as e:
        logger.warning(f"MFA challenge token JWT error: {e}")
        raise unauthorized(message="Invalid or expired verification token.")
    except Exception as e:
        logger.warning(f"MFA challenge token processing failed: {e.__class__.__name__}: {e}")
        raise unauthorized(message="Invalid or expired verification token.")

    user_query = select(User).filter(User.id == user_id)
    user_result = await db.execute(user_query)
    user: Optional[User] = user_result.scalar_one_or_none()

    if not user or not user.is_active:
        logger.warning(f"MFA login verification failed: User {user_id} not found or inactive.")
        raise unauthorized(message="MFA verification failed. User not found or account inactive.")

    # Query for the pending session, which should be inactive and match the session_jti
    session_query = select(UserSession).filter(
        UserSession.user_id == user.id,
        UserSession.jti == session_jti,
        UserSession.is_active == False, # Crucially, it must be inactive before MFA completion
        UserSession.expires_at > datetime.now(timezone.utc) # Ensure session is not expired
    )
    session_result = await db.execute(session_query)
    session: Optional[UserSession] = session_result.scalar_one_or_none()

    if not session:
        logger.warning(f"MFA login verification failed: Pending session {session_jti} not found, expired, or already active/invalid for user {user.id}.")
        raise unauthorized(message="MFA verification failed. Session not found, expired, or inactive. Please try logging in again.")

    mfa_service = MfaService(db)

    try:
        # This call will mark session.is_trusted = True in mfa_service.py
        await mfa_service.verify_login_mfa(
            user=user,
            session=session,
            otp_code=data.otp_code,
            mfa_method=data.mfa_method
        )
    except bad_request as e:
        logger.warning(f"MFA login verification failed for user {user.username} (ID: {user.id}): {e.message}")
        await log_user_activity(
            db, user.id, "mfa_login_failed",
            f"MFA login verification failed: {e.message}",
            ip_address, user_agent
        )
        raise
    except Exception as e:
        logger.error(f"Unexpected error during MFA login verification for user {user.username} (ID: {user.id}): {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred during MFA verification.")

    logger.info(f"MFA login challenge successfully verified for user {user.username}. Session {session.id} will be activated.")

    new_refresh_token = await create_refresh_token(
        {"sub": str(user.id), "username": user.username},
        expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    new_refresh_token_payload: TokenPayload = await decode_token(new_refresh_token)
    new_jti = new_refresh_token_payload.jti
    new_expires_at = new_refresh_token_payload.exp

    if not new_jti or not new_expires_at:
        logger.error("Failed to generate new JTI or expiry for refresh token after MFA verification.")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not generate new tokens.")

    # Update session with new JTI and mark as active
    session.jti = new_jti
    session.expires_at = new_expires_at
    session.last_accessed_at = datetime.now(timezone.utc)
    session.updated_at = datetime.now(timezone.utc)
    session.is_active = True
    # The session's is_trusted status should already be True from mfa_service.verify_login_mfa
    # We explicitly ensure it here for clarity and safety, in case of unexpected state.
    session.is_trusted = True
    logger.info(f"Session {session.id} updated and activated with new refresh token jti={new_jti} for user {user.username}.")


    db.add(session)
    await db.commit()
    await db.refresh(session)

    new_access_token_data = {"sub": str(user.id), "username": user.username, "session_jti": session.jti}
    new_access_token = await create_access_token(new_access_token_data)

    await log_user_activity(
        db, user_id=user.id, activity_type="login_successful_mfa", details="User logged in via MFA.",
        ip_address=ip_address, user_agent=user_agent
    )

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        mfa_required=False,
        mfa_challenge_token=None,
        mfa_method_required=None,
        is_device_trusted=session.is_trusted,
        message="MFA verified. Login successful."
    )

async def refresh_access_token(
    db: AsyncSession,
    refresh_token: str,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> TokenResponse:
    """
    Obtain a new access token and a new refresh token using a valid refresh token.
    Implements refresh token rotation.
    """
    logger.debug(f"Attempting to refresh token.")

    try:
        payload: TokenPayload = await decode_token(refresh_token)
        jti = payload.jti
        user_id_str = payload.sub

        if not jti or not user_id_str or payload.type != "refresh":
            logger.warning(f"Invalid refresh token payload for refresh: JTI missing or wrong type. JTI: {jti}, Type: {payload.type}")
            raise unauthorized("Invalid refresh token.")

        user_id = int(user_id_str)

        blacklisted_query = select(BlacklistedToken).filter(BlacklistedToken.jti == jti)
        blacklisted_result = await db.execute(blacklisted_query)
        if blacklisted_result.scalar_one_or_none():
            logger.warning(f"Refresh token with jti={jti} is blacklisted. Unauthorized access attempt.")
            raise unauthorized("Invalid or expired refresh token.")

        session_query = select(UserSession).filter(
            UserSession.jti == jti,
            UserSession.user_id == user_id,
            UserSession.is_active == True
        )
        session_result = await db.execute(session_query)
        session: Optional[UserSession] = session_result.scalar_one_or_none()

        if not session:
            logger.warning(f"No active session found for refresh token jti={jti}, user_id={user_id}.")
            raise unauthorized("Invalid or expired refresh token.")

        if session.expires_at is None or is_token_expired(session.expires_at):
            logger.warning(f"Refresh token for session {session.id} (jti={jti}) has expired or expiry missing.")
            session.is_active = False
            session.revoked_at = datetime.now(timezone.utc)
            db.add(session)
            await db.commit()
            blacklisted_token_entry = BlacklistedToken(
                jti=jti,
                token_type="refresh",
                blacklisted_at=datetime.now(timezone.utc)
            )
            db.add(blacklisted_token_entry)
            await db.commit()
            raise unauthorized("Refresh token has expired. Please log in again.")

        old_jti = session.jti
        blacklisted_token_entry = BlacklistedToken(
            jti=old_jti,
            token_type="refresh",
            blacklisted_at=datetime.now(timezone.utc)
        )
        db.add(blacklisted_token_entry)
        logger.info(f"Old refresh token (jti={old_jti}) blacklisted for rotation.")

        new_refresh_token = await create_refresh_token(
            {"sub": str(user_id), "username": payload.username},
            expires_delta=timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        )
        new_refresh_token_payload: TokenPayload = await decode_token(new_refresh_token)
        new_jti = new_refresh_token_payload.jti
        new_expires_at = new_refresh_token_payload.exp

        if not new_jti or not new_expires_at:
            logger.error("Failed to generate new JTI or expiry for refresh token during refresh operation.")
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Could not generate new tokens.")

        session.jti = new_jti
        session.expires_at = new_expires_at
        session.last_accessed_at = datetime.now(timezone.utc)
        session.updated_at = datetime.now(timezone.utc)
        db.add(session)
        await db.commit()
        await db.refresh(session)
        logger.info(f"Session {session.id} updated with new refresh token jti={new_jti}.")

        access_token_data = {"sub": str(user_id), "username": payload.username, "session_jti": session.jti}
        new_access_token = await create_access_token(access_token_data)

        await log_user_activity(
            db, user_id=user_id, activity_type="token_refreshed", details="Access and Refresh tokens refreshed",
            ip_address=ip_address, user_agent=user_agent
        )
        return TokenResponse(
            access_token=new_access_token,
            refresh_token=new_refresh_token,
            token_type="bearer",
            mfa_required=False,
            mfa_challenge_token=None,
            mfa_method_required=None,
            is_device_trusted=session.is_trusted,
            message="Token refreshed successfully."
        )

    except APIException as e:
        logger.warning(f"Token refresh failed due to APIException: {e.message}")
        raise unauthorized(message=e.message)
    except JWTError as e:
        logger.warning(f"JWT error during token refresh: {e}")
        raise unauthorized(message="Invalid or malformed refresh token.")
    except Exception as e:
        logger.error(f"Unexpected error during token refresh: {e.__class__.__name__}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="An unexpected error occurred during token refresh.")