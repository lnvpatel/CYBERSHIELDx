# app/services/session_service.py

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from app.infrastructure.database.models import BlacklistedToken, UserSession, User
from app.core.security import decode_token
from app.core.exceptions import unauthorized, not_found, bad_request
from datetime import datetime, timezone, timedelta
import logging
from typing import Optional, Sequence
from app.services.activity_service import log_user_activity
from app.config import settings

logger = logging.getLogger(__name__)

async def create_user_session(
    db: AsyncSession,
    user: User,
    jti: str, # JTI of the refresh token
    expires_at: datetime, # Expiration of the refresh token
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
    remember_me: bool = False, # Flag from login request
    device_id: Optional[str] = None, # Added device_id parameter
    # NEW PARAMETERS: Control initial active and trusted state
    is_active_initial: bool = False, # Default to False if MFA is pending, True if not
    is_trusted_initial: bool = False # <--- MODIFIED: Use this parameter to set initial trust
) -> UserSession:
    """
    Creates a new user session record, storing the refresh token's JTI and expiration.
    The session's initial 'is_active' and 'is_trusted' status depends on the login flow.
    If MFA is required, is_active should be False initially and updated upon MFA success.
    The device_id is stored to potentially mark the device as trusted after MFA verification.
    """
    logger.debug(f"Creating session for user {user.username} (ID: {user.id}) with JTI: {jti[:10]}...")

    new_session = UserSession(
        user_id=user.id,
        jti=jti,
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at,
        is_trusted=is_trusted_initial, # <--- MODIFIED: Use the passed parameter here
        is_active=is_active_initial,
        device_id=device_id, # Store the device_id passed from login
        created_at=datetime.now(timezone.utc),
        last_accessed_at=datetime.now(timezone.utc)
    )
    db.add(new_session)
    await db.commit()
    await db.refresh(new_session) # Refresh to get any default values set by DB, like 'id'

    logger.info(f"User session {new_session.id} created for user {user.username}. Initial status: Active={new_session.is_active}, Trusted={new_session.is_trusted}. Device ID: {device_id}")

    return new_session


async def update_session_last_accessed(db: AsyncSession, session_id: int):
    """
    Updates the last_accessed_at timestamp for a given session.
    """
    logger.debug(f"Updating last_accessed_at for session ID: {session_id}")
    await db.execute(
        update(UserSession)
        .where(UserSession.id == session_id)
        .values(
            last_accessed_at=datetime.now(timezone.utc),
            updated_at=datetime.now(timezone.utc)
        )
    )
    await db.commit()
    logger.debug(f"Session ID {session_id} last_accessed_at and updated_at updated.")


async def logout_session(
    db: AsyncSession,
    token: str, # This is the refresh token string
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> dict:
    """
    Invalidates the JWT by storing its JTI in the blacklist and deactivates the associated UserSession.
    Logs the logout activity.
    """
    logger.debug(f"Attempting to logout user and blacklist token: {token[:10]}...")

    payload = await decode_token(token)
    jti = payload.jti
    token_type = payload.type
    user_id = int(payload.sub)

    if not jti or not token_type or not user_id:
        logger.warning(f"Invalid token for logout: Missing JTI, type, or user_id. Token: {token[:10]}...")
        raise unauthorized("Invalid token or token payload missing essential data.")

    # 1. Blacklist the token JTI
    existing_blacklist_entry_query = select(BlacklistedToken).filter(BlacklistedToken.jti == jti)
    existing_blacklist_entry_result = await db.execute(existing_blacklist_entry_query)
    existing_blacklist_entry = existing_blacklist_entry_result.scalar_one_or_none()

    if existing_blacklist_entry:
        logger.info(f"Token with jti={jti} already blacklisted. Skipping blacklist entry.")
    else:
        blacklisted_token_entry = BlacklistedToken(
            jti=jti,
            token_type=token_type,
            blacklisted_at=datetime.now(timezone.utc)
        )
        db.add(blacklisted_token_entry)
        logger.info(f"Token with jti={jti} (type: {token_type}) successfully blacklisted.")

    # 2. Deactivate the associated UserSession
    session_query = select(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.jti == jti,
        UserSession.is_active == True # Only deactivate active sessions
    )
    session_result = await db.execute(session_query)
    session_to_deactivate: Optional[UserSession] = session_result.scalar_one_or_none()

    if session_to_deactivate:
        session_to_deactivate.is_active = False
        session_to_deactivate.revoked_at = datetime.now(timezone.utc)
        session_to_deactivate.updated_at = datetime.now(timezone.utc)
        logger.info(f"User session {session_to_deactivate.id} for user {user_id} marked as inactive.")
    else:
        logger.warning(f"No active session found to deactivate for user {user_id} with JTI {jti}. Session might be already inactive or expired.")

    await db.commit()

    # 3. Log the logout activity
    user_query = select(User).filter(User.id == user_id)
    user_result = await db.execute(user_query)
    user_for_log: Optional[User] = user_result.scalar_one_or_none()

    if user_for_log:
        await log_user_activity(
            db,
            user_id=user_for_log.id,
            activity_type="logout_successful",
            details="User logged out and session invalidated.",
            ip_address=ip_address,
            user_agent=user_agent
        )
        logger.info(f"Logout activity logged for user {user_for_log.username}.")
    else:
        logger.error(f"Could not find user {user_id} to log logout activity, but logout action proceeded.")

    return {"detail": "Logged out successfully"}


async def get_user_active_sessions(db: AsyncSession, user_id: int) -> Sequence[UserSession]:
    """
    Retrieves all active sessions for a given user ID.
    """
    logger.debug(f"Fetching active sessions for user ID: {user_id}")
    query = select(UserSession).filter(
        UserSession.user_id == user_id,
        UserSession.is_active == True
    ).order_by(UserSession.created_at.desc())

    sessions_result = await db.execute(query)
    active_sessions: Sequence[UserSession] = sessions_result.scalars().all()
    logger.info(f"Found {len(active_sessions)} active sessions for user ID: {user_id}.")
    return active_sessions

async def revoke_user_session(
    db: AsyncSession,
    user_id: int,
    session_id: int,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> dict:
    """
    Revokes a specific user session by marking it inactive and blacklisting its refresh token.
    Ensures the session belongs to the requesting user.
    """
    logger.debug(f"Attempting to revoke session ID {session_id} for user ID {user_id}")

    session_query = select(UserSession).filter(
        UserSession.id == session_id,
        UserSession.user_id == user_id,
        UserSession.is_active == True
    )
    session_result = await db.execute(session_query)
    session_to_revoke: Optional[UserSession] = session_result.scalars().one_or_none()

    if not session_to_revoke:
        logger.warning(f"Session ID {session_id} not found or not active for user {user_id}, or does not belong to user.")
        raise not_found("Session not found or already inactive.")

    # 1. Mark the session as inactive
    session_to_revoke.is_active = False
    session_to_revoke.revoked_at = datetime.now(timezone.utc)
    session_to_revoke.updated_at = datetime.now(timezone.utc)
    logger.info(f"Session {session_id} marked as inactive for user {user_id}.")

    # 2. Blacklist the refresh token's JTI from the UserSession record
    refresh_token_jti = session_to_revoke.jti

    existing_refresh_blacklist_entry_query = select(BlacklistedToken).filter(BlacklistedToken.jti == refresh_token_jti)
    existing_refresh_blacklist_entry_result = await db.execute(existing_refresh_blacklist_entry_query)
    existing_refresh_blacklist_entry = existing_refresh_blacklist_entry_result.scalars().one_or_none()

    if existing_refresh_blacklist_entry:
        logger.info(f"Refresh token with jti={refresh_token_jti} already blacklisted during session revocation. Skipping blacklist entry.")
    else:
        blacklisted_refresh_token_entry = BlacklistedToken(
            jti=refresh_token_jti,
            token_type="refresh",
            blacklisted_at=datetime.now(timezone.utc)
        )
        db.add(blacklisted_refresh_token_entry)
        logger.info(f"Refresh token with jti={refresh_token_jti} successfully blacklisted during session revocation.")

    await db.commit()

    # 3. Log the session revocation activity
    await log_user_activity(
        db,
        user_id=user_id,
        activity_type="session_revoked",
        details=f"User revoked session ID: {session_id}",
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"Session revocation activity logged for user {user_id}, session {session_id}.")

    return {"detail": f"Session ID {session_id} successfully revoked."}