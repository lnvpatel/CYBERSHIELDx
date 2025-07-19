# app/dependencies/auth.py

import logging
from typing import Optional, Annotated

from fastapi import Depends, HTTPException, status, Request, BackgroundTasks # Import BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from sqlalchemy.orm import contains_eager # For eager loading session data with user

from app.core.security import decode_token, TokenPayload
from app.infrastructure.database.session import get_db
from app.infrastructure.database.models import User, BlacklistedToken, UserSession
from app.core.exceptions import unauthorized, forbidden, APIException
from app.config import settings
from app.services.session_service import update_session_last_accessed # Import the session update helper

logger = logging.getLogger(__name__)
bearer_scheme = HTTPBearer(auto_error=False)

async def get_current_user(
    request: Request,
    token: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
    background_tasks: BackgroundTasks # Inject BackgroundTasks
) -> User:
    """
    Dependency to get the current authenticated user from an access token.
    Performs comprehensive validation including token decoding, expiration,
    blacklisting, and active session check.
    """
    credentials_exception = unauthorized("Could not validate credentials")

    if not token or not token.credentials:
        logger.warning("No token or invalid credentials provided")
        raise credentials_exception

    token_str = token.credentials
    logger.debug(f"Attempting to get current user with token: {token_str[:30]}...")

    # 1. Decode Token & Check for basic payload structure
    try:
        payload: TokenPayload = await decode_token(token_str) 
        logger.debug(
            f"Token decoded: sub={payload.sub}, "
            f"jti={payload.jti[:8] if payload.jti else 'N/A'}, "
            f"session_jti={payload.session_jti[:8] if payload.session_jti else 'N/A'}"
        )
    except APIException as e: # Catch specific APIException from decode_token
        logger.warning(f"Token decoding failed with APIException: {e.message} ({e.name})", exc_info=False)
        raise credentials_exception
    except Exception as e: # Catch any other unexpected errors during decoding
        logger.warning(f"Token decoding failed unexpectedly: {e}", exc_info=True)
        raise credentials_exception

    if not payload.sub:
        logger.warning("Token payload missing 'sub' (user ID)")
        raise credentials_exception

    user_id = int(payload.sub)
    
    # Determine which JTI to use for session lookup based on token type
    # For 'access' tokens, session_jti links to the refresh token's session.
    # For 'mfa_challenge' tokens, session_jti links to the pending session.
    session_jti_to_check = None
    if payload.type == "access" or payload.type == "mfa_challenge":
        session_jti_to_check = payload.session_jti
    
    # 2. Fetch User and associated UserSession (if applicable)
    # Start with a base query for User
    user_query = select(User).filter(User.id == user_id)
    
    current_session: Optional[UserSession] = None

    if session_jti_to_check:
        # If we need to find a specific session, join User with UserSession
        # and load the session eagerly.
        user_query = user_query.join(User.sessions).filter(
            UserSession.jti == session_jti_to_check,
            UserSession.is_active == True # Only consider active sessions
        ).options(
            contains_eager(User.sessions)
        )
        
    user_result = await db.execute(user_query)
    user: Optional[User] = user_result.unique().scalar_one_or_none() # unique() ensures distinct User object

    if not user:
        logger.warning(f"Authentication failed: User with ID {user_id} not found or associated session invalid/inactive.")
        raise credentials_exception

    # After retrieving the user, if a session JTI was being checked,
    # the user.sessions list should contain the relevant session.
    # We grab it here for easier access and to confirm its presence.
    if session_jti_to_check:
        # Filter user.sessions to get the one matching the jti_to_check, if exists
        # Although contains_eager with a filter should have done this,
        # explicitly getting it ensures clarity and handles cases where the relationship might load others.
        for session_item in user.sessions:
            if session_item.jti == session_jti_to_check:
                current_session = session_item
                break
        
        if not current_session:
            # This case should ideally not happen if contains_eager worked as expected,
            # but it's a fallback for robustness.
            logger.warning(f"Authentication failed: User {user_id} found, but session {session_jti_to_check} not eagerly loaded or matched.")
            raise credentials_exception
    
    # 3. Blacklist checks for both access token's JTI and session's JTI (refresh token's JTI)
    blacklisted_jtis_to_check = []
    if payload.jti: # JTI of the current access token
        blacklisted_jtis_to_check.append((payload.jti, "access"))
    if session_jti_to_check: # JTI of the associated refresh token (session)
        blacklisted_jtis_to_check.append((session_jti_to_check, "refresh"))

    if blacklisted_jtis_to_check:
        logger.debug(f"Checking {len(blacklisted_jtis_to_check)} JTIs for blacklist status.")
        
        # Build OR conditions for the query
        or_conditions = []
        for jti_val, token_type_val in blacklisted_jtis_to_check:
            or_conditions.append(
                (BlacklistedToken.jti == jti_val) & (BlacklistedToken.token_type == token_type_val)
            )
        
        blacklisted_query = select(BlacklistedToken).filter(or_(*or_conditions))
        blacklisted_result = await db.execute(blacklisted_query)
        blacklisted_entry = blacklisted_result.scalar_one_or_none()

        if blacklisted_entry:
            logger.warning(f"Token (JTI={blacklisted_entry.jti[:8] if blacklisted_entry.jti else 'N/A'}, Type={blacklisted_entry.token_type}) is blacklisted.")
            if blacklisted_entry.token_type == "refresh":
                raise unauthorized("Invalid session. Please log in again.")
            else: # Access token blacklisted
                raise credentials_exception


    # 4. User status checks
    if not user.is_active:
        logger.warning(f"Authentication failed: User {user.username} (ID: {user_id}) is inactive.")
        raise unauthorized("Inactive user account")
    
    # If email verification is required and user is not verified
    # MFA challenge tokens (type 'mfa_challenge') are allowed to bypass this to enable verification flow.
    # This also applies if a user is trying to verify their email (route uses this dependency).
    if (settings.REQUIRE_EMAIL_VERIFICATION and not user.is_verified and
        payload.type not in ["mfa_challenge", "email_verification"]): 
        logger.warning(f"Authentication failed: User {user.username} (ID: {user_id}) email is not verified.")
        raise unauthorized("Email not verified")

    # 5. Additional checks based on token type and session status
    if payload.type == "mfa_challenge":
        if not current_session:
            logger.warning(f"MFA challenge token for user {user.id} has no matching current session {session_jti_to_check}.")
            raise credentials_exception
            
        # For an MFA challenge token, the session should be active but NOT yet trusted
        if current_session.is_trusted:
            logger.warning(f"MFA challenge token used for user {user.id} but session {current_session.id} is already trusted.")
            raise unauthorized("Session already trusted. Please log in again.")
        
        # Attach the pending session to the request state for subsequent MFA verification steps
        request.state.pending_mfa_session = current_session
        logger.debug(f"MFA challenge token validated for user {user.username}. Session {current_session.id} pending MFA.")
    
    elif payload.type == "access":
        if not current_session:
            logger.warning(f"Access token for user {user.id} has no matching current session {session_jti_to_check}.")
            raise unauthorized("Invalid session. Please log in again.")

        # For a full access token, the session *must* be trusted if MFA is enabled for the user.
        if user.is_mfa_enabled and not current_session.is_trusted:
            logger.warning(f"Access token used for MFA-enabled user {user.id} but session {current_session.jti[:8]} is not trusted.")
            # This is the point where the 401 error you reported originates.
            raise unauthorized("MFA required. Please complete MFA verification.")
        
        # If all checks pass for an access token, update the session's last_accessed_at in the background
        background_tasks.add_task(update_session_last_accessed, db, current_session.id)
        
        logger.debug(f"User {user.username} (ID: {user.id}) successfully authenticated with access token.")
    
    else: # Handle other potential token types or invalid ones
        logger.warning(f"Authentication failed: Unhandled or invalid token type '{payload.type}' for user {user.id}.")
        raise credentials_exception

    return user


async def get_session_token(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)]
) -> str:
    """
    Returns the raw Bearer token string after validation.
    Intended for use in logout/session termination.
    """
    if not credentials or not credentials.credentials:
        logger.warning("Missing or invalid Authorization header")
        raise unauthorized("Missing authorization credentials or session token")

    token = credentials.credentials
    # Decode token to implicitly check its validity and expiration
    try:
        payload = await decode_token(token)
        # Ensure it's a refresh token or a type that can be used for session management
        if payload.type != "refresh":
            logger.warning(f"Attempt to use non-refresh token ({payload.type}) for session token operations.")
            raise unauthorized("Invalid token type for session operation.")

    except APIException as e:
        logger.warning(f"Session token decoding failed with APIException: {e.message} ({e.name})", exc_info=False)
        raise unauthorized("Invalid or expired session token.")
    except Exception as e:
        logger.warning(f"Session token decoding failed unexpectedly: {e}", exc_info=True)
        raise unauthorized("Invalid or expired session token.")
    return token


async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """
    Dependency to get the current active user.
    This dependency primarily ensures the user is active and generally authenticated.
    Additional checks like email verification (unless bypassed for specific flows)
    and MFA trust are handled in get_current_user.
    """
    return current_user

async def get_current_admin(current_user: Annotated[User, Depends(get_current_active_user)]) -> User:
    """
    Dependency to get the current active admin user.
    Ensures the user is an admin.
    """
    logger.debug(f"Attempting to get current admin for user: {current_user.username}")
    if not current_user.is_admin:
        logger.warning(f"User {current_user.username} attempted admin access but is not an admin.")
        raise forbidden("Admin privileges required")
    logger.info(f"Admin user {current_user.username} successfully authenticated for admin access.")
    return current_user