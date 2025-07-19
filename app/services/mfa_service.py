from datetime import datetime, timedelta, timezone
import logging
from typing import Optional, Literal

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import BackgroundTasks

from app.infrastructure.database.models import User, UserSession
from app.core.otp_utils import (
    generate_numeric_otp,
    verify_numeric_otp,
    generate_totp_secret,
    get_totp_provisioning_uri,
    verify_totp_code
)
from app.core.email_utils import send_email_mfa_challenge
from app.core.security import verify_password, create_mfa_status_change_token
from app.core.exceptions import bad_request, unauthorized, APIException

# Import the module directly, then reference its contents
from app.schemas import mfa as mfa_schemas

# --- START OF MODIFICATION ---
# Import the is_token_expired helper function
from app.services.auth.auth_utils import is_token_expired
# --- END OF MODIFICATION ---

from app.config import settings

logger = logging.getLogger(__name__)

class MfaService:
    """
    Service layer for handling Multi-Factor Authentication (MFA) operations.
    Orchestrates logic for enabling, disabling, setting up TOTP, and verifying MFA.
    """

    def __init__(self, db: AsyncSession, background_tasks: BackgroundTasks = BackgroundTasks()):
        self.db = db
        self.background_tasks = background_tasks

    async def initiate_mfa_enable(self, user: User, current_password: str) -> mfa_schemas.MessageResponse:
        """
        Initiates the MFA enablement process by sending an email challenge token.
        Requires the user's current password for re-authentication.
        """
        # 1. Verify current password for re-authentication
        if not await verify_password(current_password, user.hashed_password):
            logger.warning(f"MFA enable initiation failed for user {user.id}: Invalid password.")
            raise unauthorized(message="Invalid password provided.")

        # If MFA is already enabled, prevent re-initiation
        if user.is_mfa_enabled:
            logger.warning(f"MFA enable initiation requested for user {user.id} but MFA is already enabled.")
            raise bad_request(message="Multi-Factor Authentication is already enabled for this account.")

        # 2. Generate a new JWT-based MFA status change token
        token = await create_mfa_status_change_token(
            user_id=str(user.id),
            expires_delta=timedelta(minutes=settings.MFA_EMAIL_TOKEN_EXPIRE_MINUTES)
        )

        # Store the token and its expiry in the user model for verification
        user.mfa_email_challenge_token = token
        user.mfa_email_challenge_expires = datetime.now(timezone.utc) + timedelta(minutes=settings.MFA_EMAIL_TOKEN_EXPIRE_MINUTES)
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        # 3. Add the email sending to background tasks
        try:
            self.background_tasks.add_task(send_email_mfa_challenge, user.email, user.first_name, token=token, is_enable_confirm_link=True)
            logger.info(f"MFA enable initiation: Email challenge link added to background tasks for user {user.id}.")
            return mfa_schemas.MessageResponse(message="MFA enablement initiated. Please check your email for a verification link.")
        except Exception as e:
            logger.error(f"Failed to add MFA email challenge link to background tasks for user {user.id}: {e}", exc_info=True)
            user.mfa_email_challenge_token = None
            user.mfa_email_challenge_expires = None
            await self.db.commit()
            raise bad_request(message="Failed to initiate email sending. Please try again later.")


    async def confirm_mfa_enable(self, user: User, token: str) -> mfa_schemas.MessageResponse:
        """
        Confirms the MFA enablement using the provided JWT-based email challenge token.
        """
        # 1. Validate the token against the stored token in the user model
        if not user.mfa_email_challenge_token or user.mfa_email_challenge_token != token:
            logger.warning(f"MFA enable confirmation failed for user {user.id}: Invalid or missing stored token.")
            raise unauthorized(message="Invalid or expired verification token.")

        # --- START OF MODIFICATION ---
        # Use the is_token_expired helper function
        if is_token_expired(user.mfa_email_challenge_expires):
            logger.warning(f"MFA enable confirmation failed for user {user.id}: Token expired.")
            user.mfa_email_challenge_token = None
            user.mfa_email_challenge_expires = None
            await self.db.commit()
            raise unauthorized(message="Verification token has expired. Please initiate MFA enablement again.")
        # --- END OF MODIFICATION ---

        # 2. Enable MFA and clear the challenge token
        user.is_mfa_enabled = True
        user.mfa_email_challenge_token = None
        user.mfa_email_challenge_expires = None
        user.updated_at = datetime.now(timezone.utc)
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        stmt = select(UserSession).where(
            UserSession.user_id == user.id,
            UserSession.is_active == True,
        ).order_by(UserSession.last_accessed_at.desc())

        result = await self.db.execute(stmt)
        current_session = result.scalars().first()

        if current_session:
            current_session.is_trusted = True
            self.db.add(current_session)
            await self.db.commit()
            await self.db.refresh(current_session)
            logger.info(f"User {user.id}'s current session {current_session.id} marked as trusted after MFA enablement.")
        else:
            logger.warning(f"Could not find an active session for user {user.id} to mark as trusted after MFA enablement.")

        logger.info(f"MFA successfully enabled for user {user.id}.")
        return mfa_schemas.MessageResponse(message="Multi-Factor Authentication enabled successfully.")

    async def initiate_mfa_disable(self, user: User, current_password: str) -> mfa_schemas.MessageResponse:
        """
        Initiates the MFA disablement process by sending an email challenge token.
        Requires the user's current password for re-authentication.
        """
        # 1. Verify current password for re-authentication
        if not await verify_password(current_password, user.hashed_password):
            logger.warning(f"MFA disable initiation failed for user {user.id}: Invalid password.")
            raise unauthorized(message="Invalid password provided.")

        if not user.is_mfa_enabled:
            logger.warning(f"MFA disable initiation requested for user {user.id} but MFA is not enabled.")
            raise bad_request(message="MFA is not currently enabled for this account.")

        # 2. Generate a new JWT-based MFA status change token for disablement
        token = await create_mfa_status_change_token(
            user_id=str(user.id),
            expires_delta=timedelta(minutes=settings.MFA_EMAIL_TOKEN_EXPIRE_MINUTES)
        )

        # Store the token and its expiry in the user model for verification
        user.mfa_email_challenge_token = token
        user.mfa_email_challenge_expires = datetime.now(timezone.utc) + timedelta(minutes=settings.MFA_EMAIL_TOKEN_EXPIRE_MINUTES)
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        # 3. Add the email sending to background tasks
        try:
            self.background_tasks.add_task(send_email_mfa_challenge, user.email, user.first_name, token=token, is_enable_confirm_link=False)
            logger.info(f"MFA disable initiation: Email challenge link added to background tasks for user {user.id}.")
            return mfa_schemas.MessageResponse(message="MFA disablement initiated. Please check your email for a verification link.")
        except Exception as e:
            logger.error(f"Failed to add MFA disable email challenge link to background tasks for user {user.id}: {e}", exc_info=True)
            user.mfa_email_challenge_token = None
            user.mfa_email_challenge_expires = None
            await self.db.commit()
            raise bad_request(message="Failed to initiate email sending. Please try again later.")

    async def confirm_mfa_disable(self, user: User, token: str) -> mfa_schemas.MessageResponse:
        """
        Confirms the MFA disablement using the provided JWT-based email challenge token.
        """
        # 1. Validate the token against the stored token in the user model
        if not user.mfa_email_challenge_token or user.mfa_email_challenge_token != token:
            logger.warning(f"MFA disable confirmation failed for user {user.id}: Invalid or missing stored token.")
            raise unauthorized(message="Invalid or expired verification token.")

        # --- START OF MODIFICATION ---
        # Use the is_token_expired helper function
        if is_token_expired(user.mfa_email_challenge_expires):
            logger.warning(f"MFA disable confirmation failed for user {user.id}: Token expired.")
            user.mfa_email_challenge_token = None
            user.mfa_email_challenge_expires = None
            await self.db.commit()
            raise unauthorized(message="Verification token has expired. Please initiate MFA disablement again.")
        # --- END OF MODIFICATION ---

        # 2. Disable MFA and clear all MFA-related secrets and tokens
        user.is_mfa_enabled = False
        user.totp_secret = None
        user.totp_verified = False
        user.mfa_email_challenge_token = None
        user.mfa_email_challenge_expires = None
        user.updated_at = datetime.now(timezone.utc)
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        stmt = select(UserSession).where(
            UserSession.user_id == user.id,
            UserSession.is_active == True,
        ).order_by(UserSession.last_accessed_at.desc())

        result = await self.db.execute(stmt)
        current_session = result.scalars().first()

        if current_session:
            current_session.is_trusted = False
            self.db.add(current_session)
            await self.db.commit()
            await self.db.refresh(current_session)
            logger.info(f"User {user.id}'s current session {current_session.id} marked as NOT trusted after MFA disablement.")
        else:
            logger.warning(f"Could not find an active session for user {user.id} to mark as NOT trusted after MFA disablement.")

        logger.info(f"MFA successfully disabled for user {user.id}.")
        return mfa_schemas.MessageResponse(message="Multi-Factor Authentication disabled successfully.")

    async def initiate_totp_setup(self, user: User) -> mfa_schemas.MFATOTPSetupInitiateResponse:
        """
        Initiates TOTP setup for a user. Generates a secret and provisioning URI.
        The user must then verify this setup with an OTP from their authenticator app.
        """
        if not user.is_mfa_enabled:
            logger.warning(f"TOTP setup initiated for user {user.id} but MFA is not generally enabled.")
            raise bad_request(message="MFA must be enabled before setting up TOTP.")

        if user.totp_verified:
            logger.warning(f"TOTP setup initiated for user {user.id} but TOTP is already verified.")
            raise bad_request(message="TOTP is already set up and verified for this account. Disable it first to re-setup.")

        # 1. Generate a new TOTP secret
        secret = generate_totp_secret()

        # 2. Store the secret in the user model and set totp_verified to False initially
        user.totp_secret = secret
        user.totp_verified = False
        user.updated_at = datetime.now(timezone.utc)
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        # 3. Generate the provisioning URI for QR code
        totp_uri = get_totp_provisioning_uri(secret, user.email, settings.APP_NAME)

        logger.info(f"TOTP setup initiated for user {user.id}.")
        return mfa_schemas.MFATOTPSetupInitiateResponse(
            totp_secret=secret,
            totp_uri=totp_uri,
            message="Scan the QR code with your authenticator app and verify the OTP."
        )

    async def verify_totp_setup(self, user: User, otp_code: str) -> mfa_schemas.MessageResponse:
        """
        Verifies the TOTP setup by checking the provided OTP code against the stored secret.
        If successful, marks TOTP as verified for the user.
        """
        if not user.totp_secret:
            logger.warning(f"TOTP setup verification failed for user {user.id}: No TOTP secret found.")
            raise bad_request(message="TOTP setup not initiated or secret missing.")

        if user.totp_verified:
            logger.warning(f"TOTP setup verification attempted for user {user.id} but TOTP is already verified.")
            return mfa_schemas.MessageResponse(message="TOTP is already set up and verified.")

        # 1. Verify the TOTP code
        if not verify_totp_code(user.totp_secret, otp_code):
            logger.warning(f"TOTP setup verification failed for user {user.id}: Invalid TOTP code.")
            raise bad_request(message="Invalid TOTP code provided. Please try again.")

        # 2. If verification is successful, mark TOTP as verified
        user.totp_verified = True
        if not user.is_mfa_enabled: # Ensure MFA is enabled if TOTP is the first method
            user.is_mfa_enabled = True
        user.updated_at = datetime.now(timezone.utc)
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)

        logger.info(f"TOTP setup successfully verified for user {user.id}.")
        return mfa_schemas.MessageResponse(message="TOTP (Authenticator App) setup successfully completed.")

    async def handle_login_mfa_challenge(self, user: User, session: UserSession) -> Optional[Literal["email_otp", "totp"]]:
        """
        Determines if an MFA challenge is required for a login attempt and prepares it.
        Returns the type of MFA required ('email_otp' or 'totp') or None if not required.
        Email sending for OTP is now handled in the background.
        """
        if not user.is_mfa_enabled:
            logger.debug(f"No MFA challenge for user {user.id}: MFA not enabled.")
            return None

        # The session's is_trusted status is set during initial session creation in auth_core_service,
        # or updated during MFA verification. If it's already trusted, no challenge needed.
        if session.is_trusted:
            logger.debug(f"No MFA challenge for user {user.id}: Session {session.id} is trusted.")
            return None

        if user.totp_secret and user.totp_verified:
            logger.info(f"MFA challenge for user {user.id}: TOTP required.")
            return "totp"
        elif user.is_mfa_enabled: # If MFA is enabled but TOTP is not set up/verified, default to email OTP
            otp_code, expires_at = generate_numeric_otp(
                length=settings.OTP_LENGTH,
                expiration_minutes=settings.OTP_EXPIRATION_MINUTES
            )
            session.verification_otp = otp_code
            session.otp_expires_at = expires_at
            self.db.add(session)
            await self.db.commit()
            await self.db.refresh(session)

            try:
                self.background_tasks.add_task(send_email_mfa_challenge, user.email, user.first_name, otp_code=otp_code, is_login_challenge=True)
                logger.info(f"MFA challenge for user {user.id}: Email OTP added to background tasks for new device login.")
                return "email_otp"
            except Exception as e:
                logger.error(f"Failed to add login MFA email challenge to background tasks for user {user.id}: {e}", exc_info=True)
                # Clean up OTP from session if email sending fails
                session.verification_otp = None
                session.otp_expires_at = None
                self.db.add(session)
                await self.db.commit()
                raise bad_request(message="Failed to initiate MFA code sending. Please try logging in again.")

        logger.warning(f"MFA challenge logic for user {user.id} reached unexpected state. MFA enabled: {user.is_mfa_enabled}, TOTP secret: {bool(user.totp_secret)}, TOTP verified: {user.totp_verified}")
        return None

    async def verify_login_mfa(self, user: User, session: UserSession, otp_code: str, mfa_method: Optional[str] = None) -> mfa_schemas.MessageResponse:
        """
        Verifies the MFA code provided during the login challenge.
        Marks the session as trusted if successful.
        """
        if not user.is_mfa_enabled:
            logger.warning(f"Login MFA verification attempted for user {user.id} but MFA is not enabled.")
            raise bad_request(message="MFA is not enabled for this account.")

        if session.is_trusted:
            logger.warning(f"Login MFA verification attempted for user {user.id} but session {session.id} is already trusted.")
            # This case might happen if the client sends multiple verification requests
            # after the first one succeeded. It's not an error, just redundant.
            return mfa_schemas.MessageResponse(message="Session already trusted, no MFA verification needed.")

        # Determine the MFA method to verify. Prioritize explicit method from request,
        # otherwise infer from user's configured MFA.
        effective_mfa_method = mfa_method
        if effective_mfa_method is None:
            if user.totp_secret and user.totp_verified:
                effective_mfa_method = "totp"
            elif user.is_mfa_enabled:
                effective_mfa_method = "email_otp" # Fallback to email if TOTP not configured

        if effective_mfa_method == "totp":
            if not user.totp_secret or not user.totp_verified:
                logger.warning(f"Login MFA verification failed for user {user.id}: TOTP requested but not configured/verified.")
                raise bad_request(message="TOTP is not configured or verified for this account.")
            if not verify_totp_code(user.totp_secret, otp_code):
                logger.warning(f"Login MFA verification failed for user {user.id}: Invalid TOTP code.")
                raise bad_request(message="Invalid TOTP code provided.")
        elif effective_mfa_method == "email_otp":
            await verify_numeric_otp(
                stored_otp=session.verification_otp,
                stored_otp_expires_at=session.otp_expires_at,
                provided_otp=otp_code,
                otp_type="Login MFA"
            )
            # Clear OTP after successful verification
            session.verification_otp = None
            session.otp_expires_at = None
        else:
            logger.warning(f"Login MFA verification failed for user {user.id}: Unknown or unhandled MFA method requested: {mfa_method}")
            raise bad_request(message="Invalid MFA method specified or no valid MFA method configured.")

        # If verification is successful, mark the session as trusted
        session.is_trusted = True
        self.db.add(session)
        await self.db.commit()
        await self.db.refresh(session)

        logger.info(f"Login MFA successfully verified for user {user.username}. Session {session.id} marked as trusted.")
        return mfa_schemas.MessageResponse(message="MFA verified. Login successful.")

    def get_mfa_status(self, user: User) -> mfa_schemas.MFAStatusResponse:
        """
        Retrieves the current MFA status for a user.
        """
        mfa_method = None
        if user.is_mfa_enabled:
            if user.totp_secret and user.totp_verified:
                mfa_method = "totp"
            else:
                mfa_method = "email_otp" # If MFA enabled but TOTP not verified, assume email OTP is fallback

        logger.debug(f"MFA status for user {user.id}: Enabled={user.is_mfa_enabled}, Method={mfa_method}, TOTP Verified={user.totp_verified}")
        return mfa_schemas.MFAStatusResponse(
            is_mfa_enabled=user.is_mfa_enabled,
            mfa_method=mfa_method,
            totp_verified=user.totp_verified,
            message="MFA status retrieved successfully."
        )