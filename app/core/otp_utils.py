# app/core/otp_utils.py

import secrets
import string
from datetime import datetime, timedelta, timezone # Ensure timezone is imported
import logging
from typing import Optional

# Import pyotp for Time-Based One-Time Passwords (TOTP)
import pyotp

from app.config import settings
from app.core.exceptions import bad_request # Assuming you have a bad_request exception

logger = logging.getLogger(__name__)

def generate_numeric_otp(
    length: int = settings.OTP_LENGTH, 
    expiration_minutes: int = settings.OTP_EXPIRATION_MINUTES
) -> tuple[str, datetime]:
    """
    Generates a numeric OTP and its expiration time.
    Uses settings from app.config for default length and expiration.
    """
    digits = string.digits
    otp = ''.join(secrets.choice(digits) for _ in range(length))
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=expiration_minutes)
    logger.debug(f"Generated numeric OTP (length {length}, expires in {expiration_minutes} min): {otp} (expires at {expires_at})")
    return otp, expires_at

async def verify_numeric_otp(
    stored_otp: Optional[str],
    stored_otp_expires_at: Optional[datetime],
    provided_otp: str,
    otp_type: str = "general" # For logging, e.g., "MFA Email", "New Device OTP"
) -> bool:
    """
    Verifies if the provided numeric OTP matches the stored OTP and is not expired.
    Raises bad_request if verification fails.
    """
    if not stored_otp or not stored_otp_expires_at:
        logger.warning(f"Attempted to verify {otp_type} OTP but no stored OTP found or it was already consumed.")
        raise bad_request("Invalid or expired OTP. Please request a new one.")

    # Ensure provided_otp is a string for comparison
    if not isinstance(provided_otp, str):
        logger.warning(f"{otp_type} OTP provided is not a string type: {type(provided_otp)}")
        raise bad_request("Invalid OTP format.")

    # --- CRITICAL FIX START ---
    # Make stored_otp_expires_at timezone-aware (UTC) if it's naive
    # This assumes your database stores datetimes in UTC, but SQLAlchemy loads them as naive.
    if stored_otp_expires_at.tzinfo is None:
        try:
            # Attempt to localize it as UTC
            stored_otp_expires_at = stored_otp_expires_at.replace(tzinfo=timezone.utc)
        except ValueError:
            # This can happen if the datetime is already aware but tzinfo is None due to some edge case
            # Or if it's not a valid datetime. This is a fallback.
            logger.error(f"Could not localize stored_otp_expires_at to UTC. Value: {stored_otp_expires_at}")
            raise bad_request("Internal error: OTP expiration time format invalid.")
    # --- CRITICAL FIX END ---

    if datetime.now(timezone.utc) > stored_otp_expires_at:
        logger.warning(f"{otp_type} OTP expired. Current time: {datetime.now(timezone.utc)}, Expires: {stored_otp_expires_at}")
        raise bad_request("OTP has expired. Please request a new one.")

    if stored_otp != provided_otp:
        logger.warning(f"{otp_type} OTP mismatch. Provided: {provided_otp}, Stored: {stored_otp[:2]}...{stored_otp[-2:]}") # Log partial OTP for security
        raise bad_request("Invalid OTP provided.")

    logger.info(f"Successfully verified {otp_type} OTP.")
    return True

def generate_totp_secret() -> str:
    """
    Generates a new Base32 encoded TOTP secret for authenticator apps.
    This secret should be stored securely (preferably encrypted) in the database.
    """
    secret = pyotp.random_base32()
    logger.debug(f"Generated TOTP secret: {secret[:4]}...") # Log partial secret
    return secret

def get_totp_provisioning_uri(
    secret: str, 
    user_identifier: str, 
    issuer_name: str = settings.APP_NAME
) -> str:
    """
    Generates the provisioning URI for TOTP, which can be used to create a QR code.
    This URI is scanned by authenticator apps (e.g., Google Authenticator, Authy).
    
    Args:
        secret: The Base32 encoded TOTP secret for the user.
        user_identifier: A string to identify the user in the authenticator app (e.g., user's email).
        issuer_name: The name of your application, displayed in the authenticator app.
    
    Returns:
        A string representing the otpauth URI.
    """
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=user_identifier, issuer_name=issuer_name)
    logger.debug(f"Generated TOTP provisioning URI for {user_identifier}.")
    return uri

def verify_totp_code(secret: str, code: str) -> bool:
    """
    Verifies a TOTP code provided by the user against the stored secret.
    
    Args:
        secret: The Base32 encoded TOTP secret stored for the user.
        code: The OTP code provided by the user from their authenticator app.
        
    Returns:
        True if the code is valid within the allowed time window, False otherwise.
    """
    if not secret or not code:
        logger.warning("Attempted to verify TOTP code with missing secret or code.")
        return False
        
    totp = pyotp.TOTP(secret)
    # pyotp.verify automatically handles time drift (default 1 time step)
    is_valid = totp.verify(code)
    
    if is_valid:
        logger.info("Successfully verified TOTP code.")
    else:
        logger.warning(f"Failed to verify TOTP code. Provided: {code}, Secret: {secret[:4]}...")
    
    return is_valid