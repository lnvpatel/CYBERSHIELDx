# app/schemas/mfa.py

from pydantic import BaseModel, Field
from typing import Optional, Literal # Ensure Literal is imported

# --- Schemas for Initiating MFA Actions (e.g., Enable/Disable) ---

class MFAEnableRequest(BaseModel):
    """
    Schema for a user requesting to enable MFA.
    Requires current password for security re-authentication.
    """
    current_password: str = Field(
        ...,
        example="YourCurrentPassword123",
        description="User's current password for re-authentication."
    )

class MFADisableRequest(BaseModel):
    """
    Schema for a user requesting to disable MFA.
    Requires current password for security re-authentication.
    Optionally requires an OTP/TOTP code for higher security.
    """
    current_password: str = Field(
        ...,
        example="YourCurrentPassword123",
        description="User's current password for re-authentication."
    )
    otp_code: Optional[str] = Field(
        None,
        min_length=6,
        max_length=8,
        example="123456",
        description="Current OTP/TOTP code to confirm disable action (optional in schema, but often required by service if MFA is active)."
    )

# --- Schemas for Confirming MFA Actions (e.g., via Email Token) ---

class MFAStatusChangeConfirm(BaseModel):
    """
    Schema for confirming MFA enable/disable via an email token.
    This token is sent to the user's registered email for verification.
    """
    token: str = Field(
        ...,
        description="The unique token received via email to confirm MFA status change."
    )

# --- Schemas for TOTP (Authenticator App) Setup ---

class MFATOTPSetupInitiateResponse(BaseModel):
    """
    Schema for responding after initiating TOTP setup, providing the URI/QR code data.
    """
    totp_secret: str = Field(
        ...,
        description="The Base32 encoded TOTP secret (for displaying directly if needed, but QR URI is better)."
    )
    totp_uri: str = Field(
        ...,
        description="The otpauth URI to generate a QR code for authenticator apps."
    )
    message: str = Field(
        "Scan the QR code with your authenticator app and verify the OTP.",
        description="Instructions for the user."
    )

class MFATOTPSetupVerifyRequest(BaseModel):
    """
    Schema for verifying the TOTP code during initial TOTP setup.
    """
    otp_code: str = Field(
        ...,
        min_length=6,
        max_length=8,
        example="123456",
        description="The TOTP code from the authenticator app to verify setup."
    )

# --- Schema for MFA during Login ---

class MFALoginVerifyRequest(BaseModel):
    """
    Schema for verifying the OTP (email-based or TOTP) during the second step of a login flow.
    """
    otp_code: str = Field(
        ...,
        min_length=6,
        max_length=8,
        example="123456",
        description="The OTP/TOTP code provided by the user."
    )
    mfa_challenge_token: str = Field(
        ...,
        description="The temporary token received after the initial login, indicating an MFA challenge is required."
    )
    mfa_method: Optional[Literal["email_otp", "totp"]] = Field(
        None,
        description="The MFA method used for verification (e.g., 'email_otp', 'totp'). Optional if determined by context."
    )
    device_id: Optional[str] = Field(None, description="Unique identifier for the device verifying MFA (client-generated)")


# --- Schemas for Responses ---

class MFAStatusResponse(BaseModel):
    """
    Schema for responding with the current MFA status.
    Provides details on whether MFA is enabled and which method.
    """
    is_mfa_enabled: bool = Field(
        ...,
        description="True if MFA is enabled for the user, False otherwise."
    )
    mfa_method: Optional[Literal["email_otp", "totp"]] = Field(
        None,
        description="The primary MFA method configured ('email_otp', 'totp', or None if not enabled)."
    )
    totp_verified: bool = Field(
        False,
        description="True if TOTP (Authenticator App) has been successfully set up and verified for the user."
    )
    message: str = Field(
        "MFA status retrieved successfully.",
        description="A user-friendly message."
    )

class MessageResponse(BaseModel):
    """
    Generic success or informational message response.
    """
    message: str = Field(
        ...,
        example="Operation successful.",
        description="A user-friendly message."
    )