from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator
from typing import Literal, Annotated, Optional
from pydantic.types import StringConstraints

# ============================
# Login and Token Schemas
# ============================

class LoginRequest(BaseModel):
    username_or_email: str = Field(..., description="Username, email, or mobile number")
    password: str = Field(..., min_length=8, description="User's password")
    remember_me: bool = Field(False, description="Whether to keep the user logged in for an extended period")
    device_id: Optional[str] = Field(None, description="Unique identifier for the device initiating the login (client-generated)") # <--- ADDED THIS LINE

class TokenResponse(BaseModel):
    access_token: Optional[str] = Field(None, description="JWT access token for API authentication")
    refresh_token: Optional[str] = Field(None, description="JWT refresh token for obtaining new access tokens")
    token_type: Optional[Literal["bearer"]] = Field("bearer", description="Type of the token, typically 'bearer'")
    mfa_required: bool = Field(False, description="True if Multi-Factor Authentication is required to complete login")
    mfa_challenge_token: Optional[str] = Field(None, description="Temporary token for MFA verification if mfa_required is true")
    mfa_method_required: Optional[Literal["email_otp", "totp"]] = Field(None, description="The MFA method required ('email_otp' or 'totp') if mfa_required is true") # Added Literal type for clarity
    is_device_trusted: bool = Field(False, description="Indicates if the current device is recognized as trusted after login/MFA") # Added
    message: str = Field("Login successful", description="A descriptive message for the login status")


# Removed: class MfaVerifyRequest(...)
# This schema is now considered redundant if MFALoginVerifyRequest in app/schemas/mfa.py handles all necessary MFA verifications.


# NEW: Schema for Refresh Token Request
class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., description="The refresh token string to obtain a new access token")

# NEW: Schema for Logout Request (for explicit refresh token revocation)
class LogoutRequest(BaseModel):
    refresh_token: str = Field(..., description="The refresh token to be explicitly revoked from the server")

# ============================
# Forgot Password Flow Schemas
# ============================

class ForgotPasswordStartRequest(BaseModel):
    username_or_email: str = Field(..., description="Username or email address of the account to reset password for")

class ForgotPasswordConfirmRequest(BaseModel):
    username: str = Field(..., description="Username of the account")
    email: EmailStr = Field(..., description="Email address associated with the account")

class ResetPasswordRequest(BaseModel):
    token: str = Field(..., description="The password reset token received via email")
    new_password: Annotated[str, StringConstraints(min_length=8)] = Field(
        ..., description="The new password for the account"
    )
    confirm_password: Annotated[str, StringConstraints(min_length=8)] = Field(
        ..., description="Confirmation of the new password"
    )

    @field_validator('new_password')
    @classmethod
    def validate_password_strength(cls, v: str):
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v

    @model_validator(mode="after")
    def check_passwords_match(self):
        if self.new_password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self