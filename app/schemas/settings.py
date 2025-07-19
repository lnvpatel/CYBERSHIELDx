# app/schemas/settings.py

from pydantic import BaseModel, Field
from typing import Optional

class SecurityPolicyUpdate(BaseModel):
    """
    Schema for updating system-wide security policies.
    All fields are optional for partial updates.
    """
    min_password_length: Optional[int] = Field(None, ge=8, description="Minimum length required for user passwords.")
    password_history_count: Optional[int] = Field(None, ge=0, description="Number of past passwords a user cannot reuse.")
    account_lockout_attempts: Optional[int] = Field(None, ge=0, description="Number of failed login attempts before an account is locked.")
    account_lockout_duration_minutes: Optional[int] = Field(None, ge=0, description="Duration in minutes for which an account remains locked after reaching lockout attempts.")
    require_email_verification: Optional[bool] = Field(None, description="Boolean indicating if email verification is required for new user registrations.")
    api_rate_limit_per_minute: Optional[int] = Field(None, ge=0, description="Maximum number of API requests allowed per minute from a single source.")

class SecurityPolicyResponse(BaseModel):
    """
    Schema for responding with system-wide security policies.
    """
    min_password_length: int = Field(..., ge=8, description="Minimum length required for user passwords.")
    password_history_count: int = Field(..., ge=0, description="Number of past passwords a user cannot reuse.")
    account_lockout_attempts: int = Field(..., ge=0, description="Number of failed login attempts before an account is locked.")
    account_lockout_duration_minutes: int = Field(..., ge=0, description="Duration in minutes for which an account remains locked after reaching lockout attempts.")
    require_email_verification: bool = Field(..., description="Boolean indicating if email verification is required for new user registrations.")
    api_rate_limit_per_minute: int = Field(..., ge=0, description="Maximum number of API requests allowed per minute from a single source.")

    class Config:
        populate_by_name = True
        from_attributes = True

# NEW: Basic Registration Settings
class RegistrationSettingsUpdate(BaseModel):
    """
    Schema for updating basic registration settings.
    """
    is_registration_enabled: Optional[bool] = Field(None, description="Boolean indicating if new user registration is currently allowed.")

class RegistrationSettingsResponse(BaseModel):
    """
    Schema for responding with basic registration settings.
    """
    is_registration_enabled: bool = Field(..., description="Boolean indicating if new user registration is currently allowed.")

    class Config:
        populate_by_name = True
        from_attributes = True
