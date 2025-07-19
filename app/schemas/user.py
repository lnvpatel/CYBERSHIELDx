# app/schemas/user.py

from pydantic import BaseModel, EmailStr, Field, field_validator, ValidationInfo
from datetime import datetime, date
from typing import Optional, Annotated
from pydantic.types import StringConstraints
import re

# ========================
# USER BASE SCHEMA
# ========================

class UserBase(BaseModel):
    first_name: Annotated[str, StringConstraints(min_length=1, max_length=50)] = Field(...)
    last_name: Optional[Annotated[str, StringConstraints(max_length=50)]] = Field(None)
    username: Annotated[str, StringConstraints(min_length=4, max_length=30, pattern=r"^[a-zA-Z0-9_]+$")] = Field(...)
    email: EmailStr = Field(...)
    mobile_number: Annotated[str, StringConstraints(min_length=10, max_length=15)] = Field(...)
    dob: date = Field(...)

    @field_validator('mobile_number')
    @classmethod
    def validate_mobile_number(cls, v: str):
        # We enforce E.164 format for international mobile numbers.
        # This regex ensures it starts with a '+' followed by 1 to 14 digits.
        if not re.match(r"^\+[1-9]\d{1,14}$", v):
            raise ValueError("Invalid international phone number format (E.164: e.g., +1234567890)")
        return v

# ========================
# USER CREATE SCHEMA
# ========================

class UserCreate(UserBase):
    password: Annotated[str, StringConstraints(min_length=8, max_length=50)] = Field(...)
    confirm_password: str = Field(...)
    photo_url: Optional[str] = None # Assuming optional photo upload

    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v: str):
        # Basic checks, comprehensive check happens in service using config.PASSWORD_REGEX
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(not c.isalnum() for c in v):
            raise ValueError("Password must contain at least one special character")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter")
        return v

    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v: str, info: ValidationInfo):
        password = info.data.get('password')
        if password != v:
            raise ValueError("Passwords do not match")
        return v

# ========================
# USER RESPONSE SCHEMA
# ========================

class UserResponse(UserBase):
    id: int = Field(...)
    photo_url: Optional[str] = Field(None)
    is_active: bool = Field(...)
    is_verified: bool = Field(...)
    is_admin: bool = Field(...)
    created_at: datetime = Field(...)
    updated_at: Optional[datetime] = Field(None)
    last_login: Optional[datetime] = Field(None)
    
    # Fields for login attempts, account locking, and MFA
    login_attempts: int = Field(...)
    account_locked: bool = Field(...)
    is_mfa_enabled: bool = Field(...) # MODIFIED: Renamed from 'mfa_enabled' for consistency with model

    class Config:
        from_attributes = True # Enable ORM mode for Pydantic V2+

# ========================
# USER UPDATE SCHEMA
# ========================

class UserUpdate(BaseModel):
    first_name: Optional[Annotated[str, StringConstraints(min_length=1, max_length=50)]] = Field(default=None)
    last_name: Optional[Annotated[str, StringConstraints(max_length=50)]] = Field(default=None)
    username: Optional[Annotated[str, StringConstraints(min_length=4, max_length=30, pattern=r"^[a-zA-Z0-9_]+$")]] = Field(default=None)
    mobile_number: Optional[Annotated[str, StringConstraints(min_length=10, max_length=15)]] = Field(default=None)
    dob: Optional[date] = Field(default=None)
    photo_url: Optional[str] = Field(default=None)
    # is_active, is_admin, is_verified should only be modifiable by admin via specific endpoints

    @field_validator('mobile_number')
    @classmethod
    def validate_mobile_number(cls, v: Optional[str]):
        if v is not None and not re.match(r"^\+[1-9]\d{1,14}$", v):
            raise ValueError("Invalid international phone number format (E.164: e.g., +1234567890)")
        return v
    
# ========================
# Change Password Schema
# ========================

class ChangePasswordRequest(BaseModel):
    old_password: str = Field(...)
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=50,
        description="New password must meet complexity requirements."
    )
    confirm_new_password: str = Field(...)

    @field_validator('new_password')
    @classmethod
    def validate_new_password_strength(cls, v: str):
        # Basic checks, full regex check in service layer
        if not any(c.isupper() for c in v):
            raise ValueError("New password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("New password must contain at least one digit")
        if not any(not c.isalnum() for c in v):
            raise ValueError("New password must contain at least one special character")
        if not any(c.islower() for c in v):
            raise ValueError("New password must contain at least one lowercase letter")
        return v

    @field_validator('confirm_new_password')
    @classmethod
    def new_passwords_match(cls, v: str, info: ValidationInfo):
        new_password = info.data.get('new_password')
        if new_password != v:
            raise ValueError("New passwords do not match")
        return v


# ========================
# Admin User Management Schemas
# ========================

class UserStatusUpdate(BaseModel):
    """
    Schema for updating a user's active status.
    """
    is_active: bool = Field(..., description="Whether the user account is active or inactive.")

class UserRoleUpdate(BaseModel):
    """
    Schema for updating a user's admin role.
    """
    is_admin: bool = Field(..., description="Whether the user has administrative privileges.")

class UserVerificationUpdate(BaseModel):
    """
    Schema for updating a user's email verification status.
    """
    is_verified: bool = Field(..., description="Whether the user's email is verified or not.")