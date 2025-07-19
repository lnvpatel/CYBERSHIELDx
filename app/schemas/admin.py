from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
# Import UserCreate and UserResponse from your actual user schema file
from app.schemas.user import UserCreate, UserResponse


class AdminRegister(UserCreate): # Now correctly inherits from the full UserCreate
    # Removed 'example' argument
    admin_key: str = Field(...)

class AdminUserResponse(UserResponse): # Now correctly inherits from the full UserResponse
    # Removed 'example' arguments
    login_attempts: int = Field(...)
    account_locked: bool = Field(...)
    mfa_enabled: bool = Field(...)
    last_login: Optional[datetime] = Field(None)

class AdminActionLog(BaseModel):
    # Removed 'example' arguments
    admin_id: int = Field(...)
    action_type: str = Field(...)
    target_id: Optional[int] = Field(None)
    ip_address: Optional[str] = Field(None)
    details: Optional[str] = Field(None)

class AdminLogResponse(BaseModel):
    """
    Schema for responding with a retrieved administrative log.
    Includes usernames of the admin and the target user (if applicable).
    """
    id: int = Field(..., description="The unique ID of the admin log entry.")
    admin_id: int = Field(..., description="The ID of the administrator who performed the action.")
    admin_username: str = Field(..., description="The username of the administrator who performed the action.")
    target_id: Optional[int] = Field(None, description="The ID of the user on whom the action was performed (if applicable).")
    target_username: Optional[str] = Field(None, description="The username of the user on whom the action was performed (if applicable).")
    action_type: str = Field(..., max_length=50, description="The type of administrative action performed (e.g., 'user_deleted', 'user_status_update').")
    details: Optional[str] = Field(None, description="Additional details about the administrative action.")
    ip_address: Optional[str] = Field(None, max_length=45, description="The IP address from which the administrative action originated.")
    created_at: datetime = Field(..., description="The timestamp when the administrative action was logged (UTC).")

    class Config:
        from_attributes = True # Enable ORM mode for automatic mapping