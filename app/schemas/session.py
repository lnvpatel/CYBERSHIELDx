# app/schemas/session.py

from pydantic import BaseModel, Field
from datetime import datetime
from typing import Optional

class UserSessionResponse(BaseModel):
    """
    Schema for exposing user session details, excluding sensitive information.
    """
    id: int = Field(..., description="Unique identifier for the session.")
    ip_address: Optional[str] = Field(None, description="IP address from which the session originated.")
    user_agent: Optional[str] = Field(None, description="User agent string of the client device.")
    expires_at: datetime = Field(
        ...,
        description="Timestamp when the session token expires (in UTC). Clients should convert this to local time for display."
    )
    is_active: bool = Field(..., description="Indicates if the session is currently active.")
    created_at: datetime = Field(
        ...,
        description="Timestamp when the session was created (in UTC). Clients should convert this to local time for display."
    )

    class Config:
        # This tells Pydantic to read data from SQLAlchemy model attributes
        # rather than dictionary keys.
        from_attributes = True

class RevokeSessionRequest(BaseModel):
    """
    Schema for revoking a specific user session.
    Only the session_id is required, as the current access token is no longer blacklisted
    by this endpoint's direct action.
    """
    session_id: int = Field(..., description="ID of the session to revoke.")
    # Removed: current_access_token: str = Field(..., description="The access token currently in use for this session.")
