from pydantic import BaseModel, EmailStr, ConfigDict, Field
from datetime import datetime, timezone
from typing import Optional
import enum

class UserRole(str, enum.Enum):
    USER = "User"
    ADMIN = "Admin"

class UserCreate(BaseModel):
    first_name: str
    last_name: Optional[str] = None
    username: str
    email: EmailStr
    mobile_number: str
    dob: Optional[datetime] = None
    password: str
    role: UserRole = UserRole.USER
    photo_url: Optional[str] = None

class UserResponse(BaseModel):
    id: int
    first_name: str
    last_name: Optional[str] = None
    username: str
    email: EmailStr
    mobile_number: str
    dob: Optional[datetime]
    role: UserRole
    photo_url: Optional[str]
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_verified: bool
    # verification_token: Optional[str] = None # Removed verification_token

    model_config = ConfigDict(from_attributes=True)

class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    mobile_number: Optional[str] = None
    dob: Optional[datetime] = None
    password: Optional[str] = None
    is_active: Optional[bool] = None
    role: Optional[UserRole] = None
    photo_url: Optional[str] = None