from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional
import enum

# ✅ Enum for Role Management (Same as in models)
class UserRole(str, enum.Enum):
    USER = "User"
    ADMIN = "Admin"

# ✅ Schema for Creating a User (Signup)
class UserCreate(BaseModel):
    first_name: str
    last_name: Optional[str] = None
    username: str
    email: EmailStr
    mobile_number: str
    dob: datetime
    password: str  # ✅ User enters password during signup

    photo_url: Optional[str] = None  # ✅ Optional photo URL

# ✅ Schema for Returning User Data (Response)
class UserResponse(BaseModel):
    id: int
    first_name: str
    last_name: Optional[str]
    username: str
    email: str
    mobile_number: str
    dob: datetime
    role: UserRole
    is_active: bool
    is_verified: bool
    photo_url: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}  # ✅ For Pydantic v2

# ✅ Schema for Updating a User (Profile Update)
class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    mobile_number: Optional[str] = None
    dob: Optional[datetime] = None
    password: Optional[str] = None  # ✅ Allow password change
    is_active: Optional[bool] = None
    role: Optional[UserRole] = None  # ✅ Allow role updates (Admin Only)
    photo_url: Optional[str] = None
