from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from app.db import Base
import enum

# ✅ Enum for Role Management
class UserRole(str, enum.Enum):
    USER = "User"
    ADMIN = "Admin"

# ✅ User Model (Database ORM)
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=True)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    mobile_number = Column(String, unique=True, nullable=False)
    dob = Column(DateTime, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String, nullable=True)
    photo_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    token_version = Column(Integer, default=0)

    # ✅ Relationships
    admin_logs = relationship("AdminLog", back_populates="admin_user", foreign_keys="[AdminLog.admin_id]")
    activity_logs = relationship("ActivityLog", back_populates="user")

    # ✅ Ensure at least one admin remains
    @classmethod
    def ensure_admin_exists(cls, db_session):
        admin_count = db_session.query(cls).filter(cls.role == UserRole.ADMIN).count()
        if admin_count <= 1:
            raise ValueError("At least one admin must remain!")

# ✅ Admin Activity Log Model
class AdminLog(Base):
    __tablename__ = "admin_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    target_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc)) 

    admin_user = relationship("User", foreign_keys=[admin_id], back_populates="admin_logs")

# ✅ General User Activity Log Model
class ActivityLog(Base):
    __tablename__ = "activity_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    action = Column(String, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="activity_logs")
