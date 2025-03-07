from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Enum, Date
from sqlalchemy.orm import relationship, validates
from sqlalchemy.sql import func, text
from datetime import datetime, timezone
from app.db import Base
import enum

# ✅ Enum for Role Management
class UserRole(str, enum.Enum):
    USER = "User"
    ADMIN = "Admin"

# ✅ User Model
class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=True)
    username = Column(String, unique=True, nullable=False, index=True)
    email = Column(String, unique=True, nullable=False, index=True)
    mobile_number = Column(String, unique=True, nullable=False)
    dob = Column(Date, nullable=False)  
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole, native_enum=False), default=UserRole.USER, nullable=False, index=True)
    is_active = Column(Boolean, server_default=text("true"), nullable=False)
    is_verified = Column(Boolean, server_default=text("false"), nullable=False)
    verification_token = Column(String, nullable=True)  
    photo_url = Column(String, nullable=True)
    created_at = Column(DateTime, server_default=func.now(), default=lambda: datetime.now(timezone.utc), nullable=False)
    token_version = Column(Integer, default=0)

    # ✅ Relationships
    admin_logs = relationship("AdminLog", back_populates="admin_user", foreign_keys="[AdminLog.admin_id]", cascade="all, delete-orphan")
    activity_logs = relationship("ActivityLog", back_populates="user", cascade="all, delete-orphan")

    # ✅ Ensure at least one admin remains
    @classmethod
    def ensure_admin_exists(cls, db_session):
        admin_count = db_session.query(cls).filter(cls.role == UserRole.ADMIN).count()
        if admin_count <= 1:
            raise ValueError("At least one admin must remain!")

    # ✅ Prevent last admin from being demoted
    @validates("role")
    def validate_role_change(self, key, new_role):
        if self.role == UserRole.ADMIN and new_role == UserRole.USER:
            from sqlalchemy.orm.session import object_session
            session = object_session(self)
            admin_count = session.query(User).filter(User.role == UserRole.ADMIN).count()
            if admin_count <= 1:
                raise ValueError("Cannot demote the last remaining admin!")
        return new_role

# ✅ Admin Activity Log Model
class AdminLog(Base):
    __tablename__ = "admin_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    target_user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    action = Column(String, nullable=False)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False)

    admin_user = relationship("User", foreign_keys=[admin_id], back_populates="admin_logs")
    target_user = relationship("User", foreign_keys=[target_user_id])  # ✅ Added for reference

# ✅ General User Activity Log Model
class ActivityLog(Base):
    __tablename__ = "activity_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    action = Column(String, nullable=False)
    timestamp = Column(DateTime, server_default=func.now(), nullable=False)

    user = relationship("User", back_populates="activity_logs")  # ✅ Fixed syntax error
