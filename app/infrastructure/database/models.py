# app/infrastructure/database/models.py

from datetime import datetime, timezone
import sqlalchemy as sa
from sqlalchemy import String, Integer, DateTime, Boolean, Text, Date, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.sql import func
from typing import Optional 
from app.infrastructure.database.base import Base

# Removed: from sqlalchemy.dialects.postgresql import UUID # Not directly used for mapped_column type in JTI


class User(Base):
    __tablename__ = 'users'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    first_name: Mapped[str] = mapped_column(String(50), nullable=False)
    last_name: Mapped[str] = mapped_column(String(50), nullable=False)
    username: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    mobile_number: Mapped[Optional[str]] = mapped_column(String(20), unique=True, nullable=True, index=True)
    dob: Mapped[datetime] = mapped_column(Date, nullable=True) # Date type for DOB
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    
    photo_url: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, index=True) # For email verification
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, index=True)

    # Account Lockout fields
    login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    account_locked: Mapped[bool] = mapped_column(Boolean, default=False)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # MFA fields
    is_mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_email_challenge_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    mfa_email_challenge_expires: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    totp_secret: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    totp_verified: Mapped[bool] = mapped_column(Boolean, default=False) # True after TOTP setup is verified

    # Password Reset fields
    password_reset_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    password_reset_expires: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # Email Verification fields (can be reused if token expires for resend)
    verification_token: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    verification_token_expires: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    # Relationships
    sessions: Mapped[list["UserSession"]] = relationship("UserSession", back_populates="user")
    password_history: Mapped[list["PasswordHistory"]] = relationship("PasswordHistory", back_populates="user")
    activity_logs: Mapped[list["ActivityLog"]] = relationship("ActivityLog", back_populates="user")
    admin_logs_initiated: Mapped[list["AdminLog"]] = relationship("AdminLog", foreign_keys="[AdminLog.admin_id]", back_populates="admin_user")
    admin_logs_targeted: Mapped[list["AdminLog"]] = relationship("AdminLog", foreign_keys="[AdminLog.target_id]", back_populates="target_user")


    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"

    __table_args__ = (
        UniqueConstraint('username'),
        UniqueConstraint('email'),
        UniqueConstraint('mobile_number'),
        # Add explicit indexes for frequently queried columns
        sa.Index('ix_users_username_email_mobile', 'username', 'email', 'mobile_number'),
        sa.Index('ix_users_active_verified_admin', 'is_active', 'is_verified', 'is_admin'),
    )

class UserSession(Base):
    __tablename__ = 'user_sessions'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    jti: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True) # JWT ID for refresh token
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True) # IPv4 or IPv6
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True) # Session active or revoked/expired
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False, index=True) # True if MFA verified for this session/device
    
    # Fields for email OTP during MFA login challenge
    verification_otp: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)
    otp_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # --- ADDED device_id COLUMN ---
    device_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True, index=True)
    # ----------------------------

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_accessed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    user: Mapped["User"] = relationship("User", back_populates="sessions")

    def __repr__(self) -> str:
        return f"<UserSession(id={self.id}, user_id={self.user_id}, is_active={self.is_active})>"

    __table_args__ = (
        sa.Index('ix_user_sessions_user_active_trusted', 'user_id', 'is_active', 'is_trusted'),
        # Add a combined index for trusted device lookup for performance
        sa.Index('ix_user_sessions_user_device_trusted', 'user_id', 'device_id', 'is_trusted', 'is_active'),
    )


class BlacklistedToken(Base):
    __tablename__ = 'blacklisted_tokens'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    jti: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True) # JWT ID
    token_type: Mapped[str] = mapped_column(String(50), nullable=False) # e.g., 'refresh'
    blacklisted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    def __repr__(self) -> str:
        return f"<BlacklistedToken(id={self.id}, jti='{self.jti}', type='{self.token_type}')>"


class PasswordHistory(Base):
    __tablename__ = 'password_history'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    user: Mapped["User"] = relationship("User", back_populates="password_history")

    def __repr__(self) -> str:
        return f"<PasswordHistory(id={self.id}, user_id={self.user_id}, changed_at='{self.changed_at}')>"


class ActivityLog(Base):
    __tablename__ = 'activity_logs'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False, index=True)
    activity_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True) # e.g., 'login_successful', 'password_reset'
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    user: Mapped["User"] = relationship("User", back_populates="activity_logs")

    def __repr__(self) -> str:
        return f"<ActivityLog(id={self.id}, user_id={self.user_id}, type='{self.activity_type}', timestamp='{self.timestamp}')>"
    
    __table_args__ = (
        sa.Index('ix_activity_logs_user_type_timestamp', 'user_id', 'activity_type', 'timestamp'),
    )


class AdminLog(Base):
    __tablename__ = 'admin_logs'

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    admin_id: Mapped[int] = mapped_column(Integer, ForeignKey('users.id'), nullable=False, index=True) # The admin who performed the action
    target_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey('users.id'), nullable=True, index=True) # The user/resource affected
    action_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True) # e.g., 'user_deactivated', 'settings_updated'
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    admin_user: Mapped["User"] = relationship("User", foreign_keys=[admin_id], back_populates="admin_logs_initiated")
    target_user: Mapped[Optional["User"]] = relationship("User", foreign_keys=[target_id], back_populates="admin_logs_targeted")

    def __repr__(self) -> str:
        return f"<AdminLog(id={self.id}, admin_id={self.admin_id}, action='{self.action_type}', created_at='{self.created_at}')>"

    __table_args__ = (
        sa.Index('ix_admin_logs_admin_target_action', 'admin_id', 'target_id', 'action_type'),
    )