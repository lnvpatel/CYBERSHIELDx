# app/services/admin_service.py

import logging
from datetime import datetime, timezone
from typing import Optional, cast, Sequence
from fastapi import HTTPException, status # NEW: Import HTTPException and status

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from app.schemas.settings import RegistrationSettingsResponse, RegistrationSettingsUpdate
from app.schemas.admin import AdminRegister
from app.schemas.user import UserResponse
from app.infrastructure.database.models import User, PasswordHistory, AdminLog
from app.core.security import get_password_hash
from app.core.exceptions import conflict, unauthorized, not_found, APIException # NEW: Import APIException
from app.config import settings
from app.services.activity_service import log_user_activity

logger = logging.getLogger(__name__)

async def register_admin(
    db: AsyncSession,
    data: AdminRegister,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> UserResponse:
    """
    Registers a new admin user if the secret key is valid and username/email are unique.
    """
    logger.debug(f"Attempting to register admin: {data.username}")

    # FIX: Move admin_key validation outside the main try block.
    # This ensures an invalid key immediately raises HTTPException and stops the request.
    if data.admin_key != settings.ADMIN_REGISTRATION_CODE:
        logger.warning(f"Admin registration failed for {data.username}: Invalid admin key.")
        # Directly raise HTTPException for immediate FastAPI handling (401 Unauthorized)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin key."
        )

    try: # Wrap database-related logic in a try block for transaction rollback
        # Check for existing username, email, or mobile number
        existing_user_query = select(User).filter(
            (User.username == data.username) | 
            (User.email == data.email) | 
            (User.mobile_number == data.mobile_number)
        )
        
        existing_users = (await db.execute(existing_user_query)).scalars().all()
        if existing_users:
            logger.warning(f"Registration conflict: Username, email, or mobile number already exists for {data.username}/{data.email}")
            # Raise custom conflict exception; it will be caught by the except block below
            conflict("Username, email, or mobile number already registered.")

        hashed_password = await get_password_hash(data.password)

        admin_user = User(
            first_name=data.first_name,
            last_name=data.last_name,
            username=data.username,
            email=data.email,
            mobile_number=data.mobile_number,
            dob=data.dob,
            hashed_password=hashed_password,
            photo_url=data.photo_url,
            is_active=True,
            is_verified=True,
            is_admin=True
        )

        db.add(admin_user)
        # FIX: Flush and refresh here to get the admin_user.id before logging
        await db.flush() # Flushes pending changes to the database to get the ID
        await db.refresh(admin_user) # Refreshes the object to load the ID

        logger.info(f"Admin user {admin_user.username} registered successfully with ID: {admin_user.id}")

        # Log admin registration as a general user activity
        # Now admin_user.id is guaranteed to be available
        await log_user_activity(
            db,
            user_id=admin_user.id,
            activity_type="admin_registration",
            details=f"New admin user {admin_user.username} registered.",
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Also log in AdminLog for specific admin audit trail
        # Now admin_user.id is guaranteed to be available
        await log_admin_activity(
            db=db,
            admin_id=admin_user.id,
            target_id=None,
            action_type="admin_registered",
            details=f"Admin account '{admin_user.username}' self-registered.",
            ip_address=ip_address
        )

        # Add initial password to history
        password_history_entry = PasswordHistory(
            user_id=admin_user.id, # Now admin_user.id is available
            hashed_password=hashed_password,
            changed_at=datetime.now(timezone.utc)
        )
        db.add(password_history_entry)

        # Consolidate all database commits into a single commit at the end of the successful path
        await db.commit() # This single commit persists admin_user, activity_log, admin_log, password_history

        return UserResponse.model_validate(admin_user)

    except APIException as e:
        # If any custom APIException is raised, roll back the transaction
        await db.rollback()
        logger.error(f"Transaction rolled back due to APIException: {e.message}")
        raise # Re-raise the exception for FastAPI to handle

    except Exception as e:
        # Catch any other unexpected exceptions and ensure rollback
        await db.rollback()
        logger.error(f"Unexpected error during admin registration for {data.username}: {e}", exc_info=True)
        # Raise a generic HTTP 500 error for unhandled exceptions
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during admin registration."
        )


async def log_admin_activity(
    db: AsyncSession,
    admin_id: int,
    action_type: str,
    details: Optional[str] = None,
    target_id: Optional[int] = None,
    ip_address: Optional[str] = None
) -> AdminLog:
    """
    Logs an administrative action to the AdminLog table.
    This function adds the log entry to the session, but does NOT commit it.
    The caller is responsible for committing the session as part of a larger transaction.
    """
    logger.debug(f"Logging admin activity: Admin ID={admin_id}, Action='{action_type}', Target ID={target_id}")
    
    admin_log_entry = AdminLog(
        admin_id=admin_id,
        target_id=target_id,
        action_type=action_type,
        details=details,
        ip_address=ip_address
    )
    db.add(admin_log_entry)
    # FIX: Removed db.commit() and db.refresh(admin_log_entry) from here.
    # The caller will commit this as part of its transaction.
    logger.info(f"Admin activity added to session: Action={action_type}, Admin={admin_id}")
    return admin_log_entry


async def get_admin_logs(
    db: AsyncSession,
    admin_id: int,
    target_id: Optional[int] = None,
    action_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0
) -> Sequence[AdminLog]:
    """
    Retrieves administrative log entries.
    Allows filtering by target user ID and action type, with pagination.
    """
    logger.debug(f"Admin {admin_id} requesting admin logs: target_id={target_id}, action_type={action_type}, limit={limit}, offset={offset}")

    query = select(AdminLog).order_by(AdminLog.created_at.desc())

    if target_id:
        target_user_exists_query = select(User).filter(User.id == target_id)
        target_user_exists_result = await db.execute(target_user_exists_query)
        if not target_user_exists_result.scalar_one_or_none():
            logger.warning(f"Admin {admin_id} requested admin logs for non-existent target ID: {target_id}")
            not_found(f"Target user with ID {target_id} not found.")

        query = query.filter(AdminLog.target_id == target_id)

    if action_type:
        query = query.filter(AdminLog.action_type == action_type)

    query = query.offset(offset).limit(limit)

    query = query.options(
        joinedload(AdminLog.admin_user).load_only(User.username),
        joinedload(AdminLog.target_user).load_only(User.username)
    )

    admin_logs_result = await db.execute(query)
    admin_logs = admin_logs_result.scalars().unique().all()

    logger.info(f"Found {len(admin_logs)} admin logs for admin {admin_id}.")
    return admin_logs


# Simulating current settings in memory (for now)
# In a real app, this would come from a database table (e.g., AppSettings)
_CURRENT_REGISTRATION_SETTINGS = {
    "is_registration_enabled": True # Default value
}


# NEW: Basic Registration Settings Functions
async def get_registration_settings() -> RegistrationSettingsResponse:
    """
    Retrieves the current user registration settings.
    For now, returns a hardcoded value.
    """
    logger.debug("Retrieving current registration settings.")
    # In a future iteration, this would query a database table for settings
    return RegistrationSettingsResponse(**_CURRENT_REGISTRATION_SETTINGS)

async def update_registration_settings(
    db: AsyncSession,
    admin_id: int,
    data: RegistrationSettingsUpdate,
    ip_address: Optional[str] = None
) -> RegistrationSettingsResponse:
    """
    Updates the user registration settings.
    For now, updates an in-memory dictionary and logs the change.
    """
    logger.debug(f"Admin {admin_id} attempting to update registration settings: {data.model_dump()}")
    
    # Simulate updating the setting (in-memory for now)
    if data.is_registration_enabled is not None:
        _CURRENT_REGISTRATION_SETTINGS["is_registration_enabled"] = data.is_registration_enabled
        logger.info(f"User registration enabled status set to: {data.is_registration_enabled}")
        
        await log_admin_activity(
            db=db,
            admin_id=admin_id,
            target_id=None,
            action_type="registration_setting_updated",
            details=f"Registration enabled status changed to: {data.is_registration_enabled}",
            ip_address=ip_address
        )
        logger.info(f"Admin {admin_id} successfully updated registration settings.")
    else:
        logger.info(f"Admin {admin_id} attempted to update registration settings but provided no changes.")
    
    return RegistrationSettingsResponse(**_CURRENT_REGISTRATION_SETTINGS)