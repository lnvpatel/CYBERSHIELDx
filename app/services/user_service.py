# app/services/user_service.py

from datetime import datetime, timezone
from typing import Optional, Any, Sequence # Import Sequence
import logging
import re # Import the re module for regular expressions

from sqlalchemy.ext.asyncio import AsyncSession # Import AsyncSession
from sqlalchemy import select, delete # Import select for async queries, and delete for delete operations

from app.infrastructure.database.models import User, PasswordHistory # Import PasswordHistory
from app.schemas.user import UserResponse, UserUpdate
from app.core.exceptions import not_found, unauthorized, bad_request, conflict, forbidden # Import conflict and forbidden
from app.core.security import get_password_hash, verify_password # Import hashing and verification utilities
from app.services.auth.auth_utils import is_valid_password_for_history # Import the password history validation helper
from app.config import settings # Import settings for PASSWORD_HISTORY_COUNT
from app.services.activity_service import log_user_activity # Import for activity logging
from app.services.admin_service import log_admin_activity # NEW: Import for admin activity logging

logger = logging.getLogger(__name__)

# Define a regex for strong password validation:
# - At least 8 characters long (can be adjusted in settings if needed)
# - At least one uppercase letter (A-Z)
# - At least one lowercase letter (a-z)
# - At least one digit (0-9)
# - At least one special character (!@#$%^&*()_+\-=\[\]{};:'",.<>\/?`~])
PASSWORD_REGEX = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:'\",.<>\/?`~]).{8,}$"


# =========================
# User Service Logic
# =========================

async def get_user_by_id(db: AsyncSession, user_id: int) -> User:
    """
    Retrieves a user by their ID asynchronously.
    """
    logger.debug(f"Fetching user with ID: {user_id}")
    # Asynchronously query for the user
    user_query = select(User).filter(User.id == user_id)
    user_result = await db.execute(user_query)
    user: Optional[User] = user_result.scalar_one_or_none()

    if not user:
        logger.warning(f"User with ID {user_id} not found.")
        not_found("User not found")
    assert user is not None  # Pylance fix: assert user is not None after handling the None case
    logger.info(f"User {user.username} (ID: {user_id}) fetched successfully.")
    return user

async def update_user_profile(db: AsyncSession, user_id: int, data: UserUpdate, ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> UserResponse:
    """
    Updates a user's profile asynchronously.
    Only updates fields that are explicitly provided and are not None for non-nullable columns.
    """
    logger.debug(f"Attempting to update profile for user ID: {user_id}")
    user = await get_user_by_id(db, user_id) # Await the async function call

    logger.debug(f"User before update: photo_url='{user.photo_url}'")

    update_data = data.model_dump(exclude_unset=True)
    logger.debug(f"Incoming update_data: {update_data}")

    if not update_data:
        logger.info(f"No fields provided for update for user ID: {user_id}. Returning current profile.")
        return UserResponse.model_validate(user)

    non_nullable_db_fields = ['first_name', 'username', 'mobile_number', 'dob']
    updated_fields = [] # To track what was actually updated for logging

    for field, value in update_data.items():
        if field in non_nullable_db_fields and value is None:
            logger.warning(f"Attempted to set non-nullable field '{field}' to None for user {user.username} (ID: {user_id}). Skipping update for this field.")
            continue

        # Check for unique constraints if username or mobile_number are being updated
        if field in ['username', 'mobile_number'] and value is not None and value != getattr(user, field):
            existing_user_query = select(User).filter(
                (getattr(User, field) == value) & (User.id != user_id)
            )
            existing_user_result = await db.execute(existing_user_query)
            if existing_user_result.scalar_one_or_none():
                conflict(f"{field.replace('_', ' ').capitalize()} '{value}' already exists.")

        # Check if the value is actually different before setting
        current_value = getattr(user, field)
        if current_value != value:
            setattr(user, field, value)
            updated_fields.append(field)
            logger.debug(f"Setting '{field}' for user {user.username}: '{value}'")

    if updated_fields:
        user.updated_at = datetime.now(timezone.utc) # Update timestamp in UTC
        await db.commit()
        logger.debug(f"User after commit (before refresh): photo_url='{user.photo_url}'")
        await db.refresh(user)
        logger.debug(f"User after refresh: photo_url='{user.photo_url}'")

        logger.info(f"User {user.username} profile updated successfully. Fields updated: {', '.join(updated_fields)}")
        
        # Log profile update activity
        await log_user_activity(
            db,
            user_id=user.id,
            activity_type="profile_updated",
            details=f"Updated fields: {', '.join(updated_fields)}",
            ip_address=ip_address,
            user_agent=user_agent
        )
    else:
        logger.info(f"No actual changes detected for user {user.username} profile update.")


    logger.info(f"User {user.username} profile update attempt finished.")
    return UserResponse.model_validate(user)

async def change_password(
    db: AsyncSession, 
    user_id: int, 
    old_password: str, 
    new_password: str, 
    confirm_new_password: str,
    ip_address: Optional[str] = None, 
    user_agent: Optional[str] = None
) -> dict:
    """
    Allows a user to change their password after verifying the old password.
    Also checks against password history.
    """
    logger.debug(f"Attempting to change password for user ID: {user_id}")

    user = await get_user_by_id(db, user_id)
    assert user is not None # get_user_by_id already raises not_found

    # 1. Verify old password
    if not await verify_password(old_password, user.hashed_password):
        logger.warning(f"Password change failed for user {user.username}: Incorrect old password.")
        await log_user_activity(
            db,
            user_id=user.id,
            activity_type="password_change_failed",
            details="Incorrect old password",
            ip_address=ip_address,
            user_agent=user_agent
        )
        unauthorized("Incorrect old password.")

    # 2. Check if new password matches confirmation
    if new_password != confirm_new_password:
        logger.warning(f"Password change failed for user {user.username}: New passwords do not match.")
        await log_user_activity(
            db,
            user_id=user.id,
            activity_type="password_change_failed",
            details="New passwords do not match",
            ip_address=ip_address,
            user_agent=user_agent
        )
        bad_request("New passwords do not match.")

    # 3. Enforce strong password validation for the new password
    if not re.fullmatch(PASSWORD_REGEX, new_password):
        logger.warning(f"Password change failed for user {user.username}: New password does not meet complexity requirements.")
        await log_user_activity(
            db,
            user_id=user.id,
            activity_type="password_change_failed",
            details="New password does not meet complexity requirements",
            ip_address=ip_address,
            user_agent=user_agent
        )
        bad_request(
            "New password must be at least 8 characters long and include "
            "at least one uppercase letter, one lowercase letter, one number, "
            "and one special character."
        )

    # 4. Check against password history
    # Fetch user's password history, ordered by most recent
    password_history_query = select(PasswordHistory).filter(PasswordHistory.user_id == user.id).order_by(PasswordHistory.changed_at.desc())
    password_history_result = await db.execute(password_history_query)
    password_history = password_history_result.scalars().all()

    if not await is_valid_password_for_history(new_password, password_history):
        logger.warning(f"Password change failed for user {user.username}: Password previously used.")
        await log_user_activity(
            db,
            user_id=user.id,
            activity_type="password_change_failed",
            details=f"New password is one of the last {settings.PASSWORD_HISTORY_COUNT} passwords",
            ip_address=ip_address,
            user_agent=user_agent
        )
        bad_request(f"New password cannot be one of the last {settings.PASSWORD_HISTORY_COUNT} passwords.")

    # 5. Hash new password and update user
    user.hashed_password = await get_password_hash(new_password)
    user.updated_at = datetime.now(timezone.utc) # Update timestamp in UTC
    await db.commit()
    await db.refresh(user)

    # 6. Add new password to history
    password_history_entry = PasswordHistory(
        user_id=user.id,
        hashed_password=user.hashed_password,
        changed_at=datetime.now(timezone.utc) # Always store changed_at in UTC
    )
    db.add(password_history_entry)
    await db.commit()
    logger.info(f"Password successfully changed for user: {user.username}.")
    
    # Log successful password change
    await log_user_activity(
        db,
        user_id=user.id,
        activity_type="password_changed",
        details="Password changed successfully",
        ip_address=ip_address,
        user_agent=user_agent
    )
    return {"detail": "Password changed successfully."}


# =========================
# NEW: Admin User Management Service Functions
# =========================

async def get_all_users_for_admin(
    db: AsyncSession,
    limit: int = 100,
    offset: int = 0,
    search: Optional[str] = None # For searching by username, email, or mobile number
) -> Sequence[User]:
    """
    Retrieves all user accounts (for admin view), with optional search and pagination.
    """
    logger.debug(f"Admin request to fetch all users with limit={limit}, offset={offset}, search='{search}'")
    query = select(User)

    if search:
        search_pattern = f"%{search.lower()}%"
        query = query.filter(
            (User.username.ilike(search_pattern)) |
            (User.email.ilike(search_pattern)) |
            (User.mobile_number.ilike(search_pattern)) |
            (User.first_name.ilike(search_pattern)) |
            (User.last_name.ilike(search_pattern))
        )
    
    query = query.offset(offset).limit(limit)
    users_result = await db.execute(query)
    users = users_result.scalars().all()
    logger.info(f"Found {len(users)} users for admin query.")
    return users

async def update_user_status_by_admin(
    db: AsyncSession,
    target_user_id: int,
    is_active: bool,
    current_admin_id: int,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> UserResponse:
    """
    Allows an admin to activate or deactivate a user account.
    """
    logger.debug(f"Admin {current_admin_id} attempting to change status of user ID: {target_user_id} to is_active={is_active}")
    user = await get_user_by_id(db, target_user_id)
    assert user is not None # Already handled by get_user_by_id

    if user.id == current_admin_id:
        logger.warning(f"Admin {current_admin_id} attempted to change their own active status. Forbidden.")
        forbidden("You cannot change your own active status via this endpoint.")

    if user.is_active == is_active:
        logger.info(f"User {user.username} (ID: {target_user_id}) is already {'active' if is_active else 'inactive'}. No change needed.")
        return UserResponse.model_validate(user)

    user.is_active = is_active
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    activity_details = f"Account {'activated' if is_active else 'deactivated'} by admin {current_admin_id}."
    await log_user_activity(
        db,
        user_id=target_user_id,
        activity_type=f"user_account_{'activated' if is_active else 'deactivated'}",
        details=activity_details,
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"User {user.username} (ID: {target_user_id}) status changed to is_active={is_active} by admin {current_admin_id}.")
    
    # NEW: Log administrative action in AdminLog
    await log_admin_activity(
        db=db,
        admin_id=current_admin_id,
        target_id=target_user_id,
        action_type=f"user_status_update_{'active' if is_active else 'inactive'}",
        details=f"Changed user {user.username} (ID: {target_user_id}) active status to {is_active}.",
        ip_address=ip_address
    )

    return UserResponse.model_validate(user)


async def update_user_admin_status_by_admin(
    db: AsyncSession,
    target_user_id: int,
    is_admin: bool,
    current_admin_id: int,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> UserResponse:
    """
    Allows an admin to grant or revoke administrative privileges for a user.
    """
    logger.debug(f"Admin {current_admin_id} attempting to change admin status of user ID: {target_user_id} to is_admin={is_admin}")
    user = await get_user_by_id(db, target_user_id)
    assert user is not None

    if user.id == current_admin_id:
        logger.warning(f"Admin {current_admin_id} attempted to change their own admin status. Forbidden.")
        forbidden("You cannot change your own admin status via this endpoint.")

    if user.is_admin == is_admin:
        logger.info(f"User {user.username} (ID: {target_user_id}) is already {'an admin' if is_admin else 'a regular user'}. No change needed.")
        return UserResponse.model_validate(user)

    user.is_admin = is_admin
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    activity_details = f"Admin privileges {'granted' if is_admin else 'revoked'} by admin {current_admin_id}."
    await log_user_activity(
        db,
        user_id=target_user_id,
        activity_type=f"user_admin_privileges_{'granted' if is_admin else 'revoked'}",
        details=activity_details,
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"User {user.username} (ID: {target_user_id}) admin status changed to is_admin={is_admin} by admin {current_admin_id}.")

    # NEW: Log administrative action in AdminLog
    await log_admin_activity(
        db=db,
        admin_id=current_admin_id,
        target_id=target_user_id,
        action_type=f"user_role_update_{'admin' if is_admin else 'regular'}",
        details=f"Changed user {user.username} (ID: {target_user_id}) admin status to {is_admin}.",
        ip_address=ip_address
    )

    return UserResponse.model_validate(user)

async def update_user_verification_status_by_admin( # NEW: Function to update verification status
    db: AsyncSession,
    target_user_id: int,
    is_verified: bool,
    current_admin_id: int,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> UserResponse:
    """
    Allows an admin to change a user's email verification status.
    """
    logger.debug(f"Admin {current_admin_id} attempting to change verification status of user ID: {target_user_id} to is_verified={is_verified}")
    user = await get_user_by_id(db, target_user_id)
    assert user is not None

    if user.id == current_admin_id:
        logger.warning(f"Admin {current_admin_id} attempted to change their own verification status. Forbidden.")
        forbidden("You cannot change your own verification status via this endpoint.")

    if user.is_verified == is_verified:
        logger.info(f"User {user.username} (ID: {target_user_id}) is already {'verified' if is_verified else 'unverified'}. No change needed.")
        return UserResponse.model_validate(user)

    user.is_verified = is_verified
    user.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(user)

    activity_details = f"Email verification status changed to {'verified' if is_verified else 'unverified'} by admin {current_admin_id}."
    await log_user_activity(
        db,
        user_id=target_user_id,
        activity_type=f"user_email_{'verified' if is_verified else 'unverified'}",
        details=activity_details,
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"User {user.username} (ID: {target_user_id}) verification status changed to is_verified={is_verified} by admin {current_admin_id}.")
    
    # NEW: Log administrative action in AdminLog
    await log_admin_activity(
        db=db,
        admin_id=current_admin_id,
        target_id=target_user_id,
        action_type=f"user_verification_update_{'verified' if is_verified else 'unverified'}",
        details=f"Changed user {user.username} (ID: {target_user_id}) verification status to {is_verified}.",
        ip_address=ip_address
    )

    return UserResponse.model_validate(user)


async def delete_user_by_admin(
    db: AsyncSession,
    target_user_id: int,
    current_admin_id: int,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> dict:
    """
    Allows an admin to delete a user account.
    """
    logger.debug(f"Admin {current_admin_id} attempting to delete user ID: {target_user_id}")
    
    if target_user_id == current_admin_id:
        logger.warning(f"Admin {current_admin_id} attempted to delete their own account. Forbidden.")
        forbidden("You cannot delete your own account via this endpoint.")

    user = await get_user_by_id(db, target_user_id) # This will raise not_found if user doesn't exist
    assert user is not None # Pylance assertion

    # Perform the deletion
    # Delete related password history and user sessions first due to cascade="all, delete-orphan" on relationship.
    # However, if cascade is properly set and db.delete(user) is used, SQLAlchemy handles related deletes automatically.
    # We explicitly delete the user, and related records via cascade rules on relationships in models.py.
    await db.delete(user)
    await db.commit()

    activity_details = f"User account '{user.username}' (ID: {target_user_id}) deleted by admin {current_admin_id}."
    await log_user_activity(
        db,
        user_id=current_admin_id, # Log this activity under the admin's user ID
        activity_type="user_account_deleted",
        details=activity_details,
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"User {user.username} (ID: {target_user_id}) successfully deleted by admin {current_admin_id}.")
    
    # NEW: Log administrative action in AdminLog
    await log_admin_activity(
        db=db,
        admin_id=current_admin_id,
        target_id=target_user_id, # Target user ID is the deleted user
        action_type="user_account_deletion",
        details=f"Deleted user account '{user.username}' (ID: {target_user_id}).",
        ip_address=ip_address
    )

    return {"detail": f"User {user.username} (ID: {target_user_id}) deleted successfully."}