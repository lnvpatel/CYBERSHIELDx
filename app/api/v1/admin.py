# app/api/v1/endpoints/admin.py

from fastapi import APIRouter, Depends, status, Request, Query, Path
from sqlalchemy.ext.asyncio import AsyncSession
import logging
from typing import List, Optional

from app.schemas.admin import AdminRegister, AdminUserResponse
from app.schemas.activity import UserActivity, ActivityLogResponse
from app.schemas.user import UserResponse, UserStatusUpdate, UserRoleUpdate, UserVerificationUpdate
from app.schemas.admin import AdminLogResponse # NEW: Import AdminLogResponse
from app.schemas.settings import RegistrationSettingsResponse, RegistrationSettingsUpdate

from app.services.admin_service import register_admin, log_admin_activity, get_admin_logs, get_registration_settings, update_registration_settings # NEW: Import get_admin_logs
from app.services.activity_service import log_user_activity, get_activities
from app.services.user_service import (
    get_all_users_for_admin,
    get_user_by_id,
    update_user_status_by_admin,
    update_user_admin_status_by_admin,
    update_user_verification_status_by_admin,
    delete_user_by_admin
)
from app.infrastructure.database.session import get_db
from app.infrastructure.database.models import User
from app.dependencies.auth import get_current_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["Admin"])

# =========================
# Admin API Endpoints
# =========================

# Admin Register Route
@router.post("/register", response_model=AdminUserResponse, status_code=status.HTTP_201_CREATED)
async def register_admin_account(
    request: Request,
    data: AdminRegister,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new admin user (with secret key) asynchronously.
    """
    logger.debug(f"Attempting to register admin account for username: {data.username}")
    
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    new_admin = await register_admin(db, data, ip_address=ip_address, user_agent=user_agent)
    logger.info(f"Admin account {new_admin.username} registered successfully with ID: {new_admin.id}")
    return new_admin

# Admin endpoint to manually log user activity
@router.post("/activities/log", response_model=ActivityLogResponse, status_code=status.HTTP_201_CREATED)
async def create_admin_activity_log(
    request: Request,
    activity_data: UserActivity,
    current_admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Allows authenticated administrators to manually log activity for any user.
    This logs into the 'activity_logs' table, representing an action
    associated with a user (potentially initiated by an admin).
    """
    logger.debug(f"Admin {current_admin.username} (ID: {current_admin.id}) requesting to log activity for user ID: {activity_data.user_id}")
    
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    log_entry = await log_user_activity( # This logs into activity_logs
        db=db,
        user_id=activity_data.user_id,
        activity_type=activity_data.activity_type,
        details=activity_data.details,
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"Admin {current_admin.username} logged activity for user {activity_data.user_id}: {activity_data.activity_type}.")
    return log_entry

# Admin endpoint to retrieve all activities with filters
@router.get("/activities", response_model=List[ActivityLogResponse])
async def get_all_activities_endpoint(
    request: Request,
    current_admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
    target_username: Optional[str] = Query(None, description="Optional: Username of a specific user to filter activities."),
    activity_type: Optional[str] = Query(None, description="Optional: Filter activities by type (e.g., 'login', 'logout')."),
    limit: int = Query(20, gt=0, le=100, description="Maximum number of activity logs to return.")
):
    """
    Allows authenticated administrators to retrieve all activity logs, with optional filters
    by target username and activity type.
    These are logs of general user activities.
    """
    logger.debug(f"Admin {current_admin.username} requesting all activities with filters: "
                 f"target_username={target_username}, activity_type={activity_type}, limit={limit}.")
    
    activities = await get_activities(
        db=db,
        current_user=current_admin,
        target_username=target_username,
        activity_type=activity_type,
        limit=limit
    )
    
    logger.info(f"Admin {current_admin.username} successfully retrieved {len(activities)} activity logs.")
    return [ActivityLogResponse.model_validate(activity) for activity in activities]

# =========================
# Admin User Management Endpoints
# =========================

@router.get("/users", response_model=List[UserResponse])
async def get_all_users_endpoint(
    request: Request,
    current_admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(100, gt=0, le=1000, description="Maximum number of users to return."),
    offset: int = Query(0, ge=0, description="Number of users to skip for pagination."),
    search: Optional[str] = Query(None, description="Search users by username, email, mobile, first or last name.")
):
    """
    Allows authenticated administrators to retrieve a list of all user accounts,
    with optional pagination and search capabilities.
    """
    logger.debug(f"Admin {current_admin.username} requesting all users with limit={limit}, offset={offset}, search='{search}'")
    users = await get_all_users_for_admin(db, limit, offset, search)
    logger.info(f"Admin {current_admin.username} retrieved {len(users)} users.")
    return [UserResponse.model_validate(user) for user in users]

@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user_by_id_endpoint(
    user_id: int = Path(..., gt=0, description="The ID of the user to retrieve."),
    current_admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Allows authenticated administrators to retrieve a specific user's profile by ID.
    """
    logger.debug(f"Admin {current_admin.username} requesting user profile for ID: {user_id}")
    user_profile = await get_user_by_id(db, user_id)
    logger.info(f"Admin {current_admin.username} fetched profile for user ID: {user_id}.")
    return UserResponse.model_validate(user_profile)


@router.put("/users/{user_id}/status", response_model=UserResponse)
async def update_user_status_endpoint(
    request: Request,
    status_update: UserStatusUpdate,
    user_id: int = Path(..., gt=0, description="The ID of the user whose status to update."),
    current_admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Allows authenticated administrators to activate or deactivate a user account.
    """
    logger.debug(f"Admin {current_admin.username} requesting to update status of user ID: {user_id} to {status_update.is_active}")
    
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    updated_user = await update_user_status_by_admin(
        db=db,
        target_user_id=user_id,
        is_active=status_update.is_active,
        current_admin_id=current_admin.id,
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"Admin {current_admin.username} successfully updated status for user ID: {user_id}.")
    return updated_user

@router.put("/users/{user_id}/role", response_model=UserResponse)
async def update_user_role_endpoint(
    request: Request,
    role_update: UserRoleUpdate,
    user_id: int = Path(..., gt=0, description="The ID of the user whose role to update."),
    current_admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Allows authenticated administrators to grant or revoke administrative privileges for a user.
    """
    logger.debug(f"Admin {current_admin.username} requesting to update role of user ID: {user_id} to is_admin={role_update.is_admin}")

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    updated_user = await update_user_admin_status_by_admin(
        db=db,
        target_user_id=user_id,
        is_admin=role_update.is_admin,
        current_admin_id=current_admin.id,
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"Admin {current_admin.username} successfully updated role for user ID: {user_id}.")
    return updated_user

@router.put("/users/{user_id}/verify", response_model=UserResponse)
async def update_user_verification_endpoint(
    request: Request,
    verification_update: UserVerificationUpdate,
    user_id: int = Path(..., gt=0, description="The ID of the user whose verification status to update."),
    current_admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Allows authenticated administrators to set a user's email verification status.
    """
    logger.debug(f"Admin {current_admin.username} requesting to update verification status of user ID: {user_id} to {verification_update.is_verified}")

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    updated_user = await update_user_verification_status_by_admin(
        db=db,
        target_user_id=user_id,
        is_verified=verification_update.is_verified,
        current_admin_id=current_admin.id,
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"Admin {current_admin.username} successfully updated verification status for user ID: {user_id}.")
    return updated_user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user_endpoint(
    request: Request,
    user_id: int = Path(..., gt=0, description="The ID of the user to delete."),
    current_admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Allows authenticated administrators to delete a user account.
    """
    logger.debug(f"Admin {current_admin.username} requesting to delete user ID: {user_id}")

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    await delete_user_by_admin(
        db=db,
        target_user_id=user_id,
        current_admin_id=current_admin.id,
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"Admin {current_admin.username} successfully deleted user ID: {user_id}.")
    return {"detail": "User deleted successfully."}


@router.get("/admin-logs", response_model=List[AdminLogResponse])
async def get_all_admin_logs_endpoint(
    request: Request,
    current_admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db),
    target_id: Optional[int] = Query(None, description="Optional: Filter logs by the ID of the target user."),
    action_type: Optional[str] = Query(None, description="Optional: Filter logs by the type of action."),
    limit: int = Query(100, gt=0, le=1000, description="Maximum number of logs to return."),
    offset: int = Query(0, ge=0, description="Number of logs to skip for pagination.")
):
    """
    Allows authenticated administrators to retrieve a list of administrative log entries.
    Logs actions performed by admins, with optional filters for target user and action type.
    """
    logger.debug(f"Admin {current_admin.username} requesting admin logs with filters: "
                 f"target_id={target_id}, action_type={action_type}, limit={limit}, offset={offset}")
    
    admin_logs = await get_admin_logs(
        db=db,
        admin_id=current_admin.id,
        target_id=target_id,
        action_type=action_type,
        limit=limit,
        offset=offset
    )
    
    response_logs = []
    for log_entry in admin_logs:
        admin_username = log_entry.admin_user.username if log_entry.admin_user else "Unknown Admin"
        target_username = log_entry.target_user.username if log_entry.target_user else None
        
        response_logs.append(AdminLogResponse(
            id=log_entry.id,
            admin_id=log_entry.admin_id,
            admin_username=admin_username,
            target_id=log_entry.target_id,
            target_username=target_username,
            action_type=log_entry.action_type,
            details=log_entry.details,
            ip_address=log_entry.ip_address,
            created_at=log_entry.created_at
        ))
    
    logger.info(f"Admin {current_admin.username} successfully retrieved {len(response_logs)} admin logs.")
    return response_logs

# =========================
# NEW: Admin Settings Endpoints
# =========================

@router.get("/settings/registration", response_model=RegistrationSettingsResponse)
async def get_registration_settings_endpoint(
    current_admin: User = Depends(get_current_admin),
):
    """
    Retrieves the current system-wide user registration settings.
    Accessible only by administrators.
    """
    logger.debug(f"Admin {current_admin.username} requesting registration settings.")
    settings_data = await get_registration_settings()
    logger.info(f"Admin {current_admin.username} successfully retrieved registration settings.")
    return settings_data

@router.put("/settings/registration", response_model=RegistrationSettingsResponse)
async def update_registration_settings_endpoint(
    request: Request,
    settings_update: RegistrationSettingsUpdate,
    current_admin: User = Depends(get_current_admin),
    db: AsyncSession = Depends(get_db)
):
    """
    Updates system-wide user registration settings.
    Accessible only by administrators.
    """
    logger.debug(f"Admin {current_admin.username} attempting to update registration settings: {settings_update.model_dump()}")
    
    ip_address = request.client.host if request.client else None

    updated_settings = await update_registration_settings(
        db=db,
        admin_id=current_admin.id,
        data=settings_update,
        ip_address=ip_address
    )
    logger.info(f"Admin {current_admin.username} successfully updated registration settings.")
    return updated_settings
