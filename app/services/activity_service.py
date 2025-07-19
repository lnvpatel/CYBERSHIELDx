# app/services/activity_service.py
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.infrastructure.database.models import ActivityLog, User # Ensure User is imported for join
from app.schemas.activity import UserActivity # UserActivity schema will no longer be directly used by log_user_activity
from app.core.exceptions import unauthorized, not_found, bad_request
import logging
from typing import List, Sequence, Optional, cast # Import cast for explicit type hinting
# from sqlalchemy.orm import joinedload # Removed as we are now doing explicit join and selecting columns

logger = logging.getLogger(__name__)

# =========================
# Activity Service Logic
# =========================

async def log_user_activity(
    db: AsyncSession,
    user_id: int,
    activity_type: str,
    details: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> ActivityLog:
    """
    Logs a user's activity asynchronously.
    This function is designed to be called internally by other service functions
    for automatic activity logging.
    """
    logger.debug(f"Attempting to log activity: {activity_type} for user {user_id}")
    
    # Create an ActivityLog instance directly from the arguments
    log = ActivityLog(
        user_id=user_id,
        activity_type=activity_type,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
        # 'timestamp' will be automatically set by the SQLAlchemy model's default
    )
    db.add(log)
    await db.commit()
    await db.refresh(log)
    logger.info(f"User activity logged successfully: ID={log.id}, Type={activity_type}, User={user_id}")
    return log

async def get_activities(
    db: AsyncSession,
    current_user: User, # The authenticated user making the request
    target_username: Optional[str] = None, # Optional: specific username to filter by (for admins)
    activity_type: Optional[str] = None, # Optional: filter by activity type (for admins or specific queries)
    limit: int = 20
) -> Sequence[ActivityLog]: # NOTE: Return type is still ActivityLog models, not Pydantic. Pydantic conversion happens in API layer.
    """
    Retrieves user activities based on the requester's role and provided filters.
    - A regular user can only view their own activities.
    - An admin user can view their own, a specific user's, or all activities (with optional type filter).
    """
    logger.debug(f"Fetching activities: current_user={current_user.username}, target_username={target_username}, activity_type={activity_type}, limit={limit}")

    # NEW: Select ActivityLog AND User.username, and perform a JOIN
    query = select(ActivityLog, User.username).join(User, ActivityLog.user_id == User.id).order_by(ActivityLog.timestamp.desc())

    if not current_user.is_admin:
        # Regular user: can only view their own activities
        if target_username and target_username != current_user.username:
            logger.warning(f"Regular user {current_user.username} attempted to view activities of {target_username}.")
            unauthorized("You are not authorized to view activities of other users.")
        
        # Filter by current user's ID
        query = query.filter(ActivityLog.user_id == current_user.id)
        logger.debug(f"Regular user {current_user.username} fetching their own activities.")
        
        # For now, regular users cannot filter by activity_type for simplicity/security.
        if activity_type:
             logger.warning(f"Regular user {current_user.username} attempted to filter by activity_type: {activity_type}. Ignoring.")
             # Optionally, raise bad_request if this is explicitly disallowed behavior
             # bad_request("Regular users cannot filter activities by type.")


    else: # current_user.is_admin is True
        # Admin user:
        if target_username:
            # Admin wants to view a specific user's activities
            target_user_result = await db.execute(select(User).filter(User.username == target_username))
            target_user = target_user_result.scalar_one_or_none()
            if not target_user:
                logger.warning(f"Admin {current_user.username} requested activities for non-existent user: {target_username}")
                not_found(f"User '{target_username}' not found.")
            
            assert target_user is not None # Pylance fix: assert that target_user is not None here
            query = query.filter(ActivityLog.user_id == target_user.id)
            logger.debug(f"Admin {current_user.username} fetching activities for specific user: {target_username}")
        
        # Apply activity_type filter if provided (for both specific user or all logs)
        if activity_type:
            query = query.filter(ActivityLog.activity_type == activity_type)
            logger.debug(f"Admin {current_user.username} filtering activities by type: {activity_type}")
        
        # If no target_username and no activity_type, admin sees ALL logs by default.
        if not target_username and not activity_type:
            logger.debug(f"Admin {current_user.username} fetching all activities.")
        
        # If 'admin logs' means activities performed *by* users with is_admin=True,
        # you would add a join here:
        # if some_admin_specific_filter: # e.g., if activity_type == 'admin_performed' or a separate param
        #    query = query.join(User, ActivityLog.user_id == User.id).filter(User.is_admin == True)


    # Apply limit
    query = query.limit(limit)

    activities_result = await db.execute(query)
    # Fetch results as tuples: (ActivityLog_instance, username_string)
    fetched_activities_with_usernames = activities_result.all() 
    
    # Manually construct a list of ActivityLog models with a dynamically added 'username'
    # For Pydantic conversion in the API layer, we will create dictionaries
    # that include the username from the join.
    activities_for_response = []
    for activity_log, username in fetched_activities_with_usernames:
        # Create a dictionary from the ActivityLog object's attributes
        # and add the username to it.
        activity_dict = activity_log.__dict__
        activity_dict["username"] = username # Add the fetched username
        activities_for_response.append(activity_dict) # Append the dictionary

    logger.info(f"Found {len(activities_for_response)} activities for request by {current_user.username}.")
    # Returning a list of dictionaries here; the API layer will convert to ActivityLogResponse.
    return activities_for_response # Changed return type for consistency with how API layer consumes this

