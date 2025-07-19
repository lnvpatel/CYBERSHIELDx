# app/api/v1/endpoints/activity.py

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional

import logging

from app.infrastructure.database.session import get_db
from app.infrastructure.database.models import User # Ensure User model is imported
from app.services.activity_service import get_activities # Only get_activities remains for this router
from app.schemas.activity import ActivityLogResponse # Ensure ActivityLogResponse is correctly defined to match ActivityLog model
from app.dependencies.auth import get_current_user # This is an async dependency

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/activity", tags=["Activity Logs"])

# ================================
# Endpoints for User-Specific Activity Logs
# ================================

@router.get("/", response_model=List[ActivityLogResponse])
async def get_current_user_activities(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    limit: int = Query(20, gt=0, le=100, description="Maximum number of activity logs to return.")
):
    """
    Retrieves activity logs for the current authenticated user only.
    """
    logger.debug(f"Request to get activities by {current_user.username} (ID: {current_user.id}).")
    
    # Call the get_activities service function, explicitly filtering for the current user
    # and ignoring target_username/activity_type, as this endpoint is user-specific.
    activities = await get_activities(
        db=db,
        current_user=current_user,
        target_username=current_user.username, # Always filter by current user's username for this endpoint
        activity_type=None, # No type filtering for regular users from this endpoint
        limit=limit
    )
    
    logger.info(f"Successfully retrieved {len(activities)} activities for current user: {current_user.username}.")
    # Convert dictionaries (from service layer) to Pydantic response models
    return [ActivityLogResponse.model_validate(activity) for activity in activities]

# Removed the POST /log endpoint from here; it's moved to admin.py
