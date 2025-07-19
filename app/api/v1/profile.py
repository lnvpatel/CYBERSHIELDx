# app/api/v1/profile.py

from fastapi import APIRouter, Depends, Form, UploadFile, File, status, HTTPException, Request, Body, BackgroundTasks # MODIFIED: Import BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List, cast
from datetime import datetime, date
import logging
from pathlib import Path
import shutil
import io
from PIL import Image

from app.schemas.user import UserResponse, UserUpdate, ChangePasswordRequest
from app.schemas.session import UserSessionResponse, RevokeSessionRequest
from app.infrastructure.database.models import User
from app.services.user_service import get_user_by_id, update_user_profile, change_password
from app.services.session_service import get_user_active_sessions , revoke_user_session
from app.infrastructure.database.session import get_db
from app.dependencies.auth import get_current_user
from app.core.exceptions import bad_request, server_error, not_found
from app.services.activity_service import log_user_activity

# NEW: Import background task function for image processing
from app.tasks.background_tasks import process_user_photo_background

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/profile",tags=["User Profile"])

# Calculate BASE_DIR for the project root consistently
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
UPLOADS_DIR = BASE_DIR / "uploads"

# Ensure the uploads directory exists
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
logger.info(f"Ensured uploads directory exists at: {UPLOADS_DIR}")

# NEW: Define max allowed photo size (e.g., 5MB) - Keep consistent with auth_service if possible
MAX_PHOTO_SIZE_BYTES = 5 * 1024 * 1024 # 5 MB


# =========================
# Profile API Endpoints
# =========================

@router.get("/me", response_model=UserResponse)
async def get_profile(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve current authenticated user's profile asynchronously.
    """
    logger.debug(f"Fetching profile for user: {current_user.username} (ID: {current_user.id})")
    user_profile = await get_user_by_id(db, current_user.id)
    logger.info(f"Profile fetched successfully for user: {current_user.username}")
    return user_profile

@router.put("/me", response_model=UserResponse, status_code=status.HTTP_200_OK)
async def update_profile(
    request: Request,
    first_name: Optional[str] = Form(None, max_length=50),
    last_name: Optional[str] = Form(None, max_length=50),
    username: Optional[str] = Form(None, min_length=4, max_length=30),
    mobile_number: Optional[str] = Form(None, min_length=10, max_length=15),
    dob: Optional[str] = Form(None, description="Date of birth in YYYY-MM-DD format"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update current authenticated user's profile details asynchronously.
    Expects multipart/form-data. Only provided text fields will be updated.
    Profile picture updates are handled by PUT /profile/me/photo (for upload)
    and DELETE /profile/me/photo (for removal).
    """
    logger.debug(f"Attempting to update profile for user: {current_user.username} (ID: {current_user.id})")

    # Extract IP address and User-Agent
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    parsed_dob: Optional[date] = None
    if dob:
        try:
            parsed_dob = datetime.strptime(dob, "%Y-%m-%d").date()
        except ValueError:
            logger.warning(f"Invalid DOB format provided for {current_user.username}: {dob}")
            bad_request("Invalid date of birth format. Please use YYYY-MM-DD.")

    user_update_data = UserUpdate()
    if first_name is not None:
        user_update_data.first_name = first_name
    if last_name is not None:
        user_update_data.last_name = last_name
    if username is not None:
        user_update_data.username = username
    if mobile_number is not None:
        user_update_data.mobile_number = mobile_number
    if parsed_dob is not None:
        user_update_data.dob = cast(date, parsed_dob)
    
    updated_user_profile = await update_user_profile(
        db=db, 
        user_id=current_user.id, 
        data=user_update_data,
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"Profile updated successfully for user: {current_user.username}")
    return updated_user_profile


@router.put("/me/photo", response_model=UserResponse, status_code=status.HTTP_200_OK)
async def upload_profile_photo(
    request: Request,
    background_tasks: BackgroundTasks, # NEW: Inject BackgroundTasks
    photo: UploadFile = File(..., description="The new profile picture to upload."),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db) # Keep db for initial checks and activity logging
):
    """
    Uploads a new profile picture for the current authenticated user.
    If an old photo exists, it will be replaced and optimized (compressed, resized, converted to WebP)
    in a background task.
    """
    logger.debug(f"Attempting to upload new profile photo for user: {current_user.username} (ID: {current_user.id})")

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    if not photo.filename:
        logger.warning(f"No file provided in photo field for user {current_user.username}. This endpoint requires a file.")
        raise bad_request("No file provided. Please select an image to upload.")

    # NEW: Max file size validation
    # Read a small chunk to check size without loading entire file into memory initially
    first_chunk = await photo.read(MAX_PHOTO_SIZE_BYTES + 1)
    if len(first_chunk) > MAX_PHOTO_SIZE_BYTES:
        logger.warning(f"Uploaded photo exceeds max size for user {current_user.username}. Size: {len(first_chunk)} bytes")
        raise bad_request(f"Profile photo exceeds the maximum allowed size of {MAX_PHOTO_SIZE_BYTES / (1024 * 1024):.1f} MB.")
    
    # Reset file pointer for full read by the background task
    await photo.seek(0)
    image_bytes = await photo.read() # Read full image bytes for background task

    # Validate original file extension
    original_file_extension = cast(str, photo.filename).split('.')[-1].lower()
    if original_file_extension not in ["jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff"]: # Expanded allowed types for input
        logger.warning(f"Invalid original photo format uploaded by {current_user.username}: {photo.filename}")
        raise bad_request("Invalid image file format. Only JPG, PNG, GIF, WEBP, BMP, TIFF are allowed for upload.")
    
    # Offload image processing to a background task
    # The background task will handle deleting the old photo, saving the new one,
    # and updating the user's photo_url in the database.
    background_tasks.add_task(
        process_user_photo_background,
        user_id=current_user.id,
        image_bytes=image_bytes,
        original_file_extension=original_file_extension,
        current_photo_url=current_user.photo_url # Pass current photo URL for deletion logic in background
    )
    logger.info(f"Image processing for user {current_user.id} offloaded to background task.")

    # Log activity immediately, before background task completes
    await log_user_activity(
        db,
        user_id=current_user.id,
        activity_type="profile_photo_upload_initiated",
        details="User initiated profile picture upload.",
        ip_address=ip_address,
        user_agent=user_agent
    )

    # Return the current user profile immediately. The photo_url will be updated later by the background task.
    # The client might need to refetch the profile to see the updated photo_url.
    return current_user # Return the current user object, photo_url will be updated asynchronously


@router.delete("/me/photo", status_code=status.HTTP_200_OK)
async def delete_profile_photo(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Removes the current authenticated user's profile picture.
    Deletes the file from the static directory and sets photo_url to None in the database.
    """
    logger.debug(f"Attempting to remove profile photo for user: {current_user.username} (ID: {current_user.id})")

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    if current_user.photo_url is None:
        logger.warning(f"No profile picture to remove for user {current_user.username}.")
        raise bad_request("No profile picture to remove.")
    
    existing_photo_url = cast(str, current_user.photo_url)
    if not existing_photo_url.startswith("/uploads/"):
        logger.warning(f"User {current_user.username} attempted to remove a non-managed photo URL: {current_user.photo_url}")
        raise bad_request("Cannot remove external profile pictures. Only pictures uploaded through this service can be removed.")

    old_filename = existing_photo_url.split("/uploads/")[1]
    old_photo_path = UPLOADS_DIR / old_filename

    logger.debug(f"  Constructed path for deleting old photo: {old_photo_path.absolute()}")
    logger.debug(f"  Does path for deleting old photo exist? {old_photo_path.exists()}")

    if old_photo_path.exists():
        try:
            old_photo_path.unlink()
            logger.info(f"Profile photo '{old_filename}' removed from disk for user {current_user.username}.")
        except OSError as e:
            logger.error(f"Failed to delete profile photo '{old_filename}' from disk for user {current_user.username}: {e}", exc_info=True)
            raise server_error("Failed to remove profile picture due to server error.")
    else:
        logger.warning(f"Profile photo '{old_filename}' not found on disk for user {current_user.username}. Proceeding to clear DB entry.")

    user_update_data = UserUpdate(photo_url=None)
    updated_user_profile = await update_user_profile(
        db=db,
        user_id=current_user.id,
        data=user_update_data,
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"Profile photo URL cleared in DB for user: {current_user.username}.")

    await log_user_activity(
        db,
        user_id=current_user.id,
        activity_type="profile_photo_removed",
        details="User removed their profile picture.",
        ip_address=ip_address,
        user_agent=user_agent
    )

    return {"detail": "Profile picture removed successfully."}


@router.put("/change-password", status_code=status.HTTP_200_OK)
async def change_user_password(
    request: Request,
    password_data: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Allows the current authenticated user to change their password.
    Requires old password verification, new password confirmation, and strong password validation.
    """
    logger.debug(f"Change password request for user: {current_user.username} (ID: {current_user.id})")
    
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    result = await change_password(
        db=db,
        user_id=current_user.id,
        old_password=password_data.old_password,
        new_password=password_data.new_password,
        confirm_new_password=password_data.confirm_new_password,
        ip_address=ip_address,
        user_agent=user_agent
    )
    
    logger.info(f"Password change attempt completed for user: {current_user.username}")
    return result

@router.get("/sessions", response_model=List[UserSessionResponse])
async def get_my_active_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve all active sessions for the current authenticated user.
    """
    logger.debug(f"Fetching active sessions for user: {current_user.username} (ID: {current_user.id})")
    sessions = await get_user_active_sessions(db, current_user.id)
    logger.info(f"Found {len(sessions)} active sessions for user: {current_user.username}.")
    return [UserSessionResponse.model_validate(session) for session in sessions]

@router.post("/revoke-session", status_code=status.HTTP_200_OK)
async def revoke_session_endpoint(
    request: Request,
    revoke_data: RevokeSessionRequest = Body(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Allows the current authenticated user to revoke one of their active sessions.
    This will invalidate the targeted session and its refresh token,
    but WILL NOT invalidate the current access token used for this request.
    """
    logger.debug(f"User {current_user.username} (ID: {current_user.id}) attempting to revoke session ID: {revoke_data.session_id}")

    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    result = await revoke_user_session(
        db=db,
        user_id=current_user.id,
        session_id=revoke_data.session_id,
        ip_address=ip_address,
        user_agent=user_agent
    )
    logger.info(f"Session ID {revoke_data.session_id} successfully revoked for user {current_user.username}.")
    return result
