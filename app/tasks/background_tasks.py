# app/tasks/background_tasks.py

import logging
import io
from PIL import Image
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Literal
from sqlalchemy import select

# REMOVED: from app.core.email_utils import send_email # No longer needed here
from app.config import settings, Settings # Keep settings for image processing
from app.infrastructure.database.session import AsyncSessionLocal
from app.infrastructure.database.models import User


logger = logging.getLogger(__name__)

# Calculate BASE_DIR for the project root consistently
BASE_DIR = Path(__file__).resolve().parent.parent.parent
UPLOADS_DIR = BASE_DIR / "uploads"
PROCESSED_IMAGES_DIR = BASE_DIR / "processed_images"

# Ensure directories exist
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
PROCESSED_IMAGES_DIR.mkdir(parents=True, exist_ok=True)


# Helper function to get image size in KB from a BytesIO buffer
def get_buffer_size_kb(buffer: io.BytesIO) -> float:
    """Returns the size of a BytesIO buffer in kilobytes."""
    return buffer.tell() / 1024.0


async def process_user_photo_background(
    user_id: int,
    image_bytes: bytes,
    original_file_extension: str,
    current_photo_url: Optional[str] = None
):
    """
    Background task to process, optimize, and save a user's profile photo.
    This function should be called via FastAPI's BackgroundTasks.
    It manages its own database session for robustness.
    """
    logger.info(f"Starting background image processing for user ID: {user_id}")
    
    optimized_image_buffer = io.BytesIO()
    output_format = "webp"
    quality = 80
    max_size = (500, 500) # Defined max_size for this function

    try:
        img = Image.open(io.BytesIO(image_bytes))

        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")

        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        img.save(optimized_image_buffer, format=output_format, quality=quality)
        optimized_image_buffer.seek(0)
        
        logger.info(f"Image optimized for user {user_id}. Original size: {len(image_bytes)} bytes, Optimized size: {len(optimized_image_buffer.getvalue())} bytes.")

    except Exception as e:
        logger.error(f"Failed to optimize image in background for user {user_id}: {e}", exc_info=True)
        return # Exit the background task

    # Delete old photo if it exists and is managed by the application
    if current_photo_url and current_photo_url.startswith("/uploads/"):
        old_filename = current_photo_url.split("/uploads/")[1]
        old_photo_path = UPLOADS_DIR / old_filename
        
        if old_photo_path.exists():
            try:
                old_photo_path.unlink()
                logger.info(f"Old photo '{old_filename}' deleted from disk for user {user_id} during background update.")
            except OSError as e:
                logger.error(f"Failed to delete old photo '{old_filename}' for user {user_id} in background: {e}", exc_info=True)
        else:
            logger.warning(f"Old photo '{old_filename}' for user {user_id} not found at path: {old_photo_path.absolute()}. Skipping deletion.")


    # Save new optimized photo
    unique_filename = f"user_{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}.{output_format}"
    upload_path = UPLOADS_DIR / unique_filename
    
    try:
        with upload_path.open("wb") as buffer:
            buffer.write(optimized_image_buffer.getvalue())
        photo_url = f"/uploads/{unique_filename}"
        logger.info(f"Optimized photo saved as '{unique_filename}' for user {user_id}. URL: {photo_url}")
        
        # Update the user object with the new photo_url in the database
        async with AsyncSessionLocal() as db_session:
            user_query = select(User).filter(User.id == user_id)
            user_result = await db_session.execute(user_query)
            user: Optional[User] = user_result.scalar_one_or_none()

            if user:
                user.photo_url = photo_url
                user.updated_at = datetime.now(timezone.utc)
                await db_session.commit()
                await db_session.refresh(user)
                logger.info(f"User {user_id} photo_url updated in DB: {user.photo_url}")
            else:
                logger.warning(f"User with ID {user_id} not found when trying to update photo_url in background task.")

    except Exception as e:
        logger.error(f"Failed to save optimized photo locally or update DB in background for user {user_id}: {e}", exc_info=True)
