import logging
from typing import Optional, cast
from fastapi import UploadFile, BackgroundTasks
from pathlib import Path
from datetime import datetime, timezone
import uuid

# Import the updated schemas
from app.schemas.features.image_processing import ImageProcessRequest, ImageProcessResponse

# Import the background task function - this function will now handle saving the file
from app.tasks.background_task_imageprocess import perform_image_processing_background # This task will save the file

# Import custom exceptions
from app.core.exceptions import bad_request, server_error


logger = logging.getLogger(__name__)

# Define max allowed photo size (e.g., 10MB) for general image processing
MAX_IMAGE_SIZE_BYTES = 10 * 1024 * 1024 # 10 MB

# Calculate BASE_DIR for the project root consistently
# image_processing_service.py is at app/services/features/image_processing_service.py,
# so it needs 3 .parent calls to reach the root (app/services/features -> app/services -> app -> project_root)
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent # Corrected path to project root
PROCESSED_IMAGES_DIR = BASE_DIR / "processed_images" # Directory for processed images

# Ensure the processed_images directory exists
PROCESSED_IMAGES_DIR.mkdir(parents=True, exist_ok=True)
logger.info(f"Ensured processed_images directory exists at: {PROCESSED_IMAGES_DIR}")


async def process_image_request(
    background_tasks: BackgroundTasks,
    image_file: UploadFile,
    processing_params: ImageProcessRequest
) -> ImageProcessResponse:
    """
    Handles the request for image processing, offloading the actual work to a background task.
    Performs initial validation and returns an immediate response.
    The processed image will be saved to disk and served via a static URL.
    """
    logger.debug(f"Received image processing request for file: {image_file.filename}")

    if not image_file.filename:
        logger.warning("No image file provided in the request.")
        raise bad_request("No image file provided.")

    # Validate file extension
    original_file_extension = cast(str, image_file.filename).split('.')[-1].lower()
    allowed_extensions = ["jpg", "jpeg", "png", "gif", "webp", "bmp", "tiff"]
    if original_file_extension not in allowed_extensions:
        logger.warning(f"Invalid image file format uploaded: {image_file.filename}. Allowed: {', '.join(allowed_extensions)}")
        raise bad_request(f"Invalid image file format. Only {', '.join(allowed_extensions).upper()} are allowed.")

    # Read the entire image file content into bytes here.
    # This ensures the background task receives the full data,
    # independent of the UploadFile's lifecycle (which might close the file).
    try:
        # Seek to the beginning to ensure full read if already partially read (e.g., by FastAPI)
        await image_file.seek(0)
        image_bytes = await image_file.read()
    except Exception as e:
        logger.error(f"Error reading image file '{image_file.filename}': {e}", exc_info=True)
        raise server_error(f"Failed to read image file content: {e}")
    finally:
        # Explicitly close the UploadFile handle after reading its content
        # This is important for resource management.
        await image_file.close()
        logger.debug(f"Closed UploadFile handle for '{image_file.filename}' after reading.")


    # Max file size validation after reading bytes
    if len(image_bytes) > MAX_IMAGE_SIZE_BYTES:
        logger.warning(f"Uploaded image '{image_file.filename}' exceeds max size. Size: {len(image_bytes)} bytes")
        raise bad_request(f"Image exceeds the maximum allowed size of {MAX_IMAGE_SIZE_BYTES / (1024 * 1024):.1f} MB.")


    # Generate a unique filename prefix for the processed output.
    unique_output_filename_prefix = str(uuid.uuid4())

    # Construct the path where the processed image will be saved.
    processed_image_filename = f"{unique_output_filename_prefix}.{processing_params.output_format.value.lower()}"
    processed_image_path = PROCESSED_IMAGES_DIR / processed_image_filename

    # Offload the actual, potentially long-running, image processing to a background task.
    # Pass the image content as bytes, not the UploadFile object.
    background_tasks.add_task(
        perform_image_processing_background,
        image_bytes=image_bytes, # Pass image content as bytes
        original_filename=image_file.filename, # Original filename for logging/tracking
        processing_params=processing_params,
        output_filepath=processed_image_path # Correct: PASS THE output_filepath HERE
    )
    logger.info(f"Image processing for '{image_file.filename}' offloaded to background task. Output will be saved to '{processed_image_path}'.")

    # Return an immediate response to the client with the expected URL.
    processed_url: str = str(f"/image/processed_images/{processed_image_filename}")
    
    return ImageProcessResponse(
        original_filename=image_file.filename,
        processed_url=processed_url,
        message="Image processing initiated. The processed image will be available shortly."
    )
