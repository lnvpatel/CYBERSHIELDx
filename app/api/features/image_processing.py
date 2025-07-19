from fastapi import APIRouter, Depends, UploadFile, File, Form, BackgroundTasks, Request, Body, status, HTTPException
from typing import Optional, Annotated
import logging
from pydantic import ValidationError
import json
from pathlib import Path
import os
from fastapi.responses import FileResponse
from app.schemas.features.image_processing import ImageProcessRequest, ImageProcessResponse
from app.services.features import image_processing_service
from app.core.exceptions import bad_request


# IMPORTANT: Configure this path to your actual processed_images directory
PROCESSED_IMAGES_DIRECTORY = "/home/vatsalya/Desktop/fastapi-auth/processed_images"

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/image", tags=["Image Processing"])

@router.post(
    "/processor",
    response_model=ImageProcessResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Process an image with various options in the background",
    description="Uploads an image file along with JSON processing parameters to be handled by a background task. "
                "Returns an immediate response, as the actual image processing is asynchronous."
)
async def image_processor_endpoint(
    background_tasks: BackgroundTasks,
    image_file: UploadFile = File(..., description="The image file to be processed (e.g., JPEG, PNG)."),
    processing_params_json: Annotated[
        str,
        Form(
            description="JSON string containing image processing options (e.g., resize_width, crop_left, target_kb_size). "
                        "Expected format: {'resize_width': 800, 'crop_left': 100, 'crop_top': 50, 'crop_right': 700, 'crop_bottom': 500, 'output_format': 'webp', 'target_kb_size': 300, ...}"
        )
    ] = '{}'
):
    """
    Endpoint for image processing.
    The image is processed asynchronously in a background task to avoid blocking the API server.
    """
    logger.info(f"API: Received image processing request for file: '{image_file.filename}'.")

    try:
        processing_params_dict = json.loads(processing_params_json)
        processing_params = ImageProcessRequest(**processing_params_dict)
        logger.debug(f"API: Parsed processing parameters: {processing_params.model_dump()}")

    except json.JSONDecodeError as e:
        logger.warning(f"API: Invalid JSON format for 'processing_params_json': {processing_params_json}. Error: {e}")
        raise bad_request(f"Invalid JSON format for 'processing_params'. Please provide a valid JSON string. Details: {e}")
    except ValidationError as e:
        logger.warning(f"API: Validation error for 'processing_params': {processing_params_json}. Error: {e.errors()}")
        raise bad_request(f"Invalid data for image processing parameters. Details: {e.errors()}")
    except Exception as e:
        logger.error(f"API: Unexpected error during parsing of processing_params: {e}", exc_info=True)
        raise bad_request(f"An unexpected error occurred while processing parameters: {e}")

    response = await image_processing_service.process_image_request(
        background_tasks=background_tasks,
        image_file=image_file,
        processing_params=processing_params
    )

    logger.info(f"API: Image processing initiated for '{image_file.filename}'. Response: {response.message}")
    return response

@router.get(
    "/processed_images/{filename}",
    response_class=FileResponse,
    # REMOVED: include_in_schema=False, OR changed to True
    summary="Download a processed image", # Optional: Add a summary for clarity in docs
    description="Retrieves a processed image file for download, ensuring Content-Disposition is set." # Optional: Add description
)
async def get_processed_image(filename: str):
    """
    Serves processed images from the static directory for download.
    """
    file_path = Path(PROCESSED_IMAGES_DIRECTORY) / filename

    try:
        resolved_file_path = file_path.resolve()
        resolved_base_dir = Path(PROCESSED_IMAGES_DIRECTORY).resolve()

        if not resolved_file_path.is_file() or not resolved_file_path.is_relative_to(resolved_base_dir):
            logger.warning(f"Attempted to access invalid file path: {file_path}")
            raise HTTPException(status_code=404, detail="Image not found or invalid path.")
    except Exception as e:
        logger.error(f"Error during path resolution for {file_path}: {e}")
        raise HTTPException(status_code=404, detail="Image not found or invalid path.")

    return FileResponse(
        path=file_path,
        media_type="application/octet-stream",
        filename=os.path.basename(file_path)
    )