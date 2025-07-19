# app/api/v1/endpoints/protected_security_tools.py
# This file contains protected security tool routes, requiring authentication.

import logging
import io
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, status, Form, Response
from fastapi.responses import StreamingResponse
from typing import Any, IO, Optional

from app.schemas.features.steganography import (
    SteganoEmbedRequest,
    SteganoExtractRequest,
    SteganoExtractResponse,
)
from app.services.features import steganography_service
from app.dependencies.auth import get_current_user

logger = logging.getLogger(__name__)

# Create a new router specifically for protected security tools
router = APIRouter(
    prefix="/stegano",
    tags=["Steganopraphy Tool"],
    dependencies=[Depends(get_current_user)] # All routes in this router require authentication
)

@router.post(
    "/embed",
    status_code=status.HTTP_200_OK,
    summary="Embed text data into an image and download (Protected)",
    description="Uploads an image and text with a pin to hide within it. Returns the modified image directly. Requires authentication.",
)
async def embed_data(
    file: UploadFile = File(..., description="The image file (PNG, JPG, etc.) to embed data into."),
    text_to_hide: str = Form(..., min_length=1, max_length=1000, description="The text data to hide within the image."),
    pin: str = Form(..., min_length=4, max_length=32, description="The pin to protect the hidden message."),
    current_user: Any = Depends(get_current_user) # Re-enabled authentication
) -> Response:
    """
    Endpoint to embed data into an image and return the embedded image.
    """
    # user_id_for_logging is now current_user.id
    logger.info(f"User {current_user.id} received request to embed data in file: {file.filename}")
    
    try:
        embedded_image_bytes = await steganography_service.embed_data_in_image(
            image_file=file,
            text_to_hide=text_to_hide,
            pin=pin,
            user_id=current_user.id # Pass the actual user ID
        )
        
        # Ensure filename is not None before splitting
        filename_base: str = "embedded_image"
        if file.filename:
            filename_base = file.filename.split('.')[0]

        # Return the image bytes as a downloadable file
        return StreamingResponse(
            io.BytesIO(embedded_image_bytes),
            media_type="image/png",
            headers={"Content-Disposition": f"attachment; filename={filename_base}.png"}
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during steganography embedding for user {current_user.id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to embed data: {e}"
        )


@router.post(
    "/extract",
    response_model=SteganoExtractResponse,
    status_code=status.HTTP_200_OK,
    summary="Extract hidden text data from an image (Protected)",
    description="Uploads an image and a pin to extract hidden text data from it. Returns the extracted text directly. Requires authentication.",
)
async def extract_data(
    file: UploadFile = File(..., description="The image file (PNG, JPG, etc.) to extract data from."),
    pin: str = Form(..., min_length=4, max_length=32, description="The pin required to extract the hidden message."),
    current_user: Any = Depends(get_current_user) # Re-enabled authentication
) -> SteganoExtractResponse:
    """
    Endpoint to extract data from an image and return the extracted text.
    """
    # user_id_for_logging is now current_user.id
    logger.info(f"User {current_user.id} received request to extract data from file: {file.filename}")

    try:
        return await steganography_service.extract_data_from_image(
            image_file=file,
            pin=pin,
            user_id=current_user.id # Pass the actual user ID
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Error during steganography extraction for user {current_user.id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to extract data: {e}"
        )

