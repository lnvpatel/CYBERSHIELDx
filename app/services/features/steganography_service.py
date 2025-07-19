import logging
from fastapi import UploadFile, HTTPException, status
from typing import Optional

from app.schemas.features.steganography import (
    SteganoEmbedRequest,
    SteganoExtractRequest,
    SteganoExtractResponse,
)
from app.tasks.background_task_stegano import (
    embed_data_in_image_sync,
    extract_data_from_image_sync
)

logger = logging.getLogger(__name__)

async def embed_data_in_image(
    image_file: UploadFile,
    text_to_hide: str,
    pin: str,
    user_id: int
) -> bytes:
    """
    Performs synchronous embedding of text data into an image.
    Returns the bytes of the embedded image.
    """
    logger.debug(f"Service: Performing synchronous steganography embedding for user {user_id} into {image_file.filename}")

    if not image_file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No image file provided for embedding."
        )
    
    if not image_file.content_type or not image_file.content_type.startswith("image/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is not a valid image type."
        )

    try:
        image_bytes = await image_file.read()
    except Exception as e:
        logger.error(f"Failed to read image file bytes for embedding: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not read image file content."
        )

    try:
        embedded_image_bytes = await embed_data_in_image_sync(
            image_bytes=image_bytes,
            text_to_hide=text_to_hide,
            pin=pin,
            original_filename=image_file.filename,
        )
        
        logger.info(f"Steganography embedding completed for user {user_id}. Returning embedded image bytes.")
        return embedded_image_bytes
    except ValueError as ve:
        logger.error(f"Service: Invalid image format for embedding for user {user_id}, file {image_file.filename}: {ve}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        logger.error(f"Service: Unexpected error during steganography embedding for user {user_id}, file {image_file.filename}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during image embedding."
        )


async def extract_data_from_image(
    image_file: UploadFile,
    pin: str,
    user_id: int
) -> SteganoExtractResponse:
    """
    Performs synchronous extraction of hidden text data from an image.
    Returns the extracted text and a status message.
    """
    logger.debug(f"Service: Performing synchronous steganography extraction for user {user_id} from {image_file.filename}")

    if not image_file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No image file provided for extraction."
        )

    if not image_file.content_type or not image_file.content_type.startswith("image/"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is not a valid image type."
        )

    try:
        image_bytes = await image_file.read()
    except Exception as e:
        logger.error(f"Failed to read image file bytes for extraction: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not read image file content."
        )

    try:
        extracted_text_or_error_message = await extract_data_from_image_sync(
            image_bytes=image_bytes,
            pin=pin,
        )

        message = "Text extracted successfully."
        extracted_text: Optional[str] = None # Initialize as None

        # Check if the result is a string (not None) before using 'in' operator
        if extracted_text_or_error_message is not None:
            if extracted_text_or_error_message == "No hidden message found in the image.":
                message = "No hidden message found in the image."
                extracted_text = None
            elif "Decryption failed." in extracted_text_or_error_message:
                message = "Decryption failed. Incorrect pin or corrupted hidden data."
                extracted_text = None
            elif "Error processing hidden data." in extracted_text_or_error_message:
                message = "Error processing hidden data. It might be corrupted or not a valid encrypted message."
                extracted_text = None
            else:
                extracted_text = extracted_text_or_error_message # Valid text was extracted and decrypted
        else:
            # If the background task explicitly returned None, it implies a non-textual error
            # or a very specific edge case not covered by the string messages.
            # We can set a generic extraction failure message here.
            message = "Extraction failed or returned no data."
            extracted_text = None

        logger.info(f"Steganography extraction completed for user {user_id}. Message: {message}")
        return SteganoExtractResponse(
            extracted_text=extracted_text,
            message=message
        )
    except ValueError as ve:
        logger.error(f"Service: Invalid image format for extraction for user {user_id}, file {image_file.filename}: {ve}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        logger.error(f"Service: Unexpected error during steganography extraction for user {user_id}, file {image_file.filename}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred during image extraction."
        )
    
