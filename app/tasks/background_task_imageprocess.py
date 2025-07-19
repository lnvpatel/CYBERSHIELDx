import logging
from pathlib import Path
from typing import Optional
from PIL import Image
from PIL.Image import Resampling # For modern Pillow versions (Pillow 9.0.0+)
import io

from app.schemas.features.image_processing import ImageProcessRequest, ImageFormat # Import ImageFormat Enum

logger = logging.getLogger(__name__)

async def perform_image_processing_background(
    image_bytes: bytes, # Now accepts bytes directly
    original_filename: str,
    processing_params: ImageProcessRequest,
    output_filepath: Path
):
    """
    Performs the actual image processing in a background task.
    This function will now save the processed image to the specified output_filepath.
    Handles cropping, resizing, grayscale, and target file size.
    """
    logger.info(f"Starting background image processing for '{original_filename}' with params: {processing_params.model_dump_json()}")

    try:
        # Open image from bytes (which are already read in the service layer)
        img = Image.open(io.BytesIO(image_bytes))

        # --- Image Processing Order: Crop -> Grayscale -> Resize -> Save with Quality/Target Size ---

        # 1. Apply cropping if all four parameters are provided
        if (processing_params.crop_left is not None and
            processing_params.crop_top is not None and
            processing_params.crop_right is not None and
            processing_params.crop_bottom is not None):
            
            # Ensure coordinates are integers and valid
            left = int(processing_params.crop_left)
            top = int(processing_params.crop_top)
            right = int(processing_params.crop_right)
            bottom = int(processing_params.crop_bottom)

            # Clamp coordinates to image boundaries
            left = max(0, left)
            top = max(0, top)
            right = min(img.width, right)
            bottom = min(img.height, bottom)

            if right <= left or bottom <= top:
                logger.warning(f"Invalid or zero-area crop dimensions for '{original_filename}'. Skipping crop. Coords: ({left},{top},{right},{bottom}). Image size: {img.size}")
            else:
                try:
                    img = img.crop((left, top, right, bottom))
                    logger.debug(f"Cropped image to ({left}, {top}, {right}, {bottom}). New size: {img.size}")
                except Exception as crop_err:
                    logger.error(f"Failed to apply crop for '{original_filename}': {crop_err}", exc_info=True)
                    # Decide if you want to re-raise or just skip cropping on error
        else:
            # Log if some crop parameters are missing
            if any(p is not None for p in [
                processing_params.crop_left,
                processing_params.crop_top,
                processing_params.crop_right,
                processing_params.crop_bottom
            ]):
                logger.warning(f"Incomplete crop parameters provided for '{original_filename}'. Skipping crop. All four (left, top, right, bottom) are required for cropping.")


        # 2. Apply grayscale if requested (best before resizing for consistent color conversion)
        if processing_params.grayscale:
            img = img.convert("L") # "L" mode for grayscale
            logger.debug("Converted image to grayscale.")

        # 3. Apply resizing if requested
        if processing_params.resize_width is not None or processing_params.resize_height is not None:
            current_width, current_height = img.size
            target_width = processing_params.resize_width if processing_params.resize_width is not None else current_width
            target_height = processing_params.resize_height if processing_params.resize_height is not None else current_height

            # Maintain aspect ratio if only one dimension is provided
            if processing_params.resize_width is not None and processing_params.resize_height is None:
                if current_width == 0: # Avoid division by zero
                    logger.warning(f"Image has zero width, cannot resize maintaining aspect ratio for '{original_filename}'. Skipping resize.")
                else:
                    target_height = int(current_height * (target_width / current_width))
            elif processing_params.resize_height is not None and processing_params.resize_width is None:
                if current_height == 0: # Avoid division by zero
                    logger.warning(f"Image has zero height, cannot resize maintaining aspect ratio for '{original_filename}'. Skipping resize.")
                else:
                    target_width = int(current_width * (target_height / current_height))
            
            if target_width > 0 and target_height > 0: # Ensure positive dimensions
                try:
                    # Use Image.Resampling.LANCZOS for high-quality downsampling
                    img = img.resize((target_width, target_height), Resampling.LANCZOS)
                    logger.debug(f"Resized image to {target_width}x{target_height}")
                except Exception as resize_err:
                    logger.error(f"Failed to resize image for '{original_filename}': {resize_err}", exc_info=True)
            else:
                logger.warning(f"Calculated target dimensions for '{original_filename}' are non-positive ({target_width}x{target_height}). Skipping resize.")

        # 4. Determine output format and quality/target size
        output_format_str = processing_params.output_format.value.upper()
        final_quality_used = None
        
        # Check if output format supports quality (lossy formats)
        is_lossy_format = output_format_str in [ImageFormat.JPEG.value.upper(), ImageFormat.WEBP.value.upper()]

        if processing_params.target_kb_size is not None and is_lossy_format:
            # --- Iterative Quality Adjustment for Target KB Size ---
            target_bytes = processing_params.target_kb_size * 1024
            
            # Start quality: use specified quality, or a sensible default
            current_quality = processing_params.quality if processing_params.quality is not None else 85
            
            min_quality = 1
            max_quality = 100
            tolerance_bytes = 5 * 1024 # Allow +/- 5KB deviation from target
            max_iterations = 15 # Increased iterations for better convergence

            logger.debug(f"Attempting to reach target_kb_size: {processing_params.target_kb_size}KB for '{original_filename}' (target bytes: {target_bytes}). Initial quality: {current_quality}")

            best_buffer = None
            best_diff = float('inf')
            
            # Initialize prev_quality before the loop
            prev_quality = current_quality # FIX: Initialize prev_quality here

            for i in range(max_iterations):
                buffer = io.BytesIO()
                try:
                    img.save(buffer, format=output_format_str, quality=current_quality, optimize=True)
                except Exception as save_err:
                    logger.error(f"Error saving image in iteration {i+1} at quality {current_quality}: {save_err}", exc_info=True)
                    break # Break if saving fails

                current_size_bytes = buffer.tell()
                current_size_kb = current_size_bytes / 1024
                
                diff = abs(current_size_bytes - target_bytes)

                logger.debug(f"Iteration {i+1}: Quality={current_quality}, Size={current_size_kb:.2f}KB, Target={processing_params.target_kb_size}KB, Diff={diff} bytes")

                if diff < best_diff:
                    best_diff = diff
                    best_buffer = buffer
                    final_quality_used = current_quality

                if diff <= tolerance_bytes:
                    logger.info(f"Target size reached for '{original_filename}' within tolerance ({tolerance_bytes} bytes). Final size: {current_size_kb:.2f}KB, Quality: {current_quality}")
                    break
                
                if current_size_bytes > target_bytes:
                    # Too large, reduce quality. Ensure we don't go below min_quality.
                    current_quality = max(min_quality, current_quality - 5)
                else: # current_size_bytes < target_bytes
                    # Too small, increase quality. Ensure we don't go above max_quality.
                    current_quality = min(max_quality, current_quality + 5)
                
                # If quality hasn't changed and we haven't reached target, we might be stuck
                # Check for quality change after it's potentially updated
                if current_quality == prev_quality and diff > tolerance_bytes: # Check against the quality from the *previous* iteration
                    logger.warning(f"Quality stuck at {current_quality} for '{original_filename}', cannot reach target size. Stopping iterations.")
                    break
                prev_quality = current_quality # Update prev_quality for the next iteration

            if best_buffer:
                output_filepath.write_bytes(best_buffer.getvalue())
                logger.info(f"Processed image for '{original_filename}' saved to: {output_filepath} with final quality {final_quality_used}")
            else:
                # Fallback if no valid buffer was generated (e.g. initial save failed)
                logger.error(f"Failed to generate processed image for '{original_filename}' using target_kb_size logic. Attempting save with default quality.")
                # You might want to save with a default quality here as a last resort
                img.save(output_filepath, format=output_format_str, quality=85, optimize=True)
                logger.info(f"Processed image for '{original_filename}' saved to: {output_filepath} with fallback quality 85.")

        elif processing_params.quality is not None and is_lossy_format:
            # --- Save with explicit quality ---
            final_quality_used = processing_params.quality
            output_filepath.parent.mkdir(parents=True, exist_ok=True) # Ensure directory exists
            img.save(output_filepath, format=output_format_str, quality=final_quality_used, optimize=True)
            logger.info(f"Processed image for '{original_filename}' saved to: {output_filepath} with specified quality: {final_quality_used}")
        else:
            # --- Save without specific quality (Pillow default or lossless format) ---
            output_filepath.parent.mkdir(parents=True, exist_ok=True) # Ensure directory exists
            img.save(output_filepath, format=output_format_str)
            logger.info(f"Processed image for '{original_filename}' saved to: {output_filepath} without explicit quality (Pillow default or lossless).")

    except Exception as e:
        logger.error(f"Critical error during background image processing for '{original_filename}': {e}", exc_info=True)
        # In a real-world app, you might want to:
        # - Log this error to an error tracking system
        # - Potentially notify an admin
        # - Delete the partially processed file (if any)
