from fastapi import APIRouter, File, UploadFile, Query, HTTPException
from fastapi.responses import StreamingResponse
from app.services.image_service import (
    resize_image, convert_image_format, compress_image, add_watermark
)
import io

router = APIRouter(prefix="", tags=["Image Resizer"])

@router.post("/resize-image/")
async def resize_uploaded_image(
    file: UploadFile = File(...), width: int = 100, height: int = 100
):
    """Resize an uploaded image."""
    try:
        image_data = await file.read()
        resized_image = resize_image(image_data, width, height)
        return StreamingResponse(io.BytesIO(resized_image), media_type=file.content_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image resizing failed: {str(e)}")

@router.post("/convert-image/")
async def convert_image(
    file: UploadFile = File(...), output_format: str = Query("PNG", pattern="^(PNG|JPG|WEBP)$")
):
    """Convert image format (PNG, JPG, WEBP)."""
    try:
        image_data = await file.read()
        converted_image = convert_image_format(image_data, output_format)
        return StreamingResponse(io.BytesIO(converted_image), media_type=f"image/{output_format.lower()}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image conversion failed: {str(e)}")

@router.post("/compress-image/")
async def compress_uploaded_image(
    file: UploadFile = File(...), quality: int = Query(75, ge=10, le=95)
):
    """Compress image to reduce file size."""
    try:
        image_data = await file.read()
        compressed_image = compress_image(image_data, quality)
        return StreamingResponse(io.BytesIO(compressed_image), media_type=file.content_type)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image compression failed: {str(e)}")

@router.post("/watermark-image/")
async def watermark_image(
    file: UploadFile = File(...), watermark_text: str = Query("Sample Watermark")
):
    """Add watermark text to an image."""
    try:
        image_data = await file.read()
        watermarked_image = add_watermark(image_data, watermark_text)
        return StreamingResponse(io.BytesIO(watermarked_image), media_type="image/png")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Watermarking failed: {str(e)}")
