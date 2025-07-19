from pydantic import BaseModel, Field, validator
from typing import Optional
from enum import Enum

# Define an Enum for allowed output formats
class ImageFormat(str, Enum):
    JPEG = "jpeg"
    PNG = "png"
    GIF = "gif"
    WEBP = "webp"
    BMP = "bmp"
    TIFF = "tiff"

class ImageProcessRequest(BaseModel):
    """
    Schema for image processing parameters.
    """
    resize_width: Optional[int] = Field(None, description="Target width for resizing.")
    resize_height: Optional[int] = Field(None, description="Target height for resizing.")
    
    # Crop parameters - Frontend should send these based on visual selection
    # It's assumed that if one crop parameter is sent, all four are intended.
    # Backend will validate/handle incomplete sets.
    crop_left: Optional[int] = Field(None, description="Left pixel coordinate for cropping.")
    crop_top: Optional[int] = Field(None, description="Top pixel coordinate for cropping.")
    crop_right: Optional[int] = Field(None, description="Right pixel coordinate for cropping.")
    crop_bottom: Optional[int] = Field(None, description="Bottom pixel coordinate for cropping.")
    
    grayscale: Optional[bool] = Field(False, description="Whether to convert the image to grayscale.")
    output_format: ImageFormat = Field(ImageFormat.JPEG, description="Desired output format for the image.")
    quality: Optional[int] = Field(None, ge=1, le=100, description="Quality for lossy formats (JPEG, WebP). 1-100.")
    target_kb_size: Optional[int] = Field(None, description="Target file size in KB. If set, quality will be adjusted. Takes precedence over 'quality'.")

    @validator('target_kb_size', pre=True, always=True)
    def check_quality_and_size_exclusivity(cls, v, values):
        # If target_kb_size is provided, ensure quality is not also provided to avoid ambiguity.
        # Or, if both are provided, document that target_kb_size takes precedence.
        # For simplicity, we'll let target_kb_size take precedence in the service layer.
        # If strict mutual exclusivity is desired at schema level:
        # if v is not None and values.get('quality') is not None:
        #     raise ValueError("Cannot specify both 'quality' and 'target_kb_size'. 'target_kb_size' takes precedence.")
        return v


class ImageProcessResponse(BaseModel):
    """
    Schema for the response after an image processing request.
    """
    original_filename: str = Field(..., description="The original filename of the uploaded image.")
    processed_url: str = Field(..., description="The URL where the processed image will be or is available.")
    message: str = Field(..., description="A status message about the processing.")
    # Removed final_size_kb from the immediate response as it's not known instantly.
    # Clients can check the size of the image at processed_url once available.
    # If this is critical, a polling mechanism or webhook would be needed.