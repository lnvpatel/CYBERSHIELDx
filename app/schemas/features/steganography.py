# app/schemas/features/steganography.py

from pydantic import BaseModel, Field
from typing import Optional

# --- Steganography Schemas ---
class SteganoEmbedRequest(BaseModel):
    """
    Schema for a steganography embedding request.
    """
    text_to_hide: str = Field(
        ...,  # This indicates the field is required
        min_length=1,
        max_length=1000,
        example="This is a secret message to be hidden.",
        description="The text data to hide within the image."
    )
    pin: str = Field(
        ..., # Required
        min_length=4,
        max_length=32,
        example="mysecurepin123",
        description="A passphrase (PIN) used to encrypt the hidden message before embedding. Must be remembered for extraction."
    )

    class Config:
        json_schema_extra = {
            "example": {
                "text_to_hide": "Top secret information.",
                "pin": "supersecretpassword"
            }
        }

class SteganoExtractRequest(BaseModel):
    """
    Schema for a steganography extraction request.
    """
    pin: str = Field(
        ..., # Required
        min_length=4,
        max_length=32,
        example="mysecurepin123",
        description="The passphrase (PIN) required to decrypt and extract the hidden message."
    )

    class Config:
        json_schema_extra = {
            "example": {
                "pin": "supersecretpassword"
            }
        }

class SteganoExtractResponse(BaseModel):
    """
    Schema for a steganography extraction response.
    """
    extracted_text: Optional[str] = Field(
        None,  # Default value for Optional field
        description="The text extracted and decrypted from the image, if successful. Will be null if no message found or decryption failed."
    )
    message: str = Field(
        ..., # Required
        description="A status message indicating the outcome of the extraction (e.g., 'Text extracted successfully.', 'Decryption failed.')."
    )

    class Config:
        json_schema_extra = {
            "examples": [
                {
                    "extracted_text": "The hidden message was: 'Hello, World!'",
                    "message": "Text extracted successfully."
                },
                {
                    "extracted_text": None,
                    "message": "Decryption failed. Incorrect pin or corrupted hidden data."
                },
                {
                    "extracted_text": None,
                    "message": "No hidden message found in the image."
                }
            ]
        }