import logging
import io
from PIL import Image, UnidentifiedImageError # Import UnidentifiedImageError for specific error handling
# Imports for real steganography and encryption
from stegano import lsb
from cryptography.fernet import Fernet, InvalidToken # Import InvalidToken for specific decryption error
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os # For generating random salt
import asyncio # For running CPU-bound tasks in a separate thread
from typing import Optional # <--- FIX 1: Import Optional

logger = logging.getLogger(__name__)

# Define the length of the salt in bytes. 16 bytes (128 bits) is a common and secure size.
SALT_LENGTH = 16 
# Define the number of PBKDF2 iterations. OWASP recommends at least 600,000 for SHA256.
PBKDF2_ITERATIONS = 600000 


# Helper function to derive a Fernet key from a pin and a salt
def _derive_key(pin: str, salt: bytes) -> bytes:
    """
    Derives a Fernet key from a string pin and a salt.
    This is a CPU-bound operation and should be run in a separate thread.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Fernet keys are 32 bytes
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(pin.encode()))
    return key

# Steganography Functions (now correctly handle CPU-bound operations)
async def embed_data_in_image_sync(
    image_bytes: bytes,
    text_to_hide: str,
    pin: str,
    original_filename: str # Retained for logging/naming if needed
) -> bytes: # Returns the bytes of the embedded image
    """
    Embeds text data into an image using LSB steganography.
    Encrypts the text using Fernet with a randomly generated salt.
    The salt is prepended to the encrypted text before embedding.
    Returns the bytes of the embedded image.
    """
    logger.info(f"Starting steganography embedding for file: {original_filename}")
    
    try:
        # 1. Generate a unique, random salt for this embedding
        salt = os.urandom(SALT_LENGTH)
        
        # 2. Derive the key using the pin and the generated salt
        # This is CPU-bound, run in a thread
        key = await asyncio.to_thread(_derive_key, pin, salt)
        f = Fernet(key)
        
        # 3. Encrypt the text to hide
        # This is CPU-bound, run in a thread
        encrypted_text_bytes = await asyncio.to_thread(f.encrypt, text_to_hide.encode())
        
        # 4. Prepend the salt to the encrypted text.
        # We need to encode the combined data to base64urlsafe for LSB hiding,
        # as LSB works with string data.
        # The format will be: base64(salt + encrypted_text_bytes)
        full_payload_to_hide = base64.urlsafe_b64encode(salt + encrypted_text_bytes).decode('utf-8')

        # 5. Open and prepare the image
        # These are CPU-bound, run in a thread
        img = await asyncio.to_thread(Image.open, io.BytesIO(image_bytes))
        if img.mode != 'RGBA':
            img = await asyncio.to_thread(img.convert, 'RGBA')

        # Create an in-memory byte stream for the image for stegano.lsb functions
        # This is the key change for Pylance type checking.
        img_byte_arr = io.BytesIO()
        await asyncio.to_thread(img.save, img_byte_arr, format='PNG')
        img_byte_arr.seek(0) # Rewind to the beginning

        # 6. Embed the full payload into the image
        # This is CPU-bound, run in a thread
        # <--- FIX 2: Pass img_byte_arr (IO[bytes]) instead of img (Image)
        steg_img = await asyncio.to_thread(lsb.hide, img_byte_arr, full_payload_to_hide) 
        
        # Save the steganography image to a new in-memory buffer as PNG (lossless)
        output_buffer = io.BytesIO()
        # This is CPU-bound, run in a thread
        await asyncio.to_thread(steg_img.save, output_buffer, format="PNG")
        output_buffer.seek(0) # Rewind to the beginning
        
        logger.info(f"Steganography embedding completed for file: {original_filename}. Returning image bytes.")
        return output_buffer.getvalue()

    except UnidentifiedImageError:
        logger.error(f"Invalid image format or corrupted image provided for embedding: {original_filename}")
        raise ValueError("Invalid image file provided.") # Re-raise with a more specific error
    except Exception as e:
        logger.error(f"Failed to embed data for file {original_filename}: {e}", exc_info=True)
        raise # Re-raise the exception to be caught by the service/endpoint


async def extract_data_from_image_sync(
    image_bytes: bytes,
    pin: str,
) -> Optional[str]: # Returns the extracted text as a string, or None if no text/decryption failed
    """
    Extracts hidden text data from an image using LSB steganography.
    Decrypts the extracted text using Fernet with the provided pin and the embedded salt.
    Returns the extracted text, or an error message if decryption fails or no message found.
    """
    logger.info(f"Starting steganography extraction.")
    
    try:
        # 1. Open and prepare the image
        # These are CPU-bound, run in a thread
        img = await asyncio.to_thread(Image.open, io.BytesIO(image_bytes))
        if img.mode != 'RGBA':
            img = await asyncio.to_thread(img.convert, 'RGBA')

        # Create an in-memory byte stream for the image for stegano.lsb functions
        # This is the key change for Pylance type checking.
        img_byte_arr = io.BytesIO()
        await asyncio.to_thread(img.save, img_byte_arr, format='PNG')
        img_byte_arr.seek(0) # Rewind to the beginning

        # 2. Extract the hidden payload (base64 encoded salt + encrypted_text)
        # This is CPU-bound, run in a thread
        # <--- FIX 3: Pass img_byte_arr (IO[bytes]) instead of img (Image)
        hidden_payload_b64_str = await asyncio.to_thread(lsb.reveal, img_byte_arr)
        
        if not hidden_payload_b64_str:
            logger.info("No hidden message found in the image.")
            return "No hidden message found in the image."

        try:
            # 3. Decode the base64 payload to get salt and encrypted text bytes
            full_payload_bytes = base64.urlsafe_b64decode(hidden_payload_b64_str.encode('utf-8'))
            
            # 4. Separate salt and encrypted text
            if len(full_payload_bytes) < SALT_LENGTH:
                logger.warning("Extracted data is too short to contain a valid salt.")
                return "No valid hidden message found (data corrupted or too short)."

            extracted_salt = full_payload_bytes[:SALT_LENGTH]
            encrypted_text_bytes = full_payload_bytes[SALT_LENGTH:]

            # 5. Derive the key using the pin and the extracted salt
            # This is CPU-bound, run in a thread
            key = await asyncio.to_thread(_derive_key, pin, extracted_salt)
            f = Fernet(key)

            # 6. Attempt to decrypt the extracted text
            # This is CPU-bound, run in a thread
            decrypted_text_bytes = await asyncio.to_thread(f.decrypt, encrypted_text_bytes)
            extracted_text = decrypted_text_bytes.decode('utf-8')
            logger.info(f"Steganography extraction completed. Text decrypted successfully.")
            return extracted_text
        except InvalidToken:
            logger.warning(f"Decryption failed for steganography. Likely incorrect pin or corrupted data.")
            return "Decryption failed. Incorrect pin or corrupted hidden data."
        except Exception as inner_e:
            logger.warning(f"Error processing extracted steganography data (e.g., base64 decode, payload split): {inner_e}", exc_info=True)
            return "Error processing hidden data. It might be corrupted or not a valid encrypted message."

    except UnidentifiedImageError:
        logger.error(f"Invalid image format or corrupted image provided for extraction.")
        raise ValueError("Invalid image file provided.") # Re-raise with a more specific error
    except Exception as e:
        logger.error(f"Failed to extract data: {e}", exc_info=True)
        raise # Re-raise the exception to be caught by the service/endpoint