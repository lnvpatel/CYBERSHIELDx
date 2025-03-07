from fastapi import APIRouter, UploadFile, File, HTTPException, Form
from fastapi.responses import StreamingResponse, JSONResponse
import io
from app.services import stegano_service  # Ensure correct import

router = APIRouter(prefix="", tags=["Steganography"])

@router.post("/encode")
async def encode_message(
    image: UploadFile = File(...),
    message: str = Form(...),
    password: str = Form(...)
):
    """
    Encodes a secret message into an image using LSB steganography
    and returns the encoded image as a downloadable file.
    """
    try:
        image_data = await image.read()
        image_format = image.filename.split('.')[-1].upper()

        if image_format not in ["PNG", "JPG", "JPEG"]:
            raise HTTPException(status_code=400, detail="Unsupported file format. Use PNG or JPG.")

        encoded_image_bytes = stegano_service.encode_message(image_data, message, password, image_format)

        return StreamingResponse(
            io.BytesIO(encoded_image_bytes),
            media_type=f"image/{image_format.lower()}",
            headers={"Content-Disposition": f"attachment; filename=encoded_image.{image_format.lower()}"}
        )

    except ValueError as e:
        return JSONResponse(content={"detail": f"Encoding error: {str(e)}"}, status_code=400)

    except Exception as e:
        return JSONResponse(content={"detail": f"Internal Server Error: {str(e)}"}, status_code=500)


@router.post("/decode")
async def decode_message(
    image: UploadFile = File(...),
    password: str = Form(...)
):
    """
    Decodes a hidden message from an image.
    If the password is incorrect, returns an error message.
    """
    try:
        image_data = await image.read()
        decoded_message = stegano_service.decode_message(image_data, password)

        return JSONResponse(content={"decoded_message": decoded_message}, status_code=200)

    except (ValueError, UnicodeDecodeError):
        return JSONResponse(content={"detail": "Incorrect password or corrupted data"}, status_code=400)

    except Exception as e:
        return JSONResponse(content={"detail": f"Internal Server Error: {str(e)}"}, status_code=500)
