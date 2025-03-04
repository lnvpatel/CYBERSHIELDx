import pytest
from io import BytesIO
from PIL import Image
import base64

def generate_test_image(format="PNG"):
    """
    Generate an in-memory test image (PNG or JPEG).
    """
    img = Image.new("RGB", (200, 200), color=(100, 100, 250))  # A simple blue image
    img_bytes = BytesIO()
    img.save(img_bytes, format=format)
    img_bytes.seek(0)
    return img_bytes

def test_embed_message(client):
    """Test embedding a secret message inside a dynamically generated image."""
    test_image = generate_test_image()
    secret_message = "SecretMessage123!"
    password = "test123"

    response = client.post("/steganography/encode",  
        files={"image": ("test.png", test_image, "image/png")},
        data={"message": secret_message, "password": password}
    )

    assert response.status_code == 200  # ✅ Ensure successful encoding

    # Save the encoded image for debugging
    with open("encoded_test.png", "wb") as f:
        f.write(response.content)

    # Ensure the file is not empty
    assert len(response.content) > 0

def test_extract_message(client):
    """Test extracting a secret message from an encoded image."""
    secret_message = "ExtractThis!"
    password = "test123"

    # Step 1: Encode the message
    test_image = generate_test_image()
    embed_response = client.post("/steganography/encode",
        files={"image": ("test.png", test_image, "image/png")},
        data={"message": secret_message, "password": password}
    )

    assert embed_response.status_code == 200

    # Save the encoded image
    with open("encoded_test.png", "wb") as f:
        f.write(embed_response.content)

    # Step 2: Use the saved encoded image in the decoding request
    with open("encoded_test.png", "rb") as f:
        extract_response = client.post("/steganography/decode",
            files={"image": ("stego.png", f, "image/png")},
            data={"password": password}
        )

    assert extract_response.status_code == 200
    assert extract_response.json()["decoded_message"] == secret_message  # ✅ Ensure correct extraction
