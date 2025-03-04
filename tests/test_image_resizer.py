import pytest
from fastapi.testclient import TestClient
from app.main import app  # Import FastAPI app
import io
from PIL import Image

client = TestClient(app)

# Helper function to create an in-memory test image
def create_test_image(format="PNG"):
    img = Image.new("RGB", (500, 500), color=(255, 0, 0))  # Red image
    img_bytes = io.BytesIO()
    img.save(img_bytes, format=format)
    img_bytes.seek(0)
    return img_bytes

def test_resize_image():
    test_image = create_test_image()
    
    response = client.post(
        "/image/resize-image?width=100&height=100",
        files={"file": ("test.png", test_image, "image/png")}
    )

    assert response.status_code == 200
    resized_img = Image.open(io.BytesIO(response.content))
    assert resized_img.size == (100, 100)

def test_convert_image():
    test_image = create_test_image()

    response = client.post(
        "/image/convert-image/?output_format=JPG",
        files={"file": ("test.png", test_image, "image/png")}
    )

    assert response.status_code == 200
    converted_img = Image.open(io.BytesIO(response.content))
    assert converted_img.format == "JPEG"

def test_compress_image():
    test_image = create_test_image()

    response = client.post(
        "/image/compress-image/?quality=50",
        files={"file": ("test.png", test_image, "image/png")}
    )

    assert response.status_code == 200
    compressed_size = len(response.content)
    assert compressed_size < len(test_image.getvalue())  # Compressed image should be smaller

def test_watermark_image():
    test_image = create_test_image()

    response = client.post(
        "/image/watermark-image/?watermark_text=TestWatermark",
        files={"file": ("test.png", test_image, "image/png")}
    )

    assert response.status_code == 200
    watermarked_img = Image.open(io.BytesIO(response.content))
    assert watermarked_img.format == "PNG"  # Watermarked image should be in PNG format
