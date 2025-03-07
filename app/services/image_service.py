from PIL import Image, ImageDraw, ImageFont
import io

def resize_image(image_data: bytes, width: int, height: int) -> bytes:
    """Resize image while maintaining aspect ratio."""
    img = Image.open(io.BytesIO(image_data))
    img_resized = img.resize((width, height), Image.Resampling.LANCZOS)
    
    img_bytes = io.BytesIO()
    img_resized.save(img_bytes, format=img.format)
    return img_bytes.getvalue()

def convert_image_format(image_data: bytes, output_format: str) -> bytes:
    """Convert image format (PNG, JPG, WEBP)."""
    img = Image.open(io.BytesIO(image_data))
    
    # Ensure the format is valid
    valid_formats = {"PNG", "JPEG", "WEBP"}
    output_format = output_format.upper()
    
    if output_format == "JPG":  # Fix JPG to JPEG
        output_format = "JPEG"
    
    if output_format not in valid_formats:
        raise ValueError(f"Unsupported format: {output_format}")

    img_bytes = io.BytesIO()
    img.save(img_bytes, format=output_format)
    return img_bytes.getvalue()


def compress_image(image_data: bytes, quality: int = 75) -> bytes:
    """Compress image to reduce file size."""
    img = Image.open(io.BytesIO(image_data))
    img_bytes = io.BytesIO()
    img.save(img_bytes, format=img.format, quality=quality, optimize=True)
    return img_bytes.getvalue()

def add_watermark(image_data: bytes, watermark_text: str) -> bytes:
    """Add watermark text to an image."""
    img = Image.open(io.BytesIO(image_data)).convert("RGBA")
    width, height = img.size

    # Create watermark layer
    watermark = Image.new("RGBA", img.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(watermark)

    try:
        font = ImageFont.truetype("arial.ttf", 30)  # Use system font
    except IOError:
        font = ImageFont.load_default()  # Fallback font

    # Get text size using textbbox() (new PIL method)
    bbox = draw.textbbox((0, 0), watermark_text, font=font)
    text_width, text_height = bbox[2] - bbox[0], bbox[3] - bbox[1]

    position = (width - text_width - 10, height - text_height - 10)
    draw.text(position, watermark_text, fill=(255, 255, 255, 128), font=font)

    watermarked_img = Image.alpha_composite(img, watermark)
    
    img_bytes = io.BytesIO()
    watermarked_img.convert("RGB").save(img_bytes, format="PNG")
    return img_bytes.getvalue()
