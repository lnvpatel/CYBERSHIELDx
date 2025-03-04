from PIL import Image
import io
import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2

# Salt for Key Derivation
SALT = b'stegano_salt_1234'


def derive_key(password: str) -> bytes:
    """
    Derives a 32-byte AES key from a password using PBKDF2.
    """
    return PBKDF2(password, SALT, dkLen=32, count=100000)


def encrypt_message(message: str, password: str) -> str:
    """
    Encrypts the message using AES encryption with a password-derived key.
    """
    key = derive_key(password)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    return base64.b64encode(iv + encrypted_bytes).decode()


def decrypt_message(encrypted_message: str, password: str) -> str:
    """
    Decrypts an AES-encrypted message using the provided password.
    """
    key = derive_key(password)
    encrypted_data = base64.b64decode(encrypted_message)
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
    return decrypted_bytes.decode()


def process_image(image_data: bytes) -> Image.Image:
    """
    Ensures the image is in a format suitable for encoding.
    Converts images with transparency to RGB.
    """
    image = Image.open(io.BytesIO(image_data))

    # Convert to RGB to remove alpha/transparency issues
    if image.mode in ("RGBA", "P"):
        image = image.convert("RGB")

    return image


def encode_message(image_data: bytes, message: str, password: str, image_format: str) -> bytes:
    """
    Encodes an AES-encrypted message inside an image using LSB steganography.
    Supports PNG and JPEG formats.
    """
    image = process_image(image_data)
    encrypted_message = encrypt_message(message, password)

    # Convert message to binary
    binary_message = ''.join(format(ord(char), '08b') for char in encrypted_message)
    
    # Append a proper termination marker (NULL character)
    binary_message += '0000000000000000'  # Two NULL characters for robustness

    pixels = list(image.getdata())

    if len(binary_message) > len(pixels) * 3:
        raise ValueError("Message too long for image size")

    new_pixels = []
    message_index = 0

    for pixel in pixels:
        new_pixel = list(pixel)
        for i in range(3):
            if message_index < len(binary_message):
                new_pixel[i] = (new_pixel[i] & ~1) | int(binary_message[message_index])
                message_index += 1
        new_pixels.append(tuple(new_pixel))

    encoded_image = Image.new(image.mode, image.size)
    encoded_image.putdata(new_pixels)

    image_bytes = io.BytesIO()
    if image_format.upper() in ["JPG", "JPEG"]:
        encoded_image.save(image_bytes, format="JPEG", quality=95)
    else:
        encoded_image.save(image_bytes, format="PNG")

    return image_bytes.getvalue()


def decode_message(image_data: bytes, password: str) -> str:
    """
    Extracts and decrypts a hidden AES-encrypted message from an image.
    """
    image = process_image(image_data)
    pixels = list(image.getdata())

    binary_message = "".join(str(pixel[i] & 1) for pixel in pixels for i in range(3))
    
    # Split binary data into 8-bit chunks
    message_bytes = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
    
    # Convert binary chunks to characters
    extracted_message = ''.join(chr(int(byte, 2)) for byte in message_bytes)

    # Find the termination marker (NULL character)
    end_marker = extracted_message.find("\0\0")
    if end_marker != -1:
        extracted_message = extracted_message[:end_marker]

    return decrypt_message(extracted_message, password)
