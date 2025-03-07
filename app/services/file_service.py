import os
import shutil
import tempfile
from fastapi import UploadFile, HTTPException
from app.services.clamav_service import scan_file as clamav_scan_file

def scan_file(file: UploadFile):
    """
    Scans an uploaded file using ClamAV and returns a detailed scan report.
    """
    # Restrict certain file types
    restricted_extensions = {".bat", ".cmd", ".sh"}
    file_extension = os.path.splitext(file.filename)[1].lower()
    if file_extension in restricted_extensions:
        raise HTTPException(status_code=400, detail=f"File type '{file_extension}' is not allowed")

    # Save file temporarily
    try:
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            shutil.copyfileobj(file.file, temp_file)
            temp_file_path = temp_file.name
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error saving file: {str(e)}")

    # Get file size (since UploadFile has no `.size` attribute)
    file.file.seek(0, os.SEEK_END)
    file_size = file.file.tell()
    file.file.seek(0)

    # Scan file with ClamAV
    try:
        scan_result = clamav_scan_file(temp_file_path)  # ✅ Corrected function call
    except Exception as e:
        os.remove(temp_file_path)
        raise HTTPException(status_code=500, detail=f"Error scanning file: {str(e)}")

    # Delete temporary file
    os.remove(temp_file_path)

    # Return detailed scan report
    return {
        "filename": file.filename,
        "size": file_size,  # ✅ Fixed file size issue
        "scan_result": scan_result
    }
