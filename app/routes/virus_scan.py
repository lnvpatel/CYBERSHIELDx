from fastapi import APIRouter, UploadFile, File, HTTPException
import tempfile
import os
from app.services.clamav_service import scan_file

router = APIRouter(prefix="", tags=["Virus Scanning"])

@router.post("/scan")
async def scan_uploaded_file(file: UploadFile = File(...)):
    """
    Uploads and scans a file for viruses using ClamAV.
    """
    try:
        # ✅ Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(await file.read())
            temp_file_path = temp_file.name

        # ✅ Scan file using ClamAV service
        scan_result = scan_file(temp_file_path)

        # ✅ Cleanup temporary file
        os.remove(temp_file_path)

        return {
            "filename": file.filename,
            "status": "infected" if scan_result["infected"] else "clean",
            "details": scan_result
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
