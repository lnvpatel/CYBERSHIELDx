from fastapi import APIRouter, UploadFile, File, HTTPException, Depends
from sqlalchemy.orm import Session
from app.db import get_db
from app.services.file_service import scan_file
import logging
router = APIRouter(prefix="", tags=["File Scan"])

@router.post("/upload/")
async def upload_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Uploads a file and scans it for viruses using ClamAV."""
    scan_result = scan_file(file)  # ✅ Pass the `UploadFile` object directly

    if scan_result["scan_result"]["infected"]:
        return {
            "status": "infected",
            "reason": scan_result["scan_result"]["reason"],
            "filename": file.filename,
        }

    return {
        "status": "clean",
        "filename": file.filename,
    }
