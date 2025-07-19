# app/api/v1/endpoints/security_tools.py

import logging
from fastapi import APIRouter, BackgroundTasks, Depends, UploadFile, File, HTTPException, status
from typing import Any

from app.schemas.features.security_tools import (
    URLCheckRequest, URLCheckResponse,
    FileScanResponse,
    IPDetailsRequest, IPDetailsResponse
)
from app.services.features import security_tools_service # Import the service functions
# from app.api.deps import get_current_active_user # Assuming authentication is required

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/security-tools",
    tags=["Security Tools"],
)

@router.post(
    "/url-check",
    response_model=URLCheckResponse,
    status_code=status.HTTP_202_ACCEPTED, # Use 202 Accepted for background tasks
    summary="Check URL for phishing/malicious content",
    description="Submits a URL for background analysis against phishing and malicious content. Returns an immediate response with a job ID for polling.",
)
async def check_url(
    request_data: URLCheckRequest,
    background_tasks: BackgroundTasks,
) -> URLCheckResponse:
    """
    Endpoint to submit a URL for background phishing/malicious content checking.
    Returns a job ID to poll for results.
    """
    logger.info(f"Received request to check URL: {request_data.url}")
    return await security_tools_service.check_url_for_phishing(background_tasks, request_data)

@router.get(
    "/url-check-status/{job_id}",
    response_model=URLCheckResponse,
    summary="Get URL phishing check status",
    description="Retrieves the current status and results of a URL phishing check job by its ID.",
)
async def get_url_check_status(job_id: str) -> URLCheckResponse:
    """
    Endpoint to get the status and results of a URL phishing check.
    """
    logger.info(f"Received request for URL check status for job ID: {job_id}")
    return await security_tools_service.get_url_check_status(job_id)


@router.post(
    "/file-scan",
    response_model=FileScanResponse,
    status_code=status.HTTP_202_ACCEPTED, # Use 202 Accepted for background tasks
    summary="Scan file for viruses/malware",
    description="Uploads a file for background virus and malware scanning. Returns an immediate response with a job ID for polling.",
)
async def scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
) -> FileScanResponse:
    """
    Endpoint to upload a file for background virus scanning.
    Returns a job ID to poll for results.
    """
    logger.info(f"Received request to scan file: {file.filename}")
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file provided for scanning."
        )
    return await security_tools_service.scan_file_for_viruses(background_tasks, file)

@router.get(
    "/file-scan-status/{job_id}",
    response_model=FileScanResponse,
    summary="Get file scan status",
    description="Retrieves the current status and results of a file scan job by its ID.",
)
async def get_file_scan_status(job_id: str) -> FileScanResponse:
    """
    Endpoint to get the status and results of a file scan.
    """
    logger.info(f"Received request for file scan status for job ID: {job_id}")
    return await security_tools_service.get_file_scan_status(job_id)


@router.post(
    "/ip-details",
    response_model=IPDetailsResponse,
    status_code=status.HTTP_202_ACCEPTED, # Changed to 202 Accepted as it now initiates a background task
    summary="Get IP address details and reputation",
    description="Submits an IP address for background lookup of geolocation and malicious reputation. Returns an immediate response with a job ID for polling.",
)
async def get_ip_info(
    request_data: IPDetailsRequest,
    background_tasks: BackgroundTasks, # Added background_tasks as service function is now asynchronous
) -> IPDetailsResponse:
    """
    Endpoint to submit an IP address for background details and reputation lookup.
    Returns a job ID to poll for results.
    """
    logger.info(f"Received request for IP details: {request_data.ip_address}")
    # Call the service function, which will now add to background tasks
    return await security_tools_service.get_ip_details_and_reputation(background_tasks, request_data)

@router.get(
    "/ip-lookup-status/{job_id}",
    response_model=IPDetailsResponse,
    summary="Get IP lookup status",
    description="Retrieves the current status and results of an IP lookup job by its ID.",
)
async def get_ip_lookup_status(job_id: str) -> IPDetailsResponse:
    """
    Endpoint to get the status and results of an IP lookup.
    """
    logger.info(f"Received request for IP lookup status for job ID: {job_id}")
    return await security_tools_service.get_ip_lookup_status(job_id)
