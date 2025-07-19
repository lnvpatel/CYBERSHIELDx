import logging
import uuid
from typing import Optional, List, Dict, Any
from fastapi import BackgroundTasks, UploadFile, HTTPException, status
from pydantic import HttpUrl, IPvAnyAddress

from app.schemas.features.security_tools import (
    URLCheckRequest, URLCheckResponse,
    FileScanResponse,
    IPDetailsRequest, IPDetailsResponse
)
# Import the background task functions (assuming these are correctly defined in app/tasks/background_task_securitytools.py)
from app.tasks.background_task_securitytools import (
    check_url_phishing_background,
    scan_file_for_viruses_background,
    get_ip_details_and_reputation_background
)

logger = logging.getLogger(__name__)

# In-memory store for job results.
# IMPORTANT: For production, replace this with a persistent store (e.g., Redis, database).
# This dictionary will hold the latest state of each background job.
# Key: job_id (str)
# Value: Dict representing the latest URLCheckResponse, FileScanResponse, or IPDetailsResponse data
job_results_store: Dict[str, Any] = {}

async def check_url_for_phishing(
    background_tasks: BackgroundTasks,
    request_data: URLCheckRequest
) -> URLCheckResponse:
    """
    Initiates a background task to check a URL for phishing/malicious content.
    Returns an immediate placeholder response with a job ID.
    """
    job_id = str(uuid.uuid4())
    logger.debug(f"Service: Initiating URL phishing check for: {request_data.url} with job ID: {job_id}")

    # Initialize job status in the store
    initial_response = URLCheckResponse(
        job_id=job_id,
        url=request_data.url,
        is_phishing=None, # Null initially
        threat_type=None,
        provider="Initiated",
        details=None,
        message="URL check initiated in background. Results will be available shortly.",
        status="pending"
    )
    job_results_store[job_id] = initial_response.model_dump() # Store as dict for mutability

    # Add the actual check to background tasks, passing the job_id and store reference
    background_tasks.add_task(
        check_url_phishing_background,
        job_id=job_id,
        url=str(request_data.url), # Convert HttpUrl to string for background task
        job_store=job_results_store # Pass the store reference
    )

    # Return the immediate response with job ID and pending status
    return initial_response

async def get_url_check_status(job_id: str) -> URLCheckResponse:
    """
    Retrieves the current status and results of a URL phishing check job.
    """
    result = job_results_store.get(job_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job with ID '{job_id}' not found."
        )
    return URLCheckResponse(**result)


async def scan_file_for_viruses(
    background_tasks: BackgroundTasks,
    file: UploadFile
) -> FileScanResponse:
    """
    Initiates a background task to scan an uploaded file for viruses.
    Returns an immediate placeholder response with a job ID.
    """
    job_id = str(uuid.uuid4())
    logger.debug(f"Service: Initiating file virus scan for: {file.filename} with job ID: {job_id}")

    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file provided for scanning."
        )

    # Read file bytes for the background task
    file_bytes = await file.read()

    # Initialize job status in the store
    initial_response = FileScanResponse(
        job_id=job_id,
        filename=file.filename,
        is_malicious=None, # Null initially
        md5_hash=None,
        sha256_hash=None,
        provider="Initiated",
        details=None,
        message="File scan initiated in background. Results will be available shortly.",
        status="pending"
    )
    job_results_store[job_id] = initial_response.model_dump()

    # Add the actual scan to background tasks
    background_tasks.add_task(
        scan_file_for_viruses_background,
        job_id=job_id,
        filename=file.filename,
        file_bytes=file_bytes,
        job_store=job_results_store # Pass the store reference
    )

    # Return the immediate response with job ID and pending status
    return initial_response

async def get_file_scan_status(job_id: str) -> FileScanResponse:
    """
    Retrieves the current status and results of a file scan job.
    """
    result = job_results_store.get(job_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job with ID '{job_id}' not found."
        )
    return FileScanResponse(**result)


async def get_ip_details_and_reputation(
    background_tasks: BackgroundTasks, # Added BackgroundTasks for consistency
    request_data: IPDetailsRequest
) -> IPDetailsResponse:
    """
    Initiates a background task to fetch IP details and malicious reputation.
    Returns an immediate placeholder response with a job ID.
    """
    job_id = str(uuid.uuid4())
    logger.debug(f"Service: Initiating IP details and reputation lookup for: {request_data.ip_address} with job ID: {job_id}")

    # Initialize job status in the store
    initial_response = IPDetailsResponse(
        job_id=job_id,
        ip_address=request_data.ip_address,
        country=None, # Ensure all fields are explicitly passed, even if None
        region=None,
        city=None,
        isp=None,
        organization=None, # Added
        latitude=None,
        longitude=None,
        is_malicious=None,
        threat_score=None, # Added
        threat_types=None,
        malicious_provider="Initiated", # Changed from 'provider'
        malicious_details=None, # Changed from 'details'
        message="IP lookup initiated in background. Results will be available shortly.",
        status="pending"
    )
    job_results_store[job_id] = initial_response.model_dump()

    # Add the actual lookup to background tasks
    background_tasks.add_task(
        get_ip_details_and_reputation_background,
        job_id=job_id,
        ip_address=str(request_data.ip_address), # Convert IPvAnyAddress to string
        job_store=job_results_store # Pass the store reference
    )

    # Return the immediate response with job ID and pending status
    return initial_response

async def get_ip_lookup_status(job_id: str) -> IPDetailsResponse:
    """
    Retrieves the current status and results of an IP lookup job.
    """
    result = job_results_store.get(job_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job with ID '{job_id}' not found."
        )
    return IPDetailsResponse(**result)
