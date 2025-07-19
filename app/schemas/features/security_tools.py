# app/schemas/features/security_tools.py

from pydantic import BaseModel, Field, HttpUrl, IPvAnyAddress
from typing import Optional, Literal, List, Dict, Any

# --- Phishing Detection ---
class URLCheckRequest(BaseModel):
    """
    Schema for a URL phishing detection request.
    """
    url: HttpUrl = Field(..., description="The URL to check for phishing.")

    class Config:
        json_schema_extra = {
            "example": {
                "url": "http://malicious.example.com/phish"
            }
        }

class URLCheckResponse(BaseModel):
    """
    Schema for a URL phishing detection response.
    Includes job_id and status for asynchronous processing.
    """
    job_id: str = Field(..., description="Unique ID for the background job.")
    url: HttpUrl = Field(..., description="The URL that was checked.")
    is_phishing: Optional[bool] = Field(None, description="True if the URL is detected as phishing/malicious. Null if pending.")
    threat_type: Optional[str] = Field(None, description="Type of threat detected (e.g., 'MALWARE', 'PHISHING').")
    provider: str = Field(..., description="Security provider used for the check (e.g., 'Google Safe Browse', 'VirusTotal').")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional details from the security provider.")
    message: str = Field(..., description="Status message.")
    status: Literal['pending', 'completed', 'failed'] = Field(..., description="Current status of the background job.")

# --- File Virus Scanning ---
class FileScanResponse(BaseModel):
    """
    Schema for a file virus scan response.
    Includes job_id and status for asynchronous processing.
    """
    job_id: str = Field(..., description="Unique ID for the background job.")
    filename: str = Field(..., description="Name of the file that was scanned.")
    is_malicious: Optional[bool] = Field(None, description="True if the file is detected as malicious. Null if pending.")
    md5_hash: Optional[str] = Field(None, description="MD5 hash of the scanned file.")
    sha256_hash: Optional[str] = Field(None, description="SHA256 hash of the scanned file.")
    provider: str = Field(..., description="Security provider used for the scan (e.g., 'VirusTotal', 'ClamAV').")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional details from the security provider.")
    message: str = Field(..., description="Status message.")
    status: Literal['pending', 'completed', 'failed'] = Field(..., description="Current status of the background job.")

# --- IP Details & Malicious IP Detection ---
class IPDetailsRequest(BaseModel):
    """
    Schema for an IP address lookup request.
    """
    ip_address: IPvAnyAddress = Field(..., description="The IP address to lookup.")

    class Config:
        json_schema_extra = {
            "example": {
                "ip_address": "8.8.8.8"
            }
        }

class IPDetailsResponse(BaseModel):
    """
    Schema for IP address details and malicious detection response.
    Includes job_id and status for asynchronous processing.
    """
    job_id: str = Field(..., description="Unique ID for the background job.")
    ip_address: IPvAnyAddress = Field(..., description="The IP address that was looked up.")
    
    # Geolocation details
    country: Optional[str] = Field(None, description="Country of the IP address.")
    region: Optional[str] = Field(None, description="Region/State of the IP address.") # Explicitly added region
    city: Optional[str] = Field(None, description="City of the IP address.")
    isp: Optional[str] = Field(None, description="Internet Service Provider for the IP address.")
    organization: Optional[str] = Field(None, description="Organization associated with the IP address.")
    latitude: Optional[float] = Field(None, description="Latitude coordinate.")
    longitude: Optional[float] = Field(None, description="Longitude coordinate.")

    # Malicious detection details
    is_malicious: Optional[bool] = Field(None, description="True if the IP address is detected as malicious. Null if pending.")
    threat_score: Optional[int] = Field(None, ge=0, description="Threat score (e.g., from AbuseIPDB).")
    threat_types: Optional[List[str]] = Field(None, description="List of detected threat types.")
    malicious_provider: Optional[str] = Field(None, description="Security provider for malicious IP detection.")
    malicious_details: Optional[Dict[str, Any]] = Field(None, description="Additional malicious details from the security provider.")

    # General status
    message: str = Field(..., description="Status message.")
    status: Literal['pending', 'completed', 'failed'] = Field(..., description="Current status of the background job.")
