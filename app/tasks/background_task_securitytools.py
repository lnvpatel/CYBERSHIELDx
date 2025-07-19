import logging
import io
import httpx
import hashlib
import asyncio
from app.config import settings, Settings
from typing import Dict, Any, cast, Union, List, Optional
from pydantic import HttpUrl
from ipaddress import IPv4Address, IPv6Address, ip_address as parse_ip_address
from app.schemas.features.security_tools import URLCheckResponse, FileScanResponse, IPDetailsResponse

logger = logging.getLogger(__name__)

# --- Constants for API limits and Timeouts ---
# VirusTotal
VIRUSTOTAL_URL_POLLING_ATTEMPTS = 10
VIRUSTOTAL_URL_POLLING_INTERVAL_SECONDS = 3
VIRUSTOTAL_FILE_POLLING_ATTEMPTS = 20
VIRUSTOTAL_FILE_POLLING_INTERVAL_SECONDS = 5
VIRUSTOTAL_MAX_FILE_SIZE_MB = 32

# External API Call Timeouts (for initial request, polling will use these too)
DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS = 10.0
VIRUSTOTAL_FILE_UPLOAD_TIMEOUT_SECONDS = 60.0

# AbuseIPDB category mapping for clearer threat types
ABUSEIPDB_CATEGORY_MAP = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy", 10: "Web Spam",
    11: "Email Spam", 12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "IP Spoofing", 18: "Brute-Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack", 22: "SSH",
    23: "IoT Targeted", 24: "C&C Server", 25: "XSS Attack", 26: "Click Fraud",
    27: "Malware Distribution", 28: "Compromised Server", 29: "Network Scan",
    30: "Illegal Content", 31: "P2P Abuse", 32: "Spamware", 33: "Compromised Account",
    34: "Ad Fraud", 35: "Credential Stuffing", 36: "DNS Poisoning", 37: "DDoS Reflector",
    38: "BGP Hijack", 39: "Routing Abuse", 40: "Botnet C2", 41: "DDoS Bot",
    42: "Malicious File Upload", 43: "Cryptomining", 44: "Other"
}


# Background task for URL phishing detection using VirusTotal
async def check_url_phishing_background(
    job_id: str, # Added job_id
    url: str,
    job_store: Dict[str, Any] # Added job_store
):
    """
    Checks a URL for phishing/malicious content using VirusTotal.
    This runs in a background task and updates the job_store.
    """
    logger.info(f"Background task: Checking URL for phishing: {url} (Job ID: {job_id})")
    api_key = cast(Settings, settings).VIRUSTOTAL_API_KEY
    
    final_response_data: Dict[str, Any] = {} # To hold the data for the final update

    try:
        if not api_key:
            logger.warning("VIRUSTOTAL_API_KEY is not set. Skipping URL check.")
            final_response_data = URLCheckResponse(
                job_id=job_id,
                url=HttpUrl(url),
                is_phishing=False,
                threat_type=None,
                provider="N/A",
                details=None,
                message="VirusTotal API key not configured.",
                status="completed" # Task completed with a specific message
            ).model_dump()
            return # Exit early

        vt_url = "https://www.virustotal.com/api/v3/urls"
        headers = {
            "x-apikey": api_key,
        }
        data = {"url": url}

        async with httpx.AsyncClient(timeout=DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS) as client:
            # Submit URL for analysis
            response = await client.post(vt_url, headers=headers, data=data)
            response.raise_for_status()
            analysis_id = response.json()["data"]["id"]
            
            # Poll for analysis results with linear backoff
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for i in range(VIRUSTOTAL_URL_POLLING_ATTEMPTS):
                await asyncio.sleep(VIRUSTOTAL_URL_POLLING_INTERVAL_SECONDS + i * 0.5)

                try:
                    analysis_response = await client.get(analysis_url, headers=headers)
                    analysis_response.raise_for_status()
                    analysis_data = analysis_response.json()["data"]
                    
                    status = analysis_data["attributes"]["status"]
                    if status == "completed":
                        results = analysis_data["attributes"]["results"]
                        malicious_count = 0
                        threat_types_detected: List[str] = []
                        for scanner, res in results.items():
                            if res.get("category") == "malicious":
                                malicious_count += 1
                                if res.get("result"):
                                    threat_types_detected.append(res["result"])
                        
                        is_phishing = malicious_count > 0
                        unique_threat_types = sorted(list(set(threat_types_detected)))
                        final_threat_type = ", ".join(unique_threat_types) if unique_threat_types else None

                        logger.info(f"URL '{url}' VirusTotal analysis completed. Malicious: {is_phishing}, Detections: {malicious_count}")
                        final_response_data = URLCheckResponse(
                            job_id=job_id,
                            url=HttpUrl(url),
                            is_phishing=is_phishing,
                            threat_type=final_threat_type,
                            provider="VirusTotal",
                            details={"detections": malicious_count, "results": results},
                            message="URL analysis completed.",
                            status="completed"
                        ).model_dump()
                        return # Exit function after successful completion
                except httpx.HTTPStatusError as e:
                    logger.warning(f"VirusTotal polling HTTP error for URL '{url}' (attempt {i+1}/{VIRUSTOTAL_URL_POLLING_ATTEMPTS}): {e.response.status_code} - {e.response.text}")
                    if e.response.status_code in [404, 429, 503]:
                        continue
                    raise
                except httpx.TimeoutException:
                    logger.warning(f"VirusTotal polling timed out for URL '{url}' (attempt {i+1}/{VIRUSTOTAL_URL_POLLING_ATTEMPTS}). Retrying...")
                    continue
                except Exception as e:
                    logger.warning(f"Error during VirusTotal polling for URL '{url}' (attempt {i+1}/{VIRUSTOTAL_URL_POLLING_ATTEMPTS}): {e}", exc_info=True)
                    continue

            # If loop completes without success (timed out)
            logger.warning(f"VirusTotal analysis for URL '{url}' timed out after {VIRUSTOTAL_URL_POLLING_ATTEMPTS} attempts.")
            final_response_data = URLCheckResponse(
                job_id=job_id,
                url=HttpUrl(url),
                is_phishing=None, # Undetermined on timeout
                threat_type=None,
                provider="VirusTotal",
                details=None,
                message="URL analysis timed out.",
                status="failed" # Mark as failed due to timeout
            ).model_dump()

    except httpx.HTTPStatusError as e:
        logger.error(f"VirusTotal HTTP error for URL '{url}': {e.response.status_code} - {e.response.text}", exc_info=True)
        final_response_data = URLCheckResponse(
            job_id=job_id,
            url=HttpUrl(url),
            is_phishing=None,
            threat_type=None,
            provider="VirusTotal",
            details=None,
            message=f"API error: {e.response.status_code} - {e.response.text}",
            status="failed"
        ).model_dump()
    except httpx.TimeoutException:
        logger.error(f"VirusTotal initial request timed out for URL '{url}'.", exc_info=True)
        final_response_data = URLCheckResponse(
            job_id=job_id,
            url=HttpUrl(url),
            is_phishing=None,
            threat_type=None,
            provider="VirusTotal",
            details=None,
            message="Initial API request timed out.",
            status="failed"
        ).model_dump()
    except Exception as e:
        logger.error(f"Unexpected error during VirusTotal URL check for '{url}': {e}", exc_info=True)
        final_response_data = URLCheckResponse(
            job_id=job_id,
            url=HttpUrl(url),
            is_phishing=None,
            threat_type=None,
            provider="VirusTotal",
            details=None,
            message=f"An unexpected error occurred: {e}",
            status="failed"
        ).model_dump()
    finally:
        # Ensure the store is updated even if there's an early exit or an unhandled error
        if final_response_data:
            job_store[job_id] = final_response_data
        else:
            # Fallback for truly unhandled cases, though previous blocks should catch most
            job_store[job_id] = URLCheckResponse(
                job_id=job_id,
                url=HttpUrl(url),
                is_phishing=None,
                threat_type=None,
                provider="System Error",
                details=None,
                message="An unhandled error occurred in background task.",
                status="failed"
            ).model_dump()


# Background task for File Virus Scanning using VirusTotal
async def scan_file_for_viruses_background(
    job_id: str, # Added job_id
    filename: str,
    file_bytes: bytes,
    job_store: Dict[str, Any] # Added job_store
):
    """
    Scans a file for viruses using VirusTotal.
    This runs in a background task and updates the job_store.
    """
    logger.info(f"Background task: Scanning file for viruses: {filename} (Job ID: {job_id})")
    api_key = cast(Settings, settings).VIRUSTOTAL_API_KEY
    
    final_response_data: Dict[str, Any] = {}
    md5_hash: Optional[str] = None  # Initialize to None
    sha256_hash: Optional[str] = None # Initialize to None

    try:
        if not api_key:
            logger.warning("VIRUSTOTAL_API_KEY is not set. Skipping file scan.")
            final_response_data = FileScanResponse(
                job_id=job_id,
                filename=filename,
                is_malicious=False,
                md5_hash=None,
                sha256_hash=None,
                provider="N/A",
                details=None,
                message="VirusTotal API key not configured.",
                status="completed"
            ).model_dump()
            return

        # Check file size against VirusTotal's public API limit
        MAX_FILE_SIZE_BYTES = VIRUSTOTAL_MAX_FILE_SIZE_MB * 1024 * 1024
        if len(file_bytes) > MAX_FILE_SIZE_BYTES:
            logger.warning(f"File '{filename}' exceeds VirusTotal's maximum size limit of {VIRUSTOTAL_MAX_FILE_SIZE_MB}MB. Actual size: {len(file_bytes) / (1024 * 1024):.2f}MB")
            final_response_data = FileScanResponse(
                job_id=job_id,
                filename=filename,
                is_malicious=False,
                md5_hash=None,
                sha256_hash=None,
                provider="VirusTotal",
                details=None,
                message=f"File size exceeds VirusTotal's limit of {VIRUSTOTAL_MAX_FILE_SIZE_MB}MB.",
                status="failed" # Mark as failed due to size limit
            ).model_dump()
            return

        vt_url = "https://www.virustotal.com/api/v3/files"
        headers = {
            "x-apikey": api_key,
        }
        
        # Calculate hashes
        md5_hash = hashlib.md5(file_bytes).hexdigest()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()

        async with httpx.AsyncClient(timeout=VIRUSTOTAL_FILE_UPLOAD_TIMEOUT_SECONDS) as client:
            # First, check if file has been analyzed before (by its hash)
            check_hash_url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
            try:
                hash_response = await client.get(check_hash_url, headers=headers, timeout=DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS)
                if hash_response.status_code == 200:
                    data = hash_response.json()["data"]
                    last_analysis_stats = data["attributes"]["last_analysis_stats"]
                    malicious_count = last_analysis_stats.get("malicious", 0)
                    
                    is_malicious = malicious_count > 0
                    logger.info(f"File '{filename}' (SHA256: {sha256_hash[:10]}...) found in VirusTotal cache. Malicious: {is_malicious}, Detections: {malicious_count}")
                    final_response_data = FileScanResponse(
                        job_id=job_id,
                        filename=filename,
                        is_malicious=is_malicious,
                        md5_hash=md5_hash,
                        sha256_hash=sha256_hash,
                        provider="VirusTotal (Cached)",
                        details={"detections": malicious_count, "results": data["attributes"]["last_analysis_results"]},
                        message="File analysis completed (cached result).",
                        status="completed"
                    ).model_dump()
                    return
                elif hash_response.status_code == 404:
                    logger.info(f"File '{filename}' (SHA256: {sha256_hash[:10]}...) not found in VirusTotal cache. Uploading for analysis.")
                else:
                    logger.warning(f"VirusTotal hash check HTTP error for '{filename}': {hash_response.status_code} - {hash_response.text}", exc_info=True)
            except httpx.TimeoutException:
                logger.warning(f"VirusTotal hash check timed out for '{filename}'. Proceeding with upload.", exc_info=True)
            except httpx.HTTPStatusError as e:
                if e.response.status_code != 404:
                    logger.warning(f"VirusTotal hash check HTTP error for '{filename}': {e.response.status_code} - {e.response.text}", exc_info=True)
            except Exception as e:
                logger.warning(f"Error during VirusTotal hash check for '{filename}': {e}", exc_info=True)

            # If not in cache or error, upload and analyze
            files = {"file": (filename, io.BytesIO(file_bytes), "application/octet-stream")}
            response = await client.post(vt_url, headers=headers, files=files)
            response.raise_for_status()
            analysis_id = response.json()["data"]["id"]

            # Poll for analysis results with linear backoff
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for i in range(VIRUSTOTAL_FILE_POLLING_ATTEMPTS):
                await asyncio.sleep(VIRUSTOTAL_FILE_POLLING_INTERVAL_SECONDS + i * 1)

                try:
                    analysis_response = await client.get(analysis_url, headers=headers, timeout=DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS)
                    analysis_response.raise_for_status()
                    analysis_data = analysis_response.json()["data"]
                    
                    status = analysis_data["attributes"]["status"]
                    if status == "completed":
                        results = analysis_data["attributes"]["results"]
                        malicious_count = 0
                        for scanner, res in results.items():
                            if res.get("category") == "malicious":
                                malicious_count += 1
                        
                        is_malicious = malicious_count > 0
                        logger.info(f"File '{filename}' VirusTotal analysis completed. Malicious: {is_malicious}, Detections: {malicious_count}")
                        final_response_data = FileScanResponse(
                            job_id=job_id,
                            filename=filename,
                            is_malicious=is_malicious,
                            md5_hash=md5_hash,
                            sha256_hash=sha256_hash,
                            provider="VirusTotal",
                            details={"detections": malicious_count, "results": results},
                            message="File analysis completed.",
                            status="completed"
                        ).model_dump()
                        return
                except httpx.HTTPStatusError as e:
                    logger.warning(f"VirusTotal polling HTTP error for file '{filename}' (attempt {i+1}/{VIRUSTOTAL_FILE_POLLING_ATTEMPTS}): {e.response.status_code} - {e.response.text}")
                    if e.response.status_code in [404, 429, 503]:
                        continue
                    raise
                except httpx.TimeoutException:
                    logger.warning(f"VirusTotal polling timed out for file '{filename}' (attempt {i+1}/{VIRUSTOTAL_FILE_POLLING_ATTEMPTS}). Retrying...")
                    continue
                except Exception as e:
                    logger.warning(f"Error during VirusTotal polling for file '{filename}' (attempt {i+1}/{VIRUSTOTAL_FILE_POLLING_ATTEMPTS}): {e}", exc_info=True)
                    continue

            logger.warning(f"VirusTotal file analysis for '{filename}' timed out after {VIRUSTOTAL_FILE_POLLING_ATTEMPTS} attempts.")
            final_response_data = FileScanResponse(
                job_id=job_id,
                filename=filename,
                is_malicious=None,
                md5_hash=md5_hash,
                sha256_hash=sha256_hash,
                provider="VirusTotal",
                details=None,
                message="File analysis timed out.",
                status="failed"
            ).model_dump()

    except httpx.HTTPStatusError as e:
        logger.error(f"VirusTotal HTTP error for file '{filename}': {e.response.status_code} - {e.response.text}", exc_info=True)
        final_response_data = FileScanResponse(
            job_id=job_id,
            filename=filename,
            is_malicious=None,
            md5_hash=md5_hash,
            sha256_hash=sha256_hash,
            provider="VirusTotal",
            details=None,
            message=f"API error: {e.response.status_code} - {e.response.text}",
            status="failed"
        ).model_dump()
    except httpx.TimeoutException:
        logger.error(f"VirusTotal initial file upload or request timed out for '{filename}'.", exc_info=True)
        final_response_data = FileScanResponse(
            job_id=job_id,
            filename=filename,
            is_malicious=None,
            md5_hash=md5_hash,
            sha256_hash=sha256_hash,
            provider="VirusTotal",
            details=None,
            message="Initial API request timed out.",
            status="failed"
        ).model_dump()
    except Exception as e:
        logger.error(f"Unexpected error during VirusTotal file scan for '{filename}': {e}", exc_info=True)
        final_response_data = FileScanResponse(
            job_id=job_id,
            filename=filename,
            is_malicious=None,
            md5_hash=md5_hash,
            sha256_hash=sha256_hash,
            provider="VirusTotal",
            details=None,
            message=f"An unexpected error occurred: {e}",
            status="failed"
        ).model_dump()
    finally:
        if final_response_data:
            job_store[job_id] = final_response_data
        else:
            job_store[job_id] = FileScanResponse(
                job_id=job_id,
                filename=filename,
                is_malicious=None,
                md5_hash=None,
                sha256_hash=None,
                provider="System Error",
                details=None,
                message="An unhandled error occurred in background task.",
                status="failed"
            ).model_dump()


# Background task for IP Details and Malicious IP Detection
async def get_ip_details_and_reputation_background(
    job_id: str, # Added job_id
    ip_address: str,
    job_store: Dict[str, Any] # Added job_store
):
    """
    Fetches IP geolocation details from IPinfo.io and malicious reputation from AbuseIPDB.
    This runs in a background task and updates the job_store.
    """
    logger.info(f"Background task: Fetching details and reputation for IP: {ip_address} (Job ID: {job_id})")
    
    ip_details_data: Dict[str, Any] = {}
    abuseipdb_data: Dict[str, Any] = {}
    
    ip_address_obj: Union[IPv4Address, IPv6Address] = IPv4Address("0.0.0.0") # Initialize to a default value
    final_response_data: Dict[str, Any] = {}

    try:
        try:
            ip_address_obj = parse_ip_address(ip_address)
        except ValueError:
            logger.error(f"Invalid IP address format encountered: {ip_address}", exc_info=True)
            final_response_data = IPDetailsResponse(
                job_id=job_id,
                ip_address=IPv4Address("0.0.0.0"),
                country=None, region=None, city=None, isp=None, organization=None,
                latitude=None, longitude=None, is_malicious=None,
                threat_score=None, threat_types=None, malicious_provider=None,
                malicious_details=None, message="Invalid IP address format provided.",
                status="failed"
            ).model_dump()
            return

        # --- Fetch Geolocation Details from IPinfo.io ---
        ipinfo_api_key = cast(Settings, settings).IPAPI_API_KEY
        ipinfo_url = f"https://ipinfo.io/{ip_address}/json"
        if ipinfo_api_key:
            ipinfo_url += f"?token={ipinfo_api_key}"

        try:
            async with httpx.AsyncClient(timeout=DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS) as client:
                ipinfo_response = await client.get(ipinfo_url)
                ipinfo_response.raise_for_status()
                ip_details_data = ipinfo_response.json()
                logger.debug(f"IPinfo.io data for {ip_address}: {ip_details_data}")
        except httpx.HTTPStatusError as e:
            logger.error(f"IPinfo.io HTTP error for {ip_address}: {e.response.status_code} - {e.response.text}", exc_info=True)
            ip_details_data = {} # Clear if failed
        except httpx.TimeoutException:
            logger.error(f"IPinfo.io connection timed out for {ip_address}.", exc_info=True)
            ip_details_data = {}
        except Exception as e:
            logger.error(f"Unexpected error during IPinfo.io lookup for {ip_address}: {e}", exc_info=True)
            ip_details_data = {}

        # --- Fetch Malicious Reputation from AbuseIPDB ---
        abuseipdb_api_key = cast(Settings, settings).ABUSEIPDB_API_KEY
        if abuseipdb_api_key:
            abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": abuseipdb_api_key,
                "Accept": "application/json"
            }
            params = {
                "ipAddress": ip_address,
                "maxAgeInDays": 90
            }
            try:
                async with httpx.AsyncClient(timeout=DEFAULT_HTTP_REQUEST_TIMEOUT_SECONDS) as client:
                    abuseipdb_response = await client.get(abuseipdb_url, headers=headers, params=params)
                    abuseipdb_response.raise_for_status()
                    abuseipdb_data = abuseipdb_response.json().get("data", {})
                    logger.debug(f"AbuseIPDB data for {ip_address}: {abuseipdb_data}")
            except httpx.HTTPStatusError as e:
                logger.error(f"AbuseIPDB HTTP error for {ip_address}: {e.response.status_code} - {e.response.text}", exc_info=True)
                if e.response.status_code == 429:
                    logger.error(f"AbuseIPDB rate limit hit for {ip_address}. This suggests a rate limiter might be needed at a higher level.")
            except httpx.TimeoutException:
                logger.error(f"AbuseIPDB connection timed out for {ip_address}.", exc_info=True)
            except Exception as e:
                logger.error(f"Unexpected error during AbuseIPDB lookup for {ip_address}: {e}", exc_info=True)
        else:
            logger.warning("ABUSEIPDB_API_KEY is not set. Skipping malicious IP detection.")

        # --- Consolidate Results ---
        is_malicious = bool(abuseipdb_data.get("isPublic") and abuseipdb_data.get("abuseConfidenceScore", 0) > 0)
        threat_score = abuseipdb_data.get("abuseConfidenceScore")
        
        raw_reports = abuseipdb_data.get("reports", [])
        flat_threat_categories_ids = []
        for report in raw_reports:
            if "categories" in report and isinstance(report["categories"], list):
                flat_threat_categories_ids.extend(report["categories"])
        unique_category_ids = sorted(list(set(flat_threat_categories_ids)))
        
        mapped_threat_types = [ABUSEIPDB_CATEGORY_MAP.get(cat_id, f"Unknown Category ({cat_id})") for cat_id in unique_category_ids]

        response_message = "IP details and reputation fetched."
        if not ip_details_data and not abuseipdb_data:
            response_message = "Could not fetch IP details or reputation."
        elif not ip_details_data:
            response_message = "Could not fetch IP geolocation details (IPinfo.io failed)."
        elif not abuseipdb_data and abuseipdb_api_key:
            response_message = "Could not fetch malicious IP reputation (AbuseIPDB failed)."
        elif not abuseipdb_api_key:
            response_message = "Malicious IP detection skipped (AbuseIPDB API key missing)."
        else:
            pass

        # Parse latitude and longitude from IPinfo's 'loc' field
        latitude, longitude = None, None
        if ip_details_data.get("loc"):
            try:
                lat_str, lon_str = ip_details_data["loc"].split(',')
                latitude = float(lat_str)
                longitude = float(lon_str)
            except ValueError:
                logger.warning(f"Could not parse latitude/longitude from IPinfo.io 'loc': {ip_details_data['loc']}")

        final_response_data = IPDetailsResponse(
            job_id=job_id,
            ip_address=ip_address_obj,
            country=ip_details_data.get("country"),
            region=ip_details_data.get("region"), # IPinfo uses 'region' directly
            city=ip_details_data.get("city"),
            isp=ip_details_data.get("isp"),
            organization=ip_details_data.get("org"), # IPinfo uses 'org' directly
            latitude=latitude,
            longitude=longitude,
            is_malicious=is_malicious,
            threat_score=threat_score,
            threat_types=mapped_threat_types if mapped_threat_types else None,
            malicious_provider="AbuseIPDB" if abuseipdb_api_key else None,
            malicious_details=abuseipdb_data if abuseipdb_data else None,
            message=response_message,
            status="completed"
        ).model_dump()

    except Exception as e:
        logger.error(f"Unexpected error during IP details and reputation lookup for '{ip_address}' (Job ID: {job_id}): {e}", exc_info=True)
        final_response_data = IPDetailsResponse(
            job_id=job_id,
            ip_address=ip_address_obj,
            country=None, region=None, city=None, isp=None, organization=None,
            latitude=None, longitude=None, is_malicious=None,
            threat_score=None, threat_types=None, malicious_provider=None,
            malicious_details=None,
            message=f"An unexpected error occurred: {e}",
            status="failed"
        ).model_dump()
    finally:
        if final_response_data:
            job_store[job_id] = final_response_data
        else:
            # Fallback for truly unhandled cases, though previous blocks should catch most
            job_store[job_id] = IPDetailsResponse(
                job_id=job_id,
                ip_address=ip_address_obj,
                country=None, region=None, city=None, isp=None, organization=None,
                latitude=None, longitude=None, is_malicious=None,
                threat_score=None, threat_types=None, malicious_provider=None,
                malicious_details=None,
                message="An unhandled error occurred in background task.",
                status="failed"
            ).model_dump()
