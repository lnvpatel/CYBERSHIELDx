import subprocess
import logging

# ✅ Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

def scan_file(file_path: str) -> dict:
    """
    Scans a file using ClamAV and returns scan results.
    """
    try:
        # ✅ Run ClamAV scan
        result = subprocess.run(["clamscan", "--no-summary", file_path], capture_output=True, text=True)

        if result.returncode == 0:
            logger.info(f"File scan completed: {file_path} is clean.")
            return {"infected": False, "reason": "No threats detected"}

        elif result.returncode == 1:
            logger.warning(f"Virus detected in {file_path}: {result.stdout}")
            return {"infected": True, "reason": result.stdout.strip()}

        else:
            logger.error(f"ClamAV scan failed for {file_path}: {result.stderr}")
            return {"infected": None, "reason": f"Scan failed: {result.stderr.strip()}"}

    except Exception as e:
        logger.error(f"Error scanning file {file_path}: {str(e)}")
        return {"infected": None, "reason": f"Internal error: {str(e)}"}
