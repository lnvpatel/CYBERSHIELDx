import logging
from datetime import datetime, timezone
from typing import Optional

# Configure Logging
LOG_FILE = "security.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ],
)

logger = logging.getLogger(__name__)

def log_event(event_type: str, message: str, user: Optional[str] = "System", user_id: Optional[str] = None):
    """
    Logs security-related events.
    """
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    log_message = f"[{timestamp}] {event_type.upper()} - {user}{f' (ID: {user_id})' if user_id else ''}: {message}"

    event_type = event_type.upper()
    if event_type == "INFO":
        logger.info(log_message)
    elif event_type == "WARNING":
        logger.warning(log_message)
    elif event_type == "ERROR":
        logger.error(log_message)
    else:
        logger.debug(log_message)

# Example Usage
if __name__ == "__main__":
    log_event("INFO", "System initialized", "Admin", "12345")
    log_event("WARNING", "Suspicious login attempt detected", "User123", "67890")
    log_event("ERROR", "Failed to process virus scan", "Scanner")
