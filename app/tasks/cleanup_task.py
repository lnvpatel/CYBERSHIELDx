import os
import time
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

async def clean_old_processed_images(directory: Path, retention_hours: int = 24):
    """
    Deletes processed image files older than a specified retention period
    from the given directory.
    """
    logger.info(f"Starting cleanup of old processed images in {directory}...")
    cutoff_timestamp = time.time() - (retention_hours * 3600) # seconds
    deleted_count = 0
    for filepath in directory.iterdir():
        if filepath.is_file():
            try:
                # Check if the file's last modification time is older than the cutoff
                if filepath.stat().st_mtime < cutoff_timestamp:
                    os.remove(filepath)
                    logger.debug(f"Deleted old processed image: {filepath}")
                    deleted_count += 1
            except OSError as e:
                logger.error(f"Error deleting file {filepath}: {e}")
        else:
            logger.debug(f"Skipping non-file item in cleanup: {filepath}")
    logger.info(f"Cleanup finished. Deleted {deleted_count} old processed images.")