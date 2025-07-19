# app/core/logging_config.py

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
import sys # Import sys for stdout/stderr handling

# Import settings to get configuration values like LOG_LEVEL, LOG_FILE_PATH, ENVIRONMENT
from app.config import settings

# Initialize logger for this module (used for internal logging_config messages)
logger = logging.getLogger(__name__)

def configure_logging():
    """
    Sets up the logging configuration for the application based on the environment.
    - In PROD/STAGE, logs are directed ONLY to stdout for containerized environments.
    - In DEV, logs go to both stdout and a rotating file.
    """
    # Clear existing handlers to prevent duplicate logs from previous configurations
    # This is important if configure_logging might be called multiple times.
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Determine the numeric log level from settings
    log_level = settings.LOG_LEVEL.upper()
    numeric_level = getattr(logging, log_level, None)
    if not isinstance(numeric_level, int):
        # Fallback to INFO if the configured level is invalid
        logger.warning(f"Invalid log level '{settings.LOG_LEVEL}' from settings. Defaulting to INFO.")
        numeric_level = logging.INFO

    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level) # Set the root logger level

    # Define a formatter
    formatter = logging.Formatter(settings.LOG_FORMAT)

    # --- 1. Console Handler (StreamHandler) ---
    # This is CRITICAL for Render and other containerized environments.
    # All logs must go to stdout/stderr for collection by the platform.
    console_handler = logging.StreamHandler(sys.stdout) # Explicitly direct to stdout
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    logger.info("Console logging to stdout configured.")

    # --- 2. File Handler (RotatingFileHandler) ---
    # Only enable file logging in the DEV environment,
    # or if you are specifically deploying to a VM with persistent storage
    # and managing logs locally.
    if settings.ENVIRONMENT == "DEV" and settings.LOG_FILE_PATH:
        try:
            # Ensure the log directory exists for file logging
            log_dir = settings.LOG_FILE_PATH.parent
            if not log_dir.exists():
                log_dir.mkdir(parents=True, exist_ok=True)
                logger.info(f"Created logging directory for file handler: {log_dir.absolute()}")

            # Rotates logs after a certain size (e.g., 5 MB) and keeps a few backup files.
            file_handler = RotatingFileHandler(
                filename=settings.LOG_FILE_PATH.resolve(), # Use resolve() for absolute path
                maxBytes=5 * 1024 * 1024, # 5 MB
                backupCount=5, # Keep 5 backup files
                encoding='utf-8'
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
            logger.info(f"File logging to '{settings.LOG_FILE_PATH.resolve()}' configured for DEV environment.")
        except Exception as e:
            # Catch any error during file handler setup, but don't crash the app.
            # Console logging is already active, so errors will still be seen.
            logger.error(f"Failed to configure file logging: {e}", exc_info=True)
            logger.warning("File logging could not be enabled. All logs will go to console.")
    elif settings.ENVIRONMENT in ("PROD", "STAGE") and settings.LOG_FILE_PATH:
        # If LOG_FILE_PATH is set in PROD/STAGE, issue a warning.
        logger.warning(f"LOG_FILE_PATH ('{settings.LOG_FILE_PATH}') is set in {settings.ENVIRONMENT} environment. "
                       "File logging inside containers is discouraged as logs are ephemeral. "
                       "Rely on stdout/stderr for centralized logging.")


    # --- Adjust log levels for common noisy libraries ---
    # These adjustments should be applied universally regardless of environment
    # to control verbosity from third-party libraries.
    logging.getLogger("uvicorn").setLevel(logging.INFO)
    logging.getLogger("uvicorn.access").setLevel(logging.INFO) # Keep Uvicorn access logs visible
    logging.getLogger("uvicorn.error").setLevel(logging.INFO) # Critical for debugging deployment issues

    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)

    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("jose").setLevel(logging.INFO) # Keep this to see token generation/decoding logs

    # Prevent loggers from sending messages multiple times up the hierarchy
    # if they have their own handlers (which is less common for simple setups).
    # For a root logger, this is typically `False` if you want it to be the final handler.
    # However, if you explicitly set up handlers for child loggers, you might set `propagate = False` on them.
    # For the root logger, you generally want it to handle all unhandled messages.
    # Your current setup where root_logger.propagate = False is generally fine
    # if you're adding all handlers to the root.
    # If root_logger.propagate were True, and you had a specific handler on a child logger,
    # the message might be duplicated by the root's handlers too.
    # For this setup, `root_logger.propagate = False` is suitable.

    logger.info("Overall logging configuration applied successfully.")