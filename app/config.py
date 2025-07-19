# app/config.py
import os
import secrets
import json
import logging
import sys # For sys.exit() on critical errors
from pathlib import Path
from typing import Optional, Literal, List
from datetime import timedelta

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

# --- Conditional loading of .env for local development ONLY ---
# In Render (and other production environments), environment variables should
# be set directly in the Render dashboard or via a render.yaml blueprint.
# This prevents accidentally loading a .env file from the repository that
# might contain sensitive data or override production settings.
if os.getenv("ENVIRONMENT") not in ("PROD", "STAGE"): # Be explicit about when to load .env
    load_dotenv()
    print("DEVELOPMENT: .env file loaded for local environment.")
else:
    print(f"{os.getenv('ENVIRONMENT', 'UNKNOWN')}: .env file skipped. Relying on system environment variables.")


# --- Configure basic logging early to capture configuration errors ---
# For Render, all application logs should go to stdout/stderr.
# Render's infrastructure collects these logs.
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(), # Default to INFO, but allow override
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Helper for generating strong secret keys (for development/initial setup) ---
def generate_strong_secret_key(length: int = 64) -> str:
    """Generates a URL-safe text string, suitable for SECRET_KEY."""
    return secrets.token_urlsafe(length)

class Settings(BaseSettings):
    """
    FastAPI Security Backend Configuration using pydantic-settings.
    Automatically loads from environment variables (and .env in non-PROD/STAGE).
    All non-Optional fields *must* be present as environment variables.
    """

    # ========================
    # APP CORE CONFIGURATION
    # ========================
    APP_NAME: str = "CYBERSHIELDx API"
    VERSION: str = "1.0.1"
    # ENVIRONMENT MUST be explicitly defined in Render dashboard (e.g., "PROD").
    ENVIRONMENT: Literal["DEV", "STAGE", "PROD"] = "DEV" # Default for local safety
    BACKEND_URL: str
    FRONTEND_URL: str
    DEBUG: bool = True
    # Render automatically sets PORT for Web Services
    PORT: int = 8000

    # ========================
    # SECURITY CONFIGURATION
    # ========================
    # CRITICAL: This MUST be set as an environment variable in Render.
    # No default value here to force explicit setting in ALL environments,
    # preventing accidental use of a weak or generated key in production.
    SECRET_KEY: str # Required. Generate via `secrets.token_urlsafe(64)` for production.
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    REMEMBER_ME_REFRESH_TOKEN_EXPIRE_DAYS: int = 15
    PASSWORD_RESET_TIMEOUT: int = 600
    # Number of previous passwords to disallow
    PASSWORD_HISTORY_COUNT: int = 3

    # Security Policy Settings
    MIN_PASSWORD_LENGTH: int = 8
    PASSWORD_HISTORY_CHECK_COUNT: int = 5
    ACCOUNT_LOCKOUT_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_DURATION_MINUTES: int = 30
    REQUIRE_EMAIL_VERIFICATION: bool = True
    API_RATE_LIMIT_PER_MINUTE: int = 100

    # OTP settings
    OTP_LENGTH: int = 6
    OTP_EXPIRATION_MINUTES: int = 5

    # TOTP settings (if used)
    TOTP_PERIOD: int = 30
    TOTP_DIGITS: int = 6

    # MFA Settings
    MFA_OTP_EXPIRE_MINUTES: int = 5
    MFA_OTP_LENGTH: int = 6
    MFA_CHALLENGE_TOKEN_EXPIRE_MINUTES: int = 5
    MFA_EMAIL_TOKEN_EXPIRE_MINUTES: int = 15

    # Registration codes (optional)
    ADMIN_REGISTRATION_CODE: Optional[str] = None
    USER_REGISTRATION_CODE: Optional[str] = None

    PASSWORD_REGEX: str = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};:'\",.<>\/?`~]).{8,}$"

    # ========================
    # DATABASE CONFIGURATION
    # ========================
    # CRITICAL: Render automatically sets DATABASE_URL for connected Postgres instances.
    # This variable MUST be provided by the environment (e.g., Render dashboard).
    DATABASE_URL: str # No default, required for database connection.
    DB_POOL_SIZE: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 3600 # Seconds

    # ✅ SSL/TLS Configuration for Database Connection
    # These paths should point to your certificate files.
    # Set these as environment variables in production.
    DB_SSL_CA_CERT: Optional[str] = None        # Path to your CA certificate (e.g., "/etc/ssl/certs/ca-certificates.crt")
    DB_SSL_CLIENT_CERT: Optional[str] = None    # Path to your client certificate (if client authentication is needed)
    DB_SSL_CLIENT_KEY: Optional[str] = None     # Path to your client private key (if client authentication is needed)
    DB_SSL_MODE: str = "require"                # For PostgreSQL: "disable", "allow", "prefer", "require", "verify-ca", "verify-full"
                                                # Use "require" or "verify-ca"/"verify-full" for secure connections.


    # ========================
    # EMAIL SERVICE CONFIG
    # ========================
    # CRITICAL: These must be set for email functionality in PROD on Render.
    MAIL_SERVER: str
    MAIL_PORT: int = 587
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_TLS: bool = True
    MAIL_SSL: bool = False
    USE_CREDENTIALS: bool = True
    VALIDATE_CERTS: bool = True
    EMAIL_VERIFICATION_TIMEOUT: int = 60 # Seconds
    EMAIL_TEMPLATE_DIR: Path = Path(__file__).parent / "templates" / "emails"

    # ========================
    # LOGGING CONFIGURATION
    # Render collects stdout/stderr, so file logging is generally not needed.
    # LOG_LEVEL is read by basicConfig call at the top.
    # You could keep it as Optional[Path] for local dev, but ensure it's None in PROD.
    LOG_LEVEL: str = "INFO" # Default to INFO, but allow override via env var
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_FILE_PATH: Optional[Path] = None # Recommended to be None in Prod for stdout logging
    CLEANUP_INTERVAL_SECONDS: int = 3600 # 1 hour
    CLEANUP_RETENTION_HOURS: int = 24   # 24 hours
    ENABLE_ADMIN_LOGS: bool = True

    # ========================
    # FEATURE FLAGS
    # ========================
    REQUIRE_ADMIN_APPROVAL: bool = False
    ENABLE_RATE_LIMITING: bool = True

    # ========================
    # CORS ORIGINS
    # Set as a JSON array string in Render environment variables:
    # CORS_ORIGINS='["https://your-frontend.com", "https://*.your-frontend.com"]'
    CORS_ORIGINS: List[str]

    # ========================
    # SECURITY TOOLS API KEYS
    # Set as environment variables in Render.
    VIRUSTOTAL_API_KEY: Optional[str] = None
    ABUSEIPDB_API_KEY: Optional[str] = None
    IPAPI_API_KEY: Optional[str] = None

    # ========================
    # PYDANTIC SETTINGS CONFIG
    # ========================
    model_config = SettingsConfigDict(
        env_file=".env",              # Only loaded if ENVIRONMENT is not PROD/STAGE
        env_file_encoding="utf-8",
        extra="ignore",               # Allows extra fields in .env without raising error
        case_sensitive=True,          # Environment variable names are case-sensitive
    )

    def __init__(self, **values):
        super().__init__(**values)
        # Re-added logic to append sslmode to DATABASE_URL if it's a postgresql+asyncpg URL
        # and sslmode is not already present. This is the most reliable way for asyncpg.
        if "postgresql+asyncpg" in self.DATABASE_URL and "sslmode=" not in self.DATABASE_URL:
            separator = "&" if "?" in self.DATABASE_URL else "?"
            self.DATABASE_URL = f"{self.DATABASE_URL}{separator}sslmode={self.DB_SSL_MODE}"
            logger.info(f"Appended sslmode={self.DB_SSL_MODE} to DATABASE_URL: {self.DATABASE_URL}")

        self._validate_runtime_settings()
        # No need for _ensure_log_directory if logging to stdout/stderr
        # The logging configuration is already handled by basicConfig at the module level.

    def _validate_runtime_settings(self):
        """
        Custom validation and critical checks specifically for Render environments.
        These are enforced based on the `ENVIRONMENT` setting.
        """
        if self.ENVIRONMENT == "PROD":
            logger.info("Running in PRODUCTION environment on Render. Applying production specific validations.")

            if self.DEBUG:
                logger.critical("PRODUCTION ERROR: DEBUG is True in PROD environment. This is a severe security risk!")
                raise ValueError("DEBUG must be False in production.")

            if not self.SECRET_KEY or len(self.SECRET_KEY) < 32:
                logger.critical("PRODUCTION ERROR: SECRET_KEY is missing or too short. Must be a strong, unique value (min 32 chars) in production.")
                raise ValueError("SECRET_KEY must be a strong, unique value in production.")

            # Email Configuration Validation
            if not self.MAIL_SERVER or not self.MAIL_USERNAME or not self.MAIL_PASSWORD or not self.MAIL_FROM:
                logger.critical("PRODUCTION ERROR: Essential SMTP credentials (MAIL_SERVER, MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM) are not fully set. Email sending will fail.")
                raise ValueError("All essential MAIL_* settings must be configured in production.")
            if self.REQUIRE_EMAIL_VERIFICATION and (not self.MAIL_USERNAME or not self.MAIL_PASSWORD):
                logger.critical("PRODUCTION ERROR: REQUIRE_EMAIL_VERIFICATION is True, but MAIL_USERNAME or MAIL_PASSWORD are not set. Email verification will fail.")
                raise ValueError("Email credentials must be set if email verification is required.")

            # CORS Origins Validation
            if not self.CORS_ORIGINS:
                logger.critical("PRODUCTION ERROR: CORS_ORIGINS is empty. No frontend will be able to connect.")
                raise ValueError("CORS_ORIGINS must be configured with allowed origins in production.")
            if "*" in self.CORS_ORIGINS:
                logger.critical("PRODUCTION ERROR: CORS_ORIGINS cannot contain '*' in production. Please specify explicit origins.")
                raise ValueError("CORS_ORIGINS cannot be '*' in production.")

            # URL Protocol Validation (HTTPS enforcement for Render's default domains or custom domains)
            if not self.BACKEND_URL.startswith("https://"):
                logger.critical(f"PRODUCTION ERROR: BACKEND_URL '{self.BACKEND_URL}' must use HTTPS in production.")
                raise ValueError("BACKEND_URL must use HTTPS in production.")
            if not self.FRONTEND_URL.startswith("https://"):
                logger.critical(f"PRODUCTION ERROR: FRONTEND_URL '{self.FRONTEND_URL}' must use HTTPS in production.")
                raise ValueError("FRONTEND_URL must use HTTPS in production.")

            # API Key Warnings (as these might enable optional features)
            if not self.VIRUSTOTAL_API_KEY:
                logger.warning("PRODUCTION WARNING: VIRUSTOTAL_API_KEY is not set. VirusTotal features will be limited or unavailable.")
            if not self.ABUSEIPDB_API_KEY:
                logger.warning("PRODUCTION WARNING: ABUSEIPDB_API_KEY is not set. Malicious IP detection will be limited or unavailable.")
            if not self.IPAPI_API_KEY:
                logger.warning("PRODUCTION WARNING: IPAPI_API_KEY is not set. IP geo-location features will be limited or unavailable.")

            # Registration Code Warnings (if you set them in Render and don't intend to use them)
            if self.ADMIN_REGISTRATION_CODE:
                logger.warning("PRODUCTION WARNING: ADMIN_REGISTRATION_CODE is set. Ensure this is a secure, unique code and rotate if necessary. Set to None if not needed.")
            if self.USER_REGISTRATION_CODE:
                 logger.warning("PRODUCTION WARNING: USER_REGISTRATION_CODE is set. Ensure this is a secure, unique code. Consider setting to None if open registration is allowed.")

        # Ensure DATABASE_URL is set in any environment where a DB is expected
        if not self.DATABASE_URL:
            logger.critical("CRITICAL ERROR: DATABASE_URL is not set. Database connection will fail.")
            raise ValueError("DATABASE_URL must be set in environment variables.")

# --- Initialize settings with validation ---
try:
    settings = Settings()
    logger.info(f"✅ Configuration loaded successfully for {settings.ENVIRONMENT} environment.")

    # Critical check: If in PROD and DEBUG is still True after loading
    if settings.ENVIRONMENT == "PROD" and settings.DEBUG:
        logger.critical("FATAL: DEBUG is True in PRODUCTION. Exiting due to severe security misconfiguration.")
        sys.exit(1) # Exit immediately on critical misconfiguration

except Exception as e:
    logger.critical(f"❌ Critical Configuration Error: {e}")
    sys.exit(1) # Exit immediately on critical configuration error
