from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import os

# Ensure .env file is loaded
load_dotenv()

class Settings(BaseSettings):
    """Configuration settings for the FastAPI Security Backend."""
    
    # General App Settings
    APP_NAME: str 
    VERSION: str 
    BACKEND_URL: str  # Base URL for the backend

    # Database Configuration (Loaded from .env)
    DATABASE_URL: str  # Must be set in .env

    # Security & Authentication
    SECRET_KEY: str  # Must be set in .env
    ALGORITHM: str 
    ACCESS_TOKEN_EXPIRE_MINUTES: int  # 1-hour token expiration

    # Admin Logging & Monitoring
    ENABLE_ADMIN_LOGS: bool = True  # Toggle logging of admin actions
    LOG_FILE_PATH: str = "./logs/activity.log"  # Log file path

    # SMTP Configuration
    SMTP_SERVER: str  # Must be set in .env
    SMTP_PORT: int  # Must be set in .env
    SMTP_USERNAME: str = None # Must be set in .env
    SMTP_PASSWORD: str = None  # Must be set in .env
    EMAIL_FROM: str  # Must be set in .env
    SMTP_USE_TLS: bool
    SMTP_USE_SSL: bool

    # ✅ Use model_config instead of Config (Pydantic v2 fix)
    model_config = {
        "env_file": ".env",  # Load environment variables from .env file
        "env_file_encoding": "utf-8",
    }

# Load settings
settings = Settings()

# Debugging: Print if EMAIL_FROM is loaded
print(f"EMAIL_FROM: {settings.EMAIL_FROM}")
