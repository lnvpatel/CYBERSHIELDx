# app/main.py

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, Response, status, Depends
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware import Middleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text # For database health check
import logging
from pathlib import Path
import sys
import asyncio
import time
import os # For os.getenv('PORT')
import uvicorn # Added: Import uvicorn for local development run

# --- Base Directory: Points to the project root (e.g., 'cybershieldx') ---
# This assumes 'app' is a direct child of the project root.
BASE_DIR = Path(__file__).resolve().parent.parent

# --- Add BASE_DIR to sys.path: Essential for imports from project root ---
# This ensures that 'from app.config import settings' works correctly
# regardless of the current working directory from which the app is launched.
sys.path.insert(0, str(BASE_DIR))

# --- Import settings first: Configuration is paramount ---
from app.config import settings

# --- Configure logging early: Use the dedicated logging_config module ---
# This should be called before other modules are imported that might log immediately.
from app.core.logging_config import configure_logging
configure_logging() # Call once at module level startup

# Global logger for this module after configuration
logger = logging.getLogger(settings.APP_NAME) # Use app name for consistency

# --- Directory Paths & Creation (Critical for file operations) ---
# Ensure these are relative to BASE_DIR if they are meant to be in the project root.
# For Render, these directories will be ephemeral unless using a mounted disk.
# For static files, often a separate CDN or S3 bucket is used in production.
# For simple cases, Render's ephemeral disk is fine for /uploads and /processed_images
# but understand they reset on container restart/redeploy.
UPLOADS_DIR = BASE_DIR / "uploads"
PROCESSED_IMAGES_DIR = BASE_DIR / "processed_images"

try:
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Ensured uploads directory exists at: {UPLOADS_DIR.absolute()}")
    PROCESSED_IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    logger.info(f"Ensured processed_images directory exists at: {PROCESSED_IMAGES_DIR.absolute()}")
except OSError as e:
    logger.critical(f"Failed to create critical directories: {e}. Exiting.", exc_info=True)
    sys.exit(1) # Critical failure, cannot proceed without these.

# --- Custom Security Headers Middleware ---
# This is a good manual implementation. For CSP, tailor carefully!
class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            async def send_wrapper(message):
                if message["type"] == "http.response.start":
                    headers = message["headers"]
                    headers_list = list(headers)

                    # Standard Security Headers
                    headers_list.append((b"x-content-type-options", b"nosniff"))
                    headers_list.append((b"x-frame-options", b"DENY"))
                    headers_list.append((b"x-xss-protection", b"1; mode=block"))
                    headers_list.append((b"referrer-policy", b"no-referrer-when-downgrade"))

                    # HSTS: Only apply if in PROD and using HTTPS
                    # Render provides HTTPS automatically. This is good for "trust on first use".
                    if settings.ENVIRONMENT == "PROD":
                        # max-age=31536000 (1 year); includeSubDomains (for subdomains); preload (for HSTS Preload List)
                        # Be EXTREMELY careful with 'preload'. Only add after thorough testing and
                        # if you are certain all subdomains will ALWAYS be HTTPS.
                        headers_list.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                        # If you intend to apply for HSTS preload, uncomment below:
                        # headers_list.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains; preload"))


                    # Content-Security-Policy (CSP): CRITICAL for production.
                    # This is highly application-specific and needs CAREFUL tailoring.
                    # A basic, self-only CSP. ADJUST THIS BASED ON YOUR EXTERNAL ASSETS (CDNs, fonts, analytics etc.)
                    # Example: Only self-hosted scripts/styles/images, no external iframes, forms only to self
                    # 'self' refers to your application's origin.
                    # data: is for data URIs (e.g., base64 encoded images).
                    # 'unsafe-inline' and 'unsafe-eval' should be avoided if possible.
                    csp_policy = (
                        "default-src 'self';"
                        "script-src 'self';" # Add specific domains if you use external scripts (e.g., Google Analytics)
                        "style-src 'self';"  # Add specific domains if you use external stylesheets (e.g., Google Fonts, Bootstrap CDN)
                        "img-src 'self' data:;" # Add specific domains if you load images from CDNs
                        "connect-src 'self';" # Add specific domains if your JS makes XHR/fetch requests to other APIs
                        "font-src 'self';" # Add specific domains for external fonts (e.g., fonts.gstatic.com for Google Fonts)
                        "object-src 'none';" # Disallow <object>, <embed>, <applet>
                        "media-src 'self';" # For <audio>, <video>
                        "frame-ancestors 'none';" # Prevent clickjacking by disallowing embedding in iframes
                        "form-action 'self';" # Restrict where forms can submit data
                        # Add 'report-uri /csp-report-endpoint;' if you want to collect CSP violation reports.
                    )
                    headers_list.append((b"content-security-policy", csp_policy.encode('latin-1'))) # Use latin-1 for header values

                    message["headers"] = headers_list
                await send(message)
            await self.app(scope, receive, send_wrapper)
        else:
            await self.app(scope, receive, send)

# --- Import remaining modules after settings and initial setup ---
from app.infrastructure.database.session import async_engine, get_db
from app.infrastructure.database.base import Base # For metadata.create_all
from app.api.v1 import auth, admin, profile, activity
from app.api.features import image_processing, security_tools, stegano
from app.core.exceptions import APIException
from app.tasks.cleanup_task import clean_old_processed_images

# --- Helper to run the cleanup task periodically ---
async def _run_cleanup_periodically(directory: Path, retention_hours: int, interval_seconds: int):
    """
    Runs the image cleanup task at regular intervals.
    Logs if the task encounters an error to prevent the scheduler from silently failing.
    """
    logger.info(f"Scheduler started: cleanup task for {directory} will run every {interval_seconds / 3600:.1f} hours, retaining files for {retention_hours} hours.")
    while True:
        try:
            await clean_old_processed_images(directory, retention_hours)
            logger.debug(f"Cleanup task for {directory} completed successfully.")
        except Exception as e:
            logger.error(f"Error during cleanup task for {directory}: {e}", exc_info=True)
        await asyncio.sleep(interval_seconds)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Context manager for application startup and shutdown events.
    Handles database table creation on startup in DEV environment,
    and schedules the periodic image cleanup task.
    """
    # Logging is already configured at module level, so no need to reconfigure here.
    logger.info(f"🚀 {settings.APP_NAME} starting up in {settings.ENVIRONMENT} mode...")
    logger.info(f"Backend URL: {settings.BACKEND_URL}, Frontend URL: {settings.FRONTEND_URL}")

    # Database table creation (DEV only via code; production uses Alembic migrations)
    if settings.ENVIRONMENT == "DEV":
        logger.info("ENVIRONMENT is DEV: Attempting to create database tables...")
        try:
            async with async_engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database tables created successfully for DEV environment (if not already existing).")
        except Exception as e:
            logger.critical(f"Failed to create database tables in DEV environment: {e}", exc_info=True)
            # In production, this would be a fatal error (handled by outer try/except).
            # In dev, you might allow it to continue if tables exist.
            pass # Allow dev to proceed even if table creation errors if they already exist
    else:
        logger.info("Database table creation skipped for non-DEV environment. Use Alembic for migrations.")

    # Schedule the cleanup task.
    # Run in PROD/STAGE, or if DEBUG is True in DEV for testing.
    # Ensure CLEANUP_INTERVAL_SECONDS and CLEANUP_RETENTION_HOURS are in settings.
    cleanup_task_interval = getattr(settings, 'CLEANUP_INTERVAL_SECONDS', 3600) # Default to 1 hour
    cleanup_retention_hours = getattr(settings, 'CLEANUP_RETENTION_HOURS', 24) # Default to 24 hours

    if settings.ENVIRONMENT in ("PROD", "STAGE") or (settings.ENVIRONMENT == "DEV" and settings.DEBUG):
        asyncio.create_task(
            _run_cleanup_periodically(
                PROCESSED_IMAGES_DIR,
                retention_hours=cleanup_retention_hours,
                interval_seconds=cleanup_task_interval
            )
        )
        logger.info(f"Scheduled periodic image cleanup task for {PROCESSED_IMAGES_DIR}.")
        logger.info(f"  Cleanup interval: {cleanup_task_interval / 3600:.1f} hours. Retention: {cleanup_retention_hours} hours.")
    else:
        logger.info("Image cleanup task not scheduled (only runs in PROD/STAGE or if DEBUG is True in DEV).")

    yield # Application runs, serving requests

    logger.info(f"👋 {settings.APP_NAME} shutting down...")
    # Close database connections on shutdown
    try:
        await async_engine.dispose()
        logger.info("Database connections closed gracefully.")
    except Exception as e:
        logger.error(f"Error closing database connections during shutdown: {e}", exc_info=True)


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    debug=settings.DEBUG, # FastAPI's debug mode, should be False in PROD
    # Wrap lifespan in a lambda to help Pylance with type inference
    lifespan=lambda app_instance: lifespan(app_instance),
    middleware=[
        Middleware(SecurityHeadersMiddleware) # Custom security headers
    ]
)

# Configure CORS
# In production, settings.CORS_ORIGINS must contain specific frontend domains (HTTPS).
# It's a List[str] from config.py.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"], # Be explicit
    allow_headers=["*"], # Fine for now, but can be narrowed (e.g., Content-Type, Authorization)
)

# Add GZIP Compression Middleware
# This helps reduce bandwidth for text-based responses (JSON, HTML).
app.add_middleware(GZipMiddleware, minimum_size=1000) # Only compress responses > 1KB

# Mount static files directories
# For Render, these directories are inside the container's ephemeral filesystem.
# This is fine for relatively small, generated files. For large or persistent assets,
# consider Render's Disk service (mounted volume) or an external CDN/cloud storage.
logger.info(f"Mounting static files from directory: {UPLOADS_DIR.absolute()} at /uploads")
app.mount("/uploads", StaticFiles(directory=UPLOADS_DIR), name="uploads")

logger.info(f"Mounting processed_images static files from directory: {PROCESSED_IMAGES_DIR.absolute()} at /processed_images")
app.mount("/processed_images", StaticFiles(directory=PROCESSED_IMAGES_DIR), name="processed_images")


# Root endpoint
@app.get("/", summary="Welcome message", tags=["Root"])
async def read_root():
    return {"message": f"Welcome to {settings.APP_NAME} v{settings.VERSION}!", "environment": settings.ENVIRONMENT}

# Health Check Endpoint
@app.get("/health", summary="Health check endpoint", tags=["Monitoring"])
async def health_check(db_session: AsyncSession = Depends(get_db)): # Add DB dependency
    """
    Comprehensive health check endpoint.
    Checks application status and database connectivity.
    """
    db_status = "error"
    try:
        # Attempt a simple query to check database connectivity
        await db_session.execute(text("SELECT 1"))
        db_status = "ok"
    except Exception as e:
        logger.error(f"Database health check failed: {e}", exc_info=False) # Don't log full traceback for every health check failure
        db_status = "error"

    return JSONResponse(
        status_code=status.HTTP_200_OK if db_status == "ok" else status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "status": "ok" if db_status == "ok" else "degraded",
            "version": settings.VERSION,
            "environment": settings.ENVIRONMENT,
            "database_status": db_status
        }
    )

# Include API routers
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(profile.router)
app.include_router(activity.router)
app.include_router(image_processing.router)
app.include_router(security_tools.router)
app.include_router(stegano.router)


# Global exception handlers
@app.exception_handler(APIException)
async def api_exception_handler(request: Request, exc: APIException):
    logger.error(f"API Exception caught: {exc.name} - {exc.message}", exc_info=True)
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # In production, do NOT expose raw validation error details to the client.
    # Log full details internally, return a generic message externally.
    if settings.DEBUG: # Only expose full details in debug mode
        logger.error(f"Validation Error (DEBUG mode): {exc.errors()}, Body: {exc.body}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "Validation error", "errors": exc.errors(), "body": exc.body}
        )
    else:
        logger.error(f"Validation Error: {exc.errors()}", exc_info=False) # Log errors but not body to avoid sensitive info
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "Invalid input provided. Please check your request."}
        )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    # CRITICAL: In production, do NOT expose raw exception details.
    # Always log the full traceback internally.
    logger.critical(f"Unhandled Exception: {exc}", exc_info=True)
    if settings.DEBUG:
        # Only for debugging, expose more details.
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": f"An unexpected error occurred: {type(exc).__name__} - {str(exc)}"}
        )
    else:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An unexpected server error occurred. Please try again later."}
        )

# --- Run Application Block (ONLY for local development, NOT for Render production) ---
if __name__ == "__main__":
    # This block is executed when you run `python app/main.py` locally.
    # In production on Render, your `Procfile` (e.g., `web: uvicorn app.main:app --host 0.0.0.0 --port $PORT`)
    # or `render.yaml` will handle the application startup using Uvicorn or Gunicorn.

    # Re-verify logging configuration for local run
    configure_logging()
    logger = logging.getLogger(settings.APP_NAME) # Ensure logger picks up new config

    logger.info("--- Running FastAPI application in local development mode ---")
    logger.info(f"App Name: {settings.APP_NAME}, Version: {settings.VERSION}")
    logger.info(f"Environment: {settings.ENVIRONMENT}, Debug Mode: {settings.DEBUG}")
    logger.info(f"Listening on http://0.0.0.0:{settings.PORT}")

    # For local development, use settings.PORT and settings.DEBUG for reload.
    # Render will inject its own $PORT variable, which Uvicorn respects automatically.
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.PORT, # Use port from settings
        reload=settings.DEBUG, # Only reload in debug mode
        log_level=settings.LOG_LEVEL.lower(), # Use the configured log level
    )
