import logging
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from contextlib import asynccontextmanager
from sqlalchemy.sql import text
from sqlalchemy.orm import Session

# ✅ Import Routes
from app.routes import (
    netspeedtest, auth, phishing, steganography, virus_scan, 
    ip_detection, file_scan, admin, image_resizer
)
from app.security import get_current_user  # Ensure function is async or modified
from app.db import get_db
from app.services.log_service import log_event  # Logging for admin panel

# ✅ Configure Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ✅ Authentication Middleware
class AuthenticationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request.state.user = None  # Default to None if no authentication
        token = request.headers.get("Authorization")
        if token:
            try:
                user = await get_current_user(token)  # Ensure this is an async function
                request.state.user = user
            except Exception as e:
                logger.warning(f"⚠️ Authentication Failed: {e}")
        
        response = await call_next(request)
        return response

# ✅ Application Lifecycle Events
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("🛡️ CYBERSHIELDx has started.")
    yield
    logger.info("🛑 cYBERSHIELDx is shutting down.")

# ✅ Initialize FastAPI
app = FastAPI(title="CYBERSHIELDx", version="1.0.1", lifespan=lifespan)

# ✅ Middleware for Authentication
app.add_middleware(AuthenticationMiddleware)

# ✅ Security Middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])  # Set specific domain in production

# ✅ Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Change in production (e.g., ["https://yourfrontend.com"])
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ✅ Register Routes
app.include_router(admin.router, prefix="/admin", tags=["Admin"])  
app.include_router(auth.router, prefix="", tags=["Authentication"])
app.include_router(steganography.router, prefix="/steganography", tags=["Steganography"])
app.include_router(phishing.router, prefix="/phishing", tags=["Phishing Detection"])
app.include_router(image_resizer.router, prefix="/image", tags=["Image Resizer"])
app.include_router(virus_scan.router, prefix="/virus-scan", tags=["Virus Scan"])
app.include_router(ip_detection.router, prefix="/ip-detection", tags=["IP Detection"])
app.include_router(netspeedtest.router, prefix="/speedtest", tags=["Internet Speed Test"])
app.include_router(file_scan.router, prefix="/file-scan", tags=["File Scan"])

# ✅ Middleware: Log API requests & Admin Activity
@app.middleware("http")
async def log_requests(request: Request, call_next):
    logger.info(f"📩 Request: {request.method} {request.url}")

    response = await call_next(request)

    # ✅ Log admin activities
    try:
        user = request.state.user
        if user:
            log_event(
                event_type="INFO",
                message=f"{request.method} {request.url.path}",
                user=user.username,
                user_id=user.id
            )
    except Exception as e:
        logger.error(f"⚠️ Error logging activity: {e}")

    logger.info(f"📤 Response: {response.status_code}")
    return response

# ✅ Health Check Endpoint
@app.get("/")
def root(db: Session = Depends(get_db)):
    """
    Health check endpoint with database connection verification.
    """
    try:
        db.execute(text("SELECT 1"))
        logger.info("✅ Database Connection: Success")
        return {"message": "Backend Security API is running", "version": "1.0", "database": "Connected"}
    except Exception as e:
        logger.error(f"❌ Database Connection Error: {e}")
        return {"message": "Backend Security API is running", "version": "1.0", "database": "Connection Failed"}
