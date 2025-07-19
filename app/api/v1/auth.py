from datetime import datetime, date
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, status, HTTPException, Query, Form, UploadFile, File, Request, Body, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
import logging
from pathlib import Path
import os
from pydantic import BaseModel

from app.schemas.user import UserCreate, UserResponse
from app.schemas.auth import (
    TokenResponse,
    LoginRequest,
    ForgotPasswordStartRequest,
    ForgotPasswordConfirmRequest,
    ResetPasswordRequest,
    LogoutRequest,
    RefreshTokenRequest
)
from app.schemas.mfa import (
    MFAEnableRequest,
    MFADisableRequest,
    MFAStatusChangeConfirm,
    MFATOTPSetupInitiateResponse,
    MFATOTPSetupVerifyRequest,
    MFALoginVerifyRequest,
    MFAStatusResponse,
    MessageResponse
)
from app.infrastructure.database.session import get_db
from app.services.auth import auth_core_service, auth_user_service, auth_password_service
from app.dependencies.auth import get_current_user
from app.infrastructure.database.models import User
from app.services.session_service import logout_session
from app.services.mfa_service import MfaService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["Auth"])

# Calculate BASE_DIR for the project root consistently
# auth.py is at app/api/v1/auth.py, so it needs 4 .parent calls to reach the root
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
UPLOADS_DIR = BASE_DIR / "uploads"

# Ensure the uploads directory exists (main.py already does this, but safe to ensure)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
logger.info(f"Ensured uploads directory exists at: {UPLOADS_DIR}")

# --- Dependency for MfaService ---
# CORRECTED: Rearranged parameters so non-default comes before default
def get_mfa_service(
    background_tasks: BackgroundTasks, # <--- MOVED TO BE FIRST
    db: AsyncSession = Depends(get_db)
) -> MfaService:
    """
    Dependency that provides an MfaService instance,
    with BackgroundTasks already injected.
    """
    return MfaService(db, background_tasks)

# =========================
# Auth API Endpoints
# =========================

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register_user_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    first_name: Annotated[str, Form(max_length=50)],
    username: Annotated[str, Form(min_length=4, max_length=30)],
    email: Annotated[str, Form()],
    mobile_number: Annotated[str, Form(min_length=10, max_length=15)],
    dob: Annotated[str, Form()],
    password: Annotated[str, Form(min_length=8)],
    confirm_password: Annotated[str, Form()],
    last_name: Annotated[Optional[str], Form(max_length=50)] = None,
    photo: Optional[UploadFile] = File(None, description="Optional profile picture to upload."),
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user with all required details and an optional profile picture.
    The uploaded photo will be optimized (compressed, resized, converted to WebP) in the service layer.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    user_data = UserCreate(
        first_name=first_name,
        last_name=last_name,
        username=username,
        email=email,
        mobile_number=mobile_number,
        dob=datetime.strptime(dob, "%Y-%m-%d").date(),
        password=password,
        confirm_password=confirm_password,
        photo_url=None
    )

    new_user = await auth_user_service.register_user(
        db,
        user_data,
        background_tasks,
        ip_address,
        user_agent,
        photo=photo
    )
    return new_user

@router.post("/login", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def login_for_access_token(
    request: Request,
    background_tasks: BackgroundTasks,
    data: LoginRequest = Body(...),
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and return JWT tokens.
    Expects a JSON body with username_or_email and password.
    If MFA is enabled and required, returns a mfa_challenge_token and method.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    tokens = await auth_core_service.login_user(db, data, ip_address, user_agent, background_tasks)
    return tokens

@router.post("/mfa/verify", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def verify_mfa_login_challenge_endpoint(
    request: Request,
    mfa_data: MFALoginVerifyRequest = Body(...),
    db: AsyncSession = Depends(get_db)
):
    """
    Verifies the MFA OTP/TOTP code for a pending login challenge and issues final access/refresh tokens.
    Requires the mfa_challenge_token obtained from the initial /login request.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    logger.info(f"MFA login verification request received from {ip_address}")

    tokens = await auth_core_service.verify_mfa_login_challenge(
        db=db,
        data=mfa_data,
        ip_address=ip_address,
        user_agent=user_agent
    )
    return tokens


@router.post("/refresh", response_model=TokenResponse, status_code=status.HTTP_200_OK)
async def refresh_access_token_endpoint(
    request: Request,
    refresh_request: RefreshTokenRequest = Body(...),
    db: AsyncSession = Depends(get_db)
):
    """
    Obtain a new access token and a new refresh token using a valid refresh token.
    Implements refresh token rotation.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    logger.info(f"Refresh token request received from {ip_address}, User-Agent: {user_agent}")

    new_tokens = await auth_core_service.refresh_access_token(
        db=db,
        refresh_token=refresh_request.refresh_token,
        ip_address=ip_address,
        user_agent=user_agent
    )
    return new_tokens

@router.get("/verify-email", response_model=UserResponse)
async def verify_email_endpoint(
    request: Request,
    token: str = Query(..., description="Verification token received via email link"),
    db: AsyncSession = Depends(get_db)
):
    """
    Verifies user's email using a verification token.
    """
    logger.info(f"Received email verification request with token: {token[:10]}...")
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    verified_user = await auth_user_service.verify_email_token(db, token, ip_address, user_agent)
    logger.info(f"Email verified for user: {verified_user.username}")
    return verified_user

@router.post("/resend-verification", status_code=status.HTTP_200_OK, response_model=MessageResponse)
async def resend_verification_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    email: str = Query(..., description="Email address to resend verification to"),
    db: AsyncSession = Depends(get_db)
):
    """
    Resend email verification link to the provided email address.
    """
    logger.info(f"Resend verification request for email: {email}")
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    response = await auth_user_service.resend_verification_email(db, email, background_tasks, ip_address, user_agent)
    return response

@router.post("/forgot-password/start", status_code=status.HTTP_200_OK, response_model=MessageResponse)
async def forgot_password_start_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    request_data: ForgotPasswordStartRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Initiate the forgot password process.
    """
    logger.info(f"Forgot password start request for: {request_data.username_or_email}")
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    response = await auth_password_service.forgot_password_start(db, request_data.username_or_email, background_tasks, ip_address, user_agent)
    return response

@router.post("/forgot-password/confirm", status_code=status.HTTP_200_OK, response_model=MessageResponse)
async def forgot_password_confirm_endpoint(
    request: Request,
    background_tasks: BackgroundTasks,
    request_data: ForgotPasswordConfirmRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Confirm user email for password reset and send reset link.
    """
    logger.info(f"Forgot password confirm request for username: {request_data.username}, email: {request_data.email}")
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    response = await auth_password_service.confirm_user_email_for_reset(db, request_data.username, request_data.email, background_tasks, ip_address, user_agent)
    return response

@router.post("/reset-password", status_code=status.HTTP_200_OK, response_model=MessageResponse)
async def reset_password_endpoint(
    request: Request,
    request_data: ResetPasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Reset user's password using the provided token.
    """
    logger.info(f"Reset password request with token: {request_data.token[:10]}...")
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    response = await auth_password_service.reset_password(db, request_data.token, request_data.new_password, request_data.confirm_password, ip_address, user_agent)
    return response

@router.post("/logout", status_code=status.HTTP_200_OK, response_model=MessageResponse)
async def logout_endpoint(
    request: Request,
    current_user: User = Depends(get_current_user),
    logout_request: LogoutRequest = Body(...),
    db: AsyncSession = Depends(get_db)
):
    """
    Logs out a user's session by revoking the specified refresh token.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    await logout_session(
        db,
        token=logout_request.refresh_token,
        ip_address=ip_address,
        user_agent=user_agent
    )
    return {"message": "Logged out successfully."}


# =========================
# MFA Management Endpoints
# =========================

@router.post("/mfa/enable/initiate", response_model=MessageResponse, status_code=status.HTTP_200_OK)
async def initiate_mfa_enable_endpoint(
    request: Request,
    mfa_request: MFAEnableRequest = Body(...),
    current_user: User = Depends(get_current_user),
    mfa_service: MfaService = Depends(get_mfa_service)
):
    """
    Initiates the MFA enablement process for the authenticated user.
    Requires the user's current password for re-authentication.
    Sends an email with a verification link.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    logger.info(f"User {current_user.username} (ID: {current_user.id}) initiating MFA enable.")
    return await mfa_service.initiate_mfa_enable(current_user, mfa_request.current_password)

@router.post("/mfa/enable/confirm", response_model=MessageResponse, status_code=status.HTTP_200_OK)
async def confirm_mfa_enable_endpoint(
    request: Request,
    mfa_confirm: MFAStatusChangeConfirm = Body(...),
    current_user: User = Depends(get_current_user),
    mfa_service: MfaService = Depends(get_mfa_service)
):
    """
    Confirms the MFA enablement using the token received via email.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    logger.info(f"User {current_user.username} (ID: {current_user.id}) confirming MFA enable.")
    return await mfa_service.confirm_mfa_enable(current_user, mfa_confirm.token)

@router.post("/mfa/disable/initiate", response_model=MessageResponse, status_code=status.HTTP_200_OK)
async def initiate_mfa_disable_endpoint(
    request: Request,
    mfa_request: MFADisableRequest = Body(...),
    current_user: User = Depends(get_current_user),
    mfa_service: MfaService = Depends(get_mfa_service)
):
    """
    Initiates the MFA disablement process for the authenticated user.
    Requires the user's current password for re-authentication.
    Sends an email with a verification link.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    logger.info(f"User {current_user.username} (ID: {current_user.id}) initiating MFA disable.")
    return await mfa_service.initiate_mfa_disable(current_user, mfa_request.current_password)

@router.post("/mfa/disable/confirm", response_model=MessageResponse, status_code=status.HTTP_200_OK)
async def confirm_mfa_disable_endpoint(
    request: Request,
    mfa_confirm: MFAStatusChangeConfirm = Body(...),
    current_user: User = Depends(get_current_user),
    mfa_service: MfaService = Depends(get_mfa_service)
):
    """
    Confirms the MFA disablement using the token received via email.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    logger.info(f"User {current_user.username} (ID: {current_user.id}) confirming MFA disable.")
    return await mfa_service.confirm_mfa_disable(current_user, mfa_confirm.token)

@router.post("/mfa/totp/setup/initiate", response_model=MFATOTPSetupInitiateResponse, status_code=status.HTTP_200_OK)
async def initiate_totp_setup_endpoint(
    request: Request,
    current_user: User = Depends(get_current_user),
    mfa_service: MfaService = Depends(get_mfa_service)
):
    """
    Initiates TOTP (Authenticator App) setup for the authenticated user.
    Returns the TOTP secret and provisioning URI (for QR code).
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    logger.info(f"User {current_user.username} (ID: {current_user.id}) initiating TOTP setup.")
    return await mfa_service.initiate_totp_setup(current_user)

@router.post("/mfa/totp/setup/verify", response_model=MessageResponse, status_code=status.HTTP_200_OK)
async def verify_totp_setup_endpoint(
    request: Request,
    mfa_verify: MFATOTPSetupVerifyRequest = Body(...),
    current_user: User = Depends(get_current_user),
    mfa_service: MfaService = Depends(get_mfa_service)
):
    """
    Verifies the TOTP code provided by the user during the initial TOTP setup.
    If successful, marks TOTP as verified for the user.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    logger.info(f"User {current_user.username} (ID: {current_user.id}) verifying TOTP setup.")
    return await mfa_service.verify_totp_setup(current_user, mfa_verify.otp_code)

@router.get("/mfa/status", response_model=MFAStatusResponse, status_code=status.HTTP_200_OK)
async def get_mfa_status_endpoint(
    request: Request,
    current_user: User = Depends(get_current_user),
    mfa_service: MfaService = Depends(get_mfa_service)
):
    """
    Retrieves the current MFA status for the authenticated user.
    """
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    logger.info(f"User {current_user.username} (ID: {current_user.id}) requesting MFA status.")
    return mfa_service.get_mfa_status(current_user)