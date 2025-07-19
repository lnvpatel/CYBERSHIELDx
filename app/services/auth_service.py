# app/services/auth_service.py
# This file acts as a facade or an entry point for auth-related services.

# Import functions from auth_core_service
from app.services.auth.auth_core_service import (
    login_user,
    refresh_access_token
)

# Import functions from auth_user_service
from app.services.auth.auth_user_service import (
    register_user,
    verify_email_token,
    resend_verification_email
)

from app.services.auth.auth_password_service import(
    forgot_password_start,
    confirm_user_email_for_reset,
    reset_password
    
)
# You can optionally define __all__ if you want to explicitly control
# what gets imported when someone does `from .auth_service import *`
# For `import app.services.auth_service as auth_service`, this isn't strictly necessary,
# but it's good practice for clarity.
__all__ = [
    "login_user",
    "refresh_access_token",
    "forgot_password_start",
    "confirm_user_email_for_reset",
    "reset_password",
    "register_user",
    "verify_email_token",
    "resend_verification_email"
]

# Note: No direct implementation logic should typically be here.
# This file's purpose is to orchestrate and provide a unified interface
# to the underlying, specialized service modules.