# app/core/email_utils.py

import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Literal, Dict, Any, Optional
import logging
from starlette.concurrency import run_in_threadpool
from datetime import datetime # Import datetime for Jinja2 global
from jinja2 import Environment, FileSystemLoader, select_autoescape # NEW: Import Jinja2 components

from app.config import settings # Ensure settings is imported and contains EMAIL_TEMPLATE_DIR, SMTP_ details, etc.

# Initialize logger for this module
logger = logging.getLogger(__name__)

# =========================
# Jinja2 Template Setup
# =========================
# Ensure settings.EMAIL_TEMPLATE_DIR points to the directory containing your email HTML templates
template_env = Environment(
    loader=FileSystemLoader(settings.EMAIL_TEMPLATE_DIR),
    autoescape=select_autoescape(['html', 'xml'])
)

# Add datetime.now and current_year to Jinja2 environment for use in templates
template_env.globals['now'] = datetime.now
template_env.globals['current_year'] = datetime.now().year # Added for the footer of the template

# =========================
# Email Utility Functions
# =========================

async def send_email(to_email: str, subject: str, template_name: str, context: Dict[str, Any]):
    """
    Sends an email asynchronously using SMTP server configured in settings.
    Renders an HTML template using Jinja2 with the provided context.
    Uses run_in_threadpool to perform synchronous smtplib operations without blocking the event loop.

    Args:
        to_email (str): Recipient's email address.
        subject (str): Subject of the email.
        template_name (str): Name of the HTML template file (e.g., "email_verification", "password_reset", "mfa_otp").
        context (Dict[str, Any]): Dictionary of data to pass to the template.
    """
    logger.debug(f"Attempting to send email to {to_email} with subject: {subject} using template: {template_name}")

    try:
        template = template_env.get_template(f"{template_name}.html")
        html_content = template.render(context)
    except Exception as e:
        logger.error(f"Error rendering email template '{template_name}.html' for {to_email}: {e}", exc_info=True)
        raise RuntimeError(f"Failed to render email template: {template_name}")

    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = settings.MAIL_USERNAME # Use EMAIL_USERNAME as the sender's email
    message["To"] = to_email

    mime_html = MIMEText(html_content, "html")
    message.attach(mime_html)

    # Define a synchronous helper function to encapsulate the blocking SMTP operations
    def _send_sync_email():
        context = ssl.create_default_context()

        server = None
        try:
            # Use settings.MAIL_SERVER, settings.MAIL_PORT, etc.
            # Check for SSL/TLS configuration
            if settings.MAIL_TLS: # Typically STARTTLS
                server = smtplib.SMTP(settings.MAIL_SERVER, settings.MAIL_PORT)
                server.ehlo()
                server.starttls(context=context)
                server.ehlo()
            else: # Direct SSL/TLS (less common for typical email clients)
                server = smtplib.SMTP_SSL(settings.MAIL_SERVER, settings.MAIL_PORT, context=context)
            
            # Login if credentials are provided
            if settings.MAIL_USERNAME and settings.MAIL_PASSWORD: # Check if credentials are set
                server.login(settings.MAIL_USERNAME, settings.MAIL_PASSWORD)

            server.sendmail(settings.MAIL_USERNAME, to_email, message.as_string()) # Use EMAIL_USERNAME as from_addr
            logger.info(f"Email successfully sent to {to_email}")

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP Authentication Error for {to_email}: Check username/password. Details: {e}", exc_info=True)
            raise
        except smtplib.SMTPConnectError as e:
            logger.error(f"SMTP Connection Error for {to_email}: Check server/port/firewall. Details: {e}", exc_info=True)
            raise
        except smtplib.SMTPServerDisconnected as e:
            logger.error(f"SMTP Server Disconnected for {to_email}: Incorrect TLS/SSL settings or port. Details: {e}", exc_info=True)
            raise
        except smtplib.SMTPException as e:
            logger.error(f"General SMTP Error for {to_email}: {e}", exc_info=True)
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred during email sending to {to_email}: {e}", exc_info=True)
            raise
        finally:
            if server:
                server.quit()

    try:
        await run_in_threadpool(_send_sync_email)
    except Exception as e:
        raise RuntimeError(f"Failed to send email to {to_email}: {e}")


# --- Context Builders ---

def build_email_verification_context(username: str, token: str) -> Dict[str, Any]:
    """
    Prepares the context dictionary for the email verification template.
    """
    verify_url = f"{settings.FRONTEND_URL}/verify-email?token={token}"
    return {
        "username": username,
        "verify_url": verify_url,
        "app_name": settings.APP_NAME,
        "token_expiry_minutes": settings.OTP_EXPIRATION_MINUTES # Using OTP_EXPIRATION_MINUTES for consistency
    }

def build_password_reset_context(username: str, token: str) -> Dict[str, Any]:
    """
    Prepares the context dictionary for the password reset template.
    """
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    return {
        "username": username,
        "reset_url": reset_url,
        "app_name": settings.APP_NAME,
        "token_expiry_minutes": settings.OTP_EXPIRATION_MINUTES # Using OTP_EXPIRATION_MINUTES for consistency
    }

async def send_email_mfa_challenge(
    to_email: str,
    first_name: str,
    token: Optional[str] = None, # JWT token for confirmation links
    otp_code: Optional[str] = None, # Numeric OTP code for direct display
    is_enable_confirm_link: Optional[bool] = None, # True for enable, False for disable, None for OTP login challenge
    is_login_challenge: bool = False # Added this parameter to align with mfa_service.py
):
    """
    Sends an MFA challenge email. It can be for:
    1. MFA Enablement confirmation link (is_enable_confirm_link=True, token provided)
    2. MFA Disablement confirmation link (is_enable_confirm_link=False, token provided)
    3. New device login challenge (otp_code provided, is_login_challenge=True)

    Args:
        to_email (str): Recipient's email address.
        first_name (str): Recipient's first name.
        token (Optional[str]): The JWT token to include in the confirmation URL.
        otp_code (Optional[str]): The numeric OTP code to display directly.
        is_enable_confirm_link (Optional[bool]):
            - True: Email is for MFA enablement confirmation.
            - False: Email is for MFA disablement confirmation.
            - None: Email is for a login challenge (handled by is_login_challenge).
        is_login_challenge (bool): True if this email is for a new device login challenge (OTP code).
    """
    subject = f"{settings.APP_NAME} - Multi-Factor Authentication"
    template_name = "" # Will be determined by logic
    context = {
        "first_name": first_name,
        "app_name": settings.APP_NAME,
        "current_year": datetime.now().year # Pass current year to template
    }

    if is_enable_confirm_link is True: # Explicitly for MFA Enablement Confirmation
        if not token:
            logger.error("send_email_mfa_challenge: Token is required for MFA enable confirmation link.")
            raise ValueError("Token missing for MFA enable confirmation email.")
        subject = f"{settings.APP_NAME} - Confirm MFA Enablement"
        template_name = "mfa_status_change_link"
        context["confirmation_url"] = f"{settings.FRONTEND_URL}/dashboard/security/2fa-setup?mfa_email_challenge_token={token}"
        context["is_enable_confirm_link"] = True # Pass this flag to the template
        context["token_expiry_minutes"] = settings.MFA_EMAIL_TOKEN_EXPIRE_MINUTES # Use specific expiry for this token
        logger.info(f"Preparing MFA enable confirmation email for {to_email}")
    elif is_enable_confirm_link is False: # Explicitly for MFA Disablement Confirmation
        if not token:
            logger.error("send_email_mfa_challenge: Token is required for MFA disable confirmation link.")
            raise ValueError("Token missing for MFA disable confirmation email.")
        subject = f"{settings.APP_NAME} - Confirm MFA Disablement"
        template_name = "mfa_status_change_link"
        context["confirmation_url"] = f"{settings.FRONTEND_URL}/dashboard/security/2fa-setup?mfa_email_challenge_token={token}"
        context["is_enable_confirm_link"] = False # Pass this flag to the template
        context["token_expiry_minutes"] = settings.MFA_EMAIL_TOKEN_EXPIRE_MINUTES # Use specific expiry for this token
        logger.info(f"Preparing MFA disable confirmation email for {to_email}")
    elif is_login_challenge and otp_code: # This is for a direct OTP code (e.g., login challenge)
        subject = f"{settings.APP_NAME} - New Device Login Verification"
        template_name = "mfa_otp" # Assuming you have an mfa_otp.html template for OTP codes
        context["otp_code"] = otp_code
        context["token_expiry_minutes"] = settings.OTP_EXPIRATION_MINUTES # Use OTP expiry for this
        logger.info(f"Preparing MFA login challenge email (OTP) for {to_email}")
    else:
        logger.error("send_email_mfa_challenge called without sufficient parameters to determine email type.")
        raise ValueError("Invalid call to send_email_mfa_challenge: Must specify token/otp_code and type.")

    await send_email(to_email, subject, template_name, context)
    logger.info(f"MFA email sent to {to_email} with subject: {subject}")