from app.config import settings
from app.security import create_email_verification_token
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import asyncio #import asyncio

async def send_verification_email(email: str, token: str): #make it async
    """Sends an email verification link to the user's email."""
    token = create_email_verification_token(email)
    verification_link = f"{settings.BACKEND_URL}/auth/verify-email?token={token}"  # Use backend URL for testing
    
    subject = "Verify Your Email"
    body = f"""
    <p>Click the link below to verify your email:</p>
    <a href="{verification_link}">{verification_link}</a>
    """
    
    msg = MIMEMultipart()
    msg['From'] = settings.EMAIL_FROM
    msg['To'] = email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))
    
    try:
        #Use asyncio to make the smtp connection asynchronous.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, lambda: _send_email(email, msg))

    except Exception as e:
        print(f"Error sending email: {e}")

def _send_email(email, msg):
    try:
        with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
            server.starttls()
            server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USERNAME, email, msg.as_string())
    except Exception as e:
        print(f"Error sending email: {e}")