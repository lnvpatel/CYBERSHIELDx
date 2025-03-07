print(f"Loading auth_service.py from: {__file__}")
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from fastapi import HTTPException, status
from app.models import User
from app.schemas import UserCreate, UserResponse
from app.security import verify_password, create_access_token, create_email_verification_token, verify_email_token  # Import verify_email_token from security
from app.services.user_service import create_user
from app.services.email_service import send_verification_email
from typing import Dict
import logging

logger = logging.getLogger(__name__)

class AuthService:
    
    @staticmethod
    async def register_user(db: AsyncSession, user_data: UserCreate) -> UserResponse:
        """Registers a new user and sends an email verification token."""

        new_user: User = await create_user(db, user_data)

        print(f"New User: {new_user}")
        print(f"New User Email: {new_user.email}")
        print(f"New User Token: {new_user.verification_token}")

        new_user.verification_token = create_email_verification_token(new_user.email)

        db.add(new_user)  # Add the SQLAlchemy User model
        await db.commit()
        await db.refresh(new_user)

        await send_verification_email(new_user.email, new_user.verification_token)

        return UserResponse.model_validate(new_user)

    @staticmethod
    async def verify_email(db: AsyncSession, token: str):
        """Marks a user's email as verified using the token"""
        try:
            logger.info(f"Verifying email with token: {token}")
            email = verify_email_token(token)
            if not email:
                logger.warning(f"Invalid or expired token: {token}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid or expired token.",
                )

            logger.info(f"Email extracted from token: {email}")

            result = await db.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()

            if not user:
                logger.warning(f"User not found for email: {email}")
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found."
                )

            if user.is_verified:
                logger.warning(f"Email already verified for user: {email}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email already verified."
                )

            user.is_verified = True
            user.verification_token = None
            await db.commit()
            await db.refresh(user)

            logger.info(f"Email verified successfully for user: {email}")

            return {"message": "Email verified successfully."}

        except HTTPException as e:
            logger.error(f"HTTPException during email verification: {e}")
            raise e
        except Exception as e:
            logger.exception(f"Unexpected error during email verification: {e}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Internal server error during email verification.",
            )

        
    @staticmethod
    async def authenticate_user(db: AsyncSession, username: str, password: str) -> Dict[str, str]:  # Added type hints
        """Authenticates user and returns JWT token (only for verified users)"""
        try:
            result = await db.execute(select(User).where(User.username == username))
            user = result.scalar_one_or_none()
            
            if not user or not verify_password(password, user.hashed_password):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

            if not user.is_verified:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified. Please check your inbox.")

            token = create_access_token(user)
            
            return {"access_token": token, "token_type": "bearer"}
        except Exception as e: 
            # Add logging or more specific error handling here
            raise HTTPException(status_code=500, detail=str(e))
    @staticmethod
    async def logout_user(db: AsyncSession, user):
        """Logs out a user by invalidating tokens."""
        user.token_version += 1
        await db.commit()
        return {"message": "Logout successful. Token invalidated."}
