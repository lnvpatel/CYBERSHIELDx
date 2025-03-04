from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from app.models import User, UserRole
from app.schemas import UserCreate, UserResponse
from app.security import get_password_hash, verify_password, create_access_token, create_email_verification_token
import uuid

class AuthService:
    
    @staticmethod
    def register_user(db: Session, user_data: UserCreate) -> UserResponse:
        """Registers a new user and sends email verification token"""

        # Check if email or username already exists
        if db.query(User).filter(User.email == user_data.email).first():
            raise HTTPException(status_code=400, detail="Email is already registered.")
        if db.query(User).filter(User.username == user_data.username).first():
            raise HTTPException(status_code=400, detail="Username is already taken.")

        # Hash password
        hashed_password = get_password_hash(user_data.password)

        # Generate verification token
        verification_token = create_email_verification_token(user_data.email)

        # Create new user
        new_user = User(
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            username=user_data.username,
            email=user_data.email,
            mobile_number=user_data.mobile_number,
            dob=user_data.dob,
            hashed_password=hashed_password,
            role=UserRole.USER,  # Default role: USER
            verification_token=verification_token,
            is_verified=False  # Initially False until email is verified
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # TODO: Send verification email here with `verification_token`

        return UserResponse(**new_user.__dict__)

    @staticmethod
    def verify_email(db: Session, email: str):
        """Marks a user's email as verified"""
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(status_code=400, detail="User not found.")

        user.is_verified = True
        user.verification_token = None  # Remove token after verification
        db.commit()
        return {"message": "Email verified successfully."}

    @staticmethod
    def authenticate_user(db: Session, username: str, password: str):
        """Authenticates user and returns JWT token (only for verified users)"""

        # Check if user exists
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.hashed_password):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials.")

        # Check if email is verified
        if not user.is_verified:
            raise HTTPException(status_code=403, detail="Email not verified. Please check your inbox.")

        # Generate JWT token
        token = create_access_token({"sub": user.username, "role": user.role.value})
        return {"access_token": token, "token_type": "bearer"}

    @staticmethod
    def logout_user(db: Session, user: User):
        """Logs out a user by incrementing token_version."""
        user.token_version += 1  # Invalidate all old tokens
        db.commit()
        return {"message": "Logout successful. Token invalidated."}
