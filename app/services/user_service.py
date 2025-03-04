from sqlalchemy.orm import Session
from fastapi import HTTPException
from app.models import User, UserRole
from app.security import get_password_hash
from datetime import datetime
from app.schemas import UserCreate, UserUpdate

def create_user(db: Session, user_data: UserCreate):
    """Registers a new user with role set to 'User' by default."""
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()

    if existing_user:
        raise HTTPException(status_code=400, detail="Username or Email already exists")

    hashed_password = get_password_hash(user_data.password)
    role = user_data.role if user_data.role else UserRole.USER  # Default role: User

    new_user = User(
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        username=user_data.username,
        email=user_data.email,
        mobile_number=user_data.mobile_number,
        dob=user_data.dob,
        hashed_password=hashed_password,
        role=role,
        photo_url=user_data.photo_url,
        created_at=datetime.utcnow(),
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

def get_user_by_id(db: Session, user_id: int):
    """Fetch a user by ID."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

def update_user(db: Session, user_id: int, user_data: UserUpdate):
    """Update user details."""
    user = get_user_by_id(db, user_id)

    for key, value in user_data.dict(exclude_unset=True).items():
        setattr(user, key, value)

    db.commit()
    db.refresh(user)
    return user

def delete_user(db: Session, user_id: int):
    """Delete a user."""
    user = get_user_by_id(db, user_id)
    
    if user.role == UserRole.ADMIN:
        admin_count = db.query(User).filter(User.role == UserRole.ADMIN).count()
        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="At least one admin must remain!")

    db.delete(user)
    db.commit()
    return {"message": "User deleted successfully"}

def update_user_photo(db: Session, user_id: int, photo_url: str):
    """Update user's profile photo."""
    user = get_user_by_id(db, user_id)
    user.photo_url = photo_url
    db.commit()
    db.refresh(user)
    return user

def delete_user_photo(db: Session, user_id: int):
    """Delete user's profile photo."""
    user = get_user_by_id(db, user_id)
    user.photo_url = None
    db.commit()
    db.refresh(user)
    return user
