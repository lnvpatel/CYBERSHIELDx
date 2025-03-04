from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from app.services.user_service import (
    create_user, get_user_by_id, update_user, delete_user, update_user_photo, delete_user_photo
)
from app.models import User, UserRole
from app.security import is_admin, get_current_user
from app.schemas import UserCreate, UserUpdate, UserResponse
from app.db import get_db

router = APIRouter(prefix="/users", tags=["Users"])

@router.post("/", response_model=UserResponse)
def register_user(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register a new user (default role: User)."""
    return create_user(db, user_data)

@router.post("/admin", response_model=UserResponse, dependencies=[Depends(is_admin)])
def register_admin(user_data: UserCreate, db: Session = Depends(get_db)):
    """Allows only admins to register other admins."""
    user_data.role = UserRole.ADMIN  # Explicitly setting role as Admin
    return create_user(db, user_data)

@router.get("/{user_id}", response_model=UserResponse)
def get_user(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Retrieve a user by ID."""
    return get_user_by_id(db, user_id)

@router.put("/{user_id}", response_model=UserResponse)
def update_user_details(user_id: int, user_data: UserUpdate, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Update user details (admin can update any user, normal users can only update themselves)."""
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Unauthorized to update this user")
    return update_user(db, user_id, user_data)

@router.delete("/{user_id}")
def delete_user_account(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Delete a user (admin can delete any user, normal users can only delete themselves)."""
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Unauthorized to delete this user")
    return delete_user(db, user_id)

@router.put("/{user_id}/photo", response_model=UserResponse)
def upload_user_photo(user_id: int, file: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Upload/update user's profile photo."""
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Unauthorized to update this photo")
    
    photo_url = f"/uploads/{file.filename}"  # Store photo URL (Modify this logic for actual storage)
    return update_user_photo(db, user_id, photo_url)

@router.delete("/{user_id}/photo", response_model=UserResponse)
def remove_user_photo(user_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Delete user's profile photo."""
    if current_user.id != user_id and current_user.role != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Unauthorized to delete this photo")
    
    return delete_user_photo(db, user_id)
