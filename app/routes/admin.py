from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from datetime import datetime, timezone

from app.db import get_db
from app.models import User, UserRole, AdminLog
from app.security import is_admin  # Ensure this function exists in security.py

router = APIRouter(prefix="", tags=["Admin"])

# ✅ List all users (Admin Only)
@router.get("/users")
def list_users(db: Session = Depends(get_db), admin: User = Depends(is_admin)):  
    return db.query(User).all()

# ✅ Delete a User (Ensure Admins Cannot Delete Themselves & Last Admin)
@router.delete("/user/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(is_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.role == UserRole.ADMIN:
        admin_count = db.query(User).filter(User.role == UserRole.ADMIN).count()
        if admin_count <= 1:
            raise HTTPException(status_code=403, detail="At least one admin must remain")
    
    db.delete(user)
    db.commit()

    # ✅ Log admin action
    admin_log = AdminLog(
        admin_id=admin.id,
        target_user_id=user.id,
        action=f"Deleted user {user.username}",
        timestamp=datetime.now(timezone.utc)
    )
    db.add(admin_log)
    db.commit()

    return {"detail": "User deleted successfully"}

# ✅ Promote a User to Admin (Ensure At Least One Admin Exists)
@router.post("/promote/{user_id}")
def promote_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(is_admin)):
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.role == UserRole.ADMIN:
        return {"detail": "User is already an admin"}

    user.role = UserRole.ADMIN
    db.commit()
    db.refresh(user)  # ✅ Ensure update reflects

    # ✅ Log admin action
    admin_log = AdminLog(
        admin_id=admin.id,
        target_user_id=user.id,
        action=f"Promoted {user.username} to admin",
        timestamp=datetime.now(timezone.utc)
    )
    db.add(admin_log)
    db.commit()

    return {"detail": f"User {user.username} promoted to admin"}

# ✅ Demote an Admin (Ensure At Least One Admin Remains)
@router.post("/demote/{user_id}")
def demote_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(is_admin)):
    user = db.query(User).filter(User.id == user_id).first()

    if not user or user.role != UserRole.ADMIN:
        raise HTTPException(status_code=404, detail="Admin user not found")

    admin_count = db.query(User).filter(User.role == UserRole.ADMIN).count()
    if admin_count <= 1:
        raise HTTPException(status_code=400, detail="At least one admin must remain")

    user.role = UserRole.USER
    db.commit()
    db.refresh(user)  # ✅ Ensure update reflects

    # ✅ Log admin action
    admin_log = AdminLog(
        admin_id=admin.id,
        target_user_id=user.id,
        action=f"Demoted {user.username} to regular user",
        timestamp=datetime.now(timezone.utc)
    )
    db.add(admin_log)
    db.commit()

    return {"detail": f"Admin {user.username} demoted to user"}
