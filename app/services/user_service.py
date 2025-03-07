from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from fastapi import HTTPException
from app.models import User, UserRole
from app.security import get_password_hash, create_email_verification_token
from datetime import datetime, timezone
from app.schemas import UserCreate, UserUpdate, UserResponse


# -------------------- Async Function --------------------

async def create_user(db: AsyncSession, user_data: UserCreate):
    """Registers a new user with role set to 'User' by default."""
    
    stmt = select(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    )
    result = await db.execute(stmt)
    existing_user = result.scalar()

    if existing_user:
        raise HTTPException(status_code=400, detail="Username or Email already exists")

    hashed_password = get_password_hash(user_data.password)
    role = user_data.role if user_data.role else UserRole.USER  # Default role: User
    verification_token = create_email_verification_token(user_data.email)  # ✅ Generate token

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
        created_at=datetime.now(timezone.utc),  # Use timezone-aware datetime
        verification_token=verification_token,  # ✅ Ensure token is saved
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    
    return new_user


# -------------------- Async CRUD Functions --------------------

async def get_user_by_id(db: AsyncSession, user_id: int):
    """Fetch a user by ID."""
    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return user


async def update_user(db: AsyncSession, user_id: int, user_data: UserUpdate):
    """Update user details."""
    user = await get_user_by_id(db, user_id)

    for key, value in user_data.dict(exclude_unset=True).items():
        setattr(user, key, value)

    await db.commit()
    await db.refresh(user)
    return user


async def delete_user(db: AsyncSession, user_id: int):
    """Delete a user with admin safeguard."""
    user = await get_user_by_id(db, user_id)

    if user.role == UserRole.ADMIN:
        result = await db.execute(select(User).filter(User.role == UserRole.ADMIN))
        admin_count = len(result.scalars().all())  # Fetch all admin users

        if admin_count <= 1:
            raise HTTPException(status_code=400, detail="At least one admin must remain!")

    await db.delete(user)
    await db.commit()
    return {"message": "User deleted successfully"}


async def update_user_photo(db: AsyncSession, user_id: int, photo_url: str):
    """Update user's profile photo."""
    user = await get_user_by_id(db, user_id)
    user.photo_url = photo_url
    await db.commit()
    await db.refresh(user)
    return user


async def delete_user_photo(db: AsyncSession, user_id: int):
    """Delete user's profile photo."""
    user = await get_user_by_id(db, user_id)
    user.photo_url = None
    await db.commit()
    await db.refresh(user)
    return {"message": "Profile photo deleted successfully"}
