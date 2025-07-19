# app/infrastructure/database/base.py
from sqlalchemy.orm import DeclarativeBase

# ✅ Shared Base class for all models in an async setup
class Base(DeclarativeBase):
    """
    DeclarativeBase class for SQLAlchemy ORM models.
    All SQLAlchemy models in your application should inherit from this Base.
    This Base works for both synchronous and asynchronous setups.
    """
    pass
