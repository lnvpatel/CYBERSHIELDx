# app/infrastructure/database/session.py

import asyncio
from typing import AsyncGenerator, Any
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.config import settings
import os # Keep os import, though not strictly used for SSL cert paths in this version

# ✅ Asynchronous engine for database connection
# Use create_async_engine for async database operations.
# IMPORTANT: Your DATABASE_URL in app/config.py MUST use an async driver,
# e.g., "sqlite+aiosqlite:///./sql_app.db" for SQLite,
# "postgresql+asyncpg://user:password@host/dbname" for PostgreSQL,
# "mysql+aiomysql://user:password@host/dbname" for MySQL.

# Initialize connect_args with SQLite-specific setting if applicable.
# For PostgreSQL with asyncpg, SSL/TLS configuration (like sslmode)
# is expected to be part of the DATABASE_URL query parameters,
# not as separate connect_args.
final_connect_args = {"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {}

# Removed the ssl_connect_args logic as sslmode and certificate paths
# for Render PostgreSQL are best handled directly in the DATABASE_URL
# or are not required as separate connect_args for the asyncpg driver.
# The config.py ensures sslmode=require is appended to the URL.

async_engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.ENVIRONMENT == "DEV", # Echo SQL queries in development
    # ✅ Add pool configuration from settings for robust connection management
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_POOL_SIZE * 2, # Common practice: allow temporary burst connections
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_recycle=settings.DB_POOL_RECYCLE,
    # ✅ Pass the simplified connect_args.
    # For asyncpg, sslmode should be in the URL, not here.
    connect_args=final_connect_args
)

# ✅ Asynchronous sessionmaker
# Use async_sessionmaker to create asynchronous sessions.
AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False, # Important for SQLAlchemy 2.0 style with AsyncSession
    class_=AsyncSession # Specify the AsyncSession class
)

# ✅ Dependency used in FastAPI routes for asynchronous database sessions
# Corrected type hint for generator function's second parameter to None
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency that provides an asynchronous SQLAlchemy database session.
    The session is automatically managed and closed using an async context manager.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            # ✅ Crucial: Ensure the session is closed to release the connection back to the pool
            await session.close()
