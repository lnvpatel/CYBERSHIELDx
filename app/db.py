from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import settings

# Database URL from .env (default: SQLite for async)
SQLALCHEMY_DATABASE_URL = settings.DATABASE_URL

# Create the database engine (asynchronous)
engine = create_async_engine(SQLALCHEMY_DATABASE_URL, echo=True)

# Create a session factory (asynchronous)
SessionLocal = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Define the base model class
Base = declarative_base()

# Dependency: Get DB session (asynchronous)
async def get_db():
    async with SessionLocal() as session:
        yield session
