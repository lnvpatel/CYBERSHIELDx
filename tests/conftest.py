import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from app.main import app
from app.db import SessionLocal  # ✅ Correctly importing SessionLocal instead of async_session_maker



@pytest.fixture
def client():
    """Creates a FastAPI test client."""
    with TestClient(app) as client:
        yield client

@pytest_asyncio.fixture(scope="function")
async def reset_db():
    """Clears the users table before each test to prevent conflicts."""
    async with SessionLocal() as session:
        await session.execute(text("DELETE FROM users"))  # ✅ Ensure table name is correct
        await session.commit()
