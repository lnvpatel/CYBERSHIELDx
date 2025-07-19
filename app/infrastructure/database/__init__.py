# app/infrastructure/database/__init__.py

# Export the asynchronous engine and asynchronous dependency
from .session import async_engine, get_db

# You might also want to export Base for convenience if you use it directly
from .base import Base

# Note: The synchronous 'engine' and 'get_db' are no longer exported
# from session.py if you've fully transitioned to asyncio.