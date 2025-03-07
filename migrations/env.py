import asyncio
import os
from logging.config import fileConfig
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context
from dotenv import load_dotenv
from app.models import User
from app.db import Base  # Adjust this based on your project structure

# Load environment variables from .env file
load_dotenv()

# Get DATABASE_URL from .env
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./your_database.db")

# Load Alembic configuration
config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Metadata for Alembic to use
target_metadata = Base.metadata

# Convert async database URL to a synchronous version for Alembic
sync_url = DATABASE_URL.replace("sqlite+aiosqlite", "sqlite")  # For SQLite
sync_engine = create_engine(sync_url)


def run_migrations_offline():
    """Run migrations in 'offline' mode."""
    context.configure(
        url=sync_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode."""
    with sync_engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
