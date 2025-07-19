#!/usr/bin/env bash

# build.sh
# This script is executed by Render during the build process of your web service.
# It's responsible for setting up your application's environment before it starts.

# --- Exit on Error ---
# This command ensures that the script will exit immediately if any command fails.
set -o errexit

echo "Starting build process..."

# --- 1. Update pip ---
# It's good practice to ensure pip is the latest version.
echo "Updating pip to the latest version..."
python -m pip install --upgrade pip

# --- 2. Install Python Dependencies ---
# Install all packages listed in your requirements.txt file.
# Ensure your requirements.txt is in the root of your repository.
echo "Installing Python dependencies from requirements.txt..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "Error: requirements.txt not found! Please ensure it exists in the root of your repository."
    exit 1 # Exit if dependencies cannot be installed
fi

# --- 3. Run Database Migrations (Conditional) ---
# This section assumes you are using Alembic for database migrations with SQLAlchemy.
# Render automatically provides the DATABASE_URL environment variable for linked databases.
# If you are using a different migration tool (e.g., Django's `manage.py migrate`,
# Flask-Migrate, or custom SQL scripts), you MUST adjust these commands accordingly.

echo "Attempting to run database migrations..."

# Check if Alembic is installed and if an alembic.ini file exists
# This makes the migration step optional if Alembic is not set up.
if command -v alembic &> /dev/null && [ -f "alembic.ini" ]; then
    # Run Alembic migrations. 'upgrade head' applies all pending migrations.
    alembic upgrade head
    echo "Database migrations applied successfully using Alembic."
elif [ -f "manage.py" ]; then
    # Example for Django or similar frameworks
    echo "manage.py found. Attempting Django-style migrations..."
    python manage.py migrate
    echo "Django migrations applied successfully."
else
    echo "Skipping automatic database migrations: No recognized migration tool (Alembic, Django) or config found."
    echo "If your application requires migrations, please add the appropriate commands to this script."
fi

echo "Build process completed successfully!"
