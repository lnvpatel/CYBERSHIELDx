# Use a lightweight official Python image as the base.
# python:3.10-slim-buster is a good balance of features and size.
# You can update to 3.11-slim-buster or newer if desired.
FROM python:3.10-slim-buster

# Set environment variables
# PYTHONUNBUFFERED ensures that Python output is sent straight to the terminal
# (or Docker logs) without being buffered.
# PYTHONDONTWRITEBYTECODE prevents Python from writing .pyc files to disk.
ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1

# Set the working directory inside the container.
# This is where your application code will reside.
WORKDIR /app

# Create a non-root user for security best practices.
# This user will own the application files and run the application.
RUN adduser --system --group appuser
USER appuser

# Copy only the requirements file first.
# This allows Docker to cache this layer. If requirements.txt doesn't change,
# subsequent builds will use the cached layer, speeding up builds.
COPY --chown=appuser:appuser ./requirements.txt /app/requirements.txt

# Install Python dependencies.
# Use --no-cache-dir to prevent pip from storing downloaded packages,
# which reduces the final image size.
# Use --upgrade pip to ensure pip itself is up-to-date.
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# Copy the rest of your application code to the working directory.
# This should be done after installing dependencies to leverage Docker's caching.
# Ensure your project structure matches (e.g., 'app' directory inside '/app').
COPY --chown=appuser:appuser . /app

# Expose the port that the application will listen on.
# Render automatically sets the $PORT environment variable, typically 10000.
# Your Gunicorn command will use this $PORT.
EXPOSE 8000 

# Define the command to run your application.
# This uses Gunicorn to serve your FastAPI application with Uvicorn workers.
# The number of workers (e.g., 2) should be tuned based on your instance's CPU cores.
# A common rule of thumb is (2 * CPU_CORES) + 1. Render's free tier has 1 CPU.
# --bind 0.0.0.0:$PORT: Binds to all network interfaces on the port provided by Render.
# --timeout 120: Sets the worker timeout to 120 seconds. Adjust if you have very long-running requests.
# --keep-alive 5: Sets the number of seconds to wait for requests on a Keep-Alive connection.
# --log-level info: Sets Gunicorn's logging level. Your app's logging is configured by config.py.
# If you have a Procfile, Render will use that instead of this CMD.
CMD ["gunicorn", "app.main:app", "--workers", "2", "--worker-class", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:$PORT", "--timeout", "120", "--keep-alive", "5", "--log-level", "info"]

