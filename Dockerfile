# Use the official Python 3.12.3 image
FROM python:3.12.3

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    WORKDIR=/app

# Set working directory
WORKDIR $WORKDIR

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose the application port
EXPOSE 8000

# Command to run the application with Gunicorn and Uvicorn
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
