#!/bin/bash

# Set environment variables (Optional)
export HOST="0.0.0.0"
export PORT=8000
export WORKERS=2 # Adjust based on CPU cores

# Run Gunicorn with Uvicorn worker
gunicorn -k uvicorn.workers.UvicornWorker -w $WORKERS -b $HOST:$PORT app.main:app
