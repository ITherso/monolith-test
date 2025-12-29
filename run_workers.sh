#!/usr/bin/env bash
# Simple helper to start Redis (if available) and a Celery worker for monolith.tasks
set -euo pipefail

echo "Starting Redis (if installed) and Celery worker..."

if command -v redis-server >/dev/null 2>&1; then
    echo "Starting redis-server in background..."
    redis-server &
    sleep 1
else
    echo "redis-server not found in PATH — ensure Redis is running manually if you want Celery persistence"
fi

if python -c "import celery" 2>/dev/null; then
    echo "Launching Celery worker (monolith.tasks.celery)..."
    celery -A monolith.tasks.celery worker --loglevel=info
else
    echo "Celery not installed in current env. Install requirements_extra.txt and try again."
    exit 1
fi
