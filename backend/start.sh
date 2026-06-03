#!/bin/bash
set -e
# Find gunicorn from the pip-installed Python environment
GUNICORN=$(find /opt/render /home -name gunicorn -type f 2>/dev/null | head -1)
if [ -n "$GUNICORN" ]; then
    exec "$GUNICORN" app:app --workers 1 --bind "0.0.0.0:$PORT" --timeout 120 --preload
else
    # Fallback: try python3.11 directly
    exec python3.11 -m gunicorn app:app --workers 1 --bind "0.0.0.0:$PORT" --timeout 120 --preload
fi
