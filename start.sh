#!/bin/bash
# Use async workers and optimize for memory
exec gunicorn app:app \
    --bind 0.0.0.0:${PORT:-8080} \
    --worker-class aiohttp.GunicornWebWorker \
    --workers 1 \
    --timeout 120 \
    --keep-alive 2 \
    --max-requests 1000 \
    --max-requests-jitter 50 \
    --preload \
    --worker-tmp-dir /dev/shm