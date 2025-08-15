#!/bin/bash
# CRYPTON API Server Launcher
cd "$(dirname "$0")"
source venv/bin/activate 2>/dev/null || true
python3 api_server.py "$@"
