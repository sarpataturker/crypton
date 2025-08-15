#!/bin/bash
# CRYPTON Terminal App Launcher
cd "$(dirname "$0")"
source venv/bin/activate 2>/dev/null || true
python3 main.py "$@"
