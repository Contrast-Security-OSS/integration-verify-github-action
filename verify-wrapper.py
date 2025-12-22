#!/usr/bin/env python3
"""
Backward compatibility wrapper for existing GitLab/Docker users.
This script calls the actual verify.py using the virtual environment directly.
"""
import os
import subprocess
import sys

# Change to the app directory
os.chdir("/app")

# Execute the real script using the virtual environment python directly
try:
    result = subprocess.run(["/app/.venv/bin/python3", "verify.py"], check=False)
    sys.exit(result.returncode)
except Exception as e:
    print(f"Error executing verify.py: {e}", file=sys.stderr)
    sys.exit(1)
