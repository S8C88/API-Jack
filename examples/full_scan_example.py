#!/usr/bin/env python3
"""
Example: Full API scan using endpoints.json
Run: python full_scan_example.py
"""

import subprocess
import sys
import os

# Path to the apijack.py script
SCRIPT = os.path.join(os.path.dirname(__file__), "..", "apijack.py")
ENDPOINTS = os.path.join(os.path.dirname(__file__), "..", "endpoints.json")

if __name__ == "__main__":
    cmd = [
        sys.executable, SCRIPT,
        "scan",
        "--url", "https://api.example.com",
        "--endpoints", ENDPOINTS,
        "--json", "scan-report.json",
        "-v",
    ]
    print(f"Running: {' '.join(cmd)}\n")
    result = subprocess.run(cmd, cwd=os.path.dirname(SCRIPT))
    sys.exit(result.returncode)
