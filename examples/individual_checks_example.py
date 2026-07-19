#!/usr/bin/env python3
"""
Example: Individual security checks
"""

import subprocess
import sys
import os

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "apijack.py")
API = "https://api.example.com"


def run(cmd):
    """Run an API-Jack command and print output."""
    print(f"$ {' '.join(cmd)}\n{'=' * 60}")
    result = subprocess.run(cmd, cwd=os.path.dirname(SCRIPT))
    print(f"\nExit code: {result.returncode}\n")
    return result


if __name__ == "__main__":
    # 1. Detect BOLA
    run([sys.executable, SCRIPT, "detect-bola", "--url", f"{API}/users/1"])

    # 2. Rate limit test
    run([sys.executable, SCRIPT, "rate-limit", "--url", f"{API}/login", "--requests", "20"])

    # 3. Excessive data exposure
    run([sys.executable, SCRIPT, "expose", "--url", f"{API}/users/me"])

    # 4. Mass assignment test
    run([sys.executable, SCRIPT, "mass-assign", "--url", f"{API}/users",
         "--fields", "is_admin,role,balance"])
