#!/usr/bin/env python3
"""
Run ProjectLibra Web Dashboard
"""

from src.web.dashboard import run_dashboard
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

if __name__ == "__main__":
    run_dashboard(host="0.0.0.0", port=8080)
