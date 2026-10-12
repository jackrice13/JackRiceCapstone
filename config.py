"""
config.py

Loads all credentials and settings from a local .env file, so we never
have to type secrets directly into the code. If you're new to this pattern:
the .env file lives on your machine only, is never uploaded anywhere, and
this file just reads it into Python variables at runtime.
"""

import os
from dotenv import load_dotenv

# Load the .env file that sits next to this script.
load_dotenv()


def _require(name):
    """
    Fetch an environment variable and fail loudly (with a clear message)
    if it's missing, rather than silently continuing with a blank value.
    """
    value = os.environ.get(name)
    if not value or value.startswith("your_"):
        raise RuntimeError(
            f"Missing or unfilled setting: {name}. "
            f"Copy .env.example to .env and fill in your real values."
        )
    return value


# --- Action1 ---
ACTION1_CLIENT_ID = _require("ACTION1_CLIENT_ID")
ACTION1_CLIENT_SECRET = _require("ACTION1_CLIENT_SECRET")

# --- Cloudflare ---
CLOUDFLARE_API_TOKEN = _require("CLOUDFLARE_API_TOKEN")
CLOUDFLARE_ACCOUNT_ID = _require("CLOUDFLARE_ACCOUNT_ID")

# --- Nessus ---
NESSUS_HOST = _require("NESSUS_HOST")
NESSUS_ACCESS_KEY = _require("NESSUS_ACCESS_KEY")
NESSUS_SECRET_KEY = _require("NESSUS_SECRET_KEY")


# --- Your testbed's known endpoints (from your Research Methods section) ---
# name: a friendly label | ip: the static IP you assigned it
ENDPOINTS = [
    {"name": "Domain Controller", "ip": "10.0.2.55"},  # confirm this is actually right
    {"name": "Windows Server", "ip": "10.0.2.52"},
    {"name": "Linux Server", "ip": "10.0.2.50"},
    {"name": "Linux Workstation", "ip": "10.0.2.51"},
    {"name": "Windows Workstation", "ip": "10.0.2.54"},
]
