"""
config.py

Loads all credentials and settings from a local .env file, so we never
have to type secrets directly into the code. If you're new to this pattern:
the .env file lives on your machine only, is never uploaded anywhere, and
this file just reads it into Python variables at runtime.
"""

import os
from dotenv import load_dotenv

# Load the .env file that sits next to this script. override=True means the
# .env file always wins. Without it, a variable with the same name already set
# in Windows or PyCharm would silently beat the file, which is confusing when
# you edit .env and nothing changes.
load_dotenv(override=True)


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

# Action1 has a separate web address for each world region, and your
# credentials only work on the region where your account lives. This
# project's account is on "na-2", so that's the fallback below. If the
# ACTION1_BASE_URL line exists in your .env file, it wins over the fallback.
# (This one is optional, so it uses os.environ.get with a default value
# instead of _require, which would stop the program if it were missing.)
ACTION1_BASE_URL = os.environ.get(
    "ACTION1_BASE_URL", "https://app.na-2.action1.com/api/3.0"
)

# --- Cloudflare ---
CLOUDFLARE_API_TOKEN = _require("CLOUDFLARE_API_TOKEN")
CLOUDFLARE_ACCOUNT_ID = _require("CLOUDFLARE_ACCOUNT_ID")

# --- Nessus ---
NESSUS_HOST = _require("NESSUS_HOST")
NESSUS_ACCESS_KEY = _require("NESSUS_ACCESS_KEY")
NESSUS_SECRET_KEY = _require("NESSUS_SECRET_KEY")


# --- Assessment settings (see assessment.py for how these are used) ---
# These are judgement calls rather than facts about the tools, so keep them
# consistent with the criteria in your methodology section.

# How old a tool's "last seen" time (or, for Nessus, the scan time) may be,
# in minutes, before its data is called stale. A stale PASS becomes a WARN.
STALE_AFTER_MINUTES = {
    "action1": 120,     # Action1 agents on Windows check in every so often, not constantly
    "cloudflare": 60,   # the WARP client reports in frequently
    "nessus": 1440,     # scans are periodic; 24 hours old counts as stale
}

# Tool/endpoint pairs where the tool cannot be installed, so having no record
# is expected rather than a failure. They are reported as N/A with this reason.
# Delete a line if you want that gap counted as NOT_FOUND instead.
# Format: (endpoint name exactly as written below, tool key): "reason"
EXPECTED_GAPS = {
    ("Domain Controller", "cloudflare"): "Cloudflare WARP is not supported on Windows Server",
    ("Windows Server", "cloudflare"): "Cloudflare WARP is not supported on Windows Server",
}


# --- Your testbed's known endpoints (from your Research Methods section) ---
# name: a friendly label (used only in the report)
# ip: the static IP you assigned it
# hostname: the machine's real computer name, exactly as Cloudflare/Action1
#           report it. Use None where we don't know it yet.
ENDPOINTS = [
    {"name": "Domain Controller", "ip": "10.0.2.3", "hostname": "LAB-DC01"},  # IP as reported by Action1 (see note in chat about .3)
    {"name": "Windows Server", "ip": "10.0.2.52", "hostname": "WindowsServer"},
    {"name": "Linux Server", "ip": "10.0.2.50", "hostname": "linuxserv"},
    {"name": "Linux Workstation", "ip": "10.0.2.51", "hostname": "linuxws"},
    {"name": "Windows Workstation", "ip": "10.0.2.54", "hostname": "DESKTOP-E92TKTR"},  # confirm
]
