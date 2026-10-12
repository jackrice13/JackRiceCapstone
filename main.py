"""
main.py

This is the actual CCM (Continuous Controls Monitoring) tool for your
capstone project. It does three things, one after another:

  1. Pulls current data from Action1, Cloudflare, and Nessus
  2. Saves the raw (unprocessed) API responses to disk, so you can see
     exactly what each tool actually returned
  3. Builds a simple summary report, one row per endpoint per tool,
     and writes it to a CSV file you can open in Excel

IMPORTANT - read this before running it for real:
Since I (Claude) can't test this against your actual Action1/Cloudflare/
Nessus accounts, the *connection and login* code is confirmed correct
from each tool's official documentation, but the exact field names used
to summarize each endpoint's status (like "is this patched?") are my
best guess based on typical API shapes. The raw JSON files this script
saves will show us the real structure, so we can fix any mismatched
field names together after your first run.

Usage:
    1. Copy .env.example to .env and fill in your real credentials
    2. pip install -r requirements.txt
    3. python main.py
"""

import csv
import json
import os
from datetime import datetime

import config
import action1_client
import cloudflare_client
import nessus_client
from nist_mapping import NIST_CSF_MAPPING


def save_raw(tool_name, data, output_dir):
    """Dumps the raw API response to a timestamped JSON file for inspection."""
    path = os.path.join(output_dir, f"raw_{tool_name}.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"  Saved raw {tool_name} data -> {path}")


def find_by_ip(items, ip, possible_ip_keys):
    """
    Looks through a list of dicts for one whose IP address (under any of
    several possible field names) matches the given IP. Returns None if
    nothing matches, rather than crashing.
    """
    for item in items:
        for key in possible_ip_keys:
            if item.get(key) == ip:
                return item
    return None


def find_by_name_fragment(items, name, possible_name_keys):
    """
    Same idea as find_by_ip, but matches loosely on name (since Cloudflare
    devices are identified by device/user name, not local IP address).
    """
    name_lower = name.lower().replace(" ", "")
    for item in items:
        for key in possible_name_keys:
            value = item.get(key)
            if value and name_lower in str(value).lower().replace(" ", ""):
                return item
    return None


def main():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = f"ccm_report_{timestamp}"
    os.makedirs(output_dir, exist_ok=True)

    print(f"Starting CCM data collection - results going to ./{output_dir}/\n")

    # ------------------------------------------------------------------
    # Step 1: Pull data from each tool. Each is wrapped in try/except so
    # that if one tool fails (bad credentials, network issue, etc.) the
    # others still run instead of the whole script crashing.
    # ------------------------------------------------------------------
    action1_data = []
    cloudflare_data = []
    nessus_data = []

    print("Pulling Action1 data...")
    try:
        action1_data = action1_client.get_all_endpoint_data(
            config.ACTION1_CLIENT_ID, config.ACTION1_CLIENT_SECRET
        )
        save_raw("action1", action1_data, output_dir)
        print(f"  Got {len(action1_data)} endpoint(s) from Action1.\n")
    except Exception as e:
        print(f"  Action1 FAILED: {e}\n")

    print("Pulling Cloudflare Zero Trust data...")
    try:
        cloudflare_data = cloudflare_client.get_devices(
            config.CLOUDFLARE_API_TOKEN, config.CLOUDFLARE_ACCOUNT_ID
        )
        save_raw("cloudflare", cloudflare_data, output_dir)
        print(f"  Got {len(cloudflare_data)} device(s) from Cloudflare.\n")
    except Exception as e:
        print(f"  Cloudflare FAILED: {e}\n")

    print("Pulling Nessus data...")
    try:
        nessus_data = nessus_client.get_latest_scan_results(
            config.NESSUS_HOST, config.NESSUS_ACCESS_KEY, config.NESSUS_SECRET_KEY
        )
        save_raw("nessus", nessus_data, output_dir)
        print(f"  Got {len(nessus_data)} host result(s) from Nessus.\n")
    except Exception as e:
        print(f"  Nessus FAILED: {e}\n")

    # ------------------------------------------------------------------
    # Step 2: Match each tool's data back to your known testbed endpoints
    # and write one summary row per (endpoint, tool) combination.
    # ------------------------------------------------------------------
    report_rows = []

    for endpoint in config.ENDPOINTS:
        name = endpoint["name"]
        ip = endpoint["ip"]

        # --- Action1 match (by IP - try a few likely field names) ---
        a1_match = find_by_ip(action1_data, ip, ["ip_address", "ip", "ipAddress"])
        report_rows.append({
            "endpoint": name,
            "ip": ip,
            "tool": "Action1",
            "nist_csf": ", ".join(NIST_CSF_MAPPING["action1"]),
            "found": "yes" if a1_match else "no",
            "raw_snippet": json.dumps(a1_match)[:200] if a1_match else "",
        })

        # --- Cloudflare match (by name, since device IP isn't the same concept) ---
        cf_match = find_by_name_fragment(cloudflare_data, name, ["name", "user", "device_name"])
        report_rows.append({
            "endpoint": name,
            "ip": ip,
            "tool": "Cloudflare",
            "nist_csf": ", ".join(NIST_CSF_MAPPING["cloudflare"]),
            "found": "yes" if cf_match else "no",
            "raw_snippet": json.dumps(cf_match)[:200] if cf_match else "",
        })

        # --- Nessus match (by hostname/IP) ---
        n_match = None
        for host_result in nessus_data:
            if host_result.get("hostname") == ip:
                n_match = host_result
                break
        report_rows.append({
            "endpoint": name,
            "ip": ip,
            "tool": "Nessus",
            "nist_csf": ", ".join(NIST_CSF_MAPPING["nessus"]),
            "found": "yes" if n_match else "no",
            "raw_snippet": json.dumps(n_match.get("raw_summary")) [:200] if n_match else "",
        })

    # ------------------------------------------------------------------
    # Step 3: Write the summary to a CSV file
    # ------------------------------------------------------------------
    csv_path = os.path.join(output_dir, "ccm_summary.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f, fieldnames=["endpoint", "ip", "tool", "nist_csf", "found", "raw_snippet"]
        )
        writer.writeheader()
        writer.writerows(report_rows)

    print(f"\nDone. Summary report written to: {csv_path}")
    print("Open the raw_*.json files in the same folder to see full detail per tool.")


if __name__ == "__main__":
    main()
