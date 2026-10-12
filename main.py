"""
main.py

This is the actual CCM (Continuous Controls Monitoring) tool for your
capstone project. It does three things, one after another:

  1. Pulls current data from Action1, Cloudflare, and Nessus
  2. Saves the raw (unprocessed) API responses to disk, so you can see
     exactly what each tool actually returned
  3. Builds a simple summary report, one row per endpoint per tool,
     and writes it to a CSV file you can open in Excel

How endpoints are matched to each tool's data:
  - Action1:    by IP address (searched anywhere in the record), or by
                hostname if the IP isn't found
  - Cloudflare: by hostname (Cloudflare lists devices by computer name)
  - Nessus:     by IP address (Nessus lists hosts by the address scanned)

Note: the connection and login code is confirmed against each tool's
documentation and has now run successfully against your live Action1 and
Cloudflare accounts. The "found yes/no" matching is the simplest possible
check. Richer status fields (is it patched? when was it last seen?) come
from the raw_*.json files and get added to the report as the next step.

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


def value_has_ip(value, ip):
    """
    Returns True if `value` is, or contains, exactly this IP address.

    We don't know in advance which field name a tool uses for its IP
    address ("address"? "ip"? "ip_address"?), so instead of guessing, this
    looks through every value in the record. It handles three shapes:
      - a plain string, e.g. "10.0.2.50"
      - several addresses in one string, e.g. "10.0.2.50, fe80::1"
      - a dict or list that has the address somewhere inside it
    It compares whole addresses only, so "10.0.2.5" will NOT match
    "10.0.2.50".
    """
    if isinstance(value, str):
        # Turn commas and semicolons into spaces, then split into pieces.
        pieces = value.replace(",", " ").replace(";", " ").split()
        return ip in pieces
    if isinstance(value, dict):
        return any(value_has_ip(v, ip) for v in value.values())
    if isinstance(value, list):
        return any(value_has_ip(v, ip) for v in value)
    return False  # numbers, True/False, None can't be an IP address


def find_by_ip(items, ip):
    """Returns the first record that contains this IP anywhere, else None."""
    for item in items:
        if value_has_ip(item, ip):
            return item
    return None


def find_by_hostname(items, hostname, possible_name_keys):
    """
    Returns the first record whose name field equals this hostname (ignoring
    upper/lower case), else None. If we don't know the hostname yet
    (hostname is None) there is nothing to compare, so it returns None.
    """
    if not hostname:
        return None
    target = hostname.lower()
    for item in items:
        for key in possible_name_keys:
            value = item.get(key)
            if value and str(value).lower() == target:
                return item
    return None


def find_nessus_host(nessus_data, ip, hostname):
    """
    Nessus lists each host exactly as it was typed into the scan's target
    list: usually an IP like "10.0.2.51", but sometimes a name like
    "linuxws" or "linuxws.lab.local". So this accepts either form.
    """
    for result in nessus_data:
        listed = result.get("hostname")
        if not listed:
            continue
        if listed == ip:
            return result
        if hostname:
            # Compare only the part before the first dot, ignoring case, so
            # "LinuxWS.lab.local" still matches "linuxws". (An IP such as
            # "10.0.2.51" becomes "10", which won't equal a real hostname.)
            if listed.split(".")[0].lower() == hostname.lower():
                return result
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
            config.ACTION1_BASE_URL,
            config.ACTION1_CLIENT_ID,
            config.ACTION1_CLIENT_SECRET,
        )
        save_raw("action1", action1_data, output_dir)
        print(f"  Got {len(action1_data)} endpoint(s) from Action1.")
        # Diagnostic: field names and computer names are not sensitive, and
        # seeing them lets us fill in the hostnames in config.py.
        if action1_data:
            print(f"  Action1 fields: {sorted(action1_data[0].keys())}")
            print("  Action1 endpoint name -> address:")
            for e in action1_data:
                print(f"    {e.get('name')} -> {e.get('address')}")
            print()
    except Exception as e:
        print(f"  Action1 FAILED: {e}\n")

    print("Pulling Cloudflare Zero Trust data...")
    try:
        cloudflare_data = cloudflare_client.get_devices(
            config.CLOUDFLARE_API_TOKEN, config.CLOUDFLARE_ACCOUNT_ID
        )
        save_raw("cloudflare", cloudflare_data, output_dir)
        print(f"  Got {len(cloudflare_data)} device(s) from Cloudflare.")
        print(f"  Cloudflare device names: {[d.get('name') for d in cloudflare_data]}\n")
    except Exception as e:
        print(f"  Cloudflare FAILED: {e}\n")

    # Printing the (non-secret) address makes it obvious if .env isn't being
    # read the way you expect. Never print the API keys.
    print(f"Pulling Nessus data from {config.NESSUS_HOST} ...")
    try:
        nessus_data = nessus_client.get_latest_results_per_host(
            config.NESSUS_HOST, config.NESSUS_ACCESS_KEY, config.NESSUS_SECRET_KEY
        )
        save_raw("nessus", nessus_data, output_dir)
        print(f"  Got {len(nessus_data)} host result(s) from Nessus.")
        # Diagnostic: which hosts Nessus knows about and which scan each came from.
        print("  Nessus host -> scan it came from:")
        for r in nessus_data:
            print(f"    {r.get('hostname')} -> {r.get('scan_name')}")
        print()
    except Exception as e:
        print(f"  Nessus FAILED: {e}\n")

    # ------------------------------------------------------------------
    # Step 2: Match each tool's data back to your known testbed endpoints
    # and write one summary row per (endpoint, tool) combination.
    # ------------------------------------------------------------------
    report_rows = []
    found_table = []  # one entry per endpoint, used for the printout at the end

    for endpoint in config.ENDPOINTS:
        name = endpoint["name"]
        ip = endpoint["ip"]
        hostname = endpoint.get("hostname")

        # --- Action1: IP anywhere in the record, else fall back to hostname ---
        a1_match = find_by_ip(action1_data, ip)
        if a1_match is None:
            a1_match = find_by_hostname(action1_data, hostname, ["name", "hostname"])
        report_rows.append({
            "endpoint": name,
            "ip": ip,
            "tool": "Action1",
            "nist_csf": ", ".join(NIST_CSF_MAPPING["action1"]),
            "found": "yes" if a1_match else "no",
            "raw_snippet": json.dumps(a1_match)[:200] if a1_match else "",
        })

        # --- Cloudflare: by hostname (devices are listed by computer name) ---
        cf_match = find_by_hostname(cloudflare_data, hostname, ["name"])
        report_rows.append({
            "endpoint": name,
            "ip": ip,
            "tool": "Cloudflare",
            "nist_csf": ", ".join(NIST_CSF_MAPPING["cloudflare"]),
            "found": "yes" if cf_match else "no",
            "raw_snippet": json.dumps(cf_match)[:200] if cf_match else "",
        })

        # --- Nessus: by the address/name that was scanned (IP or hostname) ---
        n_match = find_nessus_host(nessus_data, ip, hostname)
        report_rows.append({
            "endpoint": name,
            "ip": ip,
            "tool": "Nessus",
            "nist_csf": ", ".join(NIST_CSF_MAPPING["nessus"]),
            "found": "yes" if n_match else "no",
            "raw_snippet": json.dumps(n_match.get("raw_summary"))[:200] if n_match else "",
        })

        found_table.append((
            name,
            "yes" if a1_match else "no",
            "yes" if cf_match else "no",
            "yes" if n_match else "no",
        ))

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

    # A quick on-screen version of the same information.
    print("Did each tool see each endpoint?")
    print(f"  {'Endpoint':<22}{'Action1':<10}{'Cloudflare':<12}{'Nessus':<8}")
    for row in found_table:
        print(f"  {row[0]:<22}{row[1]:<10}{row[2]:<12}{row[3]:<8}")

    print(f"\nDone. Summary report written to: {csv_path}")
    print("Open the raw_*.json files in the same folder to see full detail per tool.")


if __name__ == "__main__":
    main()
