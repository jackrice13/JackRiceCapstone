"""
main.py

This is the actual CCM (Continuous Controls Monitoring) tool for your
capstone project. It does three things, one after another:

  1. Pulls current data from Action1, Cloudflare, and Nessus
  2. Saves the raw (unprocessed) API responses to disk, so you can see
     exactly what each tool actually returned
  3. Judges each endpoint's data (PASS / WARN / FAIL, using the rules in
     assessment.py) and writes the results to CSV files you can open in
     Excel: a detailed one (one row per endpoint per tool, with evidence)
     and a compact one (one row per endpoint)

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
from datetime import datetime, timezone

import config
import action1_client
import assessment
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


def print_compliance_peek(action1_data, cloudflare_data, nessus_data):
    """
    Prints a short preview of the compliance-related fields from each tool,
    so we can see what real values look like before building the report
    columns. Only the fields listed below are shown on purpose. The raw
    records also contain things like usernames, serial numbers, MAC and
    public IP addresses, which should not be pasted into a chat.
    """
    def short(value):
        # Turn any value into text and cut it off at 200 characters.
        return json.dumps(value, default=str)[:200]

    action1_fields = [
        "name", "online_status", "status", "last_seen", "update_status",
        "missing_updates", "vulnerability_status", "vulnerabilities",
        "reboot_required", "OS",
    ]
    cloudflare_fields = [
        "name", "last_seen_at", "client_version", "os_version",
        "device_type", "active_registrations",
    ]

    print("Compliance data preview (what the report will be built from):")

    print("  Action1:")
    for e in action1_data:
        print(f"    {e.get('name')}")
        for field in action1_fields[1:]:
            print(f"      {field}: {short(e.get(field))}")

    print("  Cloudflare:")
    for d in cloudflare_data:
        print(f"    {d.get('name')}")
        for field in cloudflare_fields[1:]:
            print(f"      {field}: {short(d.get(field))}")

    print("  Nessus (the summary row for each host):")
    for r in nessus_data:
        print(f"    {r.get('hostname')}: {short(r.get('raw_summary'))}")
    print()


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

    print_compliance_peek(action1_data, cloudflare_data, nessus_data)

    # ------------------------------------------------------------------
    # Step 2: Match each tool's data back to your known testbed endpoints
    # and write one summary row per (endpoint, tool) combination.
    # ------------------------------------------------------------------
    report_rows = []
    status_table = []  # one entry per endpoint, used for the printout at the end

    now = datetime.now(timezone.utc)  # one timestamp for the whole run, in UTC

    for endpoint in config.ENDPOINTS:
        name = endpoint["name"]
        ip = endpoint["ip"]
        hostname = endpoint.get("hostname")

        # Find this endpoint's record in each tool's data.
        # Action1: IP anywhere in the record, else fall back to hostname
        a1_match = find_by_ip(action1_data, ip)
        if a1_match is None:
            a1_match = find_by_hostname(action1_data, hostname, ["name", "hostname"])
        # Cloudflare: by hostname (devices are listed by computer name)
        cf_match = find_by_hostname(cloudflare_data, hostname, ["name"])
        # Nessus: by the address/name that was scanned (IP or hostname)
        n_match = find_nessus_host(nessus_data, ip, hostname)

        # (label, key used in config.py and nist_mapping.py, matched record,
        #  the function in assessment.py that judges that tool's data)
        tools = [
            ("Action1", "action1", a1_match, assessment.assess_action1),
            ("Cloudflare", "cloudflare", cf_match, assessment.assess_cloudflare),
            ("Nessus", "nessus", n_match, assessment.assess_nessus),
        ]

        statuses = {}
        for label, key, match, judge in tools:
            if match is None:
                verdict = assessment.assess_missing(name, key, label, config.EXPECTED_GAPS)
            else:
                verdict = judge(match, now, config.STALE_AFTER_MINUTES[key])
            statuses[label] = verdict["status"]

            last_seen = verdict["last_seen"]
            age = assessment.minutes_between(last_seen, now)
            report_rows.append({
                "endpoint": name,
                "ip": ip,
                "tool": label,
                "nist_csf": ", ".join(NIST_CSF_MAPPING[key]),
                "found": "yes" if match is not None else "no",
                "status": verdict["status"],
                "evidence": verdict["evidence"],
                "last_seen_utc": last_seen.strftime("%Y-%m-%d %H:%M:%S") if last_seen else "",
                "minutes_since_seen": "" if age is None else age,
                "collected_utc": now.strftime("%Y-%m-%d %H:%M:%S"),
            })

        status_table.append(
            (name, statuses["Action1"], statuses["Cloudflare"], statuses["Nessus"])
        )

    # ------------------------------------------------------------------
    # Step 3: Write the results to CSV files
    # ------------------------------------------------------------------
    # The detailed file: one row per endpoint per tool, with the evidence.
    csv_path = os.path.join(output_dir, "ccm_summary.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "endpoint", "ip", "tool", "nist_csf", "found", "status",
                "evidence", "last_seen_utc", "minutes_since_seen", "collected_utc",
            ],
        )
        writer.writeheader()
        writer.writerows(report_rows)

    # The compact file: one row per endpoint, one column per tool.
    matrix_path = os.path.join(output_dir, "ccm_matrix.csv")
    with open(matrix_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["endpoint", "Action1", "Cloudflare", "Nessus"])
        writer.writerows(status_table)

    # A quick on-screen version of the compact table.
    print("Verdict for each endpoint, by tool:")
    print(f"  {'Endpoint':<22}{'Action1':<12}{'Cloudflare':<12}{'Nessus':<12}")
    for row in status_table:
        print(f"  {row[0]:<22}{row[1]:<12}{row[2]:<12}{row[3]:<12}")
    print("  (PASS / WARN / FAIL = verdict, UNKNOWN = data missing, "
          "NOT_FOUND = tool has no record, N/A = tool can't run there)")

    print(f"\nDone. Detailed report: {csv_path}")
    print(f"      Compact table:   {matrix_path}")
    print("Open the raw_*.json files in the same folder to see full detail per tool.")


if __name__ == "__main__":
    main()
