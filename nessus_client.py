"""
nessus_client.py

Talks to your local Nessus instance's REST API to pull vulnerability
scan results. Confirmed against Tenable's own API reference.

Important: Nessus Essentials/trial licenses block the /export endpoint
("Export is not allowed in trial mode"). We avoid that entirely and use
the underlying read endpoints instead (/scans, /scans/{id}, and
/scans/{id}/hosts/{host_id}), which are NOT license-gated - they return
the same underlying data, just without the packaged file wrapper.

Auth: an Access Key + Secret Key pair, sent together in one custom
header called "X-ApiKeys".

Note: Nessus uses a self-signed certificate by default (the same one
your browser warned you about), so we disable certificate verification
here. That's fine for a local lab talking to a box you control, but
would NOT be appropriate for a real production deployment.
"""

import requests
import urllib3

# Silences the "InsecureRequestWarning" that requests would otherwise
# print every time, since we're intentionally skipping cert verification
# for this local self-signed instance.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# How long to wait before giving up, in seconds: (time to connect, time to
# wait for a reply). Without this, Python waits forever if the connection
# opens but the server never answers (the "stall" you saw earlier), and the
# program just looks frozen. With it, you get a clear error after a while.
NESSUS_TIMEOUT = (10, 60)


def _headers(access_key, secret_key):
    return {
        "X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key};",
        "Content-Type": "application/json",
    }


def list_scans(host, access_key, secret_key):
    """Returns every scan (past and present) configured in this Nessus instance."""
    url = f"{host}/scans"
    response = requests.get(url, headers=_headers(access_key, secret_key), verify=False, timeout=NESSUS_TIMEOUT)
    response.raise_for_status()
    return response.json()["scans"] or []


def get_scan_details(host, access_key, secret_key, scan_id):
    """
    Returns full details for one scan, including the list of hosts it
    covered and a summary vulnerability count per host.
    """
    url = f"{host}/scans/{scan_id}"
    response = requests.get(url, headers=_headers(access_key, secret_key), verify=False, timeout=NESSUS_TIMEOUT)
    response.raise_for_status()
    return response.json()


def get_host_details(host, access_key, secret_key, scan_id, host_id):
    """Returns the detailed vulnerability findings for one specific host in a scan."""
    url = f"{host}/scans/{scan_id}/hosts/{host_id}"
    response = requests.get(url, headers=_headers(access_key, secret_key), verify=False, timeout=NESSUS_TIMEOUT)
    response.raise_for_status()
    return response.json()


def get_latest_results_per_host(host, access_key, secret_key):
    """
    Convenience function that your main CCM tool calls. For every host that
    appears in ANY completed scan, it returns that host's result from the
    NEWEST scan it appeared in.

    Why not just use the single newest scan? Because a lab often has several
    scans (for example one per group of machines). If we only read the newest
    one, every machine scanned separately would look like it was never
    assessed, which is wrong. Continuous monitoring cares about "what is the
    latest known state of each machine".
    """
    scans = list_scans(host, access_key, secret_key)

    completed_scans = [s for s in scans if s.get("status") == "completed"]
    if not completed_scans:
        raise RuntimeError(
            "No completed Nessus scans found. Run a scan first, then re-run this tool."
        )

    # Newest scan first. A host we have already seen in a newer scan is
    # skipped in older scans, which also saves API calls.
    completed_scans.sort(key=lambda s: s.get("last_modification_date", 0), reverse=True)

    newest_by_host = {}  # hostname/IP as Nessus lists it -> that host's result
    for scan in completed_scans:
        scan_id = scan["id"]
        details = get_scan_details(host, access_key, secret_key, scan_id)

        # "or []" protects against a scan that has no hosts (Nessus sends null)
        for h in details.get("hosts") or []:
            hostname = h.get("hostname")
            if hostname in newest_by_host:
                continue
            host_detail = get_host_details(host, access_key, secret_key, scan_id, h["host_id"])
            newest_by_host[hostname] = {
                "hostname": hostname,
                "scan_name": scan.get("name"),
                "scan_id": scan_id,
                "raw_summary": h,          # the summary row Nessus shows in its host list
                "raw_detail": host_detail,  # the full per-host vulnerability breakdown
            }

    return list(newest_by_host.values())
