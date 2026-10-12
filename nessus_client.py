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


def get_latest_scan_results(host, access_key, secret_key):
    """
    Convenience function: finds the most recently completed scan and
    pulls full per-host detail for every host in it. This is what your
    main CCM tool will actually call.
    """
    scans = list_scans(host, access_key, secret_key)

    completed_scans = [s for s in scans if s.get("status") == "completed"]
    if not completed_scans:
        raise RuntimeError(
            "No completed Nessus scans found. Run a scan first, then re-run this tool."
        )

    # Most recently modified completed scan
    latest = max(completed_scans, key=lambda s: s.get("last_modification_date", 0))
    scan_id = latest["id"]

    details = get_scan_details(host, access_key, secret_key, scan_id)
    hosts = details.get("hosts", [])

    results = []
    for h in hosts:
        host_detail = get_host_details(host, access_key, secret_key, scan_id, h["host_id"])
        results.append(
            {
                "hostname": h.get("hostname"),
                "scan_name": latest.get("name"),
                "raw_summary": h,          # the summary row Nessus shows in its host list
                "raw_detail": host_detail,  # the full per-host vulnerability breakdown
            }
        )

    return results
