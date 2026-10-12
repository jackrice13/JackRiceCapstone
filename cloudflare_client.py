"""
cloudflare_client.py

Talks to Cloudflare's API (v4) to pull the list of devices enrolled in
your Zero Trust organization. Confirmed against Cloudflare's official
API docs: https://developers.cloudflare.com/api/

Auth: a Cloudflare API Token (not the older Global API Key) sent as a
standard Bearer token.
"""

import requests

BASE_URL = "https://api.cloudflare.com/client/v4"


def get_devices(api_token, account_id):
    """
    Returns the list of physical devices enrolled in Zero Trust for this
    account - this is how we tell whether a given endpoint's Cloudflare
    client is actually connected and reporting in, matching your project's
    PR.AC (Access Control) mapping.
    """
    url = f"{BASE_URL}/accounts/{account_id}/devices/physical-devices"
    headers = {"Authorization": f"Bearer {api_token}"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()["result"]
