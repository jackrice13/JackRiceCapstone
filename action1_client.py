"""
action1_client.py

Talks to Action1's REST API to pull patch management status for each
managed endpoint. Confirmed against Action1's official API docs:
https://www.action1.com/api-documentation/

Auth flow: exchange your Client ID + Client Secret for a short-lived
JWT access token, then use that token as a Bearer token on every
subsequent request.

Regions: Action1 runs separate copies of its service in different parts
of the world, and each copy has its own web address. Your Client ID and
Secret only work on the copy where your account lives. If you use the
wrong address you get a "401 Unauthorized" even though the credentials
are correct. The address is passed in as `base_url` (it comes from the
ACTION1_BASE_URL setting in your .env file via config.py). The common ones:

    North America (default) -> https://app.action1.com/api/3.0
    North America 2         -> https://app.na-2.action1.com/api/3.0
    Europe                  -> https://app.eu.action1.com/api/3.0
    United Kingdom          -> https://app.uk.action1.com/api/3.0
    Australia               -> https://app.au.action1.com/api/3.0

A quick way to find yours: it's the address you see in the browser when
you are logged into the Action1 console, followed by /api/3.0.
"""

import requests


def get_access_token(base_url, client_id, client_secret):
    """
    Step 1 of every Action1 session: trade your permanent Client ID/Secret
    for a temporary access token (expires after about an hour).
    """
    url = f"{base_url}/oauth2/token"
    data = {"client_id": client_id, "client_secret": client_secret}
    response = requests.post(url, data=data, timeout=30)

    # If the login fails, show WHAT the server said and WHERE we sent it,
    # instead of only a bare "401 Unauthorized". The server's message is
    # the fastest way to tell a wrong region from a wrong secret.
    if not response.ok:
        raise RuntimeError(
            f"Action1 login failed (HTTP {response.status_code}) at {url}. "
            f"Server said: {response.text[:300]}"
        )
    return response.json()["access_token"]


def get_organizations(base_url, token):
    """Returns the list of organizations (Action1 'workspaces') on this account."""
    url = f"{base_url}/organizations"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers, timeout=30)
    response.raise_for_status()
    return response.json()["items"]


def get_managed_endpoints(base_url, token, organization_id):
    """
    Returns every endpoint Action1 manages under this organization, with
    extended fields (patch status, OS info, last-seen time, etc.)
    since we pass fields=* to ask for everything rather than the default
    summary view.
    """
    url = f"{base_url}/endpoints/managed/{organization_id}"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"fields": "*"}
    response = requests.get(url, headers=headers, params=params, timeout=30)
    response.raise_for_status()
    return response.json()["items"]


def get_all_endpoint_data(base_url, client_id, client_secret):
    """
    Convenience function that does the whole Action1 flow in one call:
    authenticate -> find your organization(s) -> pull every endpoint's data.
    Returns a flat list of endpoint dicts (raw, as Action1 sends them).
    """
    base_url = base_url.rstrip("/")  # tolerate a trailing slash in the .env value

    token = get_access_token(base_url, client_id, client_secret)
    orgs = get_organizations(base_url, token)

    all_endpoints = []
    for org in orgs:
        endpoints = get_managed_endpoints(base_url, token, org["id"])
        all_endpoints.extend(endpoints)

    return all_endpoints
