"""
action1_client.py

Talks to Action1's REST API to pull patch management status for each
managed endpoint. Confirmed against Action1's official API docs:
https://www.action1.com/api-documentation/

Auth flow: exchange your Client ID + Client Secret for a short-lived
JWT access token, then use that token as a Bearer token on every
subsequent request.
"""

import requests

BASE_URL = "https://app.action1.com/api/3.0"


def get_access_token(client_id, client_secret):
    """
    Step 1 of every Action1 session: trade your permanent Client ID/Secret
    for a temporary access token (expires after about an hour).
    """
    url = f"{BASE_URL}/oauth2/token"
    data = {"client_id": client_id, "client_secret": client_secret}
    response = requests.post(url, data=data)
    response.raise_for_status()  # raises an error here instead of failing silently later
    return response.json()["access_token"]


def get_organizations(token):
    """Returns the list of organizations (Action1 'workspaces') on this account."""
    url = f"{BASE_URL}/organizations"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()["items"]


def get_managed_endpoints(token, organization_id):
    """
    Returns every endpoint Action1 manages under this organization, with
    extended fields (patch status, OS info, last-seen time, etc.)
    since we pass fields=* to ask for everything rather than the default
    summary view.
    """
    url = f"{BASE_URL}/endpoints/managed/{organization_id}"
    headers = {"Authorization": f"Bearer {token}"}
    params = {"fields": "*"}
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    return response.json()["items"]


def get_all_endpoint_data(client_id, client_secret):
    """
    Convenience function that does the whole Action1 flow in one call:
    authenticate -> find your organization(s) -> pull every endpoint's data.
    Returns a flat list of endpoint dicts (raw, as Action1 sends them).
    """
    token = get_access_token(client_id, client_secret)
    orgs = get_organizations(token)

    all_endpoints = []
    for org in orgs:
        endpoints = get_managed_endpoints(token, org["id"])
        all_endpoints.extend(endpoints)

    return all_endpoints
