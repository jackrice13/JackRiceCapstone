# CCM Tool

Continuous Controls Monitoring tool for the capstone project. Pulls current
compliance-relevant data from Action1, Cloudflare Zero Trust, and Nessus,
and builds a summary report mapped to NIST CSF subcategories.

Sophos is not wired up yet - add it once that trial account exists.

## Setup (one-time)

1. Install Python 3.8 or newer if you don't already have it.
2. In this folder, install the required packages:
   ```
   pip install -r requirements.txt
   ```
3. Copy `.env.example` to a new file named `.env`:
   ```
   cp .env.example .env
   ```
4. Open `.env` in a text editor and fill in your real credentials for
   Action1, Cloudflare, and Nessus (see the comments in that file for
   exactly where to find each one in each tool's console).

### Action1 region (important)

Action1 runs a separate copy of its service per world region, and your
Client ID and Secret only work on the copy where your account lives.
This project's account is on **na-2**, so `.env` should contain:

```
ACTION1_BASE_URL=https://app.na-2.action1.com/api/3.0
```

If you leave that line out, the code falls back to the na-2 address. A
wrong region produces a `401 Unauthorized` even when the credentials are
correct. To find yours, look at the address bar while logged into the
Action1 console and add `/api/3.0` to the end.

## Double-check before your first run

Open `config.py` and confirm the `ENDPOINTS` list matches your actual
testbed IPs - especially the **Domain Controller's IP**, which was marked
with a "confirm this is right" comment since we never pinned it down
directly in our setup conversation. Run `ipconfig` on the DC and update
that line if it's wrong.

## Running it

```
python main.py
```

This will:
- Log into each tool and pull current data
- Save the raw (unprocessed) API response from each tool into a new
  timestamped folder, e.g. `ccm_report_20260927_143000/`
- Build a summary CSV (`ccm_summary.csv`) in that same folder, showing
  whether each endpoint was found in each tool's data

## If something looks wrong

If the summary CSV shows "no" for an endpoint you know is actually
enrolled, open the matching `raw_<tool>.json` file in that same output
folder and look at the actual field names Python got back - the
matching logic in `main.py` (the `find_by_ip` / `find_by_name_fragment`
functions) is a best guess at what those fields are called, since it
was written without being able to test live against your real accounts.
Share what the raw JSON actually looks like and the matching logic can
be adjusted to fit.

## Files

| File | What it does |
|---|---|
| `config.py` | Loads credentials from `.env`, defines your known endpoints |
| `action1_client.py` | Talks to the Action1 API |
| `cloudflare_client.py` | Talks to the Cloudflare Zero Trust API |
| `nessus_client.py` | Talks to your local Nessus instance |
| `nist_mapping.py` | Which NIST CSF subcategories each tool covers |
| `main.py` | Runs everything and builds the report |
