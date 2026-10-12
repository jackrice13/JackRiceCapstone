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

Open `config.py` and confirm the `ENDPOINTS` list matches your testbed:
each endpoint's IP address and its real computer name (`hostname`). The
Domain Controller is currently `10.0.2.3`, as Action1 reports it. Run
`ipconfig` on any machine to confirm its address.

Nessus is reached over the VirtualBox Host-Only network, so `.env` should
contain `NESSUS_HOST=https://192.168.56.52:8834`.

## Running it

```
python main.py
```

This will:
- Log into each tool and pull current data
- Save the raw (unprocessed) API response from each tool into a new
  timestamped folder, e.g. `ccm_report_20261012_155053/`
- Judge each endpoint's data and write two CSV files in that folder:
  - `ccm_summary.csv`: one row per endpoint per tool, with the verdict,
    the evidence behind it, the NIST CSF subcategories, and how long ago
    the tool last saw the endpoint
  - `ccm_matrix.csv`: one row per endpoint, one column per tool (the
    compact table, handy for pasting into a paper)

## How a verdict is decided

The rules live in `assessment.py`. Thresholds live in `config.py`.

| Tool | NIST CSF | FAIL | WARN | PASS |
|---|---|---|---|---|
| Action1 | PR.MA | Critical updates or critical vulnerabilities found | Other updates or vulnerabilities, reboot pending, agent not connected, or stale data | None of those |
| Cloudflare | PR.AC | No active registration | Not seen recently (stale) | Registered and seen recently |
| Nessus | ID.RA, PR.IP | Any critical or high finding | Medium findings, or the scan is stale | Only low or informational findings |

Other values you may see:

| Value | Meaning |
|---|---|
| UNKNOWN | The tool returned the endpoint but not the fields needed to judge it |
| NOT_FOUND | The tool has no record of the endpoint at all (worth investigating) |
| N/A | The tool cannot be installed there (listed in `EXPECTED_GAPS` in `config.py`) |

These rules are judgement calls. Keep them consistent with the pass/fail
criteria in your methodology section, and change them in one place if the
methodology changes.

## If something looks wrong

- **An endpoint shows NOT_FOUND:** check that its `ip` and `hostname` in
  `config.py` are right. Action1 is matched by IP anywhere in the record,
  falling back to hostname. Cloudflare is matched by hostname. Nessus is
  matched by the address or name that was scanned.
- **A Nessus row shows UNKNOWN:** the severity counts were in a format the
  code did not recognize. Open `raw_nessus.json` and look at the
  `raw_summary` for that host.
- **Many rows WARN with "STALE":** the data is older than the limit set in
  `STALE_AFTER_MINUTES`. Re-run the scan or wait for the agent to check in.
- **Disk full or other errors:** each tool is pulled separately, so one
  failure does not stop the others. Read the "FAILED" line for that tool.

## Files

| File | What it does |
|---|---|
| `config.py` | Loads credentials from `.env`; defines endpoints, stale limits, and expected gaps |
| `action1_client.py` | Talks to the Action1 API |
| `cloudflare_client.py` | Talks to the Cloudflare Zero Trust API |
| `nessus_client.py` | Talks to your local Nessus instance |
| `nist_mapping.py` | Which NIST CSF subcategories each tool covers |
| `assessment.py` | The PASS / WARN / FAIL rules |
| `main.py` | Runs everything and builds the report |
