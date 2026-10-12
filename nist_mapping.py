"""
nist_mapping.py

A simple lookup table connecting each monitoring tool to the NIST CSF
subcategories it's responsible for testing, matching exactly what you
defined in your Research Methods section.

Keeping this in its own file (instead of scattering it through the code)
means if your paper's mapping ever changes, there's exactly one place
to update it.
"""

NIST_CSF_MAPPING = {
    "nessus": ["ID.RA", "PR.IP"],       # Risk Assessment / vulnerabilities & patch-related
    "action1": ["PR.MA"],               # Maintenance (patch management)
    "cloudflare": ["PR.AC"],             # Access Control (DNS/web filtering enforcement)
    "sophos": ["PR.PT", "DE.CM"],        # Protective Technology / Continuous Monitoring
                                          # (not yet wired up - added once Sophos is set up)
}
