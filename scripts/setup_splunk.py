# © 2026 Manoj Mallick. SupplyGuard.
"""One-shot Splunk setup for the live dashboard demo (REST, port 8089).

Ensures the `cicd` index exists, enables HEC, and creates/fetches a HEC token.
Prints `HEC_TOKEN=<token>` on success. Credentials come from env:
    SPLUNK_REST_URL (default https://localhost:8089)
    SPLUNK_USER     (default admin)
    SPLUNK_PASSWORD (required)
"""

from __future__ import annotations

import os
import sys
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

REST = os.environ.get("SPLUNK_REST_URL", "https://localhost:8089")
USER = os.environ.get("SPLUNK_USER", "admin")
PW = os.environ.get("SPLUNK_PASSWORD", "")
TOKEN_NAME = "supplyguard"
INDEX = "cicd"


def _auth():
    return (USER, PW)


def ensure_index() -> None:
    r = requests.post(f"{REST}/services/data/indexes", auth=_auth(), verify=False,
                      data={"name": INDEX, "output_mode": "json"}, timeout=30)
    if r.status_code in (200, 201):
        print(f"  [+] index '{INDEX}' created")
    elif r.status_code == 409:
        print(f"  [=] index '{INDEX}' already exists")
    else:
        r.raise_for_status()


def enable_hec() -> None:
    r = requests.post(f"{REST}/services/data/inputs/http/http", auth=_auth(), verify=False,
                      data={"disabled": "0", "enableSSL": "1", "port": "8088",
                            "output_mode": "json"}, timeout=30)
    if r.status_code in (200, 201):
        print("  [+] HEC enabled (port 8088, SSL on)")
    else:
        print(f"  [!] HEC enable returned {r.status_code}: {r.text[:200]}")
        r.raise_for_status()


def ensure_token() -> str:
    g = requests.get(f"{REST}/services/data/inputs/http/{TOKEN_NAME}",
                     auth=_auth(), verify=False, params={"output_mode": "json"}, timeout=30)
    if g.status_code == 200:
        print(f"  [=] HEC token '{TOKEN_NAME}' already exists")
        return g.json()["entry"][0]["content"]["token"]
    c = requests.post(f"{REST}/services/data/inputs/http", auth=_auth(), verify=False,
                      data={"name": TOKEN_NAME, "index": INDEX, "indexes": INDEX,
                            "output_mode": "json"}, timeout=30)
    c.raise_for_status()
    print(f"  [+] HEC token '{TOKEN_NAME}' created")
    return c.json()["entry"][0]["content"]["token"]


def main() -> None:
    if not PW:
        sys.exit("SPLUNK_PASSWORD is not set — export it and re-run.")
    print(f"Setting up Splunk at {REST} as {USER} ...")
    ensure_index()
    enable_hec()
    print(f"HEC_TOKEN={ensure_token()}")


if __name__ == "__main__":
    main()
