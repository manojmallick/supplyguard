#!/usr/bin/env bash
# © 2026 Manoj Mallick. SupplyGuard — one-command live setup against real Splunk.
#
#   SPLUNK_USER=admin SPLUNK_PASSWORD=*** ./run_live.sh
#
# Enables HEC + creates the token, seeds index=cicd with 7 days of supply-chain
# data plus the agent's real block decision, then prints the verification search.
set -euo pipefail
cd "$(dirname "$0")"

: "${SPLUNK_USER:?set SPLUNK_USER}"
: "${SPLUNK_PASSWORD:?set SPLUNK_PASSWORD}"
export SPLUNK_REST_URL="${SPLUNK_REST_URL:-https://localhost:8089}"

echo "▶ 1/3  Splunk setup (index=cicd + HEC + token)"
TOKEN="$(python3 scripts/setup_splunk.py | sed -n 's/^HEC_TOKEN=//p')"
if [ -z "${TOKEN}" ]; then echo "setup failed — run scripts/setup_splunk.py directly to see why"; exit 1; fi
export SPLUNK_HEC_TOKEN="${TOKEN}"
export SPLUNK_HEC_URL="${SPLUNK_HEC_URL:-https://localhost:8088/services/collector/event}"
echo "  HEC token acquired: ${TOKEN:0:8}***"

echo "▶ 2/3  Seed index=cicd (7d history + live agent block decision)"
python3 scripts/seed_splunk.py

echo "▶ 3/3  Next steps"
cat <<'EOF'
  • In Splunk Web → Dashboards → Create New → Dashboard Studio → Source,
    paste dashboards/supplyguard_security.json, then set the time range to
    "Last 7 days". Every panel renders from index=cicd.
  • Verify in Search:
      index=cicd | stats count by sourcetype
      index=cicd sourcetype=supply_chain_decision action.kind=block_build
EOF
