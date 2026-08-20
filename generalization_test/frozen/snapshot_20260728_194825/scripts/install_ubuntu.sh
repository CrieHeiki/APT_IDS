#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt

mkdir -p logs state work/cicflowmeter

cat <<'MSG'
Python environment is ready.

Install CICFlowMeter separately, then update config/config.yaml:
  cicflowmeter.commands.live
  cicflowmeter.commands.pcap

Packet capture may require running the external CICFlowMeter command with
CAP_NET_RAW/CAP_NET_ADMIN or elevated shell privileges. The Python app does not
call sudo internally.
MSG

