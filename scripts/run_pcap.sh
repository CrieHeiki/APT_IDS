#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
source .venv/bin/activate

PCAP="${1:-${APT_IDS_PCAP:-samples/test.pcap}}"
python -m app.main --mode pcap --pcap "$PCAP" --config "${APT_IDS_CONFIG:-config/config.yaml}"

