#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
source .venv/bin/activate

INTERFACE="${1:-${APT_IDS_INTERFACE:-ens33}}"
python -m app.main --mode live --interface "$INTERFACE" --config "${APT_IDS_CONFIG:-config/config.yaml}"

