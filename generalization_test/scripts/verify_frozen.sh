#!/usr/bin/env bash
set -euo pipefail

source "$HOME/Downloads/APT_IDS_VM_DEPLOY/generalization_test/experiment.env"

cd "$FROZEN_ROOT"

sha256sum -c SHA256SUMS.txt
