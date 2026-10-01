#!/bin/sh
# Legacy NfSen bookkeeping integration tests. No running NfSen/RRD is needed.
command -v python3 >/dev/null 2>&1 || exit 77
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
export BINDIR="${BINDIR:-$SCRIPT_DIR/..}"
python3 "$SCRIPT_DIR/test_nfprofile.py"
