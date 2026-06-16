#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ -x ".venv/bin/packetscrubber" ]]; then
  exec ".venv/bin/packetscrubber"
fi

if [[ -x ".venv/bin/python" ]]; then
  exec ".venv/bin/python" -m packetscrubber.gui
fi

exec python3 -m packetscrubber.gui
