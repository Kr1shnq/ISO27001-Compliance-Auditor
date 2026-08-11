#!/usr/bin/env bash
# Launch the ISO 27001 Compliance Auditor.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "Creating virtual environment..."
  python3 -m venv .venv
  ./.venv/bin/pip install -q --upgrade pip
  ./.venv/bin/pip install -q -r requirements.txt
fi

# Rebuild the baseline if the generator is newer than the JSON it produces.
if [ data/build_baseline.py -nt data/iso27001_baseline.json ]; then
  ./.venv/bin/python data/build_baseline.py
fi

echo "Starting on http://localhost:8501 — press Ctrl+C to stop."
exec ./.venv/bin/streamlit run app/main.py
