#!/usr/bin/env bash
set -euo pipefail
python -m pip install -q -e ".[dev]"
ruff check .
ruff format --check .
mypy src
pytest -q --cov=zero_trust_edge_agent_mesh --cov-report=term-missing --cov-fail-under=90
bash scripts/tlc.sh
