#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
  # shellcheck disable=SC1091
  source .venv/bin/activate
  pip install -U pip
  pip install -e ".[dev]"
else
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

# Fresh audit log for a clean demo run
mkdir -p audit/logs
: > audit/logs/access.jsonl

echo "==> AgentThree Confidential AI demo (local, zero cloud cost)"
agentthree-cai demo
echo
agentthree-cai audit-show --limit 5
