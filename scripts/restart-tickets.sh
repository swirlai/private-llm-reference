#!/usr/bin/env bash
# Restart the tickets MCP server on a bare (non-Docker) stack, picking up the
# current VALIDATE_TOKEN_RESOURCE. This is the `make dev` equivalent of
#
#     docker compose up -d --force-recreate --no-deps mcp-tickets
#
# and exists so beat 2 can flip the audience check in one continuous take
# without Docker:
#
#     FLIP_CMD=./scripts/restart-tickets.sh python demos/02_wrong_audience.py --auto-flip
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"

pkill -f "services/mcp_tickets/server.py" 2>/dev/null || true
sleep 1

cd "$ROOT"
env PYTHONPATH="$ROOT" \
    ISSUER_URL="${ISSUER_URL:-http://localhost:8081}" \
    TICKETS_RESOURCE="${TICKETS_RESOURCE:-https://mcp.corp.internal/tickets}" \
    EMAIL_ALLOWED_DOMAINS="${EMAIL_ALLOWED_DOMAINS:-corp.internal}" \
    VALIDATE_TOKEN_RESOURCE="${VALIDATE_TOKEN_RESOURCE:-true}" \
    PYTHONUNBUFFERED=1 \
    nohup "$PY" services/mcp_tickets/server.py > /tmp/mcp_tickets.log 2>&1 &

for _ in $(seq 1 30); do
  if curl -fsS -m 2 http://localhost:8093/healthz >/dev/null 2>&1; then
    exit 0
  fi
  sleep 1
done

echo "mcp-tickets did not become healthy; see /tmp/mcp_tickets.log" >&2
exit 1
