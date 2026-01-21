#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Validate Postgres-backed tests locally using Docker.

Usage:
  tools/db/validate_postgres_local.sh

Environment overrides:
  PYPNM_POSTGRES_CONTAINER_NAME (default: pypnm-postgres-local)
  PYPNM_POSTGRES_PORT           (default: 5432)
  PYPNM_POSTGRES_USER           (default: pypnm)
  PYPNM_POSTGRES_PASSWORD       (default: pypnm)
  PYPNM_POSTGRES_DB             (default: pypnm)

Notes:
- Requires Docker and python3.
- Runs pytest twice: a small Postgres-gated proof set with -ra, then pytest -q.
EOF
}

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
  usage
  exit 0
elif [[ $# -gt 0 ]]; then
  usage
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found in PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found in PATH" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "Cannot talk to Docker daemon (permission denied?)." >&2
  echo "Try running with sudo or add your user to the docker group." >&2
  exit 1
fi

SCRIPT_DIR="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
cd "$REPO_ROOT"

CONTAINER_NAME="${PYPNM_POSTGRES_CONTAINER_NAME:-pypnm-postgres-local}"
POSTGRES_PORT="${PYPNM_POSTGRES_PORT:-5432}"
POSTGRES_USER="${PYPNM_POSTGRES_USER:-pypnm}"
POSTGRES_PASSWORD="${PYPNM_POSTGRES_PASSWORD:-pypnm}"
POSTGRES_DB="${PYPNM_POSTGRES_DB:-pypnm}"

cleanup() {
  if docker ps -a --format '{{.Names}}' | grep -qx "${CONTAINER_NAME}"; then
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

cleanup

docker run -d \
  --name "${CONTAINER_NAME}" \
  -e POSTGRES_USER="${POSTGRES_USER}" \
  -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
  -e POSTGRES_DB="${POSTGRES_DB}" \
  -p "${POSTGRES_PORT}:5432" \
  postgres:16 >/dev/null

for attempt in $(seq 1 30); do
  if docker exec "${CONTAINER_NAME}" pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

if ! docker exec "${CONTAINER_NAME}" pg_isready -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" >/dev/null 2>&1; then
  echo "Postgres did not become ready in time" >&2
  exit 1
fi

export PYPNM_DB_BACKEND="postgres"
export PYPNM_TEST_POSTGRES="1"
export PYPNM_DB_POSTGRES_DSN="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@localhost:${POSTGRES_PORT}/${POSTGRES_DB}"

python3 -m pip install --upgrade pip
python3 -m pip install -e ".[dev,postgres]"

python3 - <<'PY'
import os
from urllib.parse import urlparse

dsn = os.environ.get("PYPNM_DB_POSTGRES_DSN", "")
parsed = urlparse(dsn)
host = parsed.hostname or ""
port = parsed.port or ""
db = parsed.path.lstrip("/")
user = parsed.username or ""
print(f"PYPNM_DB_POSTGRES_DSN=postgresql://{user}:***@{host}:{port}/{db}")
PY
python3 -c "import psycopg; print(psycopg.__version__)"

proof_output="$(python3 -m pytest -q -ra \
  tests/test_db_schema_manager.py::test_postgres_schema_init_optional \
  tests/test_artifact_repository.py::test_postgres_transaction_artifact_resolution_optional)"
printf '%s\n' "$proof_output"
if printf '%s\n' "$proof_output" | grep -qi "skipped"; then
  echo "Postgres-gated proof tests were skipped; check env vars and psycopg install." >&2
  exit 1
fi

python3 -m pytest -q
