#!/usr/bin/env bash
# 协调端崩溃监督器：os._exit(77) 等崩溃后自动重启，从 SQLite checkpoint 恢复。
set -u
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD"
DATA_DIR="$PWD/data"
while [ ! -f "$DATA_DIR/coord.stop" ]; do
  INTERNAL_TOKEN=dev-internal-token ADMIN_TOKEN=dev-admin-token \
  DELETION_SIGNING_SECRET=dev-deletion-secret GLOBAL_TOMBSTONE_SECRET=dev-tombstone-secret \
  RESTRICT_SLA_SECONDS=8 PURGE_SLA_SECONDS=8 REQUEST_TTL_SECONDS=120 \
  CALLBACK_BASE="http://127.0.0.1:8080" POLICY_URL="http://127.0.0.1:8090" \
  COORDINATOR_DB="$DATA_DIR/coordinator.db" \
    python3 -u -m coordinator.app >>"$DATA_DIR/coordinator.log" 2>&1 &
  cp=$!
  echo "$cp" > "$DATA_DIR/coord.pid"
  wait "$cp"
  rc=$?
  echo "[supervisor] coordinator exited rc=$rc; restarting in 0.5s" \
    >>"$DATA_DIR/coordinator.log"
  sleep 0.5
done
