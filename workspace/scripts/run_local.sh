#!/usr/bin/env bash
# 无容器环境下的本地一键启动验证（仅依赖 python3 标准库）。
set -euo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="$PWD"
DATA_DIR="$PWD/data"
mkdir -p "$DATA_DIR"
export INTERNAL_TOKEN="dev-internal-token"
export ADMIN_TOKEN="dev-admin-token"
export DELETION_SIGNING_SECRET="dev-deletion-secret"
export GLOBAL_TOMBSTONE_SECRET="dev-tombstone-secret"
export RESTRICT_SLA_SECONDS=8 PURGE_SLA_SECONDS=8 REQUEST_TTL_SECONDS=120
export CALLBACK_BASE="http://127.0.0.1:8080"

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
}
trap cleanup EXIT

start_service() { # name port db extra-env
  local name=$1 port=$2 db=$3
  SERVICE_NAME="$name" SERVICE_PORT="$port" SERVICE_DB="$DATA_DIR/$db" \
    python3 -u -m services.mock_service >"$DATA_DIR/$name.log" 2>&1 &
  PIDS+=($!)
}

# 确保没有占用端口的旧实例（容器内首次运行是空操作）
for port in 8080 9101 9102 9103; do
  pid=$(python3 - "$port" <<'PY'
import sys, socket
port = int(sys.argv[1])
s = socket.socket()
try:
    s.connect(("127.0.0.1", port))
    print("busy")
except OSError:
    print("free")
finally:
    s.close()
PY
)
  if [ "$pid" = busy ]; then
    echo "端口 $port 被占用，脚本仅在干净环境运行（容器内不会发生）" >&2
    exit 2
  fi
done

rm -f "$DATA_DIR"/*.db "$DATA_DIR"/*.db-wal "$DATA_DIR"/*.db-shm "$DATA_DIR"/*.log 2>/dev/null || true
COORDINATOR_DB="$DATA_DIR/coordinator.db" python3 -u -m coordinator.app \
  >"$DATA_DIR/coordinator.log" 2>&1 &
PIDS+=($!)

start_service orders 9101 orders.db
HOLD_RECORDS="inv-1" HOLD_CODE="LEGAL_HOLD" \
HOLD_REASON="legal/financial retention" HOLD_SECONDS=6 \
  start_service billing 9102 billing.db
start_service profile 9103 profile.db

export COORD_URL="http://127.0.0.1:8080"
export ORDERS_URL="http://127.0.0.1:9101"
export BILLING_URL="http://127.0.0.1:9102"
export PROFILE_URL="http://127.0.0.1:9103"

python3 -m tests.verifier
