#!/usr/bin/env bash
# 无容器环境下的本地一键启动验证（仅依赖 python3 标准库）。
# 覆盖：policy 控制面 + coordinator（带崩溃监督重启）+ 3 个 mock 后端 + 独立 verifier。
set -euo pipefail
cd "$(dirname "$0")/.."

export PYTHONPATH="$PWD"
DATA_DIR="$PWD/data"
mkdir -p "$DATA_DIR"
export INTERNAL_TOKEN="dev-internal-token"
export ADMIN_TOKEN="dev-admin-token"
export POLICY_ADMIN_TOKEN="dev-admin-token"
export DELETION_SIGNING_SECRET="dev-deletion-secret"
export GLOBAL_TOMBSTONE_SECRET="dev-tombstone-secret"
export RESTRICT_SLA_SECONDS=8 PURGE_SLA_SECONDS=8 REQUEST_TTL_SECONDS=120
export CALLBACK_BASE="http://127.0.0.1:8080"
export POLICY_URL="http://127.0.0.1:8090"

PIDS=()
cleanup() {
  # 先显式杀掉监督器（它才会停止重启循环），再写停止标记并收尾。
  local sup=""
  for p in "${PIDS[@]:-}"; do
    if kill -0 "$p" 2>/dev/null; then
      # 监督脚本在 PIDS 中，业务进程也在；统一发 TERM，最后再置 stop 标记。
      :
    fi
  done
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  kill "$(cat "$DATA_DIR/coord.pid" 2>/dev/null)" 2>/dev/null || true
  touch "$DATA_DIR/coord.stop"
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
for port in 8080 8090 9101 9102 9103; do
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

rm -f "$DATA_DIR"/*.db "$DATA_DIR"/*.db-wal "$DATA_DIR"/*.db-shm "$DATA_DIR"/*.log \
      "$DATA_DIR/coord.stop" "$DATA_DIR/coord.pid" 2>/dev/null || true

# 1) 版本化合规策略控制面
POLICY_DB="$DATA_DIR/policy.db" POLICY_PORT=8090 \
  python3 -u -m policy.service >"$DATA_DIR/policy.log" 2>&1 &
PIDS+=($!)

# 2) coordinator 的崩溃监督器：注入崩溃（/admin/fault mode=crash）后自动重启，
#    重启从 SQLite 中的 migration checkpoint 恢复（演示可恢复迁移）。
cat >"$DATA_DIR/coord_supervisor.sh" <<'SH'
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
SH
chmod +x "$DATA_DIR/coord_supervisor.sh"
"$DATA_DIR/coord_supervisor.sh" &
PIDS+=($!)

start_service orders 9101 orders.db
HOLD_RECORDS="inv-1" HOLD_CODE="LEGAL_HOLD" \
HOLD_REASON="legal/financial retention" HOLD_SECONDS=6 \
  start_service billing 9102 billing.db
start_service profile 9103 profile.db

export COORD_URL="http://127.0.0.1:8080"
export POLICY_URL="http://127.0.0.1:8090"
export ORDERS_URL="http://127.0.0.1:9101"
export BILLING_URL="http://127.0.0.1:9102"
export PROFILE_URL="http://127.0.0.1:9103"
export LOCAL_SUPERVISOR="1"

python3 -m tests.verifier
