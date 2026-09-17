#!/usr/bin/env bash
# 仅本地验证用的协调端监督进程：迁移崩溃注入（os._exit）后自动重启协调端，
# 重启的进程读取同一 SQLite 的持久迁移检查点并完成剩余迁移。
# 容器编排（docker-compose restart: unless-stopped）提供等价能力。
set -u
cd "$(dirname "$0")/.."
export PYTHONPATH="$PWD"
: "${COORDINATOR_DB:=$PWD/data/coordinator.db}"
LOG="$PWD/data/coordinator.log"
: >"$LOG"
trap 'kill $(jobs -p) 2>/dev/null || true' EXIT
while true; do
  python3 -u -m coordinator.app >>"$LOG" 2>&1 &
  pid=$!
  wait "$pid"
  code=$?
  echo "[supervisor] coordinator exited code=$code; restarting in 0.5s" \
    >>"$LOG"
  sleep 0.5
done
