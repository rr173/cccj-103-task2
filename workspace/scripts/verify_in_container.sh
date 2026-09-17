#!/usr/bin/env sh
# 容器默认入口之一：启动整个编排栈并执行容器启动验证（CI 友好）。
# 本镜像单进程；多服务编排由 docker-compose 完成。
# verifier 服务在 compose 中的 command 即：python3 -m tests.verifier
set -e
exec python3 -m tests.verifier
