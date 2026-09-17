# 零第三方依赖：仅需 python3 标准库。选轻量稳定的 slim 基础镜像。
FROM python:3.11-slim

WORKDIR /app
COPY common.py ./
COPY coordinator/ ./coordinator/
COPY services/ ./services/
COPY tests/ ./tests/
COPY scripts/ ./scripts/

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN chmod +x scripts/*.sh && mkdir -p /data

# 默认角色由 compose 覆盖；镜像本身默认启动协调端
EXPOSE 8080
CMD ["python3", "-m", "coordinator.app"]
