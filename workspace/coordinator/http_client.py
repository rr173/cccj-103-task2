"""协调端调用业务服务的 HTTP 客户端（仅用 urllib）。"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


class ServiceError(Exception):
    def __init__(self, status: int, body: dict | str):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}: {body}")


def _request(method: str, url: str, payload: dict | None, token: str, timeout: float = 5.0):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            body = json.loads(raw)
        except Exception:
            body = raw
        raise ServiceError(e.code, body)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise ServiceError(0, f"unreachable: {e}")


def post(url: str, payload: dict, token: str, timeout: float = 5.0):
    return _request("POST", url, payload, token, timeout)


def get(url: str, token: str, timeout: float = 5.0):
    return _request("GET", url, None, token, timeout)
