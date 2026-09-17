"""协调端 -> 策略控制面 的 HTTP 客户端（urllib，独立短超时）。"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


class PolicyUnavailable(Exception):
    pass


def _request(method: str, url: str, payload: dict | None, token: str,
             timeout: float = 3.0):
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
            body = {"raw": raw}
        return e.code, body
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise PolicyUnavailable(str(e))


def get(url: str, token: str, timeout: float = 3.0):
    return _request("GET", url, None, token, timeout)


def post(url: str, payload: dict, token: str, timeout: float = 3.0):
    return _request("POST", url, payload, token, timeout)
