"""协调端访问策略控制平面的 HTTP 客户端（仅用 urllib）。"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

POLICY_URL = os.environ.get("POLICY_URL", "http://127.0.0.1:9104")
INTERNAL_TOKEN = os.environ.get("INTERNAL_TOKEN", "dev-internal-token")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")


class PolicyError(Exception):
    def __init__(self, status: int, body: dict | str):
        self.status = status
        self.body = body
        super().__init__(f"policy HTTP {status}: {body}")


def _request(method: str, path: str, payload=None, token: str = INTERNAL_TOKEN,
             timeout: float = 5.0):
    url = f"{POLICY_URL.rstrip('/')}{path}"
    data = json.dumps(payload).encode() if payload is not None else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    r.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            body = json.loads(raw)
        except Exception:
            body = raw
        raise PolicyError(e.code, body)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise PolicyError(0, f"unreachable: {e}")


def resolve_subject(subject_id: str) -> dict:
    """返回主体当前应绑定的不可变修订快照（金丝雀优先）。"""
    _, body = _request("GET", f"/policies/resolve?subject_id={subject_id}")
    return body


def get_revision(revision: int) -> dict:
    _, body = _request("GET", f"/policies/revisions/{revision}")
    return body


def get_active() -> dict:
    _, body = _request("GET", "/policies/active")
    return body


def canary(revision: int, subjects: list[str], note: str | None = None) -> dict:
    return _request("POST", f"/policies/revisions/{revision}/canary",
                    {"canary_subjects": subjects, "note": note},
                    token=ADMIN_TOKEN)[1]


def activate(revision: int, expected_version=None) -> dict:
    return _request("POST", f"/policies/revisions/{revision}/activate",
                    {"expected_version": expected_version},
                    token=ADMIN_TOKEN)[1]


def rollback(target: int | None = None, expected_version=None) -> dict:
    return _request("POST", "/policies/rollback",
                    {"target": target, "expected_version": expected_version},
                    token=ADMIN_TOKEN)[1]


def list_events() -> list[dict]:
    return _request("GET", "/policies/events")[1]["events"]
