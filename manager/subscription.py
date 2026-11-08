"""订阅管理：保存订阅地址、定时拉取、增量更新节点池。

设计要点（借鉴商业指纹浏览器的不足）：
1. 三款商业浏览器都没有代理订阅，这是差异化能力。
2. 订阅只更新「来自订阅」的节点，不碰用户手动导入的节点。
3. 记录每个订阅的节点指纹，用于判断增删改，避免每次全量重建。
4. 拉取失败保留上次结果，不破坏现有节点。
"""

import functools
import hashlib
import json
import pathlib
import re
import secrets
import sys
import threading
import time

from .paths import atomic_write_text as _atomic_write
from .paths import data_file as _data_file

SUB_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
STORE_FILE = _data_file("subscriptions.json")


def _serialized(fn):
    """串行化读改写：Flask 多线程下并发更新同一 JSON 会互相覆盖，用可重入锁包住。"""
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._mu:
            return fn(self, *args, **kwargs)
    return wrapper


class SubscriptionStore:

    def __init__(self):
        self._file = STORE_FILE
        self._mu = threading.RLock()

    # ---------- 读取 ----------

    def all(self):
        return self._read()

    def get(self, sub_id):
        self._validate(sub_id)
        return self._read().get(sub_id)

    def list_safe(self):
        out = []
        for sub_id, sub in self._read().items():
            out.append({
                "id": sub_id,
                "name": sub.get("name") or sub_id,
                "url": _mask_url(sub.get("url", "")),
                "enabled": sub.get("enabled", True),
                "group": sub.get("group", ""),
                "autoAssign": sub.get("autoAssign", False),
                "lastSync": sub.get("lastSync"),
                "lastCount": sub.get("lastCount", 0),
                "lastError": sub.get("lastError", ""),
                "nodeIds": len(sub.get("nodeIds") or []),
            })
        return out

    # ---------- 写入 ----------

    @_serialized
    def add(self, url, name="", group="", auto_assign=False, interval_minutes=0):
        sub_id = secrets.token_hex(8)
        data = self._read()
        data[sub_id] = {
            "name": name or "订阅-%s" % sub_id[:6],
            "url": url,
            "enabled": True,
            "group": group or "",
            "autoAssign": bool(auto_assign),
            "intervalMinutes": int(interval_minutes or 0),
            "lastSync": None,
            "lastCount": 0,
            "lastError": "",
            "nodeIds": [],
            "nodeHashes": {},
        }
        self._write(data)
        return sub_id

    @_serialized
    def update(self, sub_id, **fields):
        self._validate(sub_id)
        data = self._read()
        if sub_id not in data:
            raise ValueError("订阅不存在")
        allowed = {"name", "enabled", "group", "autoAssign", "intervalMinutes", "url"}
        for k, v in fields.items():
            if k in allowed:
                data[sub_id][k] = v
        self._write(data)
        return data[sub_id]

    @_serialized
    def record_sync(self, sub_id, node_ids, node_hashes, error=""):
        self._validate(sub_id)
        data = self._read()
        if sub_id not in data:
            raise ValueError("订阅不存在")
        sub = data[sub_id]
        sub["nodeIds"] = list(node_ids)
        sub["nodeHashes"] = dict(node_hashes)
        sub["lastCount"] = len(node_ids)
        sub["lastError"] = error
        if not error:
            sub["lastSync"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self._write(data)
        return sub

    @_serialized
    def delete(self, sub_id):
        self._validate(sub_id)
        data = self._read()
        item = data.pop(sub_id, None)
        self._write(data)
        return item

    # ---------- 内部 ----------

    @staticmethod
    def _validate(sub_id):
        if not isinstance(sub_id, str) or not SUB_ID_PATTERN.match(sub_id):
            raise ValueError("非法订阅编号")

    def _read(self):
        if not self._file.exists():
            return {}
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("顶层不是 JSON 对象")
            return data
        except (json.JSONDecodeError, ValueError):
            # 内容损坏：先把坏文件改名保留，再当空数据用
            self._quarantine()
            return {}
        except OSError:
            return {}

    def _quarantine(self):
        try:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            self._file.replace(self._file.with_name(
                self._file.name + ".corrupt-" + stamp))
            print("[subscription] %s 内容损坏，已改名为 .corrupt-%s 保留" % (
                self._file.name, stamp), file=sys.stderr, flush=True)
        except OSError:
            pass

    def _write(self, data):
        _atomic_write(self._file, json.dumps(data, ensure_ascii=False, indent=2))


def node_hash(node):
    """节点内容指纹，用于判断订阅更新时某节点是否变化。"""
    key = "|".join(str(node.get(k, "")) for k in (
        "protocol", "server", "port", "uuid", "password",
        "username", "sni", "path", "transport", "realityPublicKey",
    ))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _mask_url(url):
    """界面上隐去订阅地址里的 token 参数。"""
    if not url:
        return ""
    try:
        from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
        parts = urlsplit(url)
        if not parts.query:
            return url
        q = []
        for k, v in parse_qsl(parts.query, keep_blank_values=True):
            if len(v) > 8 and any(s in k.lower() for s in ("token", "key", "secret", "pass", "auth")):
                v = v[:4] + "***" + v[-2:]
            q.append((k, v))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))
    except ValueError:
        return url
