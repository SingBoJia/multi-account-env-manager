"""节点池：集中管理所有代理节点，支持批量导入、分组、分配给环境。

节点与环境分离：一个节点可以被多个环境复用，也可以在导入时按顺序自动分配。
所有数据存在单个 JSON 文件内，节点 ID 仅作字典键。
"""

import functools
import json
import pathlib
import re
import secrets
import sys
import threading
import time

from .paths import atomic_write_text as _atomic_write
from .paths import data_file as _data_file

NODE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
STORE_FILE = _data_file("nodes.json")


def _serialized(fn):
    """串行化读改写：Flask 多线程下并发更新同一 JSON 会互相覆盖，用可重入锁包住。"""
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._mu:
            return fn(self, *args, **kwargs)
    return wrapper


class NodePool:

    def __init__(self):
        self._file = STORE_FILE
        self._mu = threading.RLock()

    # ---------- 读取 ----------

    def all(self):
        return self._read()

    def get(self, node_id):
        self._validate(node_id)
        return self._read().get(node_id)

    def list_safe(self):
        """给界面用的列表，隐去密码等敏感字段的明文。"""
        out = []
        for node_id, node in self._read().items():
            item = {
                "id": node_id,
                "name": node.get("name") or node_id,
                "protocol": node.get("protocol"),
                "server": node.get("server"),
                "port": node.get("port"),
                "group": node.get("group", ""),
                "enabled": node.get("enabled", True),
                "hasAuth": bool(node.get("password") or node.get("uuid") or node.get("username")),
                "transport": node.get("transport", ""),
                "tls": bool(node.get("tls")),
                "reality": bool(node.get("reality")),
            }
            out.append(item)
        return out

    # ---------- 写入 ----------

    @_serialized
    def add_many(self, nodes, group="", auto_name_prefix=""):
        """批量加入节点池，返回新增的节点 ID 列表。"""
        data = self._read()
        added = []
        for idx, node in enumerate(nodes, 1):
            node_id = secrets.token_hex(8)
            record = dict(node)
            record.setdefault("name", "%s%s" % (auto_name_prefix or "节点", idx))
            record["group"] = group or record.get("group", "")
            record["enabled"] = True
            data[node_id] = record
            added.append(node_id)
        self._write(data)
        return added

    @_serialized
    def update(self, node_id, **fields):
        self._validate(node_id)
        data = self._read()
        if node_id not in data:
            raise ValueError("节点不存在")
        allowed = {
            "name", "group", "enabled", "server", "port", "protocol",
            "username", "password", "uuid", "security", "alterId",
            "sni", "host", "path", "transport", "tls", "reality",
            "realityPublicKey", "realityShortId", "fingerprint", "flow",
            "alpn", "insecure", "obfs",
        }
        for k, v in fields.items():
            if k in allowed:
                data[node_id][k] = v
        self._write(data)
        return data[node_id]

    @_serialized
    def delete(self, node_id):
        self._validate(node_id)
        data = self._read()
        item = data.pop(node_id, None)
        self._write(data)
        return item

    @_serialized
    def delete_many(self, node_ids):
        data = self._read()
        removed = []
        for node_id in node_ids:
            if isinstance(node_id, str) and node_id in data:
                data.pop(node_id)
                removed.append(node_id)
        self._write(data)
        return removed

    def exists(self, node_id):
        self._validate(node_id)
        return node_id in self._read()

    # ---------- 内部 ----------

    @staticmethod
    def _validate(node_id):
        if not isinstance(node_id, str) or not NODE_ID_PATTERN.match(node_id):
            raise ValueError("非法节点编号")

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
            print("[node_pool] %s 内容损坏，已改名为 .corrupt-%s 保留" % (
                self._file.name, stamp), file=sys.stderr, flush=True)
        except OSError:
            pass

    def _write(self, data):
        _atomic_write(self._file, json.dumps(data, ensure_ascii=False, indent=2))
