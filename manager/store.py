"""环境存储：保存每个环境的编号、备注、代理节点、平台等元数据。

与指纹分离：指纹是设备身份，这里是业务配置。
所有数据存在单个 JSON 文件内，环境编号仅作字典键。
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
from .kernels import normalize_firefox_version

ENV_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
STORE_FILE = _data_file("environments.json")

# PBKDF2 迭代次数：兼顾桌面端响应速度与暴力破解成本
PBKDF2_ROUNDS = 200000


def _hash_password(password, salt):
    """用 PBKDF2-HMAC-SHA256 派生密码哈希。"""
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ROUNDS,
    )
    return dk.hex()


def _verify_password(password, salt, expected):
    """常量时间比较，避免时序侧信道。"""
    if not salt or not expected:
        return False
    actual = _hash_password(password, salt)
    return secrets.compare_digest(actual, expected)


def _serialized(fn):
    """串行化读改写：Flask 多线程下并发更新同一 JSON 会互相覆盖，用可重入锁包住。"""
    @functools.wraps(fn)
    def wrapper(self, *args, **kwargs):
        with self._mu:
            return fn(self, *args, **kwargs)
    return wrapper


class EnvironmentStore:

    def __init__(self):
        self._file = STORE_FILE
        self._mu = threading.RLock()

    # ---------- 读取 ----------

    def all(self):
        return self._read()

    def get(self, env_id):
        self._validate(env_id)
        return self._read().get(env_id)

    def exists(self, env_id):
        self._validate(env_id)
        return env_id in self._read()

    # ---------- 写入 ----------

    @_serialized
    def create(self, env_id, name="", platform="", remark="", proxy=None, start_url="", node_id="", chain=None, group="", tags=None,
               browser_backend="firefox", kernel_version=""):
        self._validate(env_id)
        data = self._read()
        if env_id in data:
            raise ValueError("环境已存在: %s" % env_id)
        backend = str(browser_backend or "firefox").lower()
        # 旧配置可能还是 ads：AdsPower 已移除，统一落到本地 Firefox 150
        if backend == "ads" or backend not in ("local", "firefox"):
            backend = "firefox"
        kernel_version = str(kernel_version or "").strip()
        if backend == "firefox":
            kernel_version = normalize_firefox_version(kernel_version) or "150.0"
        else:
            kernel_version = "system"
        data[env_id] = {
            "id": env_id,
            "name": name or env_id,
            "platform": platform or "淘宝",
            "remark": remark,
            "proxy": proxy or {},
            "nodeId": node_id or "",
            # 多级代理链：按顺序经这些节点转发，前面的是落地，后面的是前置
            "chain": chain or [],
            "startUrl": start_url or "https://www.taobao.com",
            # 浏览器后端：local=本机 Chrome；firefox=本地 Firefox 150
            "browserBackend": backend,
            # 内核版本标签：chrome / 150
            "kernelVersion": kernel_version,
            # 分组与标签
            "group": group or "",
            "tags": list(tags or []),
            # 动态 IP 提取器：每次启动从这里拉一个新 IP
            "dynamicIp": {"enabled": False, "url": "", "channel": "", "lastIp": ""},
            # 指纹模式：stable=固定（推荐，登录态稳定）；random=每次启动重新随机
            "fpMode": "stable",
            # 允许无代理直连启动（默认拒绝：多环境共用真实出口 IP 会被平台关联）
            "allowDirect": False,
            # 回收站标记
            "deleted": False,
            "deletedAt": "",
            "locked": False,
            "lockHash": "",
        }
        self._write(data)
        return data[env_id]

    @_serialized
    def update(self, env_id, **fields):
        self._validate(env_id)
        data = self._read()
        if env_id not in data:
            raise ValueError("环境不存在: %s" % env_id)
        allowed = {
            "name", "platform", "remark", "proxy", "startUrl", "nodeId", "chain",
            "group", "tags", "dynamicIp", "fpMode", "allowDirect",
            "browserBackend", "kernelVersion",
        }
        for k, v in fields.items():
            if k in allowed:
                if k == "tags" and isinstance(v, list):
                    v = [str(t).strip() for t in v if str(t).strip()][:8]
                if k == "browserBackend":
                    v = str(v or "firefox").strip().lower()
                    if v == "ads" or v not in ("local", "firefox"):
                        v = "firefox"
                data[env_id][k] = v
        final_backend = str(data[env_id].get("browserBackend") or "firefox").lower()
        if final_backend == "firefox":
            data[env_id]["kernelVersion"] = (
                normalize_firefox_version(data[env_id].get("kernelVersion")) or "150.0")
        else:
            data[env_id]["kernelVersion"] = "system"
        self._write(data)
        return data[env_id]

    # ---------- 回收站 ----------

    @_serialized
    def soft_delete(self, env_id):
        """移入回收站（不真删，可恢复）。"""
        self._validate(env_id)
        data = self._read()
        if env_id not in data:
            raise ValueError("环境不存在: %s" % env_id)
        data[env_id]["deleted"] = True
        data[env_id]["deletedAt"] = time.strftime("%Y-%m-%d %H:%M:%S")
        self._write(data)
        return data[env_id]

    @_serialized
    def restore(self, env_id):
        """从回收站恢复。"""
        self._validate(env_id)
        data = self._read()
        if env_id not in data:
            raise ValueError("环境不存在: %s" % env_id)
        data[env_id]["deleted"] = False
        data[env_id]["deletedAt"] = ""
        self._write(data)
        return data[env_id]

    def list_deleted(self):
        return {k: v for k, v in self._read().items() if v.get("deleted")}

    def list_active(self):
        return {k: v for k, v in self._read().items() if not v.get("deleted")}

    @_serialized
    def purge(self, env_id):
        """彻底删除（从回收站清空时调用）。"""
        self._validate(env_id)
        data = self._read()
        item = data.pop(env_id, None)
        self._write(data)
        return item

    def groups(self):
        """所有非空分组名。"""
        out = set()
        for item in self._read().values():
            g = (item.get("group") or "").strip()
            if g:
                out.add(g)
        return sorted(out)

    def tags(self):
        """所有出现过的标签。"""
        out = set()
        for item in self._read().values():
            for t in (item.get("tags") or []):
                out.add(t)
        return sorted(out)

    # ---------- 环境锁 ----------

    @_serialized
    def set_lock(self, env_id, password):
        """上锁。密码经 PBKDF2 派生成哈希保存，不存明文。"""
        self._validate(env_id)
        if not isinstance(password, str) or len(password) < 4:
            raise ValueError("解锁密码至少 4 位")
        data = self._read()
        if env_id not in data:
            raise ValueError("环境不存在: %s" % env_id)
        salt = secrets.token_hex(16)
        digest = _hash_password(password, salt)
        data[env_id]["locked"] = True
        data[env_id]["lockSalt"] = salt
        data[env_id]["lockHash"] = digest
        self._write(data)
        return True

    @_serialized
    def unlock(self, env_id, password):
        """验证密码并解锁。密码错误返回 False。"""
        self._validate(env_id)
        data = self._read()
        item = data.get(env_id)
        if not item:
            raise ValueError("环境不存在: %s" % env_id)
        if not item.get("locked"):
            return True
        salt = item.get("lockSalt", "")
        expect = item.get("lockHash", "")
        if not salt or not expect:
            return False
        if not _verify_password(password, salt, expect):
            return False
        item["locked"] = False
        item.pop("lockSalt", None)
        item.pop("lockHash", None)
        self._write(data)
        return True

    def is_locked(self, env_id):
        self._validate(env_id)
        item = self._read().get(env_id)
        return bool(item and item.get("locked"))

    def check_password(self, env_id, password):
        """只校验密码是否正确，不改变锁状态。"""
        self._validate(env_id)
        item = self._read().get(env_id)
        if not item or not item.get("locked"):
            return True
        return _verify_password(password, item.get("lockSalt", ""), item.get("lockHash", ""))

    @_serialized
    def delete(self, env_id):
        self._validate(env_id)
        data = self._read()
        item = data.pop(env_id, None)
        self._write(data)
        return item

    # ---------- 内部 ----------

    @staticmethod
    def _validate(env_id):
        if not isinstance(env_id, str) or not ENV_ID_PATTERN.match(env_id):
            raise ValueError("非法环境编号（只允许字母数字下划线短横线，1-64位）")

    def _read(self):
        if not self._file.exists():
            return {}
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("顶层不是 JSON 对象")
            return data
        except (json.JSONDecodeError, ValueError):
            # 内容损坏：先把坏文件改名保留（唯一可恢复的线索），再当空数据用。
            # 否则下一次任意写操作会把损坏文件覆成空字典，环境"全部消失"。
            self._quarantine()
            return {}
        except OSError:
            return {}

    def _quarantine(self):
        try:
            stamp = time.strftime("%Y%m%d-%H%M%S")
            self._file.replace(self._file.with_name(
                self._file.name + ".corrupt-" + stamp))
            print("[store] %s 内容损坏，已改名为 .corrupt-%s 保留" % (
                self._file.name, stamp), file=sys.stderr, flush=True)
        except OSError:
            pass

    def _write(self, data):
        _atomic_write(self._file, json.dumps(data, ensure_ascii=False, indent=2))
