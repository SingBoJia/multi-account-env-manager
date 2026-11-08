"""团队成员与权限。

设计：
- 每个成员有用户名 + 密码（PBKDF2 存储），以及角色。
- 角色决定「能做什么」，环境授权决定「能对哪些环境做」。
- 管理员不写死：最后一个管理员的权限不能被移除，避免把自己锁死。

角色：
  admin   全部权限，可管理成员
  manager 管理环境与节点，不能管理成员
  operator 只能启动/停止/使用被授权的环境
  viewer  只能查看
"""

import hashlib
import json
import pathlib
import re
import secrets
import time

from .paths import data_file as _data_file

USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_\u4e00-\u9fa5.-]{2,32}$")
STORE_FILE = _data_file("members.json")

PBKDF2_ROUNDS = 200000

ROLES = ("admin", "manager", "operator", "viewer")

ROLE_LABELS = {
    "admin": "管理员",
    "manager": "运维",
    "operator": "操作员",
    "viewer": "只读",
}

# 角色能执行的动作
ROLE_ACTIONS = {
    "admin": {"view", "start", "stop", "edit", "delete", "manage_members",
              "manage_nodes", "manage_subs", "export", "layout", "sync"},
    "manager": {"view", "start", "stop", "edit", "delete",
                "manage_nodes", "manage_subs", "export", "layout", "sync"},
    "operator": {"view", "start", "stop", "layout", "sync"},
    "viewer": {"view"},
}

# 这些动作需要 action 级判断
ACTION_LABELS = {
    "view": "查看",
    "start": "启动环境",
    "stop": "停止环境",
    "edit": "修改配置",
    "delete": "删除环境",
    "manage_members": "管理成员",
    "manage_nodes": "管理节点",
    "manage_subs": "管理订阅",
    "export": "导出数据",
    "layout": "调整窗口",
    "sync": "同步云端",
}


class MemberError(Exception):
    pass


def _hash_password(password, salt):
    dk = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), PBKDF2_ROUNDS
    )
    return dk.hex()


def _verify(password, salt, expected):
    if not salt or not expected:
        return False
    try:
        return secrets.compare_digest(_hash_password(password, salt), expected)
    except Exception:
        return False


class MemberStore:

    def __init__(self):
        self._file = STORE_FILE

    # ---------- 读取 ----------

    def all(self):
        return self._read()

    def get(self, username):
        return self._read().get(username)

    def list_safe(self):
        out = []
        for name, m in self._read().items():
            scope = m.get("envScope") or []
            out.append({
                "username": name,
                "displayName": m.get("displayName", name),
                "role": m.get("role", "viewer"),
                "roleLabel": ROLE_LABELS.get(m.get("role", "viewer"), "只读"),
                "enabled": m.get("enabled", True),
                "envScope": scope,
                # 自助注册的账号先挂一个不存在的环境，管理员授权后清除
                "pending": scope == ["__none__"],
                "createdAt": m.get("createdAt", ""),
            })
        return out

    def has_admin(self):
        return any(
            m.get("role") == "admin" and m.get("enabled", True)
            for m in self._read().values()
        )

    def count_admins(self):
        return sum(
            1 for m in self._read().values()
            if m.get("role") == "admin" and m.get("enabled", True)
        )

    # ---------- 写入 ----------

    def add(self, username, password, role="viewer", display_name="", env_scope=None):
        if not isinstance(username, str) or not USERNAME_PATTERN.match(username):
            raise MemberError("用户名只能包含字母、数字、下划线、中文，2-32 位")
        if not isinstance(password, str) or len(password) < 6:
            raise MemberError("密码至少 6 位")
        if role not in ROLES:
            raise MemberError("无效角色: %s" % role)

        data = self._read()
        if username in data:
            raise MemberError("成员已存在: %s" % username)

        # 第一个成员必须是管理员，否则成员系统启用后会立刻锁死
        if not data:
            role = "admin"

        salt = secrets.token_hex(16)
        data[username] = {
            "username": username,
            "displayName": display_name or username,
            "role": role,
            "enabled": True,
            "salt": salt,
            "passwordHash": _hash_password(password, salt),
            # 空数组表示「授权全部环境」
            "envScope": list(env_scope or []),
            "createdAt": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        self._write(data)
        return True

    def update(self, username, **fields):
        data = self._read()
        if username not in data:
            raise MemberError("成员不存在: %s" % username)

        m = data[username]

        if "role" in fields:
            role = fields["role"]
            if role not in ROLES:
                raise MemberError("无效角色: %s" % role)
            # 不允许把最后一个管理员降级
            if m.get("role") == "admin" and role != "admin" and self.count_admins() <= 1:
                raise MemberError("这是最后一个管理员，不能降级")
            m["role"] = role

        if "enabled" in fields:
            enabled = bool(fields["enabled"])
            if not enabled and m.get("role") == "admin" and self.count_admins() <= 1:
                raise MemberError("这是最后一个管理员，不能停用")
            m["enabled"] = enabled

        if "displayName" in fields:
            m["displayName"] = str(fields["displayName"] or username)

        if "envScope" in fields:
            scope = fields["envScope"] or []
            if isinstance(scope, list):
                m["envScope"] = [str(s) for s in scope]
            else:
                m["envScope"] = []

        if "password" in fields:
            pwd = fields["password"]
            if not isinstance(pwd, str) or len(pwd) < 6:
                raise MemberError("密码至少 6 位")
            salt = secrets.token_hex(16)
            m["salt"] = salt
            m["passwordHash"] = _hash_password(pwd, salt)

        self._write(data)
        return True

    def delete(self, username):
        data = self._read()
        if username not in data:
            raise MemberError("成员不存在: %s" % username)
        if data[username].get("role") == "admin" and self.count_admins() <= 1:
            raise MemberError("这是最后一个管理员，不能删除")
        data.pop(username)
        self._write(data)
        return True

    # ---------- 认证 ----------

    def authenticate(self, username, password):
        """校验账号密码。成功返回成员信息，失败返回 None。"""
        m = self._read().get(username or "")
        if not m:
            return None
        if not m.get("enabled", True):
            return None
        if not _verify(password or "", m.get("salt", ""), m.get("passwordHash", "")):
            return None
        return {
            "username": m["username"],
            "displayName": m.get("displayName", username),
            "role": m.get("role", "viewer"),
            "envScope": m.get("envScope") or [],
        }

    # ---------- 权限判断 ----------

    @staticmethod
    def can(member, action, env_id=None):
        """判断成员能否执行某动作。

        member 为 None 表示「未启用成员系统」，此时放行所有操作。
        env_id 传入时会额外检查环境授权范围。
        """
        if member is None:
            return True

        role = member.get("role", "viewer")
        allowed = ROLE_ACTIONS.get(role, set())
        if action not in allowed:
            return False

        # 环境级授权：管理员不受限；其他人只在自己范围内
        if env_id and role != "admin":
            scope = member.get("envScope") or []
            if scope and env_id not in scope:
                return False

        return True

    # ---------- 内部 ----------

    def _read(self):
        if not self._file.exists():
            return {}
        try:
            data = json.loads(self._file.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, OSError):
            return {}

    def _write(self, data):
        self._file.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._file.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self._file)
