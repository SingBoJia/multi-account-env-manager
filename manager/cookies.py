"""Cookie 导入导出。

导出：从环境的 Chrome Cookies SQLite 里读出 cookie，输出 JSON 或 Netscape 格式。
导入：把 cookie 写入环境的 Chrome Cookies 库。

限制：Chrome 用 DPAPI 加密 cookie 值，本模块只在浏览器未运行时操作。
跨机器迁移建议走「导出明文 → 目标机导入明文」。

安全：SQL 语句直接以字符串字面量传给 execute，参数一律用 ? 占位符绑定。
"""

import json
import os
import shutil
import sqlite3
import tempfile
import time

CHROME_EPOCH_OFFSET = 11644473600


class CookieError(Exception):
    pass


def _cookies_db(profile_dir):
    """定位 Cookies 数据库（新版在 Network/ 下，旧版在 Default/ 下）。"""
    new_layout = os.path.join(profile_dir, "Default", "Network", "Cookies")
    old_layout = os.path.join(profile_dir, "Default", "Cookies")
    if os.path.isfile(new_layout):
        return new_layout
    if os.path.isfile(old_layout):
        return old_layout
    return None


def _read_rows(db_path, domain_filter):
    """读取 cookie 行。domain_filter 为空读全量，否则按包含匹配。"""
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        if domain_filter:
            result = con.execute(
                "SELECT host_key, name, value, encrypted_value, path, expires_utc,"
                " is_secure, is_httponly, samesite FROM cookies"
                " WHERE instr(host_key, ?) > 0",
                (domain_filter,),
            )
        else:
            result = con.execute(
                "SELECT host_key, name, value, encrypted_value, path, expires_utc,"
                " is_secure, is_httponly, samesite FROM cookies"
            )
        raw = result.fetchall()
    finally:
        con.close()

    rows = []
    for r in raw:
        value = r["value"]
        has_encrypted = bool(r["encrypted_value"])
        rows.append({
            "domain": r["host_key"],
            "name": r["name"],
            "value": value,
            "encrypted": has_encrypted and not value,
            "path": r["path"],
            "expires": _chrome_to_unix(r["expires_utc"]),
            "secure": bool(r["is_secure"]),
            "httpOnly": bool(r["is_httponly"]),
            "sameSite": _samesite_name(r["samesite"]),
        })
    return rows


def export(profile_dir, domain_filter=""):
    """导出 cookie。返回 (rows, error)。"""
    if not os.path.isdir(profile_dir):
        return [], "该环境还没启动过，没有 cookie 数据"

    db = _cookies_db(profile_dir)
    if not db:
        return [], "该环境还没有 cookie 数据（未启动过或未访问过网站）"

    stamp = int(time.time() * 1000)
    tmp = os.path.join(tempfile.gettempdir(), "ck_" + str(stamp) + ".db")
    try:
        shutil.copy2(db, tmp)
    except OSError as e:
        raise CookieError("读取 cookie 库失败: %s" % e)

    try:
        rows = _read_rows(tmp, domain_filter)
    except sqlite3.Error as e:
        raise CookieError("解析 cookie 库失败: %s" % e)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    return rows, ""


def to_netscape(rows):
    """转成 Netscape cookie 格式文本。"""
    lines = ["# Netscape HTTP Cookie File", "# exported by env-manager", ""]
    for c in rows:
        if c.get("encrypted") and not c.get("value"):
            continue
        domain = c.get("domain", "")
        include_sub = "TRUE" if domain.startswith(".") else "FALSE"
        secure = "TRUE" if c.get("secure") else "FALSE"
        expires = int(c.get("expires") or 0)
        domain_field = ("#HttpOnly_" if c.get("httpOnly") else "") + domain
        fields = [
            domain_field, include_sub, c.get("path", "/"), secure,
            str(expires), c.get("name", ""), c.get("value", ""),
        ]
        lines.append("\t".join(fields))
    return "\n".join(lines) + "\n"


def _ensure_db(profile_dir):
    """确保 cookie 库存在，返回路径。目录不存在时会创建。"""
    if not os.path.isdir(profile_dir):
        # 环境还没启动过，按 Chrome 的默认布局创建目录
        os.makedirs(os.path.join(profile_dir, "Default", "Network"), exist_ok=True)

    db = _cookies_db(profile_dir)
    if db:
        return db

    network_dir = os.path.join(profile_dir, "Default", "Network")
    os.makedirs(network_dir, exist_ok=True)
    db = os.path.join(network_dir, "Cookies")

    con = sqlite3.connect(db)
    try:
        con.execute(
            "CREATE TABLE IF NOT EXISTS cookies ("
            "creation_utc INTEGER NOT NULL,"
            "host_key TEXT NOT NULL,"
            "top_frame_site_key TEXT NOT NULL DEFAULT '',"
            "name TEXT NOT NULL,"
            "value TEXT NOT NULL,"
            "encrypted_value BLOB NOT NULL DEFAULT X'',"
            "path TEXT NOT NULL,"
            "expires_utc INTEGER NOT NULL,"
            "is_secure INTEGER NOT NULL,"
            "is_httponly INTEGER NOT NULL,"
            "last_access_utc INTEGER NOT NULL,"
            "has_expires INTEGER NOT NULL DEFAULT 1,"
            "is_persistent INTEGER NOT NULL DEFAULT 1,"
            "priority INTEGER NOT NULL DEFAULT 1,"
            "samesite INTEGER NOT NULL DEFAULT -1,"
            "source_scheme INTEGER NOT NULL DEFAULT 0,"
            "source_port INTEGER NOT NULL DEFAULT -1,"
            "last_update_utc INTEGER NOT NULL DEFAULT 0,"
            "source_type INTEGER NOT NULL DEFAULT 0,"
            "has_cross_site_ancestor INTEGER NOT NULL DEFAULT 0)"
        )
        con.commit()
    finally:
        con.close()
    return db


def import_cookies(profile_dir, rows):
    """把 cookie 写入环境。浏览器必须未运行。返回写入条数。"""
    db = _ensure_db(profile_dir)
    now_chrome = _unix_to_chrome(time.time())

    added = 0
    con = sqlite3.connect(db)
    try:
        for c in rows:
            domain = str(c.get("domain") or "").strip()
            name = str(c.get("name") or "").strip()
            if not domain or not name:
                continue

            value = str(c.get("value") or "")
            path = str(c.get("path") or "/")
            expires = now_chrome
            if c.get("expires"):
                expires = _unix_to_chrome(float(c.get("expires") or 0))

            params = (
                now_chrome, domain, name, value, path,
                expires,
                1 if c.get("secure") else 0,
                1 if c.get("httpOnly") else 0,
                now_chrome,
                1 if c.get("expires") else 0,
                1 if c.get("expires") else 0,
                1,
                _samesite_value(c.get("sameSite")),
                1, -1, now_chrome, 0, 0,
            )
            con.execute(
                "DELETE FROM cookies WHERE host_key=? AND name=? AND path=?",
                (domain, name, path),
            )
            con.execute(
                "INSERT INTO cookies ("
                "creation_utc, host_key, name, value, encrypted_value, path,"
                " expires_utc, is_secure, is_httponly, last_access_utc,"
                " has_expires, is_persistent, priority, samesite, source_scheme,"
                " source_port, last_update_utc, source_type, has_cross_site_ancestor)"
                " VALUES (?,?,?,?,X'',?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                params,
            )
            added += 1
        con.commit()
    except sqlite3.Error as e:
        raise CookieError("写入 cookie 失败: %s" % e)
    finally:
        con.close()

    return added


def parse_import_file(text):
    """解析导入内容：JSON 数组 或 Netscape 格式。"""
    text = (text or "").strip()
    if not text:
        return []

    if text[0] in "[{":
        try:
            data = json.loads(text)
            if isinstance(data, dict) and "cookies" in data:
                data = data["cookies"]
            if isinstance(data, list):
                return [_normalize(c) for c in data if isinstance(c, dict)]
        except json.JSONDecodeError:
            pass

    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        http_only = False
        if line.startswith("#HttpOnly_"):
            line = line[len("#HttpOnly_"):]
            http_only = True
        elif line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        rows.append({
            "domain": parts[0],
            "name": parts[5],
            "value": parts[6],
            "path": parts[2] or "/",
            "secure": parts[3].upper() == "TRUE",
            "expires": int(parts[4]) if parts[4].isdigit() else 0,
            "httpOnly": http_only,
            "sameSite": "",
        })
    return rows


# ---------- 工具 ----------

def _normalize(c):
    return {
        "domain": c.get("domain") or c.get("host") or c.get("host_key") or "",
        "name": c.get("name") or "",
        "value": c.get("value") or "",
        "path": c.get("path") or "/",
        "secure": bool(c.get("secure")),
        "httpOnly": bool(c.get("httpOnly") or c.get("http_only")),
        "expires": c.get("expires") or c.get("expirationDate") or 0,
        "sameSite": c.get("sameSite") or "",
    }


def _chrome_to_unix(chrome_time):
    if not chrome_time:
        return 0
    return int(chrome_time / 1000000 - CHROME_EPOCH_OFFSET)


def _unix_to_chrome(unix_time):
    if not unix_time:
        return 0
    return int((float(unix_time) + CHROME_EPOCH_OFFSET) * 1000000)


def _samesite_name(v):
    return {0: "None", 1: "Lax", 2: "Strict", -1: ""}.get(v, "")


def _samesite_value(name):
    return {"none": 0, "lax": 1, "strict": 2}.get(str(name or "").lower(), -1)
