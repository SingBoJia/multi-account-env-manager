"""WebDAV 云端同步。

把本地配置（环境、节点、指纹、成员）备份到 WebDAV 服务器，
也可从服务器恢复到本地。

依赖：仅用标准库 http.client（支持 PUT / GET / PROPFIND / MKCOL），
不引入第三方 WebDAV 客户端。

安全：
- 只允许 http / https
- 默认拒绝内网地址；NAS 在内网时可在配置里显式打开 allowPrivate
- 密码存本地配置文件（用户自己填的，不输出到日志）
"""

import base64
import http.client
import ipaddress
import json
import pathlib
import re
import socket
import time
import urllib.parse

from .paths import data_file as _data_file

CONFIG_FILE = _data_file("cloud_sync.json")
TIMEOUT = 25
MAX_BYTES = 8 * 1024 * 1024

SYNC_FILES = (
    "environments.json",
    "nodes.json",
    "fingerprints.json",
    "subscriptions.json",
    "members.json",
)


class WebDavError(Exception):
    pass


# ---------- 配置 ----------

def load_config():
    if not CONFIG_FILE.exists():
        return {"enabled": False, "url": "", "username": "", "password": "",
                "directory": "env-manager", "allowPrivate": False, "lastSync": "",
                "lastResult": ""}
    try:
        data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def save_config(**fields):
    conf = load_config()
    allowed = {"enabled", "url", "username", "password", "directory",
               "allowPrivate", "lastSync", "lastResult"}
    for k, v in fields.items():
        if k in allowed:
            conf[k] = v
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(conf, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(CONFIG_FILE)
    return conf


def masked_config():
    """给界面看的配置，密码打码。"""
    conf = load_config()
    pwd = conf.get("password") or ""
    if pwd:
        conf = dict(conf)
        conf["password"] = "******" if len(pwd) <= 4 else pwd[:2] + "****" + pwd[-2:]
        conf["hasPassword"] = True
    else:
        conf["hasPassword"] = False
    return conf


# ---------- 地址校验 ----------

def validate_url(url, allow_private=False):
    """校验 WebDAV 地址。返回 (normalized_url, error)。"""
    if not isinstance(url, str) or not url.strip():
        return "", "WebDAV 地址为空"
    url = url.strip()

    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "", "地址格式不正确"

    if parts.scheme not in ("http", "https"):
        return "", "只支持 http / https"

    host = (parts.hostname or "").strip().lower()
    if not host:
        return "", "地址缺少主机名"

    if not allow_private and _is_private_host(host):
        return "", "地址指向内网。如果是你自己的 NAS，请在配置里打开「允许内网地址」"

    return url, ""


def _is_private_host(host):
    h = host.strip().lower().strip("[]")
    if h in ("localhost", "ip6-localhost", "ip6-loopback", "metadata"):
        return True
    if h.endswith(".local") or h.endswith(".internal"):
        return True

    candidates = []
    try:
        candidates.append(ipaddress.ip_address(h))
    except ValueError:
        try:
            for info in socket.getaddrinfo(h, None):
                try:
                    candidates.append(ipaddress.ip_address(info[4][0]))
                except ValueError:
                    continue
        except (socket.gaierror, OSError):
            return False

    for ip in candidates:
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
        if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return True
    return False


# ---------- HTTP 底层 ----------

def _request(method, url, auth, body=None, headers=None):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https":
        conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, timeout=TIMEOUT)
    else:
        conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=TIMEOUT)

    req_headers = {"User-Agent": "env-manager/1.0"}
    if auth and auth[0]:
        token = base64.b64encode(("%s:%s" % (auth[0], auth[1] or "")).encode("utf-8")).decode("ascii")
        req_headers["Authorization"] = "Basic " + token
    if body is not None:
        req_headers["Content-Length"] = str(len(body))
    if headers:
        req_headers.update(headers)

    path = parts.path or "/"
    if parts.query:
        path = path + "?" + parts.query

    try:
        conn.request(method, path, body=body, headers=req_headers)
        resp = conn.getresponse()
        data = resp.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise WebDavError("响应超过 %d MB" % (MAX_BYTES // 1024 // 1024))
        return resp.status, data, dict(resp.getheaders())
    except (OSError, http.client.HTTPException) as e:
        raise WebDavError("连接失败: %s" % e)
    finally:
        conn.close()


def _join_url(base, directory, filename):
    """拼出远端文件 URL，处理目录的斜杠。"""
    base = base.rstrip("/")
    d = (directory or "").strip("/")
    if d:
        base = base + "/" + d
    return base + "/" + urllib.parse.quote(filename)


# ---------- 核心操作 ----------

def test_connection(conf):
    """测试连接：尝试 PROPFIND 根目录。返回 (ok, message)。"""
    url, err = validate_url(conf.get("url") or "", conf.get("allowPrivate"))
    if err:
        return False, err

    auth = (conf.get("username") or "", conf.get("password") or "")
    try:
        status, _data, _h = _request("PROPFIND", url, auth, body=_propfind_body,
                                     headers={"Depth": "0", "Content-Type": "application/xml"})
    except WebDavError as e:
        return False, str(e)

    if status in (207, 200):
        return True, "连接成功"
    if status == 401:
        return False, "认证失败：用户名或密码不正确"
    if status == 404:
        # 根路径不存在也说明服务器可达，很多 WebDAV 允许 MKCOL 创建
        return True, "服务器可达（目录不存在，上传时会自动创建）"
    return False, "服务器返回 %d" % status


def ensure_directory(conf):
    """确保远端目录存在（逐级 MKCOL）。"""
    url, err = validate_url(conf.get("url") or "", conf.get("allowPrivate"))
    if err:
        raise WebDavError(err)
    auth = (conf.get("username") or "", conf.get("password") or "")
    directory = (conf.get("directory") or "").strip("/")
    if not directory:
        return

    base = url.rstrip("/")
    for part in directory.split("/"):
        base = base + "/" + urllib.parse.quote(part)
        try:
            status, _data, _h = _request("MKCOL", base, auth)
        except WebDavError:
            raise
        # 405 = 已存在，正常
        if status not in (201, 405, 200):
            if status == 401:
                raise WebDavError("认证失败：用户名或密码不正确")
            # 某些服务器对中间目录返回 409，继续尝试下一级
            if status != 409:
                raise WebDavError("创建目录失败，服务器返回 %d" % status)


def upload(conf, payload):
    """上传一个备份文件（JSON 文本）。返回远端文件名。"""
    url, err = validate_url(conf.get("url") or "", conf.get("allowPrivate"))
    if err:
        raise WebDavError(err)

    directory = (conf.get("directory") or "").strip("/")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    filename = "backup-%s.json" % stamp

    ensure_directory(conf)
    auth = (conf.get("username") or "", conf.get("password") or "")
    target = _join_url(url, directory, filename)

    body = payload.encode("utf-8")
    try:
        status, _data, _h = _request("PUT", target, auth, body=body,
                                     headers={"Content-Type": "application/json"})
    except WebDavError:
        raise

    if status not in (200, 201, 204):
        if status == 401:
            raise WebDavError("认证失败：用户名或密码不正确")
        raise WebDavError("上传失败，服务器返回 %d" % status)

    # 同步维护一个 latest 指针
    try:
        latest = _join_url(url, directory, "latest.json")
        pointer = json.dumps({"file": filename, "time": stamp}, ensure_ascii=False)
        _request("PUT", latest, auth, body=pointer.encode("utf-8"),
                 headers={"Content-Type": "application/json"})
    except WebDavError:
        pass  # latest 写失败不影响主备份

    return filename


def list_backups(conf):
    """列出远端备份文件。返回 (files, error)。"""
    url, err = validate_url(conf.get("url") or "", conf.get("allowPrivate"))
    if err:
        return [], err

    directory = (conf.get("directory") or "").strip("/")
    auth = (conf.get("username") or "", conf.get("password") or "")

    target = url.rstrip("/")
    if directory:
        target = target + "/" + urllib.parse.quote(directory)

    try:
        status, data, _h = _request("PROPFIND", target, auth, body=_propfind_body,
                                    headers={"Depth": "1", "Content-Type": "application/xml"})
    except WebDavError as e:
        return [], str(e)

    if status == 404:
        return [], ""
    if status == 401:
        return [], "认证失败：用户名或密码不正确"
    if status != 207:
        return [], "服务器返回 %d" % status

    files = []
    try:
        text = data.decode("utf-8", "ignore")
        for m in re.finditer(r"<D:href>([^<]+)</D:href>|<d:href>([^<]+)</d:href>|<href>([^<]+)</href>",
                             text, re.I):
            href = next(g for g in m.groups() if g)
            name = urllib.parse.unquote(href.rstrip("/").rsplit("/", 1)[-1])
            if name.endswith(".json") and name.startswith("backup-"):
                files.append(name)
    except Exception as e:
        return [], "解析目录列表失败: %s" % e

    return sorted(files, reverse=True), ""


def download(conf, filename):
    """下载指定备份。返回 (dict, error)。"""
    url, err = validate_url(conf.get("url") or "", conf.get("allowPrivate"))
    if err:
        return None, err

    # 文件名白名单，防止路径穿越
    if not re.match(r"^[\w.\-]+\.json$", filename):
        return None, "非法文件名"

    directory = (conf.get("directory") or "").strip("/")
    auth = (conf.get("username") or "", conf.get("password") or "")
    target = _join_url(url, directory, filename)

    try:
        status, data, _h = _request("GET", target, auth)
    except WebDavError as e:
        return None, str(e)

    if status == 404:
        return None, "远端没有这个文件"
    if status == 401:
        return None, "认证失败：用户名或密码不正确"
    if status != 200:
        return None, "下载失败，服务器返回 %d" % status

    try:
        return json.loads(data.decode("utf-8", "ignore")), ""
    except json.JSONDecodeError as e:
        return None, "备份文件格式错误: %s" % e


_propfind_body = ('<?xml version="1.0" encoding="utf-8"?>'
                  '<D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/></D:prop></D:propfind>')
