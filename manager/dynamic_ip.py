"""动态 IP 提取器：借鉴比特浏览器的 dynamicIpUrl。

很多代理服务商提供「提取链接」：每请求一次返回一个可用 IP（或一组）。
本模块负责：
1. 校验提取链接（仅 http/https，拒绝本机/内网/保留地址）；
2. 拉取并解析多种常见返回格式；
3. 转成 sing-box 可用的节点，供环境启动时临时使用。

安全约束（硬性）：
- 只允许 http / https
- 拉取前解析主机名，拒绝 localhost、环回、私有、链路本地、保留地址
- 限制响应体大小，避免被超大响应拖死
"""

import ipaddress
import json
import re
import socket
import urllib.parse

MAX_BYTES = 256 * 1024
TIMEOUT = 20

# 私有/保留网段判断用
_INTERNAL_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata", "metadata.google.internal",
}


class FetchError(Exception):
    """提取链接不可用。"""


def check_url(url):
    """校验提取链接合法性。不合法直接抛 FetchError。"""
    if not isinstance(url, str) or not url.strip():
        raise FetchError("提取链接为空")
    url = url.strip()

    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        raise FetchError("提取链接格式不正确")

    if parts.scheme not in ("http", "https"):
        raise FetchError("提取链接只支持 http / https")

    host = (parts.hostname or "").strip().lower()
    if not host:
        raise FetchError("提取链接缺少主机名")

    if _is_internal_host(host):
        raise FetchError("提取链接不允许指向本机或内网地址")

    return url


def fetch(url):
    """拉取提取链接内容。返回文本。"""
    url = check_url(url)

    from . import ssrf_guard

    try:
        # 走统一的 SSRF 防护拉取：重定向逐跳复检、响应限长
        raw = ssrf_guard.fetch(url, timeout=TIMEOUT, max_bytes=MAX_BYTES, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                          "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "Accept": "text/plain, application/json, */*",
        })
    except Exception as e:
        raise FetchError("提取失败: %s" % e)

    if len(raw) > MAX_BYTES:
        raise FetchError("响应内容过大（超过 %d KB）" % (MAX_BYTES // 1024))

    return raw.decode("utf-8", "ignore")


def parse_ips(text):
    """从提取结果里解析出 IP:端口 列表。

    兼容格式：
      1.2.3.4:8080
      1.2.3.4:8080:user:pass
      user:pass@1.2.3.4:8080
      1.2.3.4 8080
      JSON: {"data":[{"ip":"1.2.3.4","port":8080,"username":"u","password":"p"}]}
      JSON: ["1.2.3.4:8080"]
    """
    text = (text or "").strip()
    if not text:
        return []

    # 先尝试 JSON
    if text[0] in "[{":
        try:
            data = json.loads(text)
            return _from_json(data)
        except json.JSONDecodeError:
            pass

    out = []
    for line in re.split(r"[\r\n]+", text):
        line = line.strip()
        if not line:
            continue
        # 纯 IP，无端口
        try:
            ipaddress.ip_address(line)
            out.append({"server": line, "port": 0, "username": "", "password": ""})
            continue
        except ValueError:
            pass

        # user:pass@host:port
        m = re.match(r"^([^:@\s]+):([^@\s]*)@([0-9a-zA-Z.\-]+):(\d{1,5})$", line)
        if m:
            out.append({
                "username": m.group(1), "password": m.group(2),
                "server": m.group(3), "port": int(m.group(4)),
            })
            continue

        # host:port:user:pass
        m = re.match(r"^([0-9a-zA-Z.\-]+):(\d{1,5}):([^:\s]+):(.*)$", line)
        if m:
            out.append({
                "server": m.group(1), "port": int(m.group(2)),
                "username": m.group(3), "password": m.group(4),
            })
            continue

        # host:port
        m = re.match(r"^([0-9a-zA-Z.\-]+):(\d{1,5})$", line)
        if m:
            out.append({"server": m.group(1), "port": int(m.group(2)),
                        "username": "", "password": ""})
            continue

        # host port（空格分隔）
        m = re.match(r"^([0-9a-zA-Z.\-]+)\s+(\d{1,5})$", line)
        if m:
            out.append({"server": m.group(1), "port": int(m.group(2)),
                        "username": "", "password": ""})
            continue

    return [x for x in out if _valid_entry(x)]


def parse_nodes(text):
    """解析成可直接给 sing-box 用的节点列表（默认 socks5 协议）。"""
    ips = parse_ips(text)
    nodes = []
    for i, item in enumerate(ips, 1):
        node = {
            "protocol": "socks5",
            "name": "动态IP-%d" % i,
            "server": item["server"],
            "port": item["port"] or 1080,
            "username": item["username"],
            "password": item["password"],
        }
        nodes.append(node)
    return nodes


# ---------- 内部 ----------

def _from_json(data):
    """从 JSON 结构里提取 IP 条目。"""
    out = []

    def walk(obj):
        if isinstance(obj, list):
            for item in obj:
                walk(item)
            return
        # JSON 里直接是 "host:port" 字符串
        if isinstance(obj, str):
            for parsed in parse_ips(obj):
                out.append(parsed)
            return
        if isinstance(obj, dict):
            ip = obj.get("ip") or obj.get("host") or obj.get("server") or obj.get("proxy")
            port = obj.get("port") or obj.get("proxy_port")
            if isinstance(ip, str) and ip.strip():
                # ip 字段里可能已经是 host:port
                if port is None and ":" in ip:
                    parts = ip.rsplit(":", 1)
                    if parts[1].isdigit():
                        ip, port = parts[0], parts[1]
                try:
                    port_int = int(port) if port is not None else 0
                except (TypeError, ValueError):
                    port_int = 0
                out.append({
                    "server": ip.strip(),
                    "port": port_int,
                    "username": str(obj.get("username") or obj.get("user") or ""),
                    "password": str(obj.get("password") or obj.get("pass") or ""),
                })
                return
            for v in obj.values():
                if isinstance(v, (list, dict)):
                    walk(v)
            return

    walk(data)
    return [x for x in out if _valid_entry(x)]


def _valid_entry(item):
    if not item.get("server"):
        return False
    port = item.get("port") or 0
    if port and not (1 <= int(port) <= 65535):
        return False
    return True


def _is_internal_host(host):
    """拒绝 localhost / 环回 / 私有 / 链路本地 / 保留地址。"""
    h = host.strip().lower().strip("[]")

    if h in _INTERNAL_HOSTNAMES:
        return True
    if h.endswith(".localhost") or h.endswith(".local") or h.endswith(".internal"):
        return True

    candidates = []
    # 字面 IP
    try:
        candidates.append(ipaddress.ip_address(h))
    except ValueError:
        # 域名：解析后逐个判断
        try:
            for info in socket.getaddrinfo(h, None):
                try:
                    candidates.append(ipaddress.ip_address(info[4][0]))
                except ValueError:
                    continue
        except (socket.gaierror, OSError):
            # 解析不了交给后续请求失败处理
            return False

    for ip in candidates:
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
        if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return True
        text = str(ip)
        if text.startswith("169.254.") or text.startswith("100.64."):
            return True

    return False
