"""节点解析：把分享链接、订阅内容、订阅 URL 转成统一的节点结构。

支持格式：
  vless://uuid@host:port?params#name
  vmess://base64(json)
  trojan://password@host:port?params#name
  hysteria2://password@host:port?params#name   (hy2:// 亦可)
  socks5://user:pass@host:port#name
  http://user:pass@host:port#name
  ss:// 仅识别并明确提示不支持（sing-box 支持但本站不纳入，避免混淆）

订阅：
  整体 base64 编码的多行链接
  明文多行链接
"""

import base64
import binascii
import json
import re
import urllib.parse

SUPPORTED = ("socks5", "http", "vless", "vmess", "trojan", "hysteria2", "ssh")

# 分享链接 scheme -> 内部协议名
SCHEME_MAP = {
    "vless": "vless",
    "vmess": "vmess",
    "trojan": "trojan",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
    "socks5": "socks5",
    "socks": "socks5",
    "http": "http",
    "https": "http",
    "ssh": "ssh",
}


class ParseError(Exception):
    """单条节点解析失败，附带原始行便于定位。"""

    def __init__(self, message, raw=""):
        self.raw = raw
        super().__init__(message)


# ---------- 对外接口 ----------

def parse_many(text):
    """解析多行文本，返回 (nodes, errors)。单条失败不影响其余。"""
    nodes = []
    errors = []
    for raw_line in _split_lines(text):
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        try:
            node = parse_one(line)
            if node:
                nodes.append(node)
        except ParseError as e:
            errors.append({"input": e.raw[:120], "error": str(e)})
        except Exception as e:
            errors.append({"input": line[:120], "error": "解析异常: %s" % e})
    return nodes, errors


def parse_one(line):
    """解析单条链接。"""
    line = line.strip()
    if not line:
        return None

    # 纯 base64 块（订阅整体编码）
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", line):
        decoded = _try_b64(line)
        if decoded and "://" in decoded:
            raise ParseError("这是订阅内容，请用「导入订阅」整体粘贴", line)
        raise ParseError("无法识别的格式（不是分享链接）", line)

    scheme = line.split("://", 1)[0].lower()
    if scheme not in SCHEME_MAP:
        raise ParseError("不支持的协议: %s" % scheme, line)

    proto = SCHEME_MAP[scheme]
    if proto == "vmess":
        return _parse_vmess(line)
    if proto in ("hysteria2", "socks5", "http"):
        return _parse_uri(line, proto)
    return _parse_uri(line, proto)


def decode_subscription(text):
    """订阅内容可能是整体 base64，也可能是明文；返回解密后的文本。"""
    text = (text or "").strip()
    if not text:
        return ""
    if "://" in text:
        return text
    decoded = _try_b64(text)
    return decoded if decoded else text


def is_http_url(text):
    return bool(re.match(r"^https?://", (text or "").strip(), re.I))


# ---------- 各协议解析 ----------

def _parse_vmess(line):
    """vmess://base64(json)"""
    payload = line.split("://", 1)[1]
    payload = payload.split("#", 1)[0]
    raw = _try_b64(payload)
    if not raw:
        raise ParseError("vmess 内容不是合法 base64", line)

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        raise ParseError("vmess 解码后不是合法 JSON", line)

    host = data.get("add") or data.get("host") or ""
    port = data.get("port")
    uuid = data.get("id") or ""
    if not host or not port or not uuid:
        raise ParseError("vmess 缺少 add/port/id", line)

    node = {
        "protocol": "vmess",
        "name": str(data.get("ps") or "%s:%s" % (host, port)),
        "server": str(host),
        "port": _to_port(port, line),
        "uuid": str(uuid),
        "security": str(data.get("scy") or data.get("security") or "auto"),
        "alterId": str(data.get("aid") or data.get("alterId") or "0"),
    }

    net = str(data.get("net") or "").lower()
    if net in ("ws", "grpc", "http", "h2"):
        node["transport"] = "grpc" if net == "grpc" else ("ws" if net == "ws" else "http")
    if data.get("path"):
        node["path"] = str(data["path"])
    if data.get("host") and data.get("host") != host:
        node["host"] = str(data["host"])
    if data.get("sni"):
        node["sni"] = str(data["sni"])
    tls = str(data.get("tls") or "").lower()
    if tls in ("tls", "reality", "true", "1"):
        node["tls"] = True
    if data.get("alpn"):
        alpn = data["alpn"]
        node["alpn"] = alpn if isinstance(alpn, list) else [a for a in str(alpn).split(",") if a]
    if data.get("fp"):
        node["fingerprint"] = str(data["fp"])
    return node


def _parse_uri(line, proto):
    """通用 URI 解析：vless/trojan/hysteria2/socks5/http。"""
    parsed = urllib.parse.urlsplit(line)
    if not parsed.hostname:
        raise ParseError("缺少服务器地址", line)

    server = parsed.hostname
    port = _to_port(parsed.port, line)
    query = urllib.parse.parse_qs(parsed.query or "")
    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "%s:%s" % (server, port)

    node = {
        "protocol": proto,
        "name": name or "%s:%s" % (server, port),
        "server": server,
        "port": port,
    }

    user = urllib.parse.unquote(parsed.username or "")
    pwd = urllib.parse.unquote(parsed.password or "")

    if proto == "vless":
        if not user:
            raise ParseError("vless 缺少 UUID", line)
        node["uuid"] = user
    elif proto == "trojan":
        if not user:
            raise ParseError("trojan 缺少密码", line)
        node["password"] = user
    elif proto == "hysteria2":
        if not user:
            raise ParseError("hysteria2 缺少密码", line)
        node["password"] = user
    elif proto in ("socks5", "http"):
        if user:
            node["username"] = user
        if pwd:
            node["password"] = pwd
    elif proto == "ssh":
        # ssh://user:password@host:22  或 ssh://user@host:22?privateKey=...
        if user:
            node["username"] = user
        if pwd:
            node["password"] = pwd
        pk = _first(query, "privateKey", "private_key", "key")
        if pk:
            node["privateKey"] = pk

    # 公共参数
    sni = _first(query, "sni", "peer", "servername")
    if sni:
        node["sni"] = sni

    net = (_first(query, "type", "net") or "").lower()
    if net in ("ws", "grpc", "http", "h2", "tcp"):
        node["transport"] = {"h2": "http", "tcp": ""}.get(net, net)
    path = _first(query, "path")
    if path:
        node["path"] = path
    host_param = _first(query, "host")
    if host_param:
        node["host"] = host_param

    security = (_first(query, "security") or "").lower()
    if security in ("tls", "reality", "xtls"):
        node["tls"] = True
    if security == "reality":
        node["reality"] = True

    pbk = _first(query, "pbk", "publicKey")
    if pbk:
        node["realityPublicKey"] = pbk
        node["reality"] = True
        node["tls"] = True
    sid = _first(query, "sid", "shortId")
    if sid:
        node["realityShortId"] = sid

    fp = _first(query, "fp", "fingerprint")
    if fp:
        node["fingerprint"] = fp
    flow = _first(query, "flow")
    if flow:
        node["flow"] = flow
    alpn = _first(query, "alpn")
    if alpn:
        node["alpn"] = [a for a in alpn.split(",") if a]
    insecure = _first(query, "allowInsecure", "insecure")
    if insecure in ("1", "true"):
        node["insecure"] = True
    obfs = _first(query, "obfs")
    if proto == "hysteria2" and obfs:
        node["obfs"] = obfs

    return node


# ---------- 工具 ----------

def _split_lines(text):
    if not text:
        return []
    # 订阅整体 base64 时先解码
    if "://" not in text:
        decoded = _try_b64(text)
        if decoded:
            text = decoded
    return re.split(r"[\r\n]+", text)


def _try_b64(s):
    s = re.sub(r"\s+", "", s or "")
    if len(s) < 8:
        return None
    padded = s + "=" * (-len(s) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            out = decoder(padded)
            text = out.decode("utf-8", "ignore").strip()
            if text and all(31 < ord(c) or c in "\r\n\t" for c in text[:200]):
                return text
        except (binascii.Error, ValueError):
            continue
    return None


def _to_port(value, raw):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ParseError("端口不是数字: %r" % (value,), raw)
    if not (1 <= port <= 65535):
        raise ParseError("端口超出范围: %d" % port, raw)
    return port


def _first(query, *keys):
    for k in keys:
        if k in query and query[k]:
            return query[k][0]
    return ""


def summarize(node):
    """给界面显示用的短描述。"""
    proto = node.get("protocol", "?")
    server = node.get("server", "?")
    port = node.get("port", "?")
    extras = []
    if node.get("reality"):
        extras.append("REALITY")
    elif node.get("tls"):
        extras.append("TLS")
    if node.get("transport"):
        extras.append(node["transport"])
    tail = (" [" + ",".join(extras) + "]") if extras else ""
    return "%s://%s:%s%s" % (proto, server, port, tail)
