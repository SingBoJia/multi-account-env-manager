"""SSRF 安全拉取：给「服务端按 URL 拉取外部内容」的功能统一使用。

风险面（此前校验与请求分离导致的两类绕过）：
- 302 重定向：校验通过的是公网地址，urllib 默认跟随跳转，可被 302 到
  127.0.0.1 / 169.254.169.254 等内网目标；
- DNS rebinding：校验时解析到公网，真正请求时再解析回内网。

处理：
- 重定向的每一跳都重新过目标检查，不安全立即断开；
- 请求前对主机名做全量解析并逐一检查（缩小 rebinding 窗口；
  彻底封死需要按固定 IP 直连，本地单机工具暂不做，残余窗口见注释）。
"""

import ipaddress
import socket
import urllib.error
import urllib.parse
import urllib.request

MAX_BYTES = 2 * 1024 * 1024
TIMEOUT = 20

# 已知指向本机/云元数据的主机名
_INTERNAL_HOSTNAMES = {
    "localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback",
    "metadata", "metadata.google.internal",
}


class BlockedError(Exception):
    """目标地址被 SSRF 防护拦截。"""


def is_internal_host(host):
    """拒绝 localhost / 环回 / 私有 / 链路本地 / 保留地址。

    域名会把解析出的所有地址都检查一遍：只查第一条 A 记录时，
    攻击者可以用多记录域名混过检查。
    """
    h = str(host or "").strip().lower().strip("[]")
    if not h:
        return True
    if h in _INTERNAL_HOSTNAMES:
        return True
    if h.endswith(".localhost") or h.endswith(".local") or h.endswith(".internal"):
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
            # 解析不了交给后续请求失败处理，不当作内网
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


def assert_external(url):
    """校验 URL 可安全拉取，不合法抛 BlockedError。"""
    try:
        parts = urllib.parse.urlsplit(str(url))
    except ValueError:
        raise BlockedError("地址格式不正确: %r" % (url,))
    if parts.scheme not in ("http", "https"):
        raise BlockedError("只支持 http/https 地址")
    host = (parts.hostname or "").strip().lower()
    if not host:
        raise BlockedError("地址缺少主机名")
    if is_internal_host(host):
        raise BlockedError("不允许访问本机或内网地址")


class _GuardedRedirect(urllib.request.HTTPRedirectHandler):
    """重定向的每一跳都重新校验，防止 302 跳进内网。"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            assert_external(newurl)
        except BlockedError:
            raise urllib.error.HTTPError(
                newurl, code, "redirect blocked: %s" % newurl, headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, timeout=TIMEOUT, max_bytes=MAX_BYTES, headers=None):
    """带 SSRF 防护的拉取，返回 bytes（最多 max_bytes+1，供调用方判断超长）。

    被拦截或失败抛 BlockedError / urllib.error.HTTPError / OSError。
    """
    assert_external(url)
    opener = urllib.request.build_opener(_GuardedRedirect())
    req = urllib.request.Request(url, headers=headers or {})
    with opener.open(req, timeout=timeout) as r:
        return r.read(max_bytes + 1)
