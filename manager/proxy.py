"""代理管理：把用户填写的节点参数转成 sing-box 配置，并按环境拉起独立实例。

支持协议：socks5 / http / vless / vmess / trojan / hysteria2。
每个环境一个 sing-box 进程，监听独立的本地端口，互不干扰。
"""

import json
import os
import pathlib
import socket
import subprocess
import time

# sing-box 可执行文件（scoop 安装路径）
SINGBOX_CANDIDATES = [
    pathlib.Path(os.path.expanduser("~")) / "scoop" / "shims" / "sing-box.exe",
    pathlib.Path(r"C:\Program Files\sing-box\sing-box.exe"),
    pathlib.Path("sing-box.exe"),
]

PROTOCOLS = ("socks5", "http", "vless", "vmess", "trojan", "hysteria2", "ssh")
PORT_RANGE_START = 20000
PORT_RANGE_END = 20100


def find_singbox():
    for p in SINGBOX_CANDIDATES:
        if p.is_file():
            return str(p)
    return None


def _free_port(preferred_start):
    """在预设区间内找一个可用端口。"""
    for port in range(preferred_start, PORT_RANGE_END + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise RuntimeError("没有可用本地端口")


def build_outbound(node):
    """把节点配置转成 sing-box outbound。

    node 必填：protocol, server, port
    可选：username, password, uuid, alterId, security(加密方式),
          tls(bool), sni, alpn, flow, transport(ws/grpc/tcp), path, host,
          reality(bool), realityPublicKey, realityShortId, fingerprint
    """
    proto = str(node.get("protocol", "")).lower()
    if proto not in PROTOCOLS:
        raise ValueError("不支持的协议: %s" % proto)

    server = node.get("server")
    port = node.get("port")
    if not server or not port:
        raise ValueError("节点缺少 server 或 port")

    # sing-box 的类型名与分享链接 scheme 不完全一致
    sb_type = "socks" if proto == "socks5" else proto

    out = {
        "type": sb_type,
        "tag": "proxy",
        "server": server,
        "server_port": int(port),
    }

    if proto in ("socks5", "http"):
        if node.get("username"):
            out["username"] = node["username"]
        if node.get("password"):
            out["password"] = node["password"]
        return out

    if proto == "ssh":
        # sing-box 的 ssh outbound：用账号密码或私钥登录，本地起 socks 转发
        out["user"] = node.get("username") or node.get("user") or ""
        if node.get("password"):
            out["password"] = node["password"]
        if node.get("privateKey"):
            out["private_key"] = node["privateKey"]
            if node.get("privateKeyPassphrase"):
                out["private_key_passphrase"] = node["privateKeyPassphrase"]
        if node.get("hostKey"):
            out["host_key"] = node["hostKey"]
        if node.get("hostKeyAlgorithms"):
            algorithms = node["hostKeyAlgorithms"]
            out["host_key_algorithms"] = (
                algorithms if isinstance(algorithms, list)
                else [a.strip() for a in str(algorithms).split(",") if a.strip()]
            )
        return out

    if proto == "vless":
        out["uuid"] = node.get("uuid", "")
        if node.get("flow"):
            out["flow"] = node["flow"]
        out["packet_encoding"] = node.get("packetEncoding", "xudp")
    elif proto == "vmess":
        out["uuid"] = node.get("uuid", "")
        out["security"] = node.get("security", "auto")
        out["alter_id"] = int(node.get("alterId", 0))
    elif proto == "trojan":
        out["password"] = node.get("password", "")
    elif proto == "hysteria2":
        out["password"] = node.get("password", "")

    # TLS / REALITY
    tls_enabled = bool(node.get("tls")) or bool(node.get("reality")) or proto in ("trojan", "hysteria2")
    if tls_enabled:
        tls = {
            "enabled": True,
            "server_name": node.get("sni") or server,
            "insecure": bool(node.get("insecure", False)),
        }
        if node.get("alpn"):
            tls["alpn"] = node["alpn"] if isinstance(node["alpn"], list) else [node["alpn"]]
        if node.get("fingerprint"):
            tls["utls"] = {"enabled": True, "fingerprint": node["fingerprint"]}

        if node.get("reality") and node.get("realityPublicKey"):
            pk = str(node["realityPublicKey"]).strip()
            if not _looks_like_x25519_key(pk):
                raise ValueError(
                    "REALITY 公钥格式不正确（应为 43 位 base64url 的 x25519 公钥）: %s" % pk[:20]
                )
            tls["reality"] = {
                "enabled": True,
                "public_key": pk,
                "short_id": str(node.get("realityShortId", "") or ""),
            }
        elif node.get("reality"):
            raise ValueError("节点标记了 REALITY 但缺少 public key（pbk 参数）")
        out["tls"] = tls

    # 传输层
    transport = str(node.get("transport", "")).lower()
    if transport == "ws":
        t = {"type": "ws", "path": node.get("path", "/")}
        if node.get("host"):
            t["headers"] = {"Host": node["host"]}
        out["transport"] = t
    elif transport == "grpc":
        out["transport"] = {"type": "grpc", "service_name": node.get("path", "")}
    elif transport == "http":
        t = {"type": "http", "path": node.get("path", "/")}
        if node.get("host"):
            t["host"] = [node["host"]] if isinstance(node["host"], str) else node["host"]
        out["transport"] = t

    return out


def build_config(node, local_port, chain=None):
    """生成 sing-box 完整配置。

    chain 为多级代理链：按顺序传入的节点列表。
    流量路径为 浏览器 -> chain[0] -> chain[1] -> ... -> 目标，
    即最后一个节点是「出口」，前面的都是中转。

    sing-box 通过 outbound 的 detour 字段串联：
    后一个节点 detour 指向前一个节点，最终 final 指向链条起点。
    """
    chain = chain or []
    outbounds = []

    if not chain:
        primary = build_outbound(node)
        outbounds.append(primary)
    else:
        # 逐个构建，第一个（落地/出口）在最前，后面的是前置中转
        tags = []
        for idx, hop in enumerate(chain):
            hop_out = build_outbound(hop)
            tag = "hop%d" % idx
            hop_out["tag"] = tag
            outbounds.append(hop_out)
            tags.append(tag)

        # han e.g. chain=[A, B]: A 是出口，B 是前置。
        # 浏览器 -> B -> A -> 目标，所以 B.detour = A
        for idx in range(len(tags) - 1, 0, -1):
            outbounds[idx]["detour"] = tags[idx - 1]

    outbounds.append({"type": "direct", "tag": "direct"})

    final_tag = outbounds[0]["tag"] if not chain else "hop%d" % (len(chain) - 1)

    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "mixed",
                "tag": "in",
                "listen": "127.0.0.1",
                "listen_port": local_port,
            }
        ],
        "outbounds": outbounds,
        "route": {
            "rules": [
                # 私有地址走直连，避免代理内网请求
                {"ip_is_private": True, "outbound": "direct"},
            ],
            "final": final_tag,
        },
    }


class ProxyManager:
    """为每个环境维护一个 sing-box 实例。"""

    def __init__(self, work_dir):
        self.work_dir = pathlib.Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.bin = find_singbox()
        self._procs = {}  # env_id -> (Popen, port)

    # ---------- 对外接口 ----------

    def available(self):
        return self.bin is not None

    def start(self, env_id, node, offset=0, chain=None):
        """为环境启动代理，返回本地 mixed 端口。

        chain 非空时走多级代理链，node 参数被忽略（用 chain 的第一个作为出口）。
        """
        if not self.bin:
            raise RuntimeError("未找到 sing-box，请先安装")
        self.stop(env_id)

        port = _free_port(PORT_RANGE_START + offset)
        hops = [h for h in (chain or []) if h and h.get("server")]
        if hops:
            config = build_config(hops[0], port, chain=hops)
        else:
            config = build_config(node, port)

        cfg_path = self.work_dir / ("sb-%s.json" % _safe_key(env_id))
        cfg_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")

        proc = subprocess.Popen(
            [self.bin, "run", "-c", str(cfg_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            creationflags=_no_window_flag(),
        )
        self._procs[env_id] = (proc, port, cfg_path)

        # 等待端口就绪
        if not _wait_port(port, timeout=8.0):
            err = ""
            try:
                err = proc.stderr.read().decode("utf-8", "ignore")[:400] if proc.stderr else ""
            except Exception:
                pass
            self.stop(env_id)
            raise RuntimeError("sing-box 启动失败: %s" % (err or "端口未就绪"))

        return port

    def stop(self, env_id):
        entry = self._procs.pop(env_id, None)
        if not entry:
            return
        proc, _port, cfg_path = entry
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            cfg_path.unlink(missing_ok=True)
        except OSError:
            pass

    def stop_all(self):
        for env_id in list(self._procs.keys()):
            self.stop(env_id)

    def port_of(self, env_id):
        entry = self._procs.get(env_id)
        return entry[1] if entry else None

    def running(self, env_id):
        entry = self._procs.get(env_id)
        if not entry:
            return False
        return entry[0].poll() is None

    def probe(self, port, timeout=12.0):
        """通过该代理查询出口 IP，验证链路可用。"""
        import urllib.request

        proxy = "http://127.0.0.1:%d" % port
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
        try:
            with opener.open("http://ip-api.com/json/?lang=zh-CN", timeout=timeout) as r:
                data = json.loads(r.read().decode("utf-8", "ignore"))
            return {
                "ok": True,
                "ip": data.get("query"),
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}


# ---------- 内部工具 ----------

def _looks_like_x25519_key(value):
    """REALITY public key 是 32 字节的 base64url（无填充），长度 43。"""
    import base64
    import binascii

    if not isinstance(value, str):
        return False
    v = value.strip()
    if len(v) < 40 or len(v) > 44:
        return False
    if any(c not in "-_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" for c in v):
        return False
    padded = v + "=" * (-len(v) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == 32


def _safe_key(env_id):
    """环境编号只用于内部进程/文件命名，做保守过滤。"""
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in str(env_id))[:64]


def _wait_port(port, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def _no_window_flag():
    """Windows 下隐藏子进程控制台窗口。"""
    if os.name == "nt":
        return 0x08000000  # CREATE_NO_WINDOW
    return 0
