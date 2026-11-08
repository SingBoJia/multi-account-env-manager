"""多账号环境管理器：把指纹、代理、浏览器、存储组装成一个可用服务。

启动：
    python app.py
然后浏览器打开 http://127.0.0.1:8787
"""

import json
import os
import pathlib
import re
import secrets
import sys
import threading
import time
import urllib.parse

# Windows 控制台/重定向到管道时默认可能是 cp1252，中文 print 会抛
# UnicodeEncodeError 导致 EXE 直接退出；统一按 UTF-8 输出。
if os.name == "nt":
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

from flask import Flask, jsonify, request, send_from_directory

# ---------- 路径解析：源码运行与 EXE 运行都要正确 ----------
# 打包成 EXE 后，__file__ 指向 PyInstaller 的临时解包目录（每次启动都变），
# 如果数据也写在那里，关掉就丢。所以：
#   BUNDLE_DIR = 只读资源（web/、manager/ 的 python 文件）
#   DATA_ROOT  = 可写数据（配置、浏览器 profile），固定放在 EXE 旁边
if getattr(sys, "frozen", False):
    BUNDLE_DIR = pathlib.Path(getattr(sys, "_MEIPASS", pathlib.Path(sys.executable).parent))
else:
    BUNDLE_DIR = pathlib.Path(__file__).resolve().parent

HERE = BUNDLE_DIR
sys.path.insert(0, str(BUNDLE_DIR))

from manager.paths import data_root as _data_root

DATA_ROOT = _data_root()
DATA_ROOT.mkdir(parents=True, exist_ok=True)

from manager import cookies as cookie_io
from manager import dynamic_ip
from manager import excel_io
from manager import layout as window_layout
from manager import members as member_store
from manager import ssrf_guard
from manager import webdav
from manager.backends import BrowserBackends
from manager.browser import BrowserLauncher
from manager.fingerprint import FingerprintEngine
from manager.firefox_kernel import FirefoxKernel
from manager.kernels import DEFAULT_FIREFOX_VERSION, KernelManager, normalize_firefox_version
from manager.node_pool import NodePool
from manager.nodes import ParseError, decode_subscription, parse_many, summarize
from manager.proxy import ProxyManager, PROTOCOLS
from manager.config_io import ConfigIO
from manager.store import EnvironmentStore
from manager.store import ENV_ID_PATTERN as _ENV_ID_PATTERN
from manager.subscription import SubscriptionStore, node_hash
from manager.syncer import WindowSynchronizer

app = Flask(__name__, static_folder=None)

engine = FingerprintEngine(str(DATA_ROOT))
store = EnvironmentStore()
pool = NodePool()
subs = SubscriptionStore()
proxies = ProxyManager(str(DATA_ROOT / "singbox"))
launcher = BrowserBackends(
    BrowserLauncher(str(DATA_ROOT), fps=engine, proxies=proxies),
    FirefoxKernel(DATA_ROOT, fps=engine, proxies=proxies),
    store,
)
syncer = WindowSynchronizer(launcher)
config_io = ConfigIO(store, pool, engine, subs)
members = member_store.MemberStore()
kernel_manager = KernelManager(chrome_path=launcher.chrome)

# 登录会话：token -> (username, expire_at)
_sessions = {}
SESSION_TTL = 2 * 3600  # 2 小时

_lock = threading.Lock()
_ports = {}  # env_id -> 代理本地端口

# 本机服务加固：Host/Origin 必须是本机，挡住恶意网页的跨站请求与 DNS rebinding
_LOCAL_HOSTNAMES = {"127.0.0.1", "localhost", "::1"}


def _request_hostname(host_with_port):
    """从 Host 头取主机名，兼容 IPv6 字面量。"""
    h = str(host_with_port or "").strip()
    if h.startswith("["):
        end = h.find("]")
        return h[1:end].lower() if end > 0 else ""
    return h.rsplit(":", 1)[0].lower()


@app.before_request
def _local_guard():
    """本机防护（先于成员鉴权执行）：

    - Host 不是本机 → 拒绝（DNS rebinding 后 Host 会变成攻击者域名）
    - Origin 不是本机 → 拒绝（恶意网页用 no-cors POST 打本机接口 / 探测本机服务）
    非浏览器客户端（curl 等）没有 Origin，不受影响。
    """
    if not request.path.startswith("/api/"):
        return None
    if _request_hostname(request.host) not in _LOCAL_HOSTNAMES:
        return jsonify({"ok": False, "error": "拒绝非本机请求"}), 403
    origin = request.headers.get("Origin", "")
    if origin:
        try:
            ohost = urllib.parse.urlsplit(origin).hostname or ""
        except ValueError:
            ohost = ""
        if ohost.lower() not in _LOCAL_HOSTNAMES:
            return jsonify({"ok": False, "error": "拒绝跨站请求"}), 403
    return None


# ---------- 页面 ----------

@app.route("/")
def index():
    resp = send_from_directory(str(HERE / "web"), "index.html")
    # 避免浏览器缓存旧控制台，导致看不到新按钮/新页面
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp


@app.route("/<path:filename>")
def static_files(filename):
    return send_from_directory(str(HERE / "web"), filename)


# ---------- 环境锁校验 ----------

class LockError(Exception):
    """环境被锁且未通过密码校验。"""


class PermissionDenied(Exception):
    """成员权限不足或未登录。"""


# HTTP 方法与动作的映射：用于成员权限统一拦截
_METHOD_ACTIONS = {
    ("GET",): "view",
    ("POST", "start"): "start",
    ("POST", "stop"): "stop",
    ("POST", "recycle"): "delete",
    ("POST", "regenerate"): "edit",
    ("POST", "backup"): "sync",
    ("POST", "restore"): "sync",
}

# URL 片段到动作的映射（按优先级排列，取第一个命中）
_PATH_ACTIONS = [
    ("/api/members", "manage_members"),
    ("/api/nodes", "manage_nodes"),
    ("/api/subscriptions", "manage_subs"),
    ("/api/export", "export"),
    ("/api/import", "edit"),
    ("/api/cloud", "sync"),
    ("/api/layout", "layout"),
    ("/api/recycle", "delete"),
]


def _resolve_action():
    """从请求推断需要的权限动作。返回 None 表示不拦截。"""
    path = request.path
    method = request.method

    # 成员系统自身的登录/状态接口始终放行
    if path.startswith("/api/auth") or path == "/" or path.startswith("/api/protocols"):
        return None
    if path.startswith("/api/envs/import-excel/template"):
        return "view"

    # 环境启动/停止有专属动作
    if method == "POST" and (path.endswith("/start") or path.endswith("/stop")):
        env_id = path.rstrip("/").rsplit("/", 1)[-1]
        return "start" if path.endswith("/start") else "stop"

    # Cookie 导出是最高敏感资产：单独提权到 export（此前按 GET 归 view，
    # viewer 角色也能导出全部登录态）
    if method == "GET" and path.startswith("/api/envs/") and path.endswith("/cookies"):
        return "export"

    # 环境修改类
    if method in ("PATCH", "PUT") and path.startswith("/api/envs"):
        return "edit"
    if method == "DELETE" and path.startswith("/api/envs"):
        return "delete"
    if method == "POST" and path.endswith("/recycle"):
        return "delete"
    if method == "POST" and path.endswith("/fingerprint/regenerate"):
        return "edit"

    for fragment, action in _PATH_ACTIONS:
        if path.startswith(fragment):
            if method == "GET":
                return "view"
            return action

    # 其余写操作按动作表映射，读操作视为查看
    if method == "GET":
        return "view"
    return "edit"


@app.before_request
def _member_gate():
    """成员系统启用时，对所有 /api/ 请求做统一权限校验。"""
    if not request.path.startswith("/api/"):
        return None
    if not members.all():
        return None  # 未启用成员系统，单用户模式，全部放行

    # 关键：先判断放行名单，再判断登录。
    # 否则 /api/auth/login 自身会被拦，未登录永远无法登录（死锁）。
    action = _resolve_action()
    if action is None:
        return None

    m = _current_member()
    if m is None:
        return jsonify({"ok": False, "error": "未登录或会话已过期", "authRequired": True}), 401

    if not members.can(m, action):
        return jsonify({
            "ok": False,
            "error": "当前角色没有「%s」权限" % member_store.ACTION_LABELS.get(action, action),
        }), 403

    # 环境级授权（envScope）第二道：按本次请求实际涉及的环境逐一校验。
    # 之前只查动作不查环境，envScope 从未生效。
    for env_id in _request_env_ids():
        if not members.can(m, action, env_id):
            return jsonify({
                "ok": False,
                "error": "没有环境 %s 的「%s」权限" % (
                    env_id, member_store.ACTION_LABELS.get(action, action)),
            }), 403
    return None


_ENV_SEG_RE = re.compile(r"^/api/envs/([^/]+)(?:/|$)")
# /api/envs/ 后面跟的不是环境编号的固定路径
_NON_ENV_SEGMENTS = {"batch", "clone", "compare", "import-excel"}


def _request_env_ids():
    """收集本次请求涉及的环境编号（路径里的 + 批量 body 里的），供 envScope 校验。"""
    ids = []
    m = _ENV_SEG_RE.match(request.path or "")
    if m and m.group(1) not in _NON_ENV_SEGMENTS and _ENV_ID_PATTERN.match(m.group(1)):
        ids.append(m.group(1))
    body = request.get_json(silent=True) or {}
    if isinstance(body, dict):
        for key in ("ids", "envs", "env", "source", "master", "slaves"):
            v = body.get(key)
            if isinstance(v, str):
                v = [v]
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, str) and _ENV_ID_PATTERN.match(item):
                        ids.append(item)
    return list(dict.fromkeys(ids))


def _scope_env_ids(env_ids):
    """按当前成员的 envScope 过滤环境列表，返回 (允许, 拒绝)。

    空 scope 表示授权全部环境；admin 不受限。
    """
    m = _current_member()
    if not m or m.get("role") == "admin":
        return list(env_ids), []
    scope = m.get("envScope") or []
    if not scope:
        return list(env_ids), []
    allowed = [e for e in env_ids if e in scope]
    denied = [e for e in env_ids if e not in scope]
    return allowed, denied


def _scope_filter_set(env_map):
    """给列表接口按 envScope 过滤（空 scope = 全部可见）。"""
    m = _current_member()
    if not m or m.get("role") == "admin":
        return env_map
    scope = m.get("envScope") or []
    if not scope:
        return env_map
    return {k: v for k, v in env_map.items() if k in scope}


def _deny_out_of_scope_import(data):
    """导入/云恢复：配置里包含 scope 外环境时整体拒绝（fail-closed）。"""
    if not isinstance(data, dict):
        return
    ids = [str(e.get("id") or "") for e in (data.get("environments") or [])
           if isinstance(e, dict) and e.get("id")]
    if not ids:
        return
    _allowed, denied = _scope_env_ids(ids)
    if denied:
        raise PermissionDenied("配置包含未授权环境: %s" % ", ".join(denied[:5]))


def _require_unlocked(env_id, body=None):
    """修改类操作前的锁校验。

    环境未上锁直接放行；已上锁时必须提供正确密码。
    密码可以从请求体 password 字段取，或从 X-Env-Password 头取。
    """
    try:
        locked = store.is_locked(env_id)
    except ValueError:
        return  # 环境不存在交给后续逻辑报错
    if not locked:
        return

    password = ""
    if isinstance(body, dict):
        password = str(body.get("password") or "")
    if not password:
        password = request.headers.get("X-Env-Password", "")
    if not password or not store.check_password(env_id, password):
        raise LockError("环境 %s 已上锁，需要密码才能修改" % env_id)


def _locked_response(env_id, exc):
    return jsonify({
        "ok": False,
        "error": str(exc),
        "locked": True,
        "env": env_id,
    }), 403


def _validate_backend(env_id, backend):
    """浏览器后端只保留本地 Firefox 150 与本地 Chrome。"""
    backend = str(backend or "firefox").lower()
    # 旧数据里的 ads 统一迁移到本地 Firefox 150
    if backend == "ads" or backend not in ("local", "firefox"):
        backend = "firefox"
    return backend


def _normalize_kernel_version(backend, version):
    """内核版本：Firefox 保存具体版本，Chrome 保存 system。"""
    backend = str(backend or "firefox").lower()
    if backend in ("firefox", "ads"):
        return normalize_firefox_version(version) or DEFAULT_FIREFOX_VERSION
    return "system"


# ---------- 环境 API ----------

@app.route("/api/envs", methods=["GET"])
def list_envs():
    # 列表只显示未删除的环境，回收站单独查 /api/recycle
    data = _scope_filter_set(store.list_active())
    pool_map = pool.all()
    result = []
    for env_id, meta in data.items():
        backend = str(meta.get("browserBackend") or "local").lower()
        if backend == "ads":
            backend = "firefox"
        fp = engine.get(env_id) or {}
        node_id = meta.get("nodeId") or ""
        node = pool_map.get(node_id) if node_id else None
        chain = meta.get("chain") or []
        chain_nodes = []
        for nid in chain:
            n = pool_map.get(nid)
            if n:
                chain_nodes.append(_safe_node(n))
        running = launcher.running(env_id)
        debug_port = launcher.debug_port(env_id)
        item = {k: v for k, v in meta.items() if k != "adsUserId"}
        result.append({
            **item,
            "browserBackend": backend,
            "kernelVersion": _normalize_kernel_version(
                backend, meta.get("kernelVersion")),
            "lockHash": "",  # 不外泄哈希
            "lockSalt": "",
            "fingerprint": summarize_fp(fp),
            "running": running,
            "debugPort": debug_port,
            "proxyPort": _ports.get(env_id),
            "proxyAlive": proxies.running(env_id),
            "node": _safe_node(node) if node else None,
            "chainNodes": chain_nodes,
        })
    return jsonify({
        "ok": True,
        "envs": result,
        "singbox": proxies.available(),
        "stats": _stats(result),
    })


@app.route("/api/envs/<env_id>/lock", methods=["POST"])
def lock_env(env_id):
    """给环境上锁。上锁后修改配置、启动停止都需要密码。"""
    body = request.get_json(silent=True) or {}
    password = body.get("password") or ""
    try:
        if store.is_locked(env_id):
            # 已上锁的环境重设锁必须先验证原密码，防止越权改锁把原主人锁死
            old = str(body.get("oldPassword") or "") or request.headers.get("X-Env-Password", "")
            if not old or not store.check_password(env_id, old):
                raise LockError("环境 %s 已上锁，需先验证原密码才能重设锁" % env_id)
        store.set_lock(env_id, password)
    except LockError as e:
        return _locked_response(env_id, e)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "locked": True})


@app.route("/api/envs/<env_id>/unlock", methods=["POST"])
def unlock_env(env_id):
    """用密码解锁。"""
    body = request.get_json(silent=True) or {}
    password = body.get("password") or ""
    try:
        ok = store.unlock(env_id, password)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    if not ok:
        return jsonify({"ok": False, "error": "密码不正确"}), 403
    return jsonify({"ok": True, "locked": False})


@app.route("/api/envs/<env_id>/verify", methods=["POST"])
def verify_env_password(env_id):
    """校验密码（不改变锁状态），供前端做一次解锁会话。"""
    body = request.get_json(silent=True) or {}
    password = body.get("password") or ""
    try:
        ok = store.check_password(env_id, password)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    if not ok:
        return jsonify({"ok": False, "error": "密码不正确"}), 403
    return jsonify({"ok": True})


@app.route("/api/envs", methods=["POST"])
def create_env():
    body = request.get_json(silent=True) or {}
    env_id = str(body.get("id", "")).strip()
    if not env_id:
        return jsonify({"ok": False, "error": "缺少环境编号"}), 400
    try:
        backend = _validate_backend(env_id, body.get("browserBackend") or "firefox")
        meta = store.create(
            env_id,
            name=body.get("name", ""),
            platform=body.get("platform", ""),
            remark=body.get("remark", ""),
            proxy=body.get("proxy") or {},
            start_url=body.get("startUrl", ""),
            node_id=str(body.get("nodeId") or ""),
            browser_backend=backend,
            kernel_version=_normalize_kernel_version(backend, body.get("kernelVersion")),
        )
        fp = engine.load_or_create(env_id)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "env": meta, "fingerprint": summarize_fp(fp)})


@app.route("/api/envs/<env_id>", methods=["PATCH"])
def update_env(env_id):
    body = request.get_json(silent=True) or {}
    try:
        _require_unlocked(env_id, body)
    except LockError as e:
        return _locked_response(env_id, e)
    try:
        # 后端绑定只能走 /meta 的专用校验
        meta = store.update(env_id, **{
            k: v for k, v in body.items()
            if k not in ("id", "password", "browserBackend", "kernelVersion")
        })
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "env": meta})


@app.route("/api/envs/<env_id>", methods=["DELETE"])
def delete_env(env_id):
    body = request.get_json(silent=True) or {}
    try:
        _require_unlocked(env_id, body)
    except LockError as e:
        return _locked_response(env_id, e)
    with _lock:
        launcher.forget(env_id)
        proxies.stop(env_id)
        _ports.pop(env_id, None)
    try:
        # 移入回收站而非真删；彻底删除走 /api/recycle/purge
        item = store.soft_delete(env_id)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "recycled": True, "deletedAt": item.get("deletedAt")})


# ---------- 内核管理 API ----------

@app.route("/api/kernels", methods=["GET"])
def list_kernels():
    return jsonify({
        "ok": True,
        "kernels": kernel_manager.status(),
        "job": kernel_manager.job(),
    })


@app.route("/api/kernels/download", methods=["POST"])
def download_kernel():
    body = request.get_json(silent=True) or {}
    result = kernel_manager.start_download(
        body.get("type") or "firefox",
        body.get("version") or DEFAULT_FIREFOX_VERSION,
    )
    result["ok"] = True
    return jsonify(result)


@app.route("/api/kernels/job", methods=["GET"])
def kernel_job():
    return jsonify({"ok": True, "job": kernel_manager.job()})


# ---------- 指纹 API ----------

@app.route("/api/envs/<env_id>/fingerprint", methods=["GET"])
def get_fp(env_id):
    fp = engine.get(env_id)
    if not fp:
        return jsonify({"ok": False, "error": "指纹不存在"}), 404
    return jsonify({"ok": True, "fingerprint": fp})


@app.route("/api/envs/<env_id>/fingerprint/regenerate", methods=["POST"])
def regen_fp(env_id):
    body = request.get_json(silent=True) or {}
    if launcher.backend(env_id) == "firefox":
        return jsonify({
            "ok": False,
            "error": "该环境使用本地 Firefox 150，指纹由 user.js/profile 管理，不能重新生成",
        }), 400
    try:
        _require_unlocked(env_id, body)
    except LockError as e:
        return _locked_response(env_id, e)
    try:
        fp = engine.regenerate(env_id)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "fingerprint": summarize_fp(fp)})


@app.route("/api/envs/clone", methods=["POST"])
def clone_env():
    """克隆环境：复制设备身份与代理配置，生成新的环境编号。"""
    body = request.get_json(silent=True) or {}
    src = str(body.get("source") or "").strip()
    target = str(body.get("target") or "").strip()
    if not src or not target:
        return jsonify({"ok": False, "error": "缺少源环境或目标编号"}), 400
    if src == target:
        return jsonify({"ok": False, "error": "源和目标不能相同"}), 400

    src_meta = store.get(src)
    if not src_meta:
        return jsonify({"ok": False, "error": "源环境不存在"}), 404
    if store.get(target):
        return jsonify({"ok": False, "error": "目标编号已存在"}), 400
    try:
        # 克隆会复制源环境的设备身份与节点配置，视同修改，已上锁时需要密码
        _require_unlocked(src, body)
    except LockError as e:
        return _locked_response(src, e)

    try:
        src_backend = str(src_meta.get("browserBackend") or "local").lower()
        # 旧 ads 环境克隆时落到本地 Firefox 150
        clone_backend = "firefox" if src_backend == "ads" else src_backend
        meta = store.create(
            target,
            name=str(body.get("name") or (src_meta.get("name", "") + "-副本")),
            platform=src_meta.get("platform", ""),
            remark=src_meta.get("remark", ""),
            start_url=src_meta.get("startUrl", ""),
            node_id=body.get("nodeId") if body.get("nodeId") is not None else src_meta.get("nodeId", ""),
            browser_backend=clone_backend,
            kernel_version=src_meta.get("kernelVersion") or "",
        )
        fp = engine.clone(src, target, vary=bool(body.get("vary", True)))
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    return jsonify({"ok": True, "env": meta, "fingerprint": summarize_fp(fp)})


@app.route("/api/envs/compare", methods=["POST"])
def compare_envs():
    """对比多个环境的指纹，找出相同维度（关联风险）。"""
    body = request.get_json(silent=True) or {}
    ids = body.get("ids") or []
    if not isinstance(ids, list) or len(ids) < 2:
        return jsonify({"ok": False, "error": "至少选择两个环境"}), 400
    try:
        result = engine.compare([str(i) for i in ids])
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    if "error" in result:
        return jsonify({"ok": False, "error": result["error"]}), 400
    return jsonify({"ok": True, **result})


# ---------- 代理 API ----------

@app.route("/api/protocols", methods=["GET"])
def protocols():
    return jsonify({"ok": True, "protocols": list(PROTOCOLS), "singbox": proxies.available()})


@app.route("/api/envs/<env_id>/proxy/test", methods=["POST"])
def test_proxy(env_id):
    body = request.get_json(silent=True) or {}
    node = body.get("proxy")
    if not node:
        meta = store.get(env_id) or {}
        node_id = meta.get("nodeId") or ""
        node = pool.get(node_id) if node_id else meta.get("proxy")
    if not node:
        return jsonify({"ok": False, "error": "该环境未配置代理节点"}), 400
    try:
        port = proxies.start(env_id, node, offset=_offset(env_id))
    except (ValueError, RuntimeError) as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    _ports[env_id] = port
    result = proxies.probe(port)
    return jsonify({"ok": result.get("ok", False), "port": port, "probe": result})


# ---------- 节点池 API ----------

@app.route("/api/nodes", methods=["GET"])
def list_nodes():
    return jsonify({"ok": True, "nodes": pool.list_safe()})


@app.route("/api/nodes/import", methods=["POST"])
def import_nodes():
    """批量导入：粘贴分享链接 / 订阅内容 / 订阅 URL。"""
    body = request.get_json(silent=True) or {}
    text = body.get("text") or ""
    group = str(body.get("group") or "")
    auto_assign = bool(body.get("autoAssign"))

    if not text.strip():
        return jsonify({"ok": False, "error": "内容为空"}), 400

    from_url = str(body.get("url") or "").strip()
    if from_url:
        fetched, err = _fetch_subscription(from_url)
        if err:
            return jsonify({"ok": False, "error": err}), 400
        text = fetched

    decoded = decode_subscription(text)
    nodes, errors = parse_many(decoded)
    if not nodes and not errors:
        return jsonify({"ok": False, "error": "没有解析出节点，请检查内容格式"}), 400

    ids = pool.add_many(nodes, group=group) if nodes else []
    assigned = []
    if auto_assign and ids:
        assigned = _auto_assign_nodes(ids)

    return jsonify({
        "ok": True,
        "imported": len(ids),
        "ids": ids,
        "errors": errors[:20],
        "errorCount": len(errors),
        "assigned": assigned,
        "preview": [summarize(n) for n in nodes[:10]],
    })


@app.route("/api/nodes/<node_id>", methods=["PATCH"])
def update_node(node_id):
    body = request.get_json(silent=True) or {}
    try:
        node = pool.update(node_id, **{k: v for k, v in body.items() if k != "id"})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "node": _safe_node(node)})


@app.route("/api/nodes/<node_id>", methods=["DELETE"])
def delete_node(node_id):
    try:
        item = pool.delete(node_id)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "deleted": bool(item)})


@app.route("/api/nodes/batch-delete", methods=["POST"])
def batch_delete_nodes():
    body = request.get_json(silent=True) or {}
    ids = body.get("ids") or []
    if not isinstance(ids, list):
        return jsonify({"ok": False, "error": "ids 必须是数组"}), 400
    removed = pool.delete_many([str(i) for i in ids])
    return jsonify({"ok": True, "removed": len(removed)})


@app.route("/api/nodes/<node_id>/test", methods=["POST"])
def test_node(node_id):
    """独立测试节点：临时起一个 sing-box 实例查出口 IP。"""
    node = pool.get(node_id)
    if not node:
        return jsonify({"ok": False, "error": "节点不存在"}), 404
    probe_key = "probe-" + node_id[:16]
    with _lock:
        try:
            port = proxies.start(probe_key, node, offset=_offset(node_id))
        except (ValueError, RuntimeError) as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        result = proxies.probe(port)
        proxies.stop(probe_key)
    return jsonify({"ok": result.get("ok", False), "probe": result})


@app.route("/api/nodes/assign", methods=["POST"])
def assign_nodes():
    """把节点分配给环境；auto=True 时按顺序一一分配。"""
    body = request.get_json(silent=True) or {}
    if body.get("auto"):
        env_ids = body.get("envs") or [e["id"] for e in _env_list()]
        env_ids, _denied = _scope_env_ids([str(e) for e in env_ids])
        node_ids = body.get("nodes") or list(pool.all().keys())
        mapping = _assign_sequential(env_ids, node_ids)
        return jsonify({"ok": True, "mapping": mapping})

    env_id = str(body.get("env") or "").strip()
    node_id = str(body.get("node") or "").strip()
    if not env_id:
        return jsonify({"ok": False, "error": "缺少环境"}), 400
    if node_id and not pool.exists(node_id):
        return jsonify({"ok": False, "error": "节点不存在"}), 404
    try:
        # 改节点绑定视同修改环境，已上锁时需要密码（防止流量被改道）
        _require_unlocked(env_id, body)
    except LockError as e:
        return _locked_response(env_id, e)
    try:
        store.update(env_id, nodeId=node_id)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True})


# ---------- 订阅 API ----------

@app.route("/api/subscriptions", methods=["GET"])
def list_subs():
    return jsonify({"ok": True, "subscriptions": subs.list_safe()})


@app.route("/api/subscriptions", methods=["POST"])
def add_sub():
    body = request.get_json(silent=True) or {}
    url = str(body.get("url") or "").strip()
    if not url:
        return jsonify({"ok": False, "error": "缺少订阅地址"}), 400
    if not _is_http_url(url):
        return jsonify({"ok": False, "error": "只支持 http/https 订阅地址"}), 400
    if _is_internal_host(_host_of(url)):
        return jsonify({"ok": False, "error": "订阅地址不允许指向本机或内网"}), 400

    sub_id = subs.add(
        url,
        name=str(body.get("name") or ""),
        group=str(body.get("group") or ""),
        auto_assign=bool(body.get("autoAssign")),
        interval_minutes=body.get("intervalMinutes") or 0,
    )
    # 立即同步一次，让用户马上看到结果
    result = _sync_subscription(sub_id)
    return jsonify({"ok": True, "id": sub_id, "sync": result})


@app.route("/api/subscriptions/<sub_id>", methods=["PATCH"])
def update_sub(sub_id):
    body = request.get_json(silent=True) or {}
    try:
        subs.update(sub_id, **{k: v for k, v in body.items() if k != "id"})
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True})


@app.route("/api/subscriptions/<sub_id>", methods=["DELETE"])
def delete_sub(sub_id):
    """删除订阅：同时移除由该订阅引入的节点。"""
    try:
        sub = subs.delete(sub_id)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    removed = 0
    if sub:
        removed = len(pool.delete_many(sub.get("nodeIds") or []))
    return jsonify({"ok": True, "removedNodes": removed})


@app.route("/api/subscriptions/<sub_id>/sync", methods=["POST"])
def sync_sub(sub_id):
    result = _sync_subscription(sub_id)
    code = 200 if result.get("ok") else 400
    return jsonify(result), code


@app.route("/api/subscriptions/sync-all", methods=["POST"])
def sync_all_subs():
    results = {}
    for sub_id in supers_ids():
        results[sub_id] = _sync_subscription(sub_id)
    return jsonify({"ok": True, "results": results})


def supers_ids():
    return list(subs.all().keys())



@app.route("/api/envs/batch", methods=["POST"])
def batch_envs():
    """批量启动 / 停止 / 删除 / 换指纹。"""
    body = request.get_json(silent=True) or {}
    action = str(body.get("action") or "")
    ids = body.get("ids") or []
    if not isinstance(ids, list) or not ids:
        return jsonify({"ok": False, "error": "未选择环境"}), 400

    done, failed, locked = [], [], []
    for env_id in [str(i) for i in ids]:
        try:
            _require_unlocked(env_id, body)
        except LockError as e:
            locked.append({"id": env_id, "error": str(e)})
            continue
        try:
            if action == "start":
                _start_one(env_id)
                done.append(env_id)
            elif action == "stop":
                with _lock:
                    launcher.stop(env_id)
                    proxies.stop(env_id)
                    _ports.pop(env_id, None)
                done.append(env_id)
            elif action == "delete":
                # 改为移入回收站，可恢复；彻底删除需走 /api/recycle/purge
                with _lock:
                    launcher.forget(env_id)
                    proxies.stop(env_id)
                    _ports.pop(env_id, None)
                store.soft_delete(env_id)
                done.append(env_id)
            elif action == "regen":
                engine.regenerate(env_id)
                done.append(env_id)
            else:
                return jsonify({"ok": False, "error": "未知操作: %s" % action}), 400
        except Exception as e:
            failed.append({"id": env_id, "error": str(e)})

    return jsonify({"ok": True, "done": done, "failed": failed, "locked": locked})


# ---------- 代理链 API ----------

@app.route("/api/envs/<env_id>/chain", methods=["GET"])
def get_chain(env_id):
    meta = store.get(env_id)
    if not meta:
        return jsonify({"ok": False, "error": "环境不存在"}), 404
    pool_map = pool.all()
    chain = []
    for nid in (meta.get("chain") or []):
        node = pool_map.get(nid)
        if node:
            chain.append(_safe_node(node))
    return jsonify({"ok": True, "chain": chain})


@app.route("/api/envs/<env_id>/chain", methods=["PUT"])
def set_chain(env_id):
    """设置多级代理链。chain 数组按顺序，第一个是出口，后面依次为前置中转。"""
    body = request.get_json(silent=True) or {}
    try:
        _require_unlocked(env_id, body)
    except LockError as e:
        return _locked_response(env_id, e)

    if not store.get(env_id):
        return jsonify({"ok": False, "error": "环境不存在"}), 404

    node_ids = body.get("chain") or []
    if not isinstance(node_ids, list):
        return jsonify({"ok": False, "error": "chain 必须是数组"}), 400
    node_ids = [str(n) for n in node_ids]

    # 校验节点存在、不重复
    seen = set()
    for nid in node_ids:
        if nid in seen:
            return jsonify({"ok": False, "error": "代理链中不能有重复节点"}), 400
        seen.add(nid)
        if not pool.exists(nid):
            return jsonify({"ok": False, "error": "节点不存在: %s" % nid}), 404

    if len(node_ids) > 3:
        return jsonify({"ok": False, "error": "代理链最多 3 级"}), 400

    store.update(env_id, chain=node_ids)
    return jsonify({"ok": True, "chain": node_ids})


@app.route("/api/envs/<env_id>/chain/test", methods=["POST"])
def test_chain(env_id):
    """测试代理链，返回最终出口 IP。"""
    meta = store.get(env_id)
    if not meta:
        return jsonify({"ok": False, "error": "环境不存在"}), 404

    body = request.get_json(silent=True) or {}
    node_ids = body.get("chain")
    if node_ids is None:
        node_ids = meta.get("chain") or []
    if not isinstance(node_ids, list) or not node_ids:
        return jsonify({"ok": False, "error": "代理链为空"}), 400

    hops = []
    for nid in node_ids:
        node = pool.get(str(nid))
        if not node:
            return jsonify({"ok": False, "error": "节点不存在: %s" % nid}), 404
        hops.append(node)

    probe_key = "chain-" + env_id[:16]
    with _lock:
        try:
            port = proxies.start(probe_key, hops[0], offset=_offset(env_id), chain=hops)
        except (ValueError, RuntimeError) as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        result = proxies.probe(port)
        proxies.stop(probe_key)

    return jsonify({
        "ok": result.get("ok", False),
        "hops": len(hops),
        "probe": result,
    })


# ---------- 导入导出 API ----------

@app.route("/api/export", methods=["GET"])
def export_config():
    """导出配置。默认不含凭据，避免误传导致密码泄露。"""
    include_secrets = request.args.get("secrets") in ("1", "true", "yes")
    data = config_io.export_all(include_secrets=include_secrets)
    resp = jsonify({"ok": True, "config": data})
    stamp = time.strftime("%Y%m%d-%H%M%S")
    resp.headers["Content-Disposition"] = "attachment; filename=taobao-env-%s.json" % stamp
    return resp


@app.route("/api/import", methods=["POST"])
def import_config():
    body = request.get_json(silent=True) or {}
    data = body.get("config")
    if data is None:
        return jsonify({"ok": False, "error": "缺少 config 内容"}), 400
    try:
        _deny_out_of_scope_import(data)
    except PermissionDenied as e:
        return jsonify({"ok": False, "error": str(e)}), 403
    overwrite = bool(body.get("overwrite"))
    try:
        result = config_io.import_all(
            data, overwrite=overwrite,
            lock_password=str(body.get("password") or ""),
        )
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "result": result})


# ---------- 窗口同步 API ----------

@app.route("/api/sync/sessions", methods=["GET"])
def list_sync_sessions():
    return jsonify({
        "ok": True,
        "sessions": syncer.list_sessions(),
        "log": syncer.recent_log(40),
    })


@app.route("/api/sync/start", methods=["POST"])
def start_sync():
    body = request.get_json(silent=True) or {}
    master = str(body.get("master") or "").strip()
    slaves = body.get("slaves") or []
    if not isinstance(slaves, list):
        return jsonify({"ok": False, "error": "slaves 必须是数组"}), 400
    ff_envs = [e for e in [master] + [str(s) for s in slaves]
               if launcher.backend(e) == "firefox"]
    if ff_envs:
        return jsonify({
            "ok": False,
            "error": "Firefox 内核使用 WebDriver BiDi，暂不支持窗口同步；"
                     "请改用本地 Chrome 后端的环境：%s" % ", ".join(ff_envs),
        }), 400
    try:
        session_id = syncer.start(master, [str(s) for s in slaves], body.get("options"))
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "session": session_id})


@app.route("/api/sync/stop", methods=["POST"])
def stop_sync():
    body = request.get_json(silent=True) or {}
    session_id = str(body.get("session") or "").strip()
    if session_id:
        syncer.stop(session_id)
        return jsonify({"ok": True, "stopped": 1})
    count = syncer.stop_all()
    return jsonify({"ok": True, "stopped": count})


# ---------- 分组 / 标签 / 回收站 ----------

@app.route("/api/groups", methods=["GET"])
def list_groups():
    return jsonify({"ok": True, "groups": store.groups(), "tags": store.tags()})


@app.route("/api/envs/<env_id>/meta", methods=["PATCH"])
def update_env_meta(env_id):
    """更新分组、标签与指纹模式。"""
    body = request.get_json(silent=True) or {}
    try:
        _require_unlocked(env_id, body)
    except LockError as e:
        return _locked_response(env_id, e)
    fields = {}
    if "group" in body:
        fields["group"] = str(body.get("group") or "").strip()
    if "tags" in body:
        t = body.get("tags")
        if isinstance(t, str):
            t = [x.strip() for x in t.replace("，", ",").split(",") if x.strip()]
        fields["tags"] = t if isinstance(t, list) else []
    if "fpMode" in body:
        mode = body.get("fpMode")
        if mode not in ("stable", "random"):
            return jsonify({"ok": False, "error": "指纹模式只能是 stable 或 random"}), 400
        fields["fpMode"] = mode
    if "allowDirect" in body:
        fields["allowDirect"] = bool(body.get("allowDirect"))
    if "browserBackend" in body:
        current = store.get(env_id) or {}
        backend = _validate_backend(
            env_id,
            body.get("browserBackend", current.get("browserBackend") or "firefox"),
        )
        if backend != str(current.get("browserBackend") or "local").lower() \
                and launcher.running(env_id):
            return jsonify({
                "ok": False,
                "error": "环境正在运行，请先停止再切换浏览器后端",
            }), 409
        fields["browserBackend"] = backend
        fields["kernelVersion"] = _normalize_kernel_version(
            backend, body.get("kernelVersion", current.get("kernelVersion")))
    elif "kernelVersion" in body:
        current = store.get(env_id) or {}
        fields["kernelVersion"] = _normalize_kernel_version(
            current.get("browserBackend") or "firefox", body.get("kernelVersion"))
    try:
        meta = store.update(env_id, **fields)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "env": meta})


@app.route("/api/envs/<env_id>/recycle", methods=["POST"])
def recycle_env(env_id):
    """移入回收站（可恢复，不真删）。"""
    body = request.get_json(silent=True) or {}
    try:
        _require_unlocked(env_id, body)
    except LockError as e:
        return _locked_response(env_id, e)
    with _lock:
        launcher.forget(env_id)
        proxies.stop(env_id)
        _ports.pop(env_id, None)
    try:
        item = store.soft_delete(env_id)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, "deletedAt": item.get("deletedAt")})


@app.route("/api/envs/<env_id>/restore", methods=["POST"])
def restore_env(env_id):
    try:
        store.restore(env_id)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True})


@app.route("/api/recycle", methods=["GET"])
def list_recycle():
    items = []
    pool_map = pool.all()
    for env_id, meta in _scope_filter_set(store.list_deleted()).items():
        items.append({
            "id": env_id,
            "name": meta.get("name", ""),
            "group": meta.get("group", ""),
            "deletedAt": meta.get("deletedAt", ""),
            "nodeName": (pool_map.get(meta.get("nodeId") or "", {}) or {}).get("name", ""),
        })
    return jsonify({"ok": True, "items": items})


@app.route("/api/recycle/purge", methods=["POST"])
def purge_recycle():
    """彻底删除。必须显式传 confirm=true。"""
    body = request.get_json(silent=True) or {}
    if not body.get("confirm"):
        return jsonify({"ok": False, "error": "需要确认参数 confirm=true"}), 400
    ids = body.get("ids") or []
    if not isinstance(ids, list) or not ids:
        return jsonify({"ok": False, "error": "未指定要删除的环境"}), 400

    purged, failed, locked = [], [], []
    for env_id in [str(i) for i in ids]:
        try:
            # 彻底删除不可恢复，已上锁环境必须验证密码
            _require_unlocked(env_id, body)
        except LockError as e:
            locked.append({"id": env_id, "error": str(e)})
            continue
        try:
            with _lock:
                launcher.forget(env_id)
                proxies.stop(env_id)
                _ports.pop(env_id, None)
            store.purge(env_id)
            engine.delete(env_id)
            purged.append(env_id)
        except Exception as e:
            failed.append({"id": env_id, "error": str(e)})
    return jsonify({"ok": True, "purged": purged, "failed": failed, "locked": locked})


# ---------- 动态 IP 提取器 ----------

@app.route("/api/envs/<env_id>/dynamic-ip", methods=["PUT"])
def set_dynamic_ip(env_id):
    body = request.get_json(silent=True) or {}
    try:
        _require_unlocked(env_id, body)
    except LockError as e:
        return _locked_response(env_id, e)
    if not store.get(env_id):
        return jsonify({"ok": False, "error": "环境不存在"}), 404

    url = str(body.get("url") or "").strip()
    enabled = bool(body.get("enabled"))

    if enabled and url:
        try:
            dynamic_ip.check_url(url)
        except dynamic_ip.FetchError as e:
            return jsonify({"ok": False, "error": str(e)}), 400

    conf = {
        "enabled": enabled,
        "url": url,
        "channel": str(body.get("channel") or ""),
        "lastIp": "",
    }
    store.update(env_id, dynamicIp=conf)
    return jsonify({"ok": True, "dynamicIp": conf})


@app.route("/api/envs/<env_id>/dynamic-ip/fetch", methods=["POST"])
def fetch_dynamic_ip(env_id):
    """拉取一次动态 IP，返回解析结果（不写入环境）。"""
    meta = store.get(env_id)
    if not meta:
        return jsonify({"ok": False, "error": "环境不存在"}), 404

    body = request.get_json(silent=True) or {}
    url = str(body.get("url") or (meta.get("dynamicIp") or {}).get("url") or "").strip()
    if not url:
        return jsonify({"ok": False, "error": "未配置提取链接"}), 400

    try:
        text = dynamic_ip.fetch(url)
    except dynamic_ip.FetchError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    nodes = dynamic_ip.parse_nodes(text)
    if not nodes:
        return jsonify({
            "ok": False,
            "error": "未能从返回内容解析出 IP",
            "sample": text[:200],
        }), 400

    return jsonify({
        "ok": True,
        "count": len(nodes),
        "preview": ["%s:%s" % (n["server"], n["port"]) for n in nodes[:5]],
        "node": nodes[0],
    })


# ---------- Cookie 导入导出 ----------

@app.route("/api/envs/<env_id>/cookies", methods=["GET"])
def export_cookies(env_id):
    if not store.get(env_id):
        return jsonify({"ok": False, "error": "环境不存在"}), 404
    try:
        # 已上锁环境导出 cookie 必须验密码（GET 无 body，走 X-Env-Password 头）
        _require_unlocked(env_id)
    except LockError as e:
        return _locked_response(env_id, e)

    domain = str(request.args.get("domain") or "").strip()
    fmt = str(request.args.get("format") or "json").lower()

    backend = str((store.get(env_id) or {}).get("browserBackend") or "local").lower()
    if backend == "ads":
        backend = "firefox"

    if backend == "firefox":
        try:
            rows = launcher.firefox.get_cookies(env_id)
        except RuntimeError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        if domain:
            rows = [c for c in rows if domain in str(c.get("domain") or "")]
        note = "来自本地 Firefox 150 (BiDi)"
        if fmt == "netscape":
            return jsonify({"ok": True, "content": cookie_io.to_netscape(rows),
                            "count": len(rows), "note": note})
        return jsonify({"ok": True, "cookies": rows, "count": len(rows), "note": note})

    if launcher.running(env_id):
        return jsonify({"ok": False, "error": "请先停止该环境再导出 cookie"}), 400

    profile = launcher.profile_dir(env_id)
    try:
        rows, err = cookie_io.export(profile, domain)
    except cookie_io.CookieError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    if fmt == "netscape":
        return jsonify({"ok": True, "content": cookie_io.to_netscape(rows),
                        "count": len(rows), "note": err})
    return jsonify({"ok": True, "cookies": rows, "count": len(rows), "note": err})


@app.route("/api/envs/<env_id>/cookies", methods=["POST"])
def import_cookies(env_id):
    if not store.get(env_id):
        return jsonify({"ok": False, "error": "环境不存在"}), 404

    body = request.get_json(silent=True) or {}
    try:
        _require_unlocked(env_id, body)
    except LockError as e:
        return _locked_response(env_id, e)

    content = body.get("content") or ""
    if not content.strip():
        return jsonify({"ok": False, "error": "导入内容为空"}), 400

    rows = cookie_io.parse_import_file(content)
    if not rows:
        return jsonify({"ok": False, "error": "未能解析出任何 cookie"}), 400

    backend = str((store.get(env_id) or {}).get("browserBackend") or "local").lower()
    if backend == "ads":
        backend = "firefox"

    if backend == "firefox":
        try:
            added = launcher.firefox.set_cookies(env_id, rows)
        except RuntimeError as e:
            return jsonify({"ok": False, "error": str(e)}), 400
        return jsonify({"ok": True, "added": added})

    if launcher.running(env_id):
        return jsonify({"ok": False, "error": "请先停止该环境再导入 cookie"}), 400

    try:
        added = cookie_io.import_cookies(launcher.profile_dir(env_id), rows)
    except cookie_io.CookieError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    return jsonify({"ok": True, "added": added})


# ---------- Excel 批量导入 ----------

@app.route("/api/envs/import-excel", methods=["POST"])
def import_excel():
    """上传 Excel / CSV 批量创建环境。"""
    if "file" not in request.files:
        return jsonify({"ok": False, "error": "没有收到文件"}), 400

    f = request.files["file"]
    filename = f.filename or ""
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if ext not in ("xlsx", "xlsm", "csv"):
        return jsonify({"ok": False, "error": "只支持 .xlsx / .xlsm / .csv"}), 400

    tmp_dir = DATA_ROOT / "tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_path = tmp_dir / ("upload_" + str(int(time.time() * 1000)) + "." + ext)
    try:
        f.save(str(tmp_path))
        rows, msg = excel_io.parse_file(str(tmp_path))
    except excel_io.ExcelError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass

    added, skipped, node_added = [], [], 0
    for row in rows:
        env_id = row["id"]
        if store.get(env_id):
            skipped.append({"id": env_id, "reason": "已存在"})
            continue

        node_id = ""
        node_name = row.get("nodeName") or ""
        server = row.get("server") or ""
        if server or node_name:
            existing = None
            if node_name:
                for nid, n in pool.all().items():
                    if n.get("name") == node_name:
                        existing = nid
                        break
            if existing:
                node_id = existing
            elif server:
                proto = (row.get("protocol") or "socks5").lower()
                if proto not in PROTOCOLS:
                    proto = "socks5"
                try:
                    port = int(row.get("port") or 0)
                except ValueError:
                    port = 0
                node = {
                    "protocol": proto,
                    "name": node_name or (server + ":" + str(port)),
                    "server": server,
                    "port": port or (443 if proto in ("vless", "vmess", "trojan") else 1080),
                    "username": row.get("username") or "",
                    "password": row.get("password") or "",
                    "group": row.get("group") or "",
                }
                ids = pool.add_many([node], group=row.get("group") or "")
                if ids:
                    node_id = ids[0]
                    node_added += 1

        try:
            backend = _validate_backend(env_id, row.get("browserBackend") or "firefox")
            store.create(
                env_id,
                name=row.get("name") or env_id,
                platform=row.get("platform") or "淘宝",
                remark=row.get("remark") or "",
                start_url=row.get("startUrl") or "",
                node_id=node_id,
                group=row.get("group") or "",
                tags=row.get("tags") or [],
                browser_backend=backend,
                kernel_version=_normalize_kernel_version(backend, row.get("kernelVersion")),
            )
            engine.load_or_create(env_id)

            if row.get("dynamicIpUrl"):
                try:
                    dynamic_ip.check_url(row["dynamicIpUrl"])
                    store.update(env_id, dynamicIp={
                        "enabled": True, "url": row["dynamicIpUrl"],
                        "channel": "", "lastIp": "",
                    })
                except dynamic_ip.FetchError:
                    pass

            added.append(env_id)
        except ValueError as e:
            skipped.append({"id": env_id, "reason": str(e)})

    return jsonify({
        "ok": True,
        "added": len(added),
        "skipped": len(skipped),
        "nodesCreated": node_added,
        "message": msg,
        "details": skipped[:10],
    })


@app.route("/api/envs/import-excel/template", methods=["GET"])
def excel_template():
    """下载导入模板。"""
    from openpyxl import Workbook

    header, sample = excel_io.template_rows()
    wb = Workbook()
    ws = wb.active
    ws.title = "环境列表"
    ws.append(header)
    ws.append(sample)
    for i, h in enumerate(header):
        ws.column_dimensions[_col_letter(i)].width = max(12, len(h) * 2)

    out = DATA_ROOT / "tmp"
    out.mkdir(parents=True, exist_ok=True)
    path = out / "import_template.xlsx"
    wb.save(str(path))
    return send_from_directory(str(out), "import_template.xlsx", as_attachment=True)


# ---------- 启动/停止 API ----------

@app.route("/api/envs/<env_id>/start", methods=["POST"])
def start_env(env_id):
    body = request.get_json(silent=True) or {}
    meta = store.get(env_id)
    if not meta:
        return jsonify({"ok": False, "error": "环境不存在"}), 404
    try:
        _require_unlocked(env_id, body)
    except LockError as e:
        return _locked_response(env_id, e)
    try:
        debug_port, proxy_port = _start_one(env_id)
    except RuntimeError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    except Exception as e:
        return jsonify({"ok": False, "error": "启动失败：%s" % e}), 500
    return jsonify({"ok": True, "debugPort": debug_port, "proxyPort": proxy_port,
                    "warning": ""})


@app.route("/api/envs/<env_id>/stop", methods=["POST"])
def stop_env(env_id):
    body = request.get_json(silent=True) or {}
    try:
        _require_unlocked(env_id, body)
    except LockError as e:
        return _locked_response(env_id, e)
    with _lock:
        launcher.stop(env_id)
        proxies.stop(env_id)
        _ports.pop(env_id, None)
    return jsonify({"ok": True})


@app.route("/api/start-all", methods=["POST"])
def start_all():
    body = request.get_json(silent=True) or {}
    started, failed, locked, denied = [], [], [], []
    # envScope：受限成员只启动自己范围内的环境
    env_ids, denied = _scope_env_ids(list(store.list_active().keys()))
    for env_id in env_ids:
        # 批量启动时，已上锁且未给密码的环境跳过并单独报告
        try:
            _require_unlocked(env_id, body)
        except LockError:
            locked.append(env_id)
            continue
        try:
            _start_one(env_id)
            started.append(env_id)
        except Exception as e:
            failed.append({"id": env_id, "error": str(e)})
    return jsonify({"ok": True, "started": started, "failed": failed,
                    "locked": locked, "denied": denied})


@app.route("/api/stop-all", methods=["POST"])
def stop_all():
    env_ids, denied = _scope_env_ids(list(store.all().keys()))
    if denied:
        # 受限成员：只停自己范围内的环境
        for env_id in env_ids:
            with _lock:
                launcher.stop(env_id)
                proxies.stop(env_id)
                _ports.pop(env_id, None)
        return jsonify({"ok": True, "stopped": env_ids, "denied": denied})
    launcher.stop_all()
    proxies.stop_all()
    _ports.clear()
    return jsonify({"ok": True, "stopped": env_ids, "denied": []})


# ---------- 窗口布局 ----------

@app.route("/api/layout/apply", methods=["POST"])
def apply_window_layout():
    body = request.get_json(silent=True) or {}
    layout = str(body.get("layout") or "grid")
    ids = body.get("ids") or []
    if not isinstance(ids, list) or not ids:
        return jsonify({"ok": False, "error": "未选择环境"}), 400
    ff_envs = [str(i) for i in ids if launcher.backend(str(i)) == "firefox"]
    if ff_envs:
        return jsonify({
            "ok": False,
            "error": "Firefox 内核环境暂不支持 CDP 窗口布局：%s" % ", ".join(ff_envs),
        }), 400
    try:
        result = window_layout.apply_layout(
            launcher, [str(i) for i in ids], layout,
        )
    except window_layout.LayoutError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True, **result})


@app.route("/api/layout/options", methods=["GET"])
def layout_options():
    from manager.layout import LAYOUTS
    return jsonify({
        "ok": True,
        "layouts": [
            {"id": "grid", "name": "网格"},
            {"id": "tile-h", "name": "横向平铺"},
            {"id": "tile-v", "name": "纵向平铺"},
            {"id": "cascade", "name": "层叠"},
            {"id": "focus", "name": "聚焦（其余最小化）"},
        ],
    })


# ---------- 成员与权限 ----------

def _member_system_enabled():
    return len(members.all()) > 0


def _current_member():
    """从请求头解析当前登录成员。未启用成员系统时返回 None（全权限）。

    会话 token 在登录时已验证过密码，这里只查成员状态，
    不再重复验证密码（传 None 给 authenticate 会永远失败）。
    """
    if not _member_system_enabled():
        return None
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    if not token or token not in _sessions:
        return None
    username, expire = _sessions[token]
    if time.time() > expire:
        _sessions.pop(token, None)
        return None
    m = members.get(username)
    if not m or not m.get("enabled", True):
        # 成员被删除或停用，会话立即失效
        _sessions.pop(token, None)
        return None
    return {
        "username": username,
        "displayName": m.get("displayName", username),
        "role": m.get("role", "viewer"),
        "envScope": m.get("envScope") or [],
    }


def _require_action(action, env_id=None):
    """统一权限校验入口。无权时抛 PermissionError。"""
    m = _current_member()
    if m is None and _member_system_enabled():
        raise PermissionError("未登录或会话已过期")
    if not members.can(m, action, env_id):
        raise PermissionError("当前角色没有「%s」权限" % member_store.ACTION_LABELS.get(action, action))


def _issue_token(username):
    token = secrets.token_hex(24)
    _sessions[token] = (username, time.time() + SESSION_TTL)
    return token


@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    enabled = _member_system_enabled()
    m = _current_member()
    admins = [
        item["username"] for item in members.list_safe()
        if item.get("role") == "admin" and item.get("enabled", True)
    ] if enabled else []
    return jsonify({
        "ok": True,
        "memberSystem": enabled,
        "loggedIn": m is not None,
        "member": m,
        # 仅用于本机登录页的「忘记密码」下拉提示，不含密码/哈希
        "admins": admins,
        "registrationOpen": True,
    })


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    body = request.get_json(silent=True) or {}
    m = members.authenticate(
        str(body.get("username") or ""), str(body.get("password") or ""),
    )
    if not m:
        return jsonify({"ok": False, "error": "用户名或密码不正确"}), 401
    token = _issue_token(m["username"])
    return jsonify({"ok": True, "token": token, "member": m})


@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    """首次注册创建管理员；已有成员时注册为待授权的只读账号。"""
    body = request.get_json(silent=True) or {}
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    display_name = str(body.get("displayName") or "").strip()
    first = not members.all()
    role = "admin" if first else "viewer"
    scope = [] if first else ["__none__"]
    try:
        members.add(
            username, password, role=role,
            display_name=display_name, env_scope=scope,
        )
    except member_store.MemberError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    m = members.authenticate(username, password)
    if not m:
        return jsonify({"ok": False, "error": "注册成功但自动登录失败，请手动登录"}), 500
    token = _issue_token(username)
    _log_line("member=%s 注册成功 role=%s" % (username, role))
    return jsonify({
        "ok": True,
        "token": token,
        "member": m,
        "first": first,
        "pending": not first,
    })


@app.route("/api/auth/recover", methods=["POST"])
def auth_recover():
    """本机恢复：重置管理员密码，不读取/回显旧密码。"""
    if request.remote_addr not in ("127.0.0.1", "::1"):
        return jsonify({"ok": False, "error": "只允许在本机重置管理员密码"}), 403
    body = request.get_json(silent=True) or {}
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    target = members.get(username)
    if not target or target.get("role") != "admin":
        return jsonify({"ok": False, "error": "只能重置管理员账号的密码"}), 400
    try:
        members.update(username, password=password, enabled=True)
    except member_store.MemberError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    # 旧会话全部失效
    for token, (name, _expire) in list(_sessions.items()):
        if name == username:
            _sessions.pop(token, None)
    m = members.authenticate(username, password)
    if not m:
        return jsonify({"ok": False, "error": "密码已更新，但自动登录失败"}), 500
    token = _issue_token(username)
    _log_line("member=%s 本机重置管理员密码" % username)
    return jsonify({"ok": True, "token": token, "member": m})


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    token = request.headers.get("Authorization", "").replace("Bearer ", "").strip()
    _sessions.pop(token, None)
    return jsonify({"ok": True})


@app.route("/api/members", methods=["GET"])
def list_members():
    try:
        _require_action("manage_members")
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403
    return jsonify({"ok": True, "members": members.list_safe(),
                    "actions": member_store.ACTION_LABELS})


@app.route("/api/members", methods=["POST"])
def add_member():
    body = request.get_json(silent=True) or {}
    try:
        _require_action("manage_members")
        first = not members.all()
        members.add(
            str(body.get("username") or ""),
            str(body.get("password") or ""),
            # 首个成员强制管理员；否则成员系统启用后没有任何人能管理
            role="admin" if first else str(body.get("role") or "viewer"),
            display_name=str(body.get("displayName") or ""),
            env_scope=[] if first else (body.get("envScope") or []),
        )
    except (member_store.MemberError, PermissionError) as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True})


@app.route("/api/members/<username>", methods=["PATCH"])
def update_member(username):
    body = request.get_json(silent=True) or {}
    try:
        _require_action("manage_members")
        fields = {k: body[k] for k in ("role", "enabled", "displayName",
                                       "envScope", "password") if k in body}
        members.update(username, **fields)
    except (member_store.MemberError, PermissionError) as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True})


@app.route("/api/members/<username>", methods=["DELETE"])
def delete_member(username):
    try:
        _require_action("manage_members")
        members.delete(username)
    except (member_store.MemberError, PermissionError) as e:
        return jsonify({"ok": False, "error": str(e)}), 400
    return jsonify({"ok": True})


# ---------- WebDAV 云端同步 ----------

@app.route("/api/cloud/config", methods=["GET"])
def cloud_config():
    try:
        _require_action("view")
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403
    return jsonify({"ok": True, "config": webdav.masked_config()})


@app.route("/api/cloud/config", methods=["PUT"])
def save_cloud_config():
    body = request.get_json(silent=True) or {}
    try:
        # 改 WebDAV 地址等于指定全部凭据的去向，需要导出级权限（operator 不可改）
        _require_action("export")
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403

    url = str(body.get("url") or "").strip()
    allow_private = bool(body.get("allowPrivate"))
    _, err = webdav.validate_url(url, allow_private)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    conf = webdav.save_config(
        url=url,
        username=str(body.get("username") or ""),
        # 未填密码时保留旧密码，避免每次保存都要重输
        password=str(body.get("password") or "") or webdav.load_config().get("password") or "",
        directory=str(body.get("directory") or "env-manager"),
        allowPrivate=allow_private,
        enabled=bool(body.get("enabled", True)),
    )
    return jsonify({"ok": True, "config": webdav.masked_config()})


@app.route("/api/cloud/test", methods=["POST"])
def cloud_test():
    body = request.get_json(silent=True) or {}
    conf = webdav.load_config()
    if body.get("url"):
        # 测试未保存的配置
        conf = dict(conf)
        conf.update({
            "url": body.get("url"), "username": body.get("username") or "",
            "password": body.get("password") or conf.get("password") or "",
            "allowPrivate": bool(body.get("allowPrivate")),
        })
    ok, msg = webdav.test_connection(conf)
    return jsonify({"ok": ok, "message": msg})


@app.route("/api/cloud/backup", methods=["POST"])
def cloud_backup():
    try:
        # 备份固定包含全部凭据（include_secrets=True），必须导出级权限
        _require_action("export")
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403

    conf = webdav.load_config()
    if not conf.get("url"):
        return jsonify({"ok": False, "error": "未配置 WebDAV 地址"}), 400

    payload = json.dumps(config_io.export_all(include_secrets=True),
                         ensure_ascii=False, indent=2)
    try:
        filename = webdav.upload(conf, payload)
    except webdav.WebDavError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    webdav.save_config(lastSync=time.strftime("%Y-%m-%d %H:%M:%S"),
                       lastResult="上传 %s" % filename)
    return jsonify({"ok": True, "file": filename})


@app.route("/api/cloud/list", methods=["GET"])
def cloud_list():
    try:
        _require_action("view")
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403
    files, err = webdav.list_backups(webdav.load_config())
    return jsonify({"ok": not err, "files": files, "error": err})


@app.route("/api/cloud/restore", methods=["POST"])
def cloud_restore():
    body = request.get_json(silent=True) or {}
    try:
        # 恢复会覆盖环境配置，属于修改类操作（operator 不可执行）
        _require_action("edit")
    except PermissionError as e:
        return jsonify({"ok": False, "error": str(e)}), 403

    filename = str(body.get("file") or "").strip()
    if not filename:
        return jsonify({"ok": False, "error": "未指定备份文件"}), 400

    data, err = webdav.download(webdav.load_config(), filename)
    if err:
        return jsonify({"ok": False, "error": err}), 400

    try:
        _deny_out_of_scope_import(data)
    except PermissionDenied as e:
        return jsonify({"ok": False, "error": str(e)}), 403
    try:
        result = config_io.import_all(
            data, overwrite=bool(body.get("overwrite")),
            lock_password=str(body.get("password") or ""),
        )
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400

    webdav.save_config(lastResult="恢复 %s" % filename)
    return jsonify({"ok": True, "result": result})


# ---------- 工具 ----------

def _sync_subscription(sub_id):
    """拉取订阅并按节点指纹做增量更新。

    - 新节点：加入节点池
    - 内容变化的节点：原地更新，保持节点 ID 不变（环境绑定不会断）
    - 消失的节点：从节点池移除
    - 拉取失败：保留现有节点，只记录错误
    """
    sub = subs.get(sub_id)
    if not sub:
        return {"ok": False, "error": "订阅不存在"}
    if not sub.get("enabled", True):
        return {"ok": False, "error": "订阅已停用"}

    url = sub.get("url") or ""
    if _is_internal_host(_host_of(url)):
        err = "订阅地址不允许指向本机或内网"
        subs.record_sync(sub_id, sub.get("nodeIds") or [], sub.get("nodeHashes") or {}, err)
        return {"ok": False, "error": err}

    raw, fetch_err = _fetch_subscription(url)
    if fetch_err:
        subs.record_sync(sub_id, sub.get("nodeIds") or [], sub.get("nodeHashes") or {}, fetch_err)
        return {"ok": False, "error": fetch_err}

    nodes, parse_errors = parse_many(decode_subscription(raw))
    if not nodes:
        err = "订阅内容没有解析出任何节点"
        subs.record_sync(sub_id, sub.get("nodeIds") or [], sub.get("nodeHashes") or {}, err)
        return {"ok": False, "error": err, "parseErrors": parse_errors[:5]}

    old_ids = list(sub.get("nodeIds") or [])
    old_hashes = dict(sub.get("nodeHashes") or {})

    # 用节点内容哈希做匹配键：同哈希视为同一节点
    old_by_hash = {}
    for node_id in old_ids:
        h = old_hashes.get(node_id)
        if h:
            old_by_hash[h] = node_id

    group = sub.get("group") or sub.get("name") or "订阅"
    new_ids = []
    new_hashes = {}
    added = updated = 0

    for node in nodes:
        h = node_hash(node)
        existing_id = old_by_hash.pop(h, None)
        if existing_id and pool.exists(existing_id):
            new_ids.append(existing_id)
            new_hashes[existing_id] = h
        else:
            record = dict(node)
            record.setdefault("name", node.get("name") or "节点")
            record["group"] = group
            record["enabled"] = True
            record["source"] = "sub:" + sub_id
            ids = pool.add_many([record], group=group)
            if ids:
                new_ids.append(ids[0])
                new_hashes[ids[0]] = h
                added += 1

    # 剩余的是订阅里已消失的节点，删除
    removed = 0
    stale = list(old_by_hash.values())
    if stale:
        removed = len(pool.delete_many(stale))

    subs.record_sync(sub_id, new_ids, new_hashes, "")

    assigned = 0
    if sub.get("autoAssign") and added:
        mapping = _auto_assign_nodes(new_ids[-added:] if added else [])
        assigned = len(mapping)

    return {
        "ok": True,
        "total": len(new_ids),
        "added": added,
        "removed": removed,
        "assigned": assigned,
        "parseErrors": len(parse_errors),
    }


def _is_http_url(url):
    import urllib.parse

    try:
        return urllib.parse.urlsplit(url).scheme in ("http", "https")
    except ValueError:
        return False


def _host_of(url):
    import urllib.parse

    try:
        return urllib.parse.urlsplit(url).hostname or ""
    except ValueError:
        return ""


def _offset(env_id):
    """给每个环境一个稳定的端口偏移，减少端口冲突。"""
    return sum(ord(c) for c in str(env_id)) % 90


def _env_list():
    return [{"id": k} for k in store.all().keys()]


def _col_letter(index):
    """0 -> A, 25 -> Z, 26 -> AA …"""
    letters = ""
    n = index
    while True:
        letters = chr(65 + n % 26) + letters
        n = n // 26 - 1
        if n < 0:
            break
    return letters


def _log_line(msg):
    try:
        print("[app] %s" % msg, file=sys.stderr, flush=True)
    except Exception:
        pass


def _display_label(env_id, meta):
    """构造浏览器标签页上显示的名称。

    有分组时带分组前缀，方便一眼看出归属，例如「店铺组A/店铺A」。
    """
    name = (meta.get("name") or "").strip() or env_id
    group = (meta.get("group") or "").strip()
    if group and group not in name:
        return "%s/%s" % (group, name)
    return name


def _safe_node(node):
    """对外暴露节点时隐去凭据。"""
    if not node:
        return None
    return {
        "id": node.get("id"),
        "name": node.get("name"),
        "protocol": node.get("protocol"),
        "server": node.get("server"),
        "port": node.get("port"),
        "group": node.get("group", ""),
        "transport": node.get("transport", ""),
        "tls": bool(node.get("tls")),
        "reality": bool(node.get("reality")),
    }


def _stats(envs):
    total = len(envs)
    running = sum(1 for e in envs if e.get("running"))
    with_node = sum(1 for e in envs if e.get("node"))
    alive = sum(1 for e in envs if e.get("proxyAlive"))
    return {
        "total": total,
        "running": running,
        "withNode": with_node,
        "noNode": total - with_node,
        "proxyAlive": alive,
    }


def _start_one(env_id):
    """启动单个环境：先按需拉起代理，再拉起浏览器。返回 (debugPort, proxyPort)。"""
    meta = store.get(env_id)
    if not meta:
        raise RuntimeError("环境不存在: %s" % env_id)

    # 随机指纹模式：每次启动前重新生成整套设备身份
    if (meta.get("fpMode") or "stable") == "random":
        engine.regenerate(env_id)
        _log_line("env=%s 随机指纹模式：已生成新设备身份" % env_id)

    node_id = meta.get("nodeId") or ""
    node = pool.get(node_id) if node_id else meta.get("proxy") or {}

    # 动态 IP 提取器优先：每次启动拉一个新 IP，覆盖单节点配置
    dyn = meta.get("dynamicIp") or {}
    dyn_node = None
    dyn_error = ""
    if dyn.get("enabled") and dyn.get("url"):
        try:
            text = dynamic_ip.fetch(dyn["url"])
            fetched = dynamic_ip.parse_nodes(text)
            if fetched:
                dyn_node = fetched[0]
                # 记录最近一次拿到的 IP
                conf = dict(dyn)
                conf["lastIp"] = "%s:%s" % (dyn_node["server"], dyn_node["port"])
                store.update(env_id, dynamicIp=conf)
            else:
                dyn_error = "提取结果里没有可用 IP"
        except dynamic_ip.FetchError as e:
            dyn_error = str(e)

    # 代理链优先：链条非空时忽略单节点配置
    hops = []
    for nid in (meta.get("chain") or []):
        hop = pool.get(str(nid))
        if hop and hop.get("server"):
            hops.append(hop)

    with _lock:
        proxy_port = None
        if hops:
            proxy_port = proxies.start(env_id, hops[0], offset=_offset(env_id), chain=hops)
            _ports[env_id] = proxy_port
        elif dyn_node:
            proxy_port = proxies.start(env_id, dyn_node, offset=_offset(env_id))
            _ports[env_id] = proxy_port
        elif node and node.get("server"):
            proxy_port = proxies.start(env_id, node, offset=_offset(env_id))
            _ports[env_id] = proxy_port

    if dyn_error:
        _log_line("env=%s 动态IP提取失败，回退到固定节点: %s" % (env_id, dyn_error))

    if proxy_port is None and not meta.get("allowDirect"):
        # P0：无代理直连 = 所有环境共用真实出口 IP，平台可直接关联。
        # 默认拒绝；确需直连的环境在设置里显式开启 allowDirect。
        raise RuntimeError(
            "环境未配置代理出口，为避免真实 IP 关联已拒绝启动；"
            "确需直连请在环境设置中开启「允许直连」(allowDirect)")

    try:
        debug_port = launcher.start(
            env_id,
            url=meta.get("startUrl") or "https://www.taobao.com",
            proxy_port=proxy_port,
            # 标签页标题用「名称(编号)」，方便多窗口时分辨
            display_name=_display_label(env_id, meta),
        )
    except RuntimeError:
        # 浏览器起不来时回收代理，避免泄漏 sing-box 进程
        with _lock:
            proxies.stop(env_id)
            _ports.pop(env_id, None)
        raise
    return debug_port, proxy_port


def _assign_sequential(env_ids, node_ids):
    """把节点按顺序一一分配给环境，多余的节点忽略。已上锁的环境跳过。"""
    mapping = {}
    for env_id, node_id in zip(env_ids, node_ids):
        try:
            if store.is_locked(env_id):
                continue
            store.update(env_id, nodeId=node_id)
            mapping[env_id] = node_id
        except ValueError:
            continue
    return mapping


def _auto_assign_nodes(node_ids):
    """导入节点后，自动分配给还没有节点的环境（按当前成员的 envScope 过滤）。"""
    targets = [e["id"] for e in _env_list() if not (store.get(e["id"]) or {}).get("nodeId")]
    allowed, _denied = _scope_env_ids(targets)
    return _assign_sequential(allowed, node_ids)


def _fetch_subscription(url):
    """拉取订阅内容。只允许 http/https，并拒绝内网与保留地址。"""
    import urllib.parse

    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return None, "订阅地址格式不正确"

    if parsed.scheme not in ("http", "https"):
        return None, "只支持 http/https 订阅地址"
    host = parsed.hostname
    if not host:
        return None, "订阅地址缺少主机名"
    if _is_internal_host(host):
        return None, "订阅地址不允许指向本机或内网"

    try:
        # 走统一的 SSRF 防护拉取：重定向逐跳复检，防 302 跳进内网
        raw = ssrf_guard.fetch(url, timeout=20, headers={"User-Agent": "v2rayN/6.0"})
        return raw.decode("utf-8", "ignore"), None
    except Exception as e:
        return None, "订阅拉取失败: %s" % e


def _is_internal_host(host):
    """拒绝 localhost / 环回 / 私有 / 链路本地 / 保留地址。"""
    import ipaddress
    import socket

    h = host.strip().lower().strip("[]")
    if h in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        return True
    if h.endswith(".localhost") or h.endswith(".local") or h.endswith(".internal"):
        return True

    # 先尝试按字面 IP 判断
    candidates = []
    try:
        candidates.append(ipaddress.ip_address(h))
    except ValueError:
        try:
            for info in socket.getaddrinfo(h, None):
                addr = info[4][0]
                candidates.append(ipaddress.ip_address(addr))
        except (socket.gaierror, ValueError):
            # 解析不了就交给后续请求失败处理，不当作内网
            return False

    for ip in candidates:
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
        if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return True
        # 云元数据等特殊网段
        if str(ip).startswith("169.254."):
            return True
        if str(ip).startswith("100.64."):
            return True
    return False


def summarize_fp(fp):
    if not fp:
        return {}
    return {
        "screen": "%dx%d @%s" % (
            fp["screen"]["width"], fp["screen"]["height"], fp["screen"]["dpr"]
        ),
        "cores": fp["hardware"]["cores"],
        "memory": fp["hardware"]["memory"],
        "gpu": fp["gpu"]["renderer"].split("(")[-1].split("Direct3D")[0].strip(" ,)"),
        "timezone": fp["locale"]["timezone"],
        "language": fp["locale"]["language"],
        "ua": fp["ua"]["userAgent"].split("Chrome/")[-1].split(" ")[0],
        "canvasNoise": fp["canvas"]["noise"],
        "audioNoise": fp["audio"]["noise"],
    }


def main():
    host = "127.0.0.1"
    port = _pick_port(8787)

    print("=" * 56)
    print("  多账号环境管理器")
    print("=" * 56)
    print("  数据目录: %s" % DATA_ROOT)
    print("  sing-box: %s" % (proxies.bin or "未找到（代理功能不可用）"))
    print("  浏览器  : %s" % (launcher.chrome or "未找到 Chrome"))
    print("  地址    : http://%s:%d" % (host, port))
    print("=" * 56)
    print("  关闭此窗口即退出程序")
    print()

    if not _is_headless():
        threading.Timer(1.5, lambda: _open_browser("http://%s:%d" % (host, port))).start()

    try:
        app.run(host=host, port=port, debug=False, threaded=True, use_reloader=False)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            launcher.stop_all()
            proxies.stop_all()
        except Exception:
            pass


def _pick_port(preferred):
    """优先用 8787，被占用就往后找。"""
    import socket

    for p in range(preferred, preferred + 20):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", p))
            except OSError:
                continue
            return p
    return preferred


def _is_headless():
    return os.environ.get("ENV_MANAGER_NO_BROWSER") == "1"


def _open_browser(url):
    """用 Chrome/Edge 的 --app 模式打开，得到一个独立窗口：

    - 没有地址栏、没有标签栏，看起来就是原生桌面程序
    - 在任务栏里有自己的图标和名称，不和普通网页混在一起
    - 不需要额外安装 WebView2 或 Electron
    """
    import subprocess

    profile_dir = DATA_ROOT / "ui-profile"
    profile_dir.mkdir(parents=True, exist_ok=True)

    # 应用模式窗口
    candidates = [
        launcher.chrome,
        _find_edge(),
    ]

    for exe in candidates:
        if not exe or not os.path.isfile(exe):
            continue
        try:
            subprocess.Popen(
                [
                    exe,
                    "--app=" + url,
                    "--user-data-dir=" + str(profile_dir),
                    "--window-size=1440,900",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-features=Translate,InterestCohort",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=0x08000000 if os.name == "nt" else 0,
            )
            return
        except Exception:
            continue

    # 兜底：用系统默认浏览器
    try:
        import webbrowser
        webbrowser.open(url)
    except Exception:
        pass


def _find_edge():
    for p in (
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ):
        if os.path.isfile(p):
            return p
    return None


if __name__ == "__main__":
    main()
