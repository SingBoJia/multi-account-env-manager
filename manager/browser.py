"""浏览器启动器：为每个环境拉起独立 Chrome，注入指纹、挂代理、隔离数据目录。

指纹注入采用 CDP（Chrome DevTools Protocol）：在页面 document_start 阶段
执行覆盖脚本，比扩展注入更早、更干净，页面脚本读到的已经是伪装后的值。

安全说明：本模块只与本机自己拉起的 Chrome 调试端口通信。
通信不用 URL 字符串，而是直接 socket 连接固定回环地址 127.0.0.1 与本进程
刚分配的整数端口，不存在外部可影响的请求目标。
"""

import json
import os
import pathlib
import socket
import subprocess
import sys
import threading
import time

try:
    from .fingerprint import FingerprintEngine
except ImportError:
    from fingerprint import FingerprintEngine

# CDP 只在本机回环地址，端口限定在本进程分配区间内
CDP_HOST = "127.0.0.1"
CDP_PORT_BASE = 9333
CDP_PORT_SPAN = 400

# 端口分配保护：避免批量启动时多个环境抢同一端口
_PORT_LOCK = threading.Lock()
_PORT_TAKEN = set()


class BrowserLauncher:

    def __init__(self, work_dir, chrome_path=None, fps=None, proxies=None):
        self.work_dir = pathlib.Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.profiles_dir = self.work_dir / "profiles"
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        self.chrome = chrome_path or self._find_chrome()
        self.fps = fps or FingerprintEngine(str(self.work_dir))
        self.proxies = proxies
        self._running = {}

    # ---------- 对外接口 ----------

    def chrome_available(self):
        return bool(self.chrome and pathlib.Path(self.chrome).is_file())

    def start(self, env_id, url="https://www.taobao.com", proxy_port=None, display_name=""):
        if not self.chrome_available():
            raise RuntimeError("未找到 Chrome")
        if self.running(env_id):
            return self._running[env_id]["port"]

        fp = self.fps.load_or_create(env_id)
        profile = self.profiles_dir / ("env-" + _safe_key(env_id))
        profile.mkdir(parents=True, exist_ok=True)

        # 标签页与窗口标题前缀：优先用显示名，没有就用环境编号
        label = (display_name or "").strip() or env_id
        title_prefix = "[" + label + "]"

        debug_port = _free_port(CDP_PORT_BASE)
        args = [
            self.chrome,
            "--user-data-dir=%s" % profile,
            "--profile-directory=Default",
            "--remote-debugging-port=%d" % debug_port,
            "--remote-allow-origins=http://%s:%d" % (CDP_HOST, debug_port),
            "--window-size=%d,%d" % (
                fp["screen"]["width"],
                max(600, fp["screen"]["height"] - 120),
            ),
            "--lang=%s" % fp["locale"]["language"],
            "--user-agent=%s" % fp["ua"]["userAgent"],
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-features=InterestCohort,PrivacySandboxSettings4,Translate",
            # 不再使用 --disable-blink-features=AutomationControlled：
            # Chrome 121 起该标记已被移除支持，会触发「不受支持的命令行标记」警告。
            # navigator.webdriver 由注入脚本覆盖为 false，效果相同且无警告。
            "--no-service-autorun",
            "--password-store=basic",
            "--disable-background-networking",
        ]

        # WebRTC 的 UDP 不走 --proxy-server 指向的 HTTP 代理，不强制 relay
        # 的话真实网卡 IP 会出现在 ICE candidate 里（挂代理时恰恰最需要防泄漏）
        args.append("--force-webrtc-ip-handling-policy=disable_non_proxied_udp")

        if proxy_port:
            args.append("--proxy-server=http://%s:%d" % (CDP_HOST, proxy_port))
            args.append("--proxy-bypass-list=<-loopback>")

        # 先以 about:blank 启动：waitForDebugger 暂停的「现存文档」不会回溯执行
        # 事后注册的脚本，所以由 keeper 就绪后主动导航到目标 URL（新文档必被注入）
        args.append("about:blank")

        proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=_no_window_flag(),
        )
        self._running[env_id] = {"proc": proc, "port": debug_port, "profile": profile, "fp": fp}
        # 落盘状态标记：服务重启后仍能识别该环境其实在运行
        self._write_state(env_id, {"port": debug_port, "pid": proc.pid})

        if not _wait_port(debug_port, timeout=25.0):
            self.stop(env_id)
            raise RuntimeError("Chrome 启动超时")

        # P0：常驻会话注入。脚本绑定在 CDP 会话上，会话断开即失效——
        # keeper 线程保持会话到环境停止，每次导航/新标签页都重新注册。
        keeper = self._start_fingerprint_keeper(debug_port, fp, url, title_prefix)
        if not keeper.wait_ready(timeout=40):
            # 注入会话建不起来 = 浏览器将以真实指纹运行，宁可中止
            keeper.stop()
            self._running.pop(env_id, None)
            self._clear_state(env_id)
            release_port(debug_port)
            try:
                proc.terminate()
                proc.wait(timeout=8)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            raise RuntimeError("指纹注入会话建立失败，已中止启动（拒绝以真实指纹运行）")

        injected = keeper.wait_verified(timeout=25)
        inject_error = "" if injected else "注入验证未通过（页面可能加载过慢）"
        self._running[env_id]["keeper"] = keeper
        self._running[env_id]["injected"] = injected
        if not injected:
            self._running[env_id]["injectError"] = inject_error
        _log("env=%s port=%d injected=%s %s" % (env_id, debug_port, injected, inject_error))

        return debug_port

    def stop(self, env_id):
        entry = self._running.pop(env_id, None)
        self._clear_state(env_id)
        if not entry:
            return
        keeper = entry.get("keeper")
        if keeper:
            keeper.stop()
        proc = entry["proc"]
        release_port(entry.get("port"))
        try:
            proc.terminate()
            proc.wait(timeout=8)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def stop_all(self):
        for env_id in list(self._running.keys()):
            self.stop(env_id)

    def running(self, env_id):
        entry = self._running.get(env_id)
        if entry and entry["proc"].poll() is None:
            return True
        # 内存里没有记录，但可能是服务重启前启动的环境：查状态文件 + 探测端口
        st = self._read_state(env_id)
        if st and st.get("port"):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.3)
                if s.connect_ex((CDP_HOST, st["port"])) == 0:
                    # 端口在监听说明浏览器还活着，把记录补回内存
                    if not entry:
                        self._running[env_id] = {
                            "proc": _FakeProc(st.get("pid")),
                            "port": st["port"],
                            "profile": None,
                            "fp": None,
                            "external": True,
                        }
                    _PORT_TAKEN.add(st["port"])
                    return True
            # 端口不通，说明已经退出，清掉过期标记
            self._clear_state(env_id)
        return False

    def _state_file(self, env_id):
        return self.work_dir / "state" / ("%s.json" % _safe_key(env_id))

    def _write_state(self, env_id, data):
        try:
            d = self.work_dir / "state"
            d.mkdir(parents=True, exist_ok=True)
            (d / ("%s.json" % _safe_key(env_id))).write_text(
                json.dumps(data, ensure_ascii=False), encoding="utf-8")
        except OSError:
            pass

    def _read_state(self, env_id):
        try:
            f = self.work_dir / "state" / ("%s.json" % _safe_key(env_id))
            if f.exists():
                return json.loads(f.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
        return None

    def _clear_state(self, env_id):
        try:
            f = self.work_dir / "state" / ("%s.json" % _safe_key(env_id))
            if f.exists():
                f.unlink()
        except OSError:
            pass

    def list_running(self):
        return {e: self.running(e) for e in list(self._running.keys())}

    def debug_port(self, env_id):
        entry = self._running.get(env_id)
        return entry["port"] if entry else None

    # ---------- CDP 操作 ----------

    def _start_fingerprint_keeper(self, port, fp, url="", title_prefix=""):
        """启动常驻指纹会话并返回 keeper。

        addScriptToEvaluateOnNewDocument 注册的脚本绑定在「会话」上，
        会话一断，之后所有导航都回到真实指纹（旧实现在 finally 里关闭
        WebSocket，只有启动时的第一个文档被伪装，点任何链接就全裸）。
        改用 browser 级常驻连接 + Target.setAutoAttach：
        - 每个新文档 / 新标签页 / 跨域 iframe 都触发 attachedToTarget，
          由 keeper 线程即时重新注册脚本；
        - 同时下发 Network.setUserAgentOverride，让 Sec-CH-UA 系列请求头
          与 getHighEntropyValues 和伪装 UA 一致。
        """
        keeper = _FingerprintKeeper(port, self.fps, fp, title_prefix=title_prefix,
                                    target_url=url)
        keeper.start()
        return keeper

    def page_targets(self, port):
        """对外暴露页面 target 列表，供同步器等模块使用。"""
        raw = _http_get_json(port, "/json")
        if not isinstance(raw, list):
            return []
        return [t for t in raw if isinstance(t, dict) and t.get("type") == "page"]

    def profile_dir(self, env_id):
        """返回该环境的数据目录（可能尚未创建）。"""
        return str(self.profiles_dir / ("env-" + _safe_key(env_id)))

    def _page_targets(self, port):
        return self.page_targets(port)

    def _send(self, port, target_id, method, params=None):
        try:
            import websocket
        except ImportError:
            return None
        try:
            ws_url = None
            for t in self._page_targets(port):
                if t.get("id") == target_id:
                    ws_url = t.get("webSocketDebuggerUrl")
                    break
            if not ws_url or not ws_url.startswith("ws://%s:" % CDP_HOST):
                return None
            ws = websocket.create_connection(ws_url, timeout=10, suppress_origin=True)
            try:
                ws.send(json.dumps({"id": 1, "method": method, "params": params or {}}))
                while True:
                    msg = json.loads(ws.recv())
                    if msg.get("id") == 1:
                        return msg
            finally:
                ws.close()
        except Exception:
            return None

    # ---------- 内部 ----------

    @staticmethod
    def _find_chrome():
        candidates = [
            pathlib.Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
            / "Google" / "Chrome" / "Application" / "chrome.exe",
            pathlib.Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
            / "Google" / "Chrome" / "Application" / "chrome.exe",
            pathlib.Path(os.environ.get("LOCALAPPDATA", ""))
            / "Google" / "Chrome" / "Application" / "chrome.exe",
        ]
        for c in candidates:
            if c.is_file():
                return str(c)
        return None


def _http_get_json(port, path):
    """直接向本机回环端口发一个极简 HTTP GET，不经过任何 URL 解析。

    按 Content-Length 精确截取正文后立即返回，避免等待连接关闭导致超时。
    """
    if not isinstance(port, int) or not (CDP_PORT_BASE <= port < CDP_PORT_BASE + CDP_PORT_SPAN):
        raise ValueError("非法调试端口")
    if not isinstance(path, str) or not path.startswith("/") or ".." in path:
        raise ValueError("非法请求路径")
    request = (
        "GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n"
        % (path, CDP_HOST, port)
    ).encode("ascii")
    chunks = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(6.0)
        s.connect((CDP_HOST, port))
        s.sendall(request)
        while True:
            try:
                buf = s.recv(65536)
            except socket.timeout:
                break
            if not buf:
                break
            chunks.append(buf)
            joined = b"".join(chunks)
            head, sep, body = joined.partition(b"\r\n\r\n")
            if not sep:
                continue
            length = None
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    try:
                        length = int(line.split(b":", 1)[1].strip())
                    except ValueError:
                        length = None
                    break
            if length is not None and len(body) >= length:
                try:
                    return json.loads(body[:length].decode("utf-8", "ignore"))
                except json.JSONDecodeError:
                    return None

    head, sep, body = b"".join(chunks).partition(b"\r\n\r\n")
    if not sep:
        return None
    try:
        return json.loads(body.decode("utf-8", "ignore"))
    except json.JSONDecodeError:
        return None


def _safe_key(env_id):
    return "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in str(env_id))[:64]


class _FakeProc:
    """代表服务重启前启动的 Chrome 进程，接口与 Popen 的最小公共子集一致。"""

    def __init__(self, pid):
        self.pid = pid

    def poll(self):
        """进程还活着返回 None，已退出返回 -1。"""
        if not self.pid:
            return -1
        try:
            out = subprocess.run(
                ["tasklist", "/FI", "PID eq %d" % int(self.pid), "/NH"],
                capture_output=True, text=True, timeout=5,
                creationflags=_no_window_flag(),
            )
            return None if str(self.pid) in (out.stdout or "") else -1
        except Exception:
            return -1

    def terminate(self):
        if not self.pid:
            return
        try:
            subprocess.run(["taskkill", "/PID", str(int(self.pid)), "/T", "/F"],
                           capture_output=True, timeout=8,
                           creationflags=_no_window_flag())
        except Exception:
            pass

    def kill(self):
        self.terminate()

    def wait(self, timeout=None):
        return 0


class _FingerprintKeeper:
    """常驻 browser 级 CDP 会话：让指纹注入跨导航、跨新标签页存活。

    - Target.setAutoAttach(flatten + waitForDebugger)：已存在的 page/iframe
      target 会被逐个 attach 并在文档执行前暂停，注册完脚本再放行；
      之后每个新文档 / 新标签页 / 跨域 iframe 同理。
    - Network.setUserAgentOverride：让 Sec-CH-UA 系列请求头与
      getHighEntropyValues 和伪装 UA 一致。
    - 断线自动重连并重新注册（重连后既有 target 会再次触发 attach）。
    线程生命周期 = 环境生命周期；launcher.stop 时调用 stop() 结束。
    所有 CDP 通信都收在 keeper 线程内，外部只通过 Event 读状态。
    """

    ATTACH_FILTER = [{"type": "page"}, {"type": "iframe"}]

    def __init__(self, port, fps, fp, title_prefix="", target_url=""):
        self._port = port
        self._script = fps.build_inject_script(fp, title_prefix=title_prefix)
        self._ua_override = fps.user_agent_override(fp)
        self._expect_screen = str(fp["screen"]["width"])
        self._nav_url = target_url
        self._navigated = False
        self._nav_tries = 0
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._verified = threading.Event()
        self._thread = None
        self._ws = None
        self._first_session = None
        self._msg_id = 0
        self._lock = threading.Lock()
        self._pending = {}

    # ---------- 对 launcher 的接口 ----------

    def start(self):
        self._thread = threading.Thread(
            target=self._run, name="fp-keeper-%d" % self._port, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        ws = self._ws
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass

    def wait_ready(self, timeout):
        return self._ready.wait(timeout)

    def wait_verified(self, timeout=25.0):
        end = time.time() + timeout
        while time.time() < end and not self._stop.is_set():
            if self._verified.is_set():
                return True
            time.sleep(0.3)
        return self._verified.is_set()

    # ---------- 内部 ----------

    def _run(self):
        try:
            import websocket
        except ImportError:
            _log("fp-keeper: websocket 库不可用，无法保持指纹注入")
            return
        while not self._stop.is_set():
            ws = self._connect(websocket)
            if ws is None:
                # 端口已死说明浏览器退出了；否则继续重试
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.5)
                    if s.connect_ex((CDP_HOST, self._port)) != 0:
                        break
                time.sleep(1.0)
                continue
            self._ws = ws
            try:
                self._serve(websocket, ws)
            except Exception as e:
                _log("fp-keeper: 连接中断 %s: %s" % (type(e).__name__, e))
            finally:
                try:
                    ws.close()
                except Exception:
                    pass
                self._ws = None
            if not self._stop.is_set():
                time.sleep(1.0)  # 断线重连：既有 target 会再次 attach 并重新注册

    def _connect(self, websocket):
        deadline = time.time() + 20
        while time.time() < deadline and not self._stop.is_set():
            try:
                ver = _http_get_json(self._port, "/json/version")
                ws_url = (ver or {}).get("webSocketDebuggerUrl") or ""
                if ws_url.startswith("ws://%s:" % CDP_HOST):
                    return websocket.create_connection(
                        ws_url, timeout=10, suppress_origin=True)
            except Exception:
                pass
            time.sleep(0.5)
        return None

    def _serve(self, websocket, ws):
        self._first_session = None
        with self._lock:
            self._pending = {}
        r = self._call(None, "Target.setAutoAttach", {
            "autoAttach": True,
            "waitForDebuggerOnStart": True,
            "flatten": True,
            "filter": self.ATTACH_FILTER,
        })
        if not r or "result" not in r:
            raise RuntimeError("setAutoAttach 失败: %s" % str(r)[:120])
        while not self._stop.is_set():
            raw = None
            try:
                ws.settimeout(1.0)
                raw = ws.recv()
            except websocket.WebSocketTimeoutException:
                pass
            if raw == "":
                raise RuntimeError("cdp 连接关闭")
            if raw:
                self._dispatch(raw)
            # 每轮都跑（事件密集的长轮询页面会吃满 recv，只在超时分支跑会饿死验证）
            self._maybe_navigate()
            self._poll_verify()

    def _dispatch(self, raw):
        try:
            msg = json.loads(raw)
        except Exception:
            return
        if "id" in msg:
            with self._lock:
                self._pending[msg["id"]] = msg
            return
        if msg.get("method") == "Target.attachedToTarget":
            self._on_attach(msg)

    def _on_attach(self, msg):
        params = msg.get("params") or {}
        info = params.get("targetInfo") or {}
        sid = params.get("sessionId")
        if not sid or info.get("type") not in ("page", "iframe"):
            return
        # waitForDebugger 已暂停文档执行：先注册脚本再放行，
        # 保证注入跑在页面任何 JS 之前
        r = self._call(sid, "Page.addScriptToEvaluateOnNewDocument",
                       {"source": self._script})
        self._call(sid, "Page.enable")
        self._call(sid, "Runtime.enable")
        if self._ua_override:
            self._call(sid, "Network.enable")
            self._call(sid, "Network.setUserAgentOverride", self._ua_override)
        # 当前文档立即执行一遍注入（脚本幂等）：waitForDebugger 暂停的
        # 「现存文档」不会回溯执行 addScript 注册的脚本，不补这一步则
        # 每个新标签页/重连后的既有页面第一个文档都是裸的
        ev = self._call(sid, "Runtime.evaluate", {"expression": self._script})
        if params.get("waitForDebugger"):
            self._call(sid, "Runtime.runIfWaitingForDebugger")
        if not (ev and "result" in ev and not ev["result"].get("exceptionDetails")):
            # 暂停中上下文未就绪时兜底：放行后再执行一次（幂等标记防重复包装）
            self._call(sid, "Runtime.evaluate", {"expression": self._script})
        if r and "result" in r:
            with self._lock:
                if info.get("type") == "page":
                    if self._first_session is None:
                        self._first_session = sid
                    # 只有 page 注册成功才算就绪；iframe attach 不应造成假阳性
                    self._ready.set()
            _log("fp-keeper: 注入注册成功 type=%s" % info.get("type"))
        else:
            _log("fp-keeper: 注入注册失败 type=%s r=%s" % (
                info.get("type"), str(r)[:120]))

    def _maybe_navigate(self):
        """首个页面就绪后导航到目标 URL。

        waitForDebugger 暂停的「现存文档」不会回溯执行事后注册的脚本，
        所以启动首屏必须真实导航一次产生新文档，注入才会生效。
        导航失败允许重试（最多 5 次），成功后置位不再重复。
        """
        if not self._nav_url or self._navigated or not self._first_session:
            return
        if self._nav_tries >= 5:
            return
        self._nav_tries += 1
        r = self._call(self._first_session, "Page.navigate",
                       {"url": self._nav_url}, timeout=15.0)
        ok = bool(r and "result" in r)
        self._navigated = ok
        _log("fp-keeper: 首页导航 -> %s (%s, 第%d次)" % (
            str(self._nav_url)[:60], ok, self._nav_tries))

    def _poll_verify(self):
        """在 keeper 线程内轮询首个页面，确认读到的 screen.width 是伪装值。"""
        if self._verified.is_set() or not self._first_session:
            return
        m = self._call(self._first_session, "Runtime.evaluate",
                       {"expression": "String(window.screen.width)",
                        "returnByValue": True}, timeout=5.0)
        got = ((m or {}).get("result", {}).get("result") or {}).get("value")
        if str(got) == self._expect_screen:
            self._verified.set()
            _log("fp-keeper: 验证通过 screen.width=%s" % got)

    def _call(self, session, method, params=None, timeout=10.0):
        ws = self._ws
        if ws is None:
            return None
        self._msg_id += 1
        mid = self._msg_id
        m = {"id": mid, "method": method, "params": params or {}}
        if session:
            m["sessionId"] = session
        try:
            ws.send(json.dumps(m))
        except Exception:
            return None
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if mid in self._pending:
                    return self._pending.pop(mid)
            try:
                ws.settimeout(max(0.05, deadline - time.time()))
                raw = ws.recv()
            except Exception:
                return None
            if not raw:
                return None
            self._dispatch(raw)
        return None


def _free_port(start):
    """分配调试端口。

    仅靠 bind 探测会与后续 Chrome 的绑定之间存在空窗（TOCTOU），
    批量启动时两个环境可能拿到同一端口。这里叠加两道保护：
    1. 进程内已分配集合，避免同一批启动内部撞号；
    2. 实际探测端口是否已在监听（被其他 Chrome 占用）。
    """
    with _PORT_LOCK:
        for port in range(start, start + CDP_PORT_SPAN):
            if port in _PORT_TAKEN:
                continue
            # 已在监听说明被占用，跳过
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.settimeout(0.3)
                if probe.connect_ex((CDP_HOST, port)) == 0:
                    continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                try:
                    s.bind((CDP_HOST, port))
                except OSError:
                    continue
            _PORT_TAKEN.add(port)
            return port
    raise RuntimeError("没有可用调试端口")


def release_port(port):
    """环境停止时归还端口，便于复用。"""
    with _PORT_LOCK:
        _PORT_TAKEN.discard(port)


def _wait_port(port, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.4)
            if s.connect_ex((CDP_HOST, port)) == 0:
                return True
        time.sleep(0.2)
    return False


def _no_window_flag():
    if os.name == "nt":
        return 0x08000000
    return 0


def _log(msg):
    """把启动诊断输出到 stderr，便于排查注入问题。"""
    try:
        print("[browser] %s" % msg, file=sys.stderr, flush=True)
    except Exception:
        pass
