"""Firefox 本地多版本内核启动器。

与本地 Chrome 启动器的区别：
- 按环境配置的 kernelVersion 选择 Firefox 147/150/151 等版本；
- 每个环境独立 profile，内核目录为 kernels/firefox/<version>；
- 指纹通过 profile 的 user.js 写入（UA / 语言 / CPU / DPR / 代理），
  Firefox 原生读取，不依赖 CDP 注入；
- 控制协议是 WebDriver BiDi（ws://127.0.0.1:PORT/session），不是 CDP。

说明：本地 Firefox 不修改内核源码，Canvas/WebGL/时区等深层指纹不如
商业指纹浏览器完整；定位是多版本内核兼容与隔离测试。
"""

import json
import os
import pathlib
import re
import socket
import subprocess
import threading
import time
from datetime import datetime

from .bidi import BidiError, BidiSession
from .kernels import (
    DEFAULT_FIREFOX_VERSION,
    installed_firefox_kernels,
    normalize_firefox_version,
    resolve_firefox_kernel,
)
from .paths import atomic_write_text

_SAFE_RE = re.compile(r"[^A-Za-z0-9_-]+")


def _safe_key(env_id):
    return _SAFE_RE.sub("_", str(env_id))[:80] or "env"


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _port_open(port, timeout=0.5):
    try:
        with socket.create_connection(("127.0.0.1", int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _js_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    return json.dumps(str(value), ensure_ascii=False)


class FirefoxKernel:

    def __init__(self, work_dir, kernel_path=None, fps=None, proxies=None):
        self.work_dir = pathlib.Path(work_dir)
        self.state_dir = self.work_dir / "firefox-state"
        self.profiles_dir = self.work_dir / "profiles"
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
        override = kernel_path or os.environ.get("FIREFOX150_PATH")
        self.kernel_override = pathlib.Path(override) if override else None
        self.fps = fps
        self.proxies = proxies
        self._sessions = {}
        self._procs = {}
        self._lock = threading.RLock()
        self._cache = {}

    # ---------- 状态文件 ----------

    def _state_file(self, env_id):
        return self.state_dir / ("%s.json" % _safe_key(env_id))

    def _read_state(self, env_id):
        try:
            p = self._state_file(env_id)
            if p.exists():
                return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        return None

    def _write_state(self, env_id, state):
        state = dict(state)
        state["envId"] = env_id
        state["updatedAt"] = _now()
        try:
            atomic_write_text(self._state_file(env_id), json.dumps(state, ensure_ascii=False, indent=2))
        except OSError:
            pass

    def _all_states(self):
        out = []
        try:
            for p in self.state_dir.glob("*.json"):
                try:
                    out.append(json.loads(p.read_text(encoding="utf-8")))
                except (OSError, ValueError):
                    continue
        except OSError:
            pass
        return out

    # ---------- 可用性 ----------

    @staticmethod
    def _version_key(version):
        nums = [int(x) for x in re.findall(r"\d+", str(version))]
        return tuple(nums + [0] * (4 - len(nums)))[:4]

    def _pick_version(self, version=None):
        v = normalize_firefox_version(version)
        if v:
            return v
        installed = installed_firefox_kernels()
        if installed:
            return sorted(installed.keys(), key=self._version_key, reverse=True)[0]
        return DEFAULT_FIREFOX_VERSION

    def available(self, version=None):
        if self.kernel_override:
            return self.kernel_override.is_file()
        return resolve_firefox_kernel(version) is not None

    def kernel_path(self, version=None):
        if self.kernel_override:
            return str(self.kernel_override)
        p = resolve_firefox_kernel(version)
        return str(p) if p else ""

    # ---------- 启动 / 停止 ----------

    def start(self, env_id, url="https://www.taobao.com", proxy_port=None,
              display_name="", version=None):
        version = self._pick_version(version)
        kernel_path = self.kernel_path(version)
        if not kernel_path:
            raise RuntimeError(
                "未找到 Firefox %s 内核；请到「内核」页下载安装，"
                "或把官方包解压到 kernels/firefox/%s/extract/core/" % (version, version)
            )

        state = self._read_state(env_id) or {}
        if self.running(env_id):
            return int(state.get("port") or 0)

        fp = (self.fps.load_or_create(env_id) if self.fps else {}) or {}
        profile = self.profiles_dir / ("fx%s-%s" % (
            _SAFE_RE.sub("_", version), _safe_key(env_id)))
        profile.mkdir(parents=True, exist_ok=True)
        self._write_prefs(profile, fp, proxy_port, url, version)

        screen = fp.get("screen") or {}
        width = int(screen.get("width") or 1366)
        height = int(screen.get("height") or 768)
        height = max(600, height - 120)
        port = _free_port()
        args = [
            str(kernel_path),
            "-profile", str(profile),
            "-no-remote",
            "-new-instance",
            "--remote-debugging-port", str(port),
            "-width", str(width),
            "-height", str(height),
            url or "about:blank",
        ]
        proc = subprocess.Popen(
            args,
            cwd=str(pathlib.Path(kernel_path).parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            deadline = time.time() + 30
            while time.time() < deadline:
                if _port_open(port):
                    break
                if proc.poll() is not None:
                    raise RuntimeError("Firefox 150 启动后立即退出（exit=%s）" % proc.returncode)
                time.sleep(0.4)
            else:
                raise RuntimeError("Firefox 150 调试端口 %s 在 30 秒内未就绪" % port)

            bidi = BidiSession("ws://127.0.0.1:%d/session" % port)
            bidi.connect()
        except Exception:
            try:
                proc.terminate()
            except Exception:
                pass
            raise

        context = ""
        try:
            tops = bidi.top_contexts()
            for c in tops:
                if str(c.get("url") or "") not in ("", "about:blank"):
                    context = c.get("context") or ""
                    break
            if not context and tops:
                context = tops[0].get("context") or ""
            if not context:
                context = bidi.create_tab(background=False)
            if url and context:
                try:
                    bidi.navigate(context, url, wait="interactive")
                except BidiError:
                    try:
                        bidi.navigate(context, url, wait="none")
                    except BidiError:
                        pass
            label = str(display_name or "").strip()
            if label and context:
                try:
                    bidi.evaluate(
                        context,
                        "document.title = %s + document.title" % json.dumps("[" + label + "] "),
                    )
                except BidiError:
                    pass
        except BidiError:
            context = ""

        caps = bidi.capabilities or {}
        state = {
            "envId": env_id,
            "port": int(port),
            "ws": "ws://127.0.0.1:%d/session" % port,
            "pid": int(proc.pid),
            "profile": str(profile),
            "context": context,
            "label": str(display_name or "").strip(),
            "browserVersion": str(caps.get("browserVersion") or version),
            "kernelVersion": version,
            "kernelPath": str(kernel_path),
            "userAgent": str(caps.get("userAgent") or ""),
            "running": True,
            "startedAt": _now(),
            "backend": "firefox",
            "kernel": "firefox-" + version,
        }
        self._write_state(env_id, state)
        with self._lock:
            self._sessions[env_id] = {"bidi": bidi, "port": int(port)}
            self._procs[env_id] = proc
            self._cache.pop(env_id, None)
        return int(port)

    def stop(self, env_id):
        state = self._read_state(env_id)
        with self._lock:
            entry = self._sessions.pop(env_id, None)
            proc = self._procs.pop(env_id, None)
            self._cache.pop(env_id, None)

        if entry and entry.get("bidi"):
            try:
                entry["bidi"].command("browser.close", timeout=3)
            except Exception:
                pass
            entry["bidi"].close()

        if proc is None and state:
            pid = state.get("pid")
            if pid:
                try:
                    subprocess.run(
                        ["taskkill", "/PID", str(pid), "/T", "/F"],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        timeout=8,
                    )
                except Exception:
                    pass
        elif proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=8)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        if state:
            state["running"] = False
            state["stoppedAt"] = _now()
            self._write_state(env_id, state)

    def stop_all(self):
        for st in self._all_states():
            if st.get("envId") and st.get("running"):
                self.stop(st["envId"])

    # ---------- 查询 ----------

    def running(self, env_id):
        state = self._read_state(env_id)
        if not state or state.get("running") is False:
            return False
        port = state.get("port")
        if not port:
            return False
        now = time.time()
        cached = self._cache.get(env_id)
        if cached and now - cached[0] < 1.5:
            return cached[1]
        with self._lock:
            proc = self._procs.get(env_id)
        if proc is not None and proc.poll() is not None:
            alive = False
        else:
            alive = _port_open(port)
        self._cache[env_id] = (now, alive)
        return alive

    def debug_port(self, env_id):
        state = self._read_state(env_id) or {}
        if state.get("running") and state.get("port"):
            return int(state["port"])
        return None

    def profile_dir(self, env_id):
        state = self._read_state(env_id) or {}
        return state.get("profile") or None

    def browser_version(self, env_id):
        state = self._read_state(env_id) or {}
        return state.get("browserVersion") or ""

    def list_running(self):
        out = {}
        for st in self._all_states():
            env_id = st.get("envId")
            if env_id:
                out[env_id] = self.running(env_id)
        return out

    # ---------- Cookie（BiDi） ----------

    def _ensure_session(self, env_id):
        with self._lock:
            entry = self._sessions.get(env_id)
        if entry and entry.get("bidi"):
            return entry["bidi"]
        state = self._read_state(env_id) or {}
        if not state.get("running") or not state.get("ws"):
            raise RuntimeError("Firefox 150 环境尚未启动，无法操作 Cookie")
        bidi = BidiSession(state["ws"])
        try:
            bidi.connect()
        except BidiError as e:
            raise RuntimeError("连接 Firefox 150 BiDi 入口失败：%s" % e) from e
        with self._lock:
            self._sessions[env_id] = {"bidi": bidi, "port": int(state.get("port") or 0)}
        return bidi

    def get_cookies(self, env_id):
        return self._ensure_session(env_id).get_cookies()

    def set_cookies(self, env_id, rows):
        bidi = self._ensure_session(env_id)
        ok = 0
        errors = []
        for row in rows or []:
            try:
                bidi.set_cookie(row)
                ok += 1
            except BidiError as e:
                errors.append(str(e))
        if ok == 0 and errors:
            raise RuntimeError("Cookie 写入失败：%s" % errors[0])
        return ok

    # ---------- 指纹 prefs ----------

    def _write_prefs(self, profile, fp, proxy_port, start_url, version):
        locale = fp.get("locale") or {}
        language = str(locale.get("language") or "en-US")
        languages = locale.get("languages") or [language]
        if not isinstance(languages, list) or not languages:
            languages = [language]
        screen = fp.get("screen") or {}
        hardware = fp.get("hardware") or {}
        dpr = screen.get("dpr") or 1
        cores = int(hardware.get("cores") or 8)

        ua = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:%s) "
            "Gecko/20100101 Firefox/%s" % (version, version)
        )
        prefs = [
            # 浏览器身份
            ("general.useragent.override", ua),
            ("general.appname.override", "Netscape"),
            ("general.appversion.override", "5.0 (Windows)"),
            ("general.platform.override", "Win32"),
            ("general.oscpu.override", "Windows NT 10.0; Win64; x64"),
            ("intl.accept_languages", ",".join(str(x) for x in languages)),
            ("intl.locale.requested", language),
            ("javascript.use_us_english_locale", language.lower().startswith("en")),
            ("dom.maxHardwareConcurrency", cores),
            ("layout.css.devPixelsPerPx", str(dpr)),
            # 指纹开关：不要启用 resistFingerprinting，否则时区会被强制 UTC
            ("privacy.resistFingerprinting", False),
            ("privacy.resistFingerprinting.letterboxing", False),
            ("webgl.disabled", False),
            ("webgl.force-enabled", True),
            ("media.peerconnection.enabled", False),
            ("media.navigator.enabled", False),
            # 启动行为
            ("browser.startup.page", 1),
            ("browser.startup.homepage", start_url or "about:blank"),
            ("browser.aboutwelcome.enabled", False),
            ("browser.shell.checkDefaultBrowser", False),
            ("browser.sessionstore.resume_from_crash", False),
            ("browser.tabs.warnOnClose", False),
            ("datareporting.policy.dataSubmissionEnabled", False),
            ("toolkit.telemetry.enabled", False),
            ("app.update.enabled", False),
            ("app.update.auto", False),
        ]

        if proxy_port:
            prefs.extend([
                ("network.proxy.type", 1),
                ("network.proxy.http", "127.0.0.1"),
                ("network.proxy.http_port", int(proxy_port)),
                ("network.proxy.ssl", "127.0.0.1"),
                ("network.proxy.ssl_port", int(proxy_port)),
                ("network.proxy.share_proxy_settings", True),
                ("network.proxy.no_proxies_on", ""),
                ("network.proxy.allow_hijacking_localhost", True),
            ])
        else:
            prefs.append(("network.proxy.type", 0))

        lines = [
            "// 由 taobao_env 生成：环境 %s，内核 Firefox 150" % profile.name,
            "// 修改后重启该环境生效",
        ]
        for key, value in prefs:
            lines.append("user_pref(%s, %s);" % (json.dumps(key), _js_value(value)))
        atomic_write_text(profile / "user.js", "\n".join(lines) + "\n")
