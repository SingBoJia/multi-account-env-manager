"""窗口同步器：把一个窗口的操作实时同步到其他窗口。

比特浏览器是主流指纹浏览器里唯一提供此功能的，用于多店铺同步骤操作
（例如同时把多个店铺切到同一个活动页、同时填写同一个表单）。

实现方式：通过 CDP 监听主窗口（master）的导航与输入事件，
再向从窗口（slave）投递等价命令。

与比特的差异：本实现只同步「导航 / 点击 / 输入 / 滚动 / 按键」五类语义动作，
不做像素级鼠标轨迹回放，避免在多环境不同分辨率下坐标错位。
"""

import json
import threading
import time

SYNC_ACTIONS = ("navigate", "click", "input", "scroll", "keypress")


class WindowSynchronizer:
    """管理一组主从窗口的同步会话。"""

    def __init__(self, launcher):
        self.launcher = launcher
        self._sessions = {}  # session_id -> {"master": env_id, "slaves": [...], "options": {...}}
        self._threads = {}
        self._stop_flags = {}
        self._lock = threading.Lock()
        self._log = []

    # ---------- 会话管理 ----------

    def start(self, master, slaves, options=None):
        """开始同步。master 与 slaves 都是环境编号。"""
        if not master:
            raise ValueError("缺少主窗口")
        slaves = [s for s in (slaves or []) if s and s != master]
        if not slaves:
            raise ValueError("至少需要一个从窗口")

        if not self.launcher.running(master):
            raise ValueError("主窗口未运行: %s" % master)
        for s in slaves:
            if not self.launcher.running(s):
                raise ValueError("从窗口未运行: %s" % s)

        session_id = "%s-%d" % (master, int(time.time() * 1000))
        opts = {
            "click": True,
            "input": True,
            "scroll": True,
            "keypress": True,
            "navigate": True,
            "delayMs": 120,
        }
        if options:
            for k in list(opts.keys()):
                if k in options:
                    opts[k] = bool(options[k])
            if "delayMs" in options:
                try:
                    opts["delayMs"] = max(0, min(3000, int(options["delayMs"])))
                except (TypeError, ValueError):
                    pass

        with self._lock:
            self._sessions[session_id] = {
                "id": session_id,
                "master": master,
                "slaves": slaves,
                "options": opts,
                "startedAt": time.strftime("%H:%M:%S"),
                "events": 0,
            }
            self._stop_flags[session_id] = threading.Event()

        t = threading.Thread(target=self._run, args=(session_id,), daemon=True)
        self._threads[session_id] = t
        t.start()
        self._record(session_id, "会话开始，主=%s 从=%s" % (master, ",".join(slaves)))
        return session_id

    def stop(self, session_id):
        with self._lock:
            flag = self._stop_flags.get(session_id)
            if flag:
                flag.set()
        self._record(session_id, "会话已停止")
        return True

    def stop_all(self):
        with self._lock:
            ids = list(self._stop_flags.keys())
        for sid in ids:
            self.stop(sid)
        return len(ids)

    def list_sessions(self):
        with self._lock:
            return [dict(v) for v in self._sessions.values()]

    def recent_log(self, limit=30):
        with self._lock:
            return list(self._log[-limit:])

    # ---------- 同步主循环 ----------

    def _run(self, session_id):
        sess = self._sessions.get(session_id)
        if not sess:
            return
        stop = self._stop_flags[session_id]
        master = sess["master"]
        slaves = sess["slaves"]
        opts = sess["options"]

        port = self.launcher.debug_port(master)
        if not port:
            self._record(session_id, "主窗口调试端口不可用，会话终止")
            return

        try:
            import websocket
        except ImportError:
            self._record(session_id, "缺少 websocket 依赖，会话终止")
            return

        targets = self.launcher.page_targets(port)
        if not targets:
            self._record(session_id, "主窗口找不到页面，会话终止")
            return
        ws_url = targets[0].get("webSocketDebuggerUrl", "")
        if not ws_url.startswith("ws://127.0.0.1:"):
            self._record(session_id, "主窗口调试地址异常，会话终止")
            return

        try:
            ws = websocket.create_connection(ws_url, timeout=10, suppress_origin=True)
        except Exception as e:
            self._record(session_id, "连接主窗口失败: %s" % e)
            return

        try:
            # 开启事件监听
            self._send(ws, 1, "Page.enable")
            self._send(ws, 2, "Runtime.enable")
            # 用 addScriptToEvaluateOnNewDocument 保证每次导航后上报脚本都会重新装上
            self._send(ws, 3, "Page.addScriptToEvaluateOnNewDocument", {"source": _REPORTER_JS})
            # 当前页面也立即注入一次
            self._send(ws, 4, "Runtime.evaluate", {
                "expression": _REPORTER_JS,
                "returnByValue": True,
            })

            self._record(session_id, "已连接主窗口，开始监听")
            ws.settimeout(0.5)

            # 主循环：轮询页面动作队列 + 接收导航事件
            # 说明：Chrome 155 的 Runtime.bindingCalled 在本环境下不投递，
            # 因此改用「页面缓存队列 + CDP 轮询拉取」，实测稳定。
            next_nav_check = 0.0
            while not stop.is_set():
                # 拉取动作队列
                drained = self._drain_actions(ws)
                for action in drained:
                    if self._should_sync(action, opts):
                        self._dispatch(session_id, slaves, action, opts)

                # 顺带处理可能到达的导航事件（尽力而为，不依赖它）
                try:
                    raw = ws.recv()
                except Exception:
                    raw = None
                if raw:
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        msg = None
                    if msg:
                        self._handle_nav_event(msg, session_id, sess, slaves, opts)

                # 定期主动核对主窗口 URL，兜住漏掉的导航事件
                now = time.time()
                if now >= next_nav_check:
                    next_nav_check = now + 1.5
                    cur = self._current_url(ws)
                    if cur and cur != sess.get("lastUrl") and opts.get("navigate", True):
                        prev = sess.get("lastUrl")
                        sess["lastUrl"] = cur
                        if prev is not None and not cur.startswith("about:"):
                            self._dispatch(session_id, slaves, {"kind": "navigate", "url": cur}, opts)

                time.sleep(0.15)
        finally:
            try:
                ws.close()
            except Exception:
                pass
            with self._lock:
                if session_id in self._sessions:
                    del self._sessions[session_id]

    def _handle_nav_event(self, msg, session_id, sess, slaves, opts):
        if msg.get("method") != "Page.frameNavigated":
            return
        frame = (msg.get("params", {}) or {}).get("frame", {}) or {}
        if frame.get("parentId"):
            return
        url = frame.get("url") or ""
        if not url or not opts.get("navigate", True):
            return
        if url.startswith("about:") or url.startswith("chrome-error:"):
            return
        if url == sess.get("lastUrl"):
            return
        sess["lastUrl"] = url
        self._dispatch(session_id, slaves, {"kind": "navigate", "url": url}, opts)

    def _drain_actions(self, ws):
        """从页面取走待同步动作。"""
        r = self._send(ws, 900, "Runtime.evaluate", {
            "expression": "(window.__syncDrain ? window.__syncDrain() : '[]')",
            "returnByValue": True,
        })
        if not r:
            return []
        raw = r.get("result", {}).get("result", {}).get("value")
        if not raw or raw == "[]":
            return []
        try:
            actions = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return []
        return actions if isinstance(actions, list) else []

    def _current_url(self, ws):
        r = self._send(ws, 901, "Runtime.evaluate", {
            "expression": "location.href",
            "returnByValue": True,
        })
        if not r:
            return ""
        return r.get("result", {}).get("result", {}).get("value") or ""

    def _should_sync(self, action, opts):
        kind = action.get("kind")
        if kind not in SYNC_ACTIONS:
            return False
        return bool(opts.get(kind, False))

    def _dispatch(self, session_id, slaves, action, opts):
        """把动作投递到所有从窗口。"""
        delay = opts.get("delayMs", 0) / 1000.0
        ok_count = 0
        for slave in slaves:
            port = self.launcher.debug_port(slave)
            if not port:
                continue
            try:
                self._apply(port, action)
                ok_count += 1
            except Exception:
                continue
            if delay:
                time.sleep(delay)
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id]["events"] += 1
        self._record(session_id, "%s -> %d/%d 窗口" % (action.get("kind"), ok_count, len(slaves)))

    def _apply(self, port, action):
        """在指定窗口执行等价动作。"""
        import websocket

        targets = self.launcher.page_targets(port)
        if not targets:
            return
        ws_url = targets[0].get("webSocketDebuggerUrl", "")
        if not ws_url.startswith("ws://127.0.0.1:"):
            return
        ws = websocket.create_connection(ws_url, timeout=6, suppress_origin=True)
        try:
            kind = action.get("kind")
            if kind == "navigate":
                self._send(ws, 1, "Page.navigate", {"url": action.get("url", "")})
            elif kind == "click":
                expr = _click_js(action)
                self._send(ws, 1, "Runtime.evaluate", {"expression": expr, "returnByValue": True})
            elif kind == "input":
                expr = _input_js(action)
                self._send(ws, 1, "Runtime.evaluate", {"expression": expr, "returnByValue": True})
            elif kind == "scroll":
                expr = "window.scrollTo(%d,%d);" % (
                    int(action.get("x", 0)), int(action.get("y", 0)))
                self._send(ws, 1, "Runtime.evaluate", {"expression": expr, "returnByValue": True})
            elif kind == "keypress":
                self._send(ws, 1, "Input.dispatchKeyEvent", {
                    "type": "keyDown",
                    "key": action.get("key", ""),
                    "code": action.get("code", ""),
                })
        finally:
            try:
                ws.close()
            except Exception:
                pass

    @staticmethod
    def _send(ws, mid, method, params=None):
        ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.time() + 6
        while time.time() < deadline:
            try:
                msg = json.loads(ws.recv())
            except Exception:
                return None
            if msg.get("id") == mid:
                return msg
        return None

    def _record(self, session_id, text):
        with self._lock:
            self._log.append({
                "time": time.strftime("%H:%M:%S"),
                "session": session_id,
                "text": text,
            })
            if len(self._log) > 500:
                del self._log[:200]


# ---------- 注入到主窗口的上报脚本 ----------

_REPORTER_JS = r"""
(function () {
  if (window.__SYNC_REPORTER__) return 'already';
  window.__SYNC_REPORTER__ = true;

  // 动作先缓存到页面队列，由 CDP 侧轮询拉走。
  // 不用 Runtime.addBinding：Chrome 155 上该事件在本环境不投递（已实测）。
  var queue = [];
  window.__syncDrain = function () {
    var out = queue.slice(0);
    queue.length = 0;
    try { return JSON.stringify(out); } catch (e) { return '[]'; }
  };

  var REPORT = function (obj) {
    try {
      if (queue.length < 200) queue.push(obj);
    } catch (e) {}
  };

  // 用 CSS 选择器定位元素，跨窗口才能对准同一个目标
  function pathOf(el) {
    if (!el || el.nodeType !== 1) return '';
    if (el.id) return '#' + CSS.escape(el.id);
    var parts = [];
    var cur = el;
    var depth = 0;
    while (cur && cur.nodeType === 1 && depth < 6) {
      var tag = cur.tagName.toLowerCase();
      var parent = cur.parentElement;
      if (parent) {
        var sameTag = Array.prototype.filter.call(parent.children, function (c) {
          return c.tagName === cur.tagName;
        });
        if (sameTag.length > 1) {
          tag += ':nth-of-type(' + (sameTag.indexOf(cur) + 1) + ')';
        }
      }
      parts.unshift(tag);
      cur = parent;
      depth++;
    }
    return parts.join(' > ');
  }

  document.addEventListener('click', function (e) {
    var t = e.target;
    REPORT({kind: 'click', path: pathOf(t), x: Math.round(e.clientX), y: Math.round(e.clientY)});
  }, true);

  document.addEventListener('change', function (e) {
    var t = e.target;
    if (!t || !('value' in t)) return;
    REPORT({kind: 'input', path: pathOf(t), value: String(t.value).slice(0, 2000)});
  }, true);

  // 滚动：同时监听 window、document 与捕获阶段的 scroll，
  // 因为部分页面把滚动放在内层容器里，只监听 window 会漏。
  // 不做防抖，靠坐标去重；防抖会丢掉快速连续滚动后的最终位置。
  var lastScrollX = -1, lastScrollY = -1;
  function reportScroll() {
    var x = Math.round(window.scrollX);
    var y = Math.round(window.scrollY);
    if (y === lastScrollY && x === lastScrollX) return;
    lastScrollX = x;
    lastScrollY = y;
    REPORT({kind: 'scroll', x: x, y: y});
  }
  window.addEventListener('scroll', reportScroll, true);
  document.addEventListener('scroll', reportScroll, true);
  setInterval(reportScroll, 500);

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' || e.key === 'Escape' || e.key === 'Tab') {
      REPORT({kind: 'keypress', key: e.key, code: e.code || ''});
    }
  }, true);

  return 'installed';
})();
"""


def _click_js(action):
    """在从窗口按选择器点击；找不到时退回坐标点击。"""
    path = json.dumps(str(action.get("path", "")))
    x = int(action.get("x", 0))
    y = int(action.get("y", 0))
    return """
(function(){
  try {
    var el = document.querySelector(%s);
    if (el) { el.click(); return 'clicked-by-selector'; }
  } catch(e) {}
  try {
    var t = document.elementFromPoint(%d, %d);
    if (t) { t.click(); return 'clicked-by-point'; }
  } catch(e) {}
  return 'not-found';
})()
""" % (path, x, y)


def _input_js(action):
    """在从窗口填值，并派发 input/change 事件让页面框架响应。"""
    path = json.dumps(str(action.get("path", "")))
    value = json.dumps(str(action.get("value", "")))
    return """
(function(){
  try {
    var el = document.querySelector(%s);
    if (!el) return 'not-found';
    var v = %s;
    el.focus();
    el.value = v;
    el.dispatchEvent(new Event('input', {bubbles: true}));
    el.dispatchEvent(new Event('change', {bubbles: true}));
    return 'filled';
  } catch(e) { return 'error'; }
})()
""" % (path, value)
