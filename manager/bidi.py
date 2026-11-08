"""最小 WebDriver BiDi 客户端（Firefox）。

Firefox 的远程调试端点不是 CDP：
- CDP 的 /json/version 在这里是 404；
- 正确协议是 W3C WebDriver BiDi，连上后先 session.new，再发 browsingContext.*。

只实现管理器需要的命令：标签页、导航、Cookie、脚本执行、关标签。
"""

import json
import threading
import time

import websocket


class BidiError(RuntimeError):
    pass


class BidiSession:

    def __init__(self, ws_url, timeout=15):
        self.ws_url = ws_url
        self.timeout = timeout
        self.session_id = ""
        self.capabilities = {}
        self._ws = None
        self._id = 0
        self._lock = threading.RLock()

    # ---------- 连接 ----------

    def connect(self):
        if self._ws is not None:
            return self
        try:
            # Firefox Remote Agent 可能拒绝带 Origin 的握手
            self._ws = websocket.create_connection(
                self.ws_url, timeout=self.timeout, suppress_origin=True)
        except Exception as e:
            raise BidiError("连接 Firefox 调试入口失败：%s" % e) from e

        try:
            self.new_session()
        except BidiError:
            self.close()
            raise
        return self

    def new_session(self, capabilities=None):
        result = self.command("session.new", {"capabilities": capabilities or {}})
        self.session_id = str(result.get("sessionId") or "")
        if not self.session_id:
            raise BidiError("Firefox 没有返回 sessionId")
        self.capabilities = result.get("capabilities") or {}
        return result

    def close(self):
        ws = self._ws
        self._ws = None
        if ws is not None:
            try:
                ws.close()
            except Exception:
                pass

    # ---------- 命令通道 ----------

    def command(self, method, params=None, timeout=None):
        if self._ws is None:
            raise BidiError("BiDi 连接尚未建立")
        with self._lock:
            self._id += 1
            msg_id = self._id
            payload = {"id": msg_id, "method": method, "params": params or {}}
            try:
                self._ws.send(json.dumps(payload, ensure_ascii=False))
                self._ws.settimeout(timeout or self.timeout)
                deadline = time.time() + (timeout or self.timeout)
                while time.time() < deadline:
                    raw = self._ws.recv()
                    if raw is None or raw == "":
                        raise BidiError("Firefox 连接已关闭")
                    try:
                        msg = json.loads(raw)
                    except ValueError:
                        continue
                    if msg.get("id") != msg_id:
                        # 事件（无 id）或其他请求的响应，跳过
                        continue
                    if msg.get("type") == "error" or msg.get("error"):
                        raise BidiError("%s: %s" % (method, msg.get("message") or msg.get("error")))
                    if msg.get("type") != "success":
                        raise BidiError("%s: 非 BiDi 成功响应 %s" % (method, str(msg)[:200]))
                    return msg.get("result") or {}
                raise BidiError("%s 超时（%ss）" % (method, timeout or self.timeout))
            except websocket.WebSocketTimeoutException as e:
                raise BidiError("%s 超时（%ss）" % (method, timeout or self.timeout)) from e
            except BidiError:
                raise
            except Exception as e:
                raise BidiError("%s 失败：%s" % (method, e)) from e

    # ---------- 标签页 ----------

    def get_tree(self, max_depth=2):
        return self.command("browsingContext.getTree", {"maxDepth": max_depth})

    def top_contexts(self):
        tree = self.get_tree()
        return [c for c in (tree.get("contexts") or []) if not c.get("parent")]

    def create_tab(self, background=False):
        result = self.command("browsingContext.create", {
            "type": "tab",
            "background": bool(background),
        })
        return result.get("context") or ""

    def navigate(self, context, url, wait="interactive"):
        return self.command("browsingContext.navigate", {
            "context": context,
            "url": url,
            "wait": wait,
        })

    def close_tab(self, context):
        return self.command("browsingContext.close", {"context": context})

    def activate(self, context):
        return self.command("browsingContext.activate", {"context": context})

    def set_viewport(self, context, width, height, dpr=None):
        params = {"context": context, "viewport": {"width": int(width), "height": int(height)}}
        if dpr:
            params["devicePixelRatio"] = float(dpr)
        return self.command("browsingContext.setViewport", params)

    # ---------- 脚本 ----------

    def evaluate(self, context, expression, await_promise=True):
        result = self.command("script.evaluate", {
            "expression": expression,
            "target": {"context": context},
            "awaitPromise": bool(await_promise),
            "resultOwnership": "none",
        })
        value = result.get("result") or {}
        if value.get("type") == "exception":
            raise BidiError("页面脚本异常：%s" % (value.get("value") or value))
        return _flatten_value(value)

    # ---------- Cookie ----------

    def get_cookies(self):
        result = self.command("storage.getCookies", {})
        return [_plain_cookie(c) for c in (result.get("cookies") or [])]

    def set_cookie(self, cookie):
        name = str(cookie.get("name") or "").strip()
        domain = str(cookie.get("domain") or "").strip()
        if not name or not domain:
            raise BidiError("Cookie 缺少 name 或 domain")
        value = cookie.get("value")
        if not isinstance(value, str):
            value = "" if value is None else str(value)
        item = {
            "name": name,
            "value": {"type": "string", "value": value},
            "domain": domain,
            "path": str(cookie.get("path") or "/") or "/",
            "secure": bool(cookie.get("secure")),
            "httpOnly": bool(cookie.get("httpOnly", cookie.get("httponly", False))),
        }
        same_site = str(cookie.get("sameSite") or cookie.get("same_site") or "").lower()
        if same_site in ("no_restriction", "no-restriction"):
            same_site = "none"
        if same_site in ("strict", "lax", "none"):
            item["sameSite"] = same_site
            if same_site == "none":
                item["secure"] = True
        expiry = cookie.get("expiry", cookie.get("expires", cookie.get("expirationDate")))
        try:
            expiry = int(float(expiry))
        except (TypeError, ValueError):
            expiry = 0
        if expiry > 10 ** 12:
            expiry = expiry // 1000  # 毫秒时间戳转秒
        if expiry > 0:
            item["expiry"] = expiry
        return self.command("storage.setCookie", {"cookie": item})

    def delete_cookies(self, domain=None):
        params = {"filter": {}}
        if domain:
            params["filter"]["domain"] = domain
        return self.command("storage.deleteCookies", params)


def _flatten_value(value):
    if isinstance(value, dict) and "type" in value:
        return value.get("value")
    return value


def _plain_cookie(cookie):
    value = cookie.get("value")
    if isinstance(value, dict):
        value = value.get("value", "")
    return {
        "name": cookie.get("name", ""),
        "value": value,
        "domain": cookie.get("domain", ""),
        "path": cookie.get("path", "/"),
        "secure": bool(cookie.get("secure")),
        "httpOnly": bool(cookie.get("httpOnly")),
        "sameSite": cookie.get("sameSite", ""),
        "expiry": cookie.get("expiry", 0),
        "expires": cookie.get("expiry", 0),
        "encrypted": False,
        "size": cookie.get("size", 0),
    }
