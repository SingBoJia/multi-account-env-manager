"""窗口布局管理：把已启动的环境浏览器按指定方式排列。

借鉴比特浏览器的窗口同步器布局能力，但实现方式不同：
比特是在它的 Electron 主窗口里内嵌浏览器视图来排列，
我们用 CDP 的 Browser.setWindowBounds 直接控制独立 Chrome 窗口的位置和大小。

支持布局：
  grid      网格（自动算行列）
  tile-h    横向平铺（一行排开）
  tile-v    纵向平铺（一列排开）
  cascade   层叠（每个窗口偏移一点）
  focus     只保留主窗口可见，其余最小化
"""

import json
import socket
import time

CDP_HOST = "127.0.0.1"

LAYOUTS = ("grid", "tile-h", "tile-v", "cascade", "focus")


class LayoutError(Exception):
    pass


def _screen_size():
    """取主屏可用区域（不含任务栏）。"""
    try:
        import ctypes
        from ctypes import wintypes

        class RECT(ctypes.Structure):
            _fields_ = [
                ("left", wintypes.LONG), ("top", wintypes.LONG),
                ("right", wintypes.LONG), ("bottom", wintypes.LONG),
            ]

        rect = RECT()
        # SPI_GETWORKAREA = 0x0030，取扣除任务栏后的工作区
        if ctypes.windll.user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(rect), 0):
            w = rect.right - rect.left
            h = rect.bottom - rect.top
            if w > 200 and h > 200:
                return rect.left, rect.top, w, h
    except Exception:
        pass
    return 0, 0, 1920, 1040


def _cdp_call(port, method, params=None):
    """向浏览器级 CDP 端点发一条命令（/json/version 的 webSocketDebuggerUrl）。"""
    try:
        import websocket
    except ImportError:
        raise LayoutError("缺少 websocket 依赖")

    version = _get_json(port, "/json/version")
    if not isinstance(version, dict):
        raise LayoutError("无法读取浏览器信息")
    ws_url = version.get("webSocketDebuggerUrl") or ""
    if not ws_url.startswith("ws://%s:" % CDP_HOST):
        raise LayoutError("调试地址异常")

    ws = websocket.create_connection(ws_url, timeout=8, suppress_origin=True)
    try:
        ws.send(json.dumps({"id": 1, "method": method, "params": params or {}}))
        deadline = time.time() + 8
        while time.time() < deadline:
            try:
                msg = json.loads(ws.recv())
            except Exception:
                break
            if msg.get("id") == 1:
                return msg
        return None
    finally:
        try:
            ws.close()
        except Exception:
            pass


def _get_json(port, path):
    req = ("GET %s HTTP/1.1\r\nHost: %s:%d\r\nConnection: close\r\n\r\n"
           % (path, CDP_HOST, port)).encode("ascii")
    chunks = []
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect((CDP_HOST, port))
        s.sendall(req)
        while True:
            try:
                b = s.recv(65536)
            except socket.timeout:
                break
            if not b:
                break
            chunks.append(b)
            joined = b"".join(chunks)
            head, sep, body = joined.partition(b"\r\n\r\n")
            if not sep:
                continue
            for line in head.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    n = int(line.split(b":", 1)[1].strip())
                    if len(body) >= n:
                        try:
                            return json.loads(body[:n].decode("utf-8", "ignore"))
                        except json.JSONDecodeError:
                            return None
    return None


def _window_for_target(port, target_id):
    """取某个页面 target 所属的浏览器窗口 id。"""
    r = _cdp_call(port, "Browser.getWindowForTarget", {"targetId": target_id})
    if not r:
        return None
    return (r.get("result") or {}).get("windowId")


def _set_bounds(port, window_id, left, top, width, height, state="normal"):
    params = {
        "windowId": window_id,
        "bounds": {
            "left": int(left), "top": int(top),
            "width": int(width), "height": int(height),
            "windowState": state,
        },
    }
    return _cdp_call(port, "Browser.setWindowBounds", params)


def compute_positions(count, layout, screen=None):
    """算出每个窗口应放的位置。返回 [(left, top, width, height), ...]"""
    if count <= 0:
        return []
    if layout not in LAYOUTS:
        raise LayoutError("不支持的布局: %s" % layout)

    sx, sy, sw, sh = screen or _screen_size()
    gap = 6

    if layout == "focus":
        # 主窗口占大部分，其余最小化（位置返回 None 表示最小化）
        return [(sx + gap, sy + gap, sw - gap * 2, sh - gap * 2)] + [None] * (count - 1)

    if layout == "cascade":
        step = 34
        w = int(sw * 0.68)
        h = int(sh * 0.78)
        out = []
        for i in range(count):
            left = sx + (i * step) % max(1, sw - w)
            top = sy + (i * step) % max(1, sh - h)
            out.append((left, top, w, h))
        return out

    if layout == "tile-h":
        cols, rows = count, 1
    elif layout == "tile-v":
        cols, rows = 1, count
    else:  # grid：尽量接近正方形
        import math
        cols = max(1, int(math.ceil(math.sqrt(count))))
        rows = int(math.ceil(count / cols))

    cell_w = (sw - gap * (cols + 1)) // cols
    cell_h = (sh - gap * (rows + 1)) // rows
    cell_w = max(320, cell_w)
    cell_h = max(240, cell_h)

    out = []
    for i in range(count):
        r = i // cols
        c = i % cols
        left = sx + gap + c * (cell_w + gap)
        top = sy + gap + r * (cell_h + gap)
        out.append((left, top, cell_w, cell_h))
    return out


def apply_layout(launcher, env_ids, layout="grid"):
    """对一组已启动的环境应用布局。返回每个环境的处理结果。"""
    if not env_ids:
        raise LayoutError("没有可排列的环境")

    # 只处理真正在运行的
    running = [e for e in env_ids if launcher.running(e)]
    if not running:
        raise LayoutError("选中的环境都没有运行，请先启动")

    positions = compute_positions(len(running), layout)
    results = []

    for env_id, pos in zip(running, positions):
        port = launcher.debug_port(env_id)
        if not port:
            results.append({"env": env_id, "ok": False, "error": "调试端口不可用"})
            continue

        targets = launcher.page_targets(port)
        if not targets:
            results.append({"env": env_id, "ok": False, "error": "找不到页面"})
            continue

        try:
            window_id = _window_for_target(port, targets[0]["id"])
            if window_id is None:
                results.append({"env": env_id, "ok": False, "error": "取窗口 id 失败"})
                continue

            if pos is None:
                # 最小化
                _set_bounds(port, window_id, 0, 0, 400, 300, state="minimized")
                results.append({"env": env_id, "ok": True, "action": "minimized"})
                continue

            left, top, w, h = pos
            # 先恢复普通状态再设位置，否则最小化状态下设坐标无效
            _set_bounds(port, window_id, left, top, w, h, state="normal")
            results.append({
                "env": env_id, "ok": True, "action": "moved",
                "bounds": {"left": left, "top": top, "width": w, "height": h},
            })
        except Exception as e:
            results.append({"env": env_id, "ok": False, "error": str(e)})

    return {
        "layout": layout,
        "count": len(running),
        "skipped": [e for e in env_ids if e not in running],
        "results": results,
    }
