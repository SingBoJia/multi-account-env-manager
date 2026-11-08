"""内核注册表 + Firefox 官方包下载。

对齐 AdsPower 的 browser_kernel_config{type, version} 模型：
- 内核按 type + version 并存；
- 环境只保存 type/version，启动时按版本解析可执行文件；
- Firefox 版本目录：kernels/firefox/<version>/extract/core/firefox.exe
- 兼容旧目录：kernels/firefox-<major>/extract/core/firefox.exe
"""

import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import threading
import urllib.request
from datetime import datetime

DEFAULT_FIREFOX_VERSION = "150.0"

# 官方 win64 en-US 安装包与 SHA256（来自 Mozilla archive 的 SHA256SUMS）
FIREFOX_CATALOG = {
    "147.0.4": {
        "url": "https://archive.mozilla.org/pub/firefox/releases/147.0.4/win64/en-US/Firefox%20Setup%20147.0.4.exe",
        "sha256": "e30d6091c17327599b50d2ac6012328e45a3ccfb113f42905e4539e4aefb7e52",
    },
    "150.0": {
        "url": "https://archive.mozilla.org/pub/firefox/releases/150.0/win64/en-US/Firefox%20Setup%20150.0.exe",
        "sha256": "7029e4b01635fcc24ca553a292af99d88ba11e502c45c12f1a4b9c10c3757076",
    },
    "151.0": {
        "url": "https://archive.mozilla.org/pub/firefox/releases/151.0/win64/en-US/Firefox%20Setup%20151.0.exe",
        "sha256": "358381238a840831da8a6cda16721692df91a74bc44847ff0285da12de788a8d",
    },
}


def _base_dir():
    if getattr(sys, "frozen", False):
        return pathlib.Path(sys.executable).resolve().parent
    return pathlib.Path(__file__).resolve().parent.parent


def kernel_root():
    """内核根目录：环境变量 > EXE/源码同级 > 上一级（dist 布局）。"""
    override = os.environ.get("TAOBAO_KERNEL_ROOT")
    if override:
        p = pathlib.Path(override).resolve()
        p.mkdir(parents=True, exist_ok=True)
        return p
    base = _base_dir()
    for c in (base / "kernels", base.parent / "kernels"):
        if c.exists():
            return c
    return base / "kernels"


def normalize_firefox_version(version):
    """147 -> 147.0.4（若目录只有该小版本）；150 -> 150.0；空值返回空。"""
    v = str(version or "").strip()
    if not v or v.lower() in ("firefox", "default", "system"):
        return ""
    if re.fullmatch(r"\d+", v):
        matches = [x for x in FIREFOX_CATALOG if x.split(".", 1)[0] == v]
        if len(matches) == 1:
            return matches[0]
        return v + ".0"
    return v


def _version_key(version):
    nums = [int(x) for x in re.findall(r"\d+", str(version))]
    return tuple(nums + [0] * (4 - len(nums)))[:4]


def firefox_install_dir(version):
    return kernel_root() / "firefox" / normalize_firefox_version(version) / "extract"


def _probe_core(base):
    for core in (pathlib.Path(base) / "extract" / "core", pathlib.Path(base) / "core"):
        exe = core / "firefox.exe"
        if exe.is_file():
            return core, exe
    return None, None


def _read_version(core_dir):
    ini = pathlib.Path(core_dir) / "application.ini"
    try:
        for line in ini.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.strip().startswith("Version="):
                return line.split("=", 1)[1].strip()
    except OSError:
        pass
    return ""


def installed_firefox_kernels():
    """返回 {version: {core, path}}，同时兼容新目录和旧 firefox-150 目录。"""
    root = kernel_root()
    out = {}
    for d in sorted(root.glob("firefox/*")):
        if not d.is_dir():
            continue
        core, exe = _probe_core(d)
        if not exe:
            continue
        version = _read_version(core) or normalize_firefox_version(d.name)
        out[version] = {"core": str(core), "path": str(exe), "source": "registry"}
    for d in sorted(root.glob("firefox-*")):
        if not d.is_dir():
            continue
        core, exe = _probe_core(d)
        if not exe:
            continue
        version = _read_version(core) or normalize_firefox_version(d.name.split("-", 1)[-1])
        out.setdefault(version, {"core": str(core), "path": str(exe), "source": "legacy"})
    return out


def resolve_firefox_kernel(version=None):
    """按版本解析 firefox.exe；未指定版本时取已安装的最高版本。"""
    v = normalize_firefox_version(version)
    installed = installed_firefox_kernels()
    if v:
        item = installed.get(v)
        if item:
            return pathlib.Path(item["path"])
        major = v.split(".")[0]
        candidates = [
            kernel_root() / "firefox" / v,
            kernel_root() / ("firefox-" + v),
            kernel_root() / ("firefox-" + major),
        ]
        for base in candidates:
            _core, exe = _probe_core(base)
            if exe:
                return exe
        return None
    if installed:
        latest = sorted(installed.keys(), key=_version_key, reverse=True)[0]
        return pathlib.Path(installed[latest]["path"])
    # 最后兜底旧的 150 目录
    _core, exe = _probe_core(kernel_root() / "firefox-150")
    return exe


def _chrome_version(chrome_path):
    try:
        app_dir = pathlib.Path(chrome_path).parent
        versions = [
            d.name for d in app_dir.iterdir()
            if d.is_dir() and re.match(r"^\d+\.", d.name)
        ]
        if not versions:
            return ""
        versions.sort(key=lambda s: [int(x) for x in re.findall(r"\d+", s)])
        return versions[-1]
    except OSError:
        return ""


def _find_7z():
    candidates = [
        shutil.which("7z"),
        str(pathlib.Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "7-Zip" / "7z.exe"),
        str(pathlib.Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "7-Zip" / "7z.exe"),
        str(pathlib.Path.home() / "scoop" / "shims" / "7z.exe"),
    ]
    for c in candidates:
        if c and pathlib.Path(c).is_file():
            return c
    return None


def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class KernelManager:

    def __init__(self, chrome_path=None):
        self.chrome_path = chrome_path
        self._lock = threading.RLock()
        self._job = {
            "state": "idle",
            "progress": 0,
            "message": "",
            "error": "",
            "startedAt": "",
            "finishedAt": "",
            "path": "",
            "version": "",
            "type": "",
        }
        self._thread = None

    # ---------- 状态 ----------

    def status(self):
        items = []
        installed = installed_firefox_kernels()
        for v in sorted(installed.keys(), key=_version_key, reverse=True):
            items.append({
                "id": "firefox-" + v,
                "name": "Firefox " + v,
                "type": "firefox",
                "version": v,
                "kernelVersion": v,
                "installed": True,
                "downloadable": True,
                "path": installed[v]["path"],
            })
        for v in sorted(FIREFOX_CATALOG.keys(), key=_version_key, reverse=True):
            if v in installed:
                continue
            target = firefox_install_dir(v) / "core" / "firefox.exe"
            items.append({
                "id": "firefox-" + v,
                "name": "Firefox " + v,
                "type": "firefox",
                "version": v,
                "kernelVersion": v,
                "installed": False,
                "downloadable": True,
                "path": str(target),
            })

        chrome = pathlib.Path(self.chrome_path) if self.chrome_path else None
        chrome_version = _chrome_version(chrome) if chrome and chrome.is_file() else ""
        items.append({
            "id": "chrome-system",
            "name": "本地 Google Chrome",
            "type": "chrome",
            "version": chrome_version or "system",
            "kernelVersion": "system",
            "installed": bool(chrome and chrome.is_file()),
            "downloadable": False,
            "path": str(chrome) if chrome else "",
        })
        return items

    def job(self):
        with self._lock:
            return dict(self._job)

    # ---------- 下载任务 ----------

    def start_download(self, kernel_type="firefox", version=DEFAULT_FIREFOX_VERSION):
        kernel_type = str(kernel_type or "firefox").lower()
        version = normalize_firefox_version(version) or DEFAULT_FIREFOX_VERSION
        if kernel_type != "firefox":
            return {"started": False, "message": "目前只支持下载 Firefox 内核", "job": self.job()}
        if version not in FIREFOX_CATALOG:
            return {
                "started": False,
                "message": "不支持的 Firefox 版本：%s（可选：%s）" % (
                    version, ", ".join(sorted(FIREFOX_CATALOG))),
                "job": self.job(),
            }
        if version in installed_firefox_kernels():
            return {"started": False, "message": "Firefox %s 已安装" % version, "job": self.job()}
        with self._lock:
            if self._job.get("state") in ("downloading", "verifying", "extracting"):
                return {"started": False, "message": "下载任务已在运行", "job": dict(self._job)}
            self._job = {
                "state": "downloading",
                "progress": 0,
                "message": "准备下载 Firefox %s…" % version,
                "error": "",
                "startedAt": _now(),
                "finishedAt": "",
                "path": "",
                "version": version,
                "type": "firefox",
            }
            self._thread = threading.Thread(target=self._run, args=(version,), daemon=True)
            self._thread.start()
            return {"started": True, "message": "已开始下载 Firefox %s" % version, "job": dict(self._job)}

    def _set(self, **kw):
        with self._lock:
            self._job.update(kw)

    def _run(self, version):
        try:
            meta = FIREFOX_CATALOG[version]
            root = kernel_root()
            cache = root / ".cache"
            cache.mkdir(parents=True, exist_ok=True)
            installer = cache / ("Firefox Setup %s.exe" % version)

            expected = meta["sha256"].lower()
            if installer.is_file() and self._sha256(installer) == expected:
                self._set(progress=68, message="本地安装包已存在且校验通过")
            else:
                self._download(installer, meta["url"], version)

            self._set(state="verifying", progress=72, message="校验 Firefox %s SHA256…" % version)
            actual = self._sha256(installer)
            if actual != expected:
                raise RuntimeError("SHA256 不匹配：期望 %s…，实际 %s…" % (expected[:12], actual[:12]))

            target = firefox_install_dir(version)
            core = target / "core"
            if not (core / "firefox.exe").is_file():
                self._set(state="extracting", progress=78, message="解压 Firefox %s…" % version)
                self._extract(installer, target)

            exe = core / "firefox.exe"
            if not exe.is_file():
                raise RuntimeError("解压完成但没有找到 core/firefox.exe")
            actual_version = _read_version(core) or version
            if actual_version != version:
                raise RuntimeError("安装版本不一致：期望 %s，实际 %s" % (version, actual_version))
            self._set(
                state="done",
                progress=100,
                message="Firefox %s 安装完成" % actual_version,
                finishedAt=_now(),
                path=str(exe),
                version=actual_version,
            )
        except Exception as e:
            self._set(
                state="error",
                message="安装失败",
                error=str(e),
                finishedAt=_now(),
            )

    def _download(self, installer, url, version):
        self._set(state="downloading", progress=0, message="连接 Mozilla 下载 Firefox %s…" % version)
        req = urllib.request.Request(url, headers={"User-Agent": "taobao-env/1.0"})
        tmp = installer.with_suffix(installer.suffix + ".part")
        with urllib.request.urlopen(req, timeout=60) as resp, open(tmp, "wb") as f:
            total = int(resp.headers.get("Content-Length") or 0)
            done = 0
            while True:
                chunk = resp.read(1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                done += len(chunk)
                if total:
                    pct = min(68, int(done * 68 / total))
                    self._set(
                        progress=pct,
                        message="下载 Firefox %s：%d%%" % (version, int(done * 100 / total)),
                    )
        os.replace(str(tmp), str(installer))

    def _extract(self, installer, target):
        seven = _find_7z()
        if not seven:
            raise RuntimeError("未找到 7-Zip（7z.exe），无法解压 Firefox 安装包")
        target.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            [seven, "x", "-y", "-o" + str(target), str(installer)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=600,
            creationflags=0x08000000 if os.name == "nt" else 0,
        )
        if proc.returncode not in (0, 1):
            text = (proc.stdout or b"").decode("utf-8", "replace")[-400:]
            raise RuntimeError("7-Zip 解压失败（%s）：%s" % (proc.returncode, text))
        self._set(progress=94, message="解压完成，检查内核文件…")

    @staticmethod
    def _sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
