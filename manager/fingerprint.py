"""指纹引擎：为每个环境生成一次随机指纹，永久复用。

设计原则：
1. 持久稳定 —— 同一环境每次启动指纹必须一致，随机变化本身就是异常信号。
2. 内部自洽 —— 屏幕分辨率 / DPR / 时区 / 语言 / UA 版本必须互相匹配。
3. 结构安全 —— 指纹库固定在本模块同级的唯一文件，环境编号仅作字典键，不参与路径构造。
"""

import functools
import hashlib
import json
import pathlib
import re
import secrets
import sys
import threading
import time

from .paths import atomic_write_text as _atomic_write
from .paths import data_file as _data_file

ENV_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# 指纹结构版本：新增维度时递增，旧数据会自动补齐
CURRENT_VERSION = 5

# WebGPU 适配器信息，必须与 WebGL 的 GPU 厂商一致，否则两者矛盾会被识破
_WEBGPU_VENDOR = {
    "nvidia": "nvidia",
    "amd": "amd",
    "intel": "intel",
}
_WEBGPU_ARCH = {
    "nvidia": "ampere",
    "amd": "rdna-2",
    "intel": "gen-12lp",
}

# 固定存储位置：与本模块同级，不接受任何外部路径输入
STORE_FILE = _data_file("fingerprints.json")

# 指纹库读改写串行锁：Flask 多线程下并发写会互相覆盖（可重入，clone 内部会调 get）
_STORE_LOCK = threading.RLock()


def _locked(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        with _STORE_LOCK:
            return fn(*args, **kwargs)
    return wrapper


class _Stream:
    """由密码学哈希派生的确定性字节流，用于候选池抽样。"""

    def __init__(self, salt):
        self._salt = str(salt).encode("utf-8")
        self._counter = 0
        self._buf = b""

    def _refill(self):
        block = hashlib.sha256(self._salt + b":" + str(self._counter).encode("ascii")).digest()
        self._counter += 1
        self._buf += block

    def take(self, n):
        while len(self._buf) < n:
            self._refill()
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def below(self, bound):
        """返回 [0, bound) 内的确定性整数。

        小范围用单字节拒绝采样消除取模偏差；大范围直接用 8 字节取模
        （偏差小到可忽略，且不会因 limit 计算产生死循环）。
        """
        if bound <= 0:
            raise ValueError("bound must be positive")
        if bound == 1:
            return 0
        if bound > 256:
            return int.from_bytes(self.take(8), "big") % bound
        limit = 256 - (256 % bound)
        while True:
            b = self.take(1)[0]
            if b < limit:
                return b % bound

    def pick(self, seq):
        return seq[self.below(len(seq))]

    def unit(self):
        return int.from_bytes(self.take(8), "big") / float(1 << 64)


class FingerprintEngine:

    # 分辨率池按真实市场分布加权：1920x1080 占多数，其余分散。
    # 池子足够大才能让多个环境的「分辨率组合」不撞车。
    RESOLUTIONS = [
        (1920, 1080), (1920, 1080), (1920, 1080),
        (2560, 1440), (1366, 768), (1536, 864),
        (1600, 900), (1680, 1050), (1440, 900),
        (2560, 1600), (3840, 2160), (1280, 720),
        (1920, 1200), (2560, 1080), (3440, 1440),
        (2880, 1800), (3840, 1600), (2256, 1504),
        (2736, 1824), (2880, 1920), (2304, 1440),
        (2160, 1440), (1600, 1200), (1280, 1024),
        (1360, 768), (1400, 1050), (1920, 1080),
    ]

    DPR_BY_WIDTH = {
        1280: [1], 1360: [1], 1366: [1], 1400: [1],
        1440: [1], 1536: [1, 1.25], 1600: [1, 1.25],
        1680: [1], 1920: [1, 1.25, 1.5],
        2160: [1.25, 1.5], 2256: [1.5], 2304: [1.25, 1.5],
        2560: [1, 1.25, 1.5], 2736: [1.5], 2880: [1.5, 2],
        3440: [1, 1.25], 3840: [1.5, 2],
    }

    # 核心数覆盖常见的真实 CPU 配置
    CORES = [2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 12, 14, 16, 16, 20, 24, 32]
    MEMORY = [2, 4, 4, 8, 8, 8, 12, 16, 16, 16, 24, 32, 32, 64]

    # 核心数与内存的合理搭配，避免出现现实中不存在的配置（如 8 核 / 2G）
    MEMORY_BY_CORES = {
        2: [2, 4, 8],
        4: [4, 8, 8, 16],
        6: [8, 16, 16],
        8: [8, 16, 16, 32],
        10: [16, 16, 32],
        12: [16, 16, 32, 32],
        14: [16, 32],
        16: [16, 32, 32, 64],
        20: [32, 64],
        24: [32, 64, 64],
        32: [32, 64, 64],
    }

    LANGUAGES = [
        ("zh-CN", ["zh-CN", "zh"]),
        ("zh-CN", ["zh-CN", "zh", "en"]),
        ("zh-CN", ["zh-CN", "zh", "en-US", "en"]),
        ("zh-CN", ["zh-CN", "zh-Hans", "zh", "en"]),
        ("zh-CN", ["zh-CN", "zh", "en-GB", "en"]),
        ("zh-CN", ["zh-CN"]),
    ]

    GPUS = [
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)", "nvidia"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Direct3D11 vs_5_0 ps_5_0, D3D11)", "nvidia"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 4060 Ti Direct3D11 vs_5_0 ps_5_0, D3D11)", "nvidia"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3070 Direct3D11 vs_5_0 ps_5_0, D3D11)", "nvidia"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3080 Direct3D11 vs_5_0 ps_5_0, D3D11)", "nvidia"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)", "nvidia"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1650 Direct3D11 vs_5_0 ps_5_0, D3D11)", "nvidia"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 2060 Direct3D11 vs_5_0 ps_5_0, D3D11)", "nvidia"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce MX250 Direct3D11 vs_5_0 ps_5_0, D3D11)", "nvidia"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6600 Direct3D11 vs_5_0 ps_5_0, D3D11)", "amd"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 580 Series Direct3D11 vs_5_0 ps_5_0, D3D11)", "amd"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)", "amd"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon Vega 8 Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)", "amd"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)", "intel"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics 620 Direct3D11 vs_5_0 ps_5_0, D3D11)", "intel"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) Iris(R) Xe Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)", "intel"),
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) Arc(TM) A750 Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)", "intel"),
    ]

    CHROME_VERSIONS = [
        "128.0.0.0", "129.0.0.0", "130.0.0.0", "131.0.0.0",
        "132.0.0.0", "133.0.0.0", "134.0.0.0", "135.0.0.0",
        "136.0.0.0",
    ]
    TIMEZONES = ["Asia/Shanghai"]

    def __init__(self, store_dir=None):
        # 存储位置固定为模块同级 fingerprints.json；
        # store_dir 仅为兼容调用方签名而保留，不参与任何路径构造。
        self.store_dir = str(STORE_FILE.parent)

    # ---------- 读取与写入 ----------

    @staticmethod
    def _read_all():
        if not STORE_FILE.exists():
            return {}
        try:
            data = json.loads(STORE_FILE.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("顶层不是 JSON 对象")
            return data
        except (json.JSONDecodeError, ValueError):
            # 内容损坏：先把坏文件改名保留（唯一可恢复的线索），再当空数据用
            try:
                stamp = time.strftime("%Y%m%d-%H%M%S")
                STORE_FILE.replace(STORE_FILE.with_name(
                    STORE_FILE.name + ".corrupt-" + stamp))
                print("[fingerprint] fingerprints.json 内容损坏，已改名保留为 .corrupt-%s" % stamp,
                      file=sys.stderr, flush=True)
            except OSError:
                pass
            return {}
        except OSError:
            return {}

    @staticmethod
    def _write_all(data):
        _atomic_write(STORE_FILE, json.dumps(data, ensure_ascii=False, indent=2))

    # ---------- 对外接口 ----------

    @_locked
    def load_or_create(self, env_id):
        self._validate_id(env_id)
        data = self._read_all()
        existing = data.get(env_id)
        if self._is_valid(existing):
            # 旧版本指纹缺少新维度字段，就地补齐（保持原有身份不变）
            upgraded = self._upgrade(existing)
            if upgraded is not existing:
                data[env_id] = upgraded
                self._write_all(data)
            return upgraded
        fp = self._generate_unique(env_id, data)
        data[env_id] = fp
        self._write_all(data)
        return fp

    def _generate_unique(self, env_id, existing_data, attempts=40):
        """生成指纹时尽量避开已有环境的「设备画像组合」。

        单个维度取值再多，组合撞车的概率也不低。这里以
        「分辨率 + 核心数 + 内存 + 显卡」作为设备画像签名，
        重试直到与所有现有环境都不同（最多 attempts 次）。
        """
        signatures = set()
        for other_id, fp in existing_data.items():
            if other_id == env_id or not isinstance(fp, dict):
                continue
            sig = self._profile_sig(fp)
            if sig:
                signatures.add(sig)

        candidate = None
        for i in range(attempts):
            token = "u%d" % i if i else None
            candidate = self.generate(env_id, rotate_token=token)
            if self._profile_sig(candidate) not in signatures:
                return candidate
        # 池子耗尽时退回最后一次结果，不阻断创建
        return candidate

    @staticmethod
    def _profile_sig(fp):
        """设备画像签名：这四项组合是平台最容易用来关联的强信号。"""
        try:
            return (
                fp["screen"]["width"], fp["screen"]["height"], fp["screen"]["dpr"],
                fp["hardware"]["cores"], fp["hardware"]["memory"],
                fp["gpu"]["renderer"], fp["ua"]["userAgent"],
            )
        except (KeyError, TypeError):
            return None

    def _upgrade(self, fp):
        """给旧版指纹补齐新增字段，已有字段一律不动，保证设备身份稳定。"""
        if not isinstance(fp, dict):
            return fp
        changed = False
        s = _Stream("%s|upgrade-v2" % fp.get("envId", "env"))
        gpu = fp.setdefault("gpu", {})
        for key, choices in (
            ("maxTextureSize", [8192, 16384, 32768]),
            ("maxViewport", [16384, 32768]),
            ("maxRenderbuffer", [16384, 32768]),
            ("maxVertexAttribs", [16, 16, 32]),
        ):
            if key not in gpu:
                gpu[key] = s.pick(choices)
                changed = True

        canvas = fp.setdefault("canvas", {})
        if "textNoise" not in canvas:
            canvas["textNoise"] = s.below(1000000) + 1
            changed = True

        audio = fp.setdefault("audio", {})
        if "sampleRate" not in audio:
            audio["sampleRate"] = s.pick([44100, 48000])
            changed = True

        if "fonts" not in fp:
            fp["fonts"] = {
                "extra": s.pick([[], ["Cambria"], ["Calibri", "Cambria"], ["Consolas"],
                                 ["Segoe UI"], ["Tahoma"], ["Georgia", "Verdana"], ["Arial Narrow"]]),
                "missing": s.pick([[], ["Comic Sans MS"], ["Wingdings"], ["Garamond"]]),
            }
            changed = True

        # UA-CH 高熵字段：老指纹补齐，CDP override 与 JS 兜底共用
        ua = fp.setdefault("ua", {})
        for _key, _value in (
            ("platformVersion", "13.0.0"),
            ("architecture", "x86"),
            ("bitness", "64"),
        ):
            if _key not in ua:
                ua[_key] = _value
                changed = True
        if "fullVersion" not in ua:
            _major = (ua.get("userAgent") or "").split("Chrome/")[-1].split(" ")[0].split(".")[0]
            if _major:
                ua["fullVersion"] = "%s.0.0.0" % _major
                ua["fullVersionList"] = [
                    {"brand": "Chromium", "version": "%s.0.0.0" % _major},
                    {"brand": "Google Chrome", "version": "%s.0.0.0" % _major},
                    {"brand": "Not_A Brand", "version": "24"},
                ]
                changed = True

        if "media" not in fp:
            fp["media"] = {
                "audioInputs": s.pick([0, 1, 1, 2]),
                "audioOutputs": s.pick([1, 1, 2]),
                "videoInputs": s.pick([0, 0, 1]),
                "labelsHide": True,
            }
            changed = True

        if "clientRects" not in fp:
            fp["clientRects"] = {
                "enabled": True,
                "noise": (s.below(1000) + 1) / 100000.0,
            }
            changed = True

        if "webrtc" not in fp:
            fp["webrtc"] = {"mode": s.pick(["proxy", "proxy", "disabled"])}
            changed = True

        if "portScan" not in fp:
            fp["portScan"] = {"protect": True}
            changed = True

        if "storage" not in fp:
            fp["storage"] = {"quotaGB": s.pick([80, 120, 160, 200, 256, 320, 400, 512, 640, 800, 1000, 1200])}
            changed = True

        if "webgpu" not in fp:
            family = (fp.get("gpu") or {}).get("family", "intel")
            fp["webgpu"] = {
                "enabled": True,
                "vendor": _WEBGPU_VENDOR.get(family, "intel"),
                "architecture": _WEBGPU_ARCH.get(family, "gen-12lp"),
                "device": "",
                "description": "",
                "fallbackAdapter": False,
            }
            changed = True

        if "plugins" not in fp:
            fp["plugins"] = {
                "enabled": True,
                "count": s.pick([5, 5, 5, 3, 4]),
                "names": [
                    "PDF Viewer",
                    "Chrome PDF Viewer",
                    "Chromium PDF Viewer",
                    "Microsoft Edge PDF Viewer",
                    "WebKit built-in PDF",
                ],
            }
            changed = True

        if changed and fp.get("version") != CURRENT_VERSION:
            fp["version"] = CURRENT_VERSION
        return fp

    @_locked
    def get(self, env_id):
        self._validate_id(env_id)
        data = self._read_all()
        fp = data.get(env_id)
        if not self._is_valid(fp):
            return fp
        upgraded = self._upgrade(fp)
        if upgraded != fp:
            data[env_id] = upgraded
            self._write_all(data)
        return upgraded

    @_locked
    def clone(self, source_id, target_id, vary=True):
        """把 source 的指纹复制给 target。

        vary=True 时对噪声种子做偏移，让两个环境的 Canvas/Audio 指纹不同，
        但屏幕、硬件、GPU 等「用户可感知的一致性维度」保持一致。
        """
        self._validate_id(source_id)
        self._validate_id(target_id)
        src = self.get(source_id)
        if not src:
            raise ValueError("源环境指纹不存在")

        cloned = json.loads(json.dumps(src, ensure_ascii=False))
        cloned["envId"] = target_id

        if vary:
            s = _Stream("%s|clone" % target_id)
            cloned["canvas"]["noise"] = s.below(1000000) + 1
            cloned["canvas"]["textNoise"] = s.below(1000000) + 1
            cloned["audio"]["noise"] = round(s.unit() * 0.01 + 0.0001, 6)
            cloned["gpu"]["webglNoise"] = s.below(1000000) + 1
            cloned["clientRects"]["noise"] = (s.below(1000) + 1) / 100000.0

        self.save(target_id, cloned)
        return cloned

    def compare(self, env_ids):
        """对比多个环境的指纹，标出相同的维度（用于检查关联风险）。"""
        fps = []
        for env_id in env_ids:
            fp = self.get(env_id)
            if fp:
                fps.append((env_id, fp))
        if len(fps) < 2:
            return {"error": "至少需要两个环境"}

        def sig(fp, path):
            cur = fp
            for k in path:
                if not isinstance(cur, dict) or k not in cur:
                    return None
                cur = cur[k]
            return json.dumps(cur, sort_keys=True, ensure_ascii=False) if isinstance(cur, (dict, list)) else cur

        dims = [
            ("屏幕分辨率", ("screen", "width"), ("screen", "height")),
            ("像素比", ("screen", "dpr"),),
            ("CPU 核心", ("hardware", "cores"),),
            ("设备内存", ("hardware", "memory"),),
            ("显卡型号", ("gpu", "renderer"),),
            ("Canvas 噪声", ("canvas", "noise"),),
            ("音频噪声", ("audio", "noise"),),
            ("音频采样率", ("audio", "sampleRate"),),
            ("语言", ("locale", "language"),),
            ("时区", ("locale", "timezone"),),
            ("UA", ("ua", "userAgent"),),
            ("WebGL 纹理上限", ("gpu", "maxTextureSize"),),
            ("WebRTC 模式", ("webrtc", "mode"),),
            ("存储配额", ("storage", "quotaGB"),),
            ("ClientRects 噪声", ("clientRects", "noise"),),
        ]

        rows = []
        for label, *paths in dims:
            values = []
            for env_id, fp in fps:
                parts = [str(sig(fp, p)) for p in paths]
                values.append("/".join(parts))
            unique = len(set(values))
            rows.append({
                "dimension": label,
                "values": values,
                "unique": unique,
                "same": unique < len(values),
            })
        return {"envs": [e for e, _ in fps], "rows": rows}

    @_locked
    def save(self, env_id, fp):
        self._validate_id(env_id)
        data = self._read_all()
        data[env_id] = fp
        self._write_all(data)

    @_locked
    def regenerate(self, env_id):
        """强制重新生成（会改变该环境的设备身份）。

        rotate_token 必须每次不同，否则同样的环境数会产出
        完全相同的「随机」指纹（之前踩过的坑）。
        同时避开其他环境的设备画像，防止撞车。
        """
        self._validate_id(env_id)
        data = self._read_all()
        existing = {k: v for k, v in data.items() if k != env_id}
        other_sigs = set()
        for v in existing.values():
            if isinstance(v, dict):
                sig = self._profile_sig(v)
                if sig:
                    other_sigs.add(sig)

        fp = None
        for attempt in range(40):
            token = secrets.token_hex(16) + "|" + str(attempt)
            candidate = self.generate(env_id, rotate_token=token)
            sig = self._profile_sig(candidate)
            if not sig or sig not in other_sigs:
                fp = candidate
                break
        if fp is None:
            fp = self.generate(env_id, rotate_token=secrets.token_hex(16))
        data[env_id] = fp
        self._write_all(data)
        return fp

    @_locked
    def delete(self, env_id):
        self._validate_id(env_id)
        data = self._read_all()
        data.pop(env_id, None)
        self._write_all(data)

    @_locked
    def all(self):
        data = dict(self._read_all())
        changed = False
        for env_id, fp in list(data.items()):
            if not self._is_valid(fp):
                continue
            upgraded = self._upgrade(fp)
            if upgraded != fp:
                data[env_id] = upgraded
                changed = True
        if changed:
            self._write_all(data)
        return data

    # ---------- 生成 ----------

    def generate(self, env_id, rotate_token=None):
        self._validate_id(env_id)
        salt = "%s|%s" % (env_id, rotate_token if rotate_token else "stable")
        s = _Stream(salt)

        width, height = s.pick(self.RESOLUTIONS)
        dpr = s.pick(self.DPR_BY_WIDTH.get(width, [1]))
        lang_code, lang_list = s.pick(self.LANGUAGES)
        vendor, renderer, gpu_family = s.pick(self.GPUS)
        chrome_ver = s.pick(self.CHROME_VERSIONS)
        major = chrome_ver.split(".")[0]

        cores = s.pick(self.CORES)
        # 内存必须与核心数匹配：真实机器不存在「8 核 + 2G」这种组合
        mem_pool = self.MEMORY_BY_CORES.get(cores, [8, 16])
        memory = s.pick(mem_pool)

        return {
            "version": CURRENT_VERSION,
            "envId": str(env_id),
            "screen": {
                "width": width,
                "height": height,
                "availHeight": height - s.pick([40, 48, 60]),
                "dpr": dpr,
            },
            "hardware": {"cores": cores, "memory": memory},
            "gpu": {
                "vendor": vendor,
                "renderer": renderer,
                "family": gpu_family,
                "webglNoise": s.below(1000000) + 1,
                # WebGL 参数微扰：让 getParameter 返回的常量带个体差异
                "maxTextureSize": s.pick([8192, 16384, 16384, 32768]),
                # MAX_VIEWPORT_DIMS 真实返回 Int32Array 二元组 [宽上限, 高上限]
                "maxViewport": [s.pick([16384, 32768])] * 2,
                "maxRenderbuffer": s.pick([8192, 16384, 16384, 32768]),
                "maxVertexAttribs": s.pick([16, 16, 32]),
            },
            "canvas": {
                "noise": s.below(1000000) + 1,
                "mode": "random",
                # 第二组噪声用于 fillText 场景，比单纯改像素更难被去噪
                "textNoise": s.below(1000000) + 1,
            },
            "audio": {
                "noise": round(s.unit() * 0.01 + 0.0001, 6),
                "mode": "random",
                "sampleRate": s.pick([44100, 48000]),
            },
            "fonts": {
                # 每个环境随机挑选可用字体子集，制造字体枚举差异
                "extra": s.pick([
                    [], ["Cambria"], ["Calibri", "Cambria"],
                    ["Consolas"], ["Segoe UI"], ["Tahoma"],
                    ["Georgia", "Verdana"], ["Arial Narrow"],
                ]),
                "missing": s.pick([
                    [], ["Comic Sans MS"], ["Wingdings"], ["Garamond"],
                ]),
            },
            "media": {
                # 摄像头 / 麦克风 / 扬声器枚举数量与标签
                "audioInputs": s.pick([0, 1, 1, 2]),
                "audioOutputs": s.pick([1, 1, 2]),
                "videoInputs": s.pick([0, 0, 1]),
                "labelsHide": True,
            },
            "locale": {
                "language": lang_code,
                "languages": lang_list,
                "timezone": s.pick(self.TIMEZONES),
            },
            "ua": {
                "userAgent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/%s Safari/537.36" % chrome_ver
                ),
                "platform": "Win32",
                "brands": [
                    {"brand": "Chromium", "version": major},
                    {"brand": "Google Chrome", "version": major},
                    {"brand": "Not_A Brand", "version": "24"},
                ],
                # UA-CH 高熵字段：CDP override 与 JS 兜底共用同一来源，
                # 必须与 UA 字符串（NT 10.0 / x64）一致，否则服务端比对即穿帮
                "platformVersion": "13.0.0",
                "architecture": "x86",
                "bitness": "64",
                "fullVersion": "%s.0.0.0" % major,
                "fullVersionList": [
                    {"brand": "Chromium", "version": "%s.0.0.0" % major},
                    {"brand": "Google Chrome", "version": "%s.0.0.0" % major},
                    {"brand": "Not_A Brand", "version": "24"},
                ],
            },
            "misc": {
                "doNotTrack": s.pick([None, None, "1"]),
                "colorDepth": 24,
                "pixelDepth": 24,
                "touchPoints": 0,
            },
            # ClientRects 噪声：元素布局矩形的亚像素抖动，是常见指纹源
            "clientRects": {
                "enabled": True,
                "noise": (s.below(1000) + 1) / 100000.0,
            },
            # WebRTC 策略：disabled=完全关闭 / proxy=强制 relay / real=真实
            "webrtc": {"mode": s.pick(["proxy", "proxy", "disabled"])},
            # WebGPU：与 GPU 厂商保持一致的适配器信息（Chrome 113+ 新增指纹面）
            "webgpu": {
                "enabled": True,
                "vendor": _WEBGPU_VENDOR.get(gpu_family, "intel"),
                "architecture": _WEBGPU_ARCH.get(gpu_family, "gen-12lp"),
                "device": "",
                "description": "",
                "fallbackAdapter": False,
            },
            # 端口扫描防护：阻断对本地端口的探测
            "portScan": {"protect": True},
            # 插件列表：现代 Chrome 已固定为 5 个内置 PDF 插件，各环境随机裁剪
            "plugins": {
                "enabled": True,
                "count": s.pick([5, 5, 5, 3, 4]),
                "names": [
                    "PDF Viewer",
                    "Chrome PDF Viewer",
                    "Chromium PDF Viewer",
                    "Microsoft Edge PDF Viewer",
                    "WebKit built-in PDF",
                ],
            },
            # 存储配额：每环境不同，取值分散避免撞车
            "storage": {"quotaGB": s.pick([80, 120, 160, 200, 256, 320, 400, 512, 640, 800, 1000, 1200])},
        }

    def build_inject_script(self, fp, title_prefix=""):
        """生成注入脚本。title_prefix 用于在浏览器标签页上显示环境名。"""
        payload = json.dumps(fp, ensure_ascii=False)
        script = INJECT_TEMPLATE.replace("__FP_PAYLOAD__", payload)
        if title_prefix:
            tag = json.dumps(str(title_prefix), ensure_ascii=False)
            block = _TITLE_LOCK_JS.replace("__TITLE_PREFIX__", tag)
            script = script.replace("__TITLE_LOCK__", block)
        else:
            script = script.replace("__TITLE_LOCK__", "")
        return script

    def user_agent_override(self, fp):
        """CDP Network.setUserAgentOverride 的参数。

        此前只改了 --user-agent 字符串：服务端比对 UA 头与 Sec-CH-UA 头、
        JS 读 getHighEntropyValues 即可识破。这里把 Sec-CH-UA 系列请求头
        与高熵值一并改成与伪装 UA 同源的值。
        """
        ua = fp.get("ua") or {}
        agent = ua.get("userAgent") or ""
        major = agent.split("Chrome/")[-1].split(" ")[0].split(".")[0] or "135"
        brands = [
            {"brand": b.get("brand"), "version": b.get("version")}
            for b in (ua.get("brands") or [])
        ] or [
            {"brand": "Chromium", "version": major},
            {"brand": "Google Chrome", "version": major},
            {"brand": "Not_A Brand", "version": "24"},
        ]
        full = ua.get("fullVersion") or ("%s.0.0.0" % major)
        full_list = ua.get("fullVersionList") or [
            {"brand": b["brand"], "version": full} for b in brands
        ]
        langs = (fp.get("locale") or {}).get("languages") or ["zh-CN"]
        q = []
        for i, lang in enumerate(langs):
            q.append(lang if i == 0 else "%s;q=0.%d" % (lang, max(1, 9 - i)))
        return {
            "userAgent": agent,
            "acceptLanguage": ",".join(q),
            "userAgentMetadata": {
                "brands": brands,
                "fullVersionList": full_list,
                "fullVersion": full,
                "platform": "Windows",
                "platformVersion": ua.get("platformVersion") or "13.0.0",
                "architecture": ua.get("architecture") or "x86",
                "bitness": ua.get("bitness") or "64",
                "model": "",
                "mobile": False,
                "wow64": False,
            },
        }

    # ---------- 内部 ----------

    @staticmethod
    def _validate_id(env_id):
        if not isinstance(env_id, str) or not ENV_ID_PATTERN.match(env_id):
            raise ValueError("非法环境编号")

    @staticmethod
    def _is_valid(data):
        # 版本号随维度扩充递增（当前 5），只要结构可识别即有效；
        # 旧版本字段由 _upgrade 自动补齐。之前固定检查 version==1，
        # 导致新版本指纹被判无效、每次加载都回退到 stable 确定性输出。
        return (
            isinstance(data, dict)
            and isinstance(data.get("version"), int)
            and data["version"] >= 1
            and "screen" in data
        )


INJECT_TEMPLATE = r"""
(function () {
  'use strict';
  var FP = __FP_PAYLOAD__;
  // 幂等标记：脚本可能在同一文档被执行两次（attach 时 evaluate 立即伪装 +
  // 后续重连时重放），重复包装会叠加噪声反而暴露。键名按环境噪声派生、
  // 不可枚举，常规遍历与已知标记名探测都不可见。
  var _fpKey = '__fp' + (FP.canvas && FP.canvas.noise ? (FP.canvas.noise % 9973) : 0);
  if (Object.getOwnPropertyDescriptor(window, _fpKey)) { return; }
  Object.defineProperty(window, _fpKey, {
    value: 1, enumerable: false, configurable: false, writable: false
  });

__TITLE_LOCK__

  var nativeToString = Function.prototype.toString;
  var patched = new WeakSet();
  var fakeToString = function () {
    if (patched.has(this)) {
      return 'function ' + (this.name || '') + '() { [native code] }';
    }
    return nativeToString.apply(this, arguments);
  };
  Function.prototype.toString = fakeToString;
  patched.add(fakeToString);

  function defineGetter(obj, prop, value) {
    try {
      var d = Object.getOwnPropertyDescriptor(obj, prop);
      var getter = function () { return value; };
      Object.defineProperty(obj, prop, {
        get: getter,
        configurable: d ? d.configurable : true,
        enumerable: d ? d.enumerable : true
      });
      patched.add(getter);
    } catch (e) {}
  }

  var s = FP.screen;
  defineGetter(window.screen, 'width', s.width);
  defineGetter(window.screen, 'height', s.height);
  defineGetter(window.screen, 'availWidth', s.width);
  defineGetter(window.screen, 'availHeight', s.availHeight);
  defineGetter(window.screen, 'colorDepth', FP.misc.colorDepth);
  defineGetter(window.screen, 'pixelDepth', FP.misc.pixelDepth);
  defineGetter(window, 'devicePixelRatio', s.dpr);

  defineGetter(navigator, 'hardwareConcurrency', FP.hardware.cores);
  // Device Memory API 规范钳制 ≤8：真实 32G/64G 机器也只报 8，
  // 注入 12/24 这类值一行检测即穿帮
  defineGetter(navigator, 'deviceMemory', Math.min(FP.hardware.memory, 8));
  defineGetter(navigator, 'platform', FP.ua.platform);
  defineGetter(navigator, 'language', FP.locale.language);
  Object.defineProperty(navigator, 'languages', {
    get: function () { return Object.freeze(FP.locale.languages.slice()); },
    configurable: true
  });
  defineGetter(navigator, 'doNotTrack', FP.misc.doNotTrack);
  defineGetter(navigator, 'maxTouchPoints', FP.misc.touchPoints);
  defineGetter(navigator, 'webdriver', false);

  if (navigator.userAgentData) {
    try {
      Object.defineProperty(navigator.userAgentData, 'brands', {
        get: function () {
          return FP.ua.brands.map(function (b) { return { brand: b.brand, version: b.version }; });
        },
        configurable: true
      });
      Object.defineProperty(navigator.userAgentData, 'mobile', {
        get: function () { return false; }, configurable: true
      });
      Object.defineProperty(navigator.userAgentData, 'platform', {
        get: function () { return 'Windows'; }, configurable: true
      });
      // UA-CH 高熵值兜底：CDP override 正常时两者本就一致，这里防 override 缺席
      if (typeof navigator.userAgentData.getHighEntropyValues === 'function') {
        var origGEHV = navigator.userAgentData.getHighEntropyValues.bind(navigator.userAgentData);
        var wrappedGEHV = function (hints) {
          return origGEHV.apply(navigator.userAgentData, arguments).then(function (v) {
            try {
              var keys = Array.isArray(hints) ? hints.join(',') : String(hints || '');
              var u = FP.ua;
              if (keys.indexOf('platformVersion') >= 0 && u.platformVersion) v.platformVersion = u.platformVersion;
              if (keys.indexOf('architecture') >= 0 && u.architecture) v.architecture = u.architecture;
              if (keys.indexOf('bitness') >= 0 && u.bitness) v.bitness = u.bitness;
              if (keys.indexOf('fullVersionList') >= 0 && u.fullVersionList) {
                v.fullVersionList = u.fullVersionList.map(function (b) {
                  return { brand: b.brand, version: b.version };
                });
              }
              if (keys.indexOf('uaFullVersion') >= 0 && u.fullVersion) v.uaFullVersion = u.fullVersion;
              if (keys.indexOf('model') >= 0) v.model = '';
              if (keys.indexOf('mobile') >= 0) v.mobile = false;
              if (keys.indexOf('wow64') >= 0) v.wow64 = false;
            } catch (e) {}
            return v;
          });
        };
        navigator.userAgentData.getHighEntropyValues = wrappedGEHV;
        patched.add(wrappedGEHV);
      }
    } catch (e) {}
  }

  function patchGL(proto) {
    if (!proto) return;
    var orig = proto.getParameter;
    var wrapped = function (p) {
      if (p === 37445) return FP.gpu.vendor;
      if (p === 37446) return FP.gpu.renderer;
      return orig.apply(this, arguments);
    };
    proto.getParameter = wrapped;
    patched.add(wrapped);
  }
  patchGL(window.WebGLRenderingContext && window.WebGLRenderingContext.prototype);
  if (window.WebGL2RenderingContext) patchGL(window.WebGL2RenderingContext.prototype);

  var noise = FP.canvas.noise;
  function hashNoise(x, y, salt) {
    var v = Math.sin(x * 12.9898 + y * 78.233 + salt) * 43758.5453;
    return (v - Math.floor(v)) - 0.5;
  }
  var origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
  var wrappedImageData = function () {
    var data = origGetImageData.apply(this, arguments);
    try {
      var d = data.data;
      for (var i = 0; i < d.length; i += 4001) {
        d[i] = (d[i] + Math.round(hashNoise(i, i % 97, noise) * 2)) & 255;
      }
    } catch (e) {}
    return data;
  };
  CanvasRenderingContext2D.prototype.getImageData = wrappedImageData;
  patched.add(wrappedImageData);

  var origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  var wrappedDataURL = function () {
    try {
      var ctx = this.getContext('2d');
      if (ctx && this.width && this.height) {
        var w = Math.min(this.width, 32), h = Math.min(this.height, 32);
        // 在离屏画布上加噪导出，不回写原画布——回写会让同一画布第二次导出
        // 在已污染像素上叠加噪声，两次哈希不同（经典检测点），且永久篡改页面内容
        var img = origGetImageData.call(ctx, 0, 0, w, h);
        for (var i = 0; i < img.data.length; i += 997) {
          img.data[i] = (img.data[i] + Math.round(hashNoise(i, w, noise) * 2)) & 255;
        }
        var off = document.createElement('canvas');
        off.width = this.width;
        off.height = this.height;
        var octx = off.getContext('2d');
        octx.putImageData(img, 0, 0);
        if (this.width > w) {
          octx.drawImage(this, w, 0, this.width - w, this.height, w, 0, this.width - w, this.height);
        }
        if (this.height > h) {
          octx.drawImage(this, 0, h, w, this.height - h, 0, h, w, this.height - h);
        }
        return origToDataURL.apply(off, arguments);
      }
    } catch (e) {}
    return origToDataURL.apply(this, arguments);
  };
  HTMLCanvasElement.prototype.toDataURL = wrappedDataURL;
  patched.add(wrappedDataURL);

  var audioNoise = FP.audio.noise;
  if (window.AnalyserNode) {
    var origFreq = window.AnalyserNode.prototype.getFloatFrequencyData;
    if (origFreq) {
      var wrappedFreq = function (arr) {
        origFreq.apply(this, arguments);
        for (var i = 0; i < arr.length; i += 137) arr[i] = arr[i] + audioNoise;
      };
      window.AnalyserNode.prototype.getFloatFrequencyData = wrappedFreq;
      patched.add(wrappedFreq);
    }
  }

  // OfflineAudioContext 渲染路径的音频指纹（fingerprintjs 的标准做法）：
  // 给 AudioBuffer.getChannelData 加确定性噪声。同一 buffer 只加一次——
  // getChannelData 每次返回同一个数组，重复加会累积、两次读取结果不一致。
  (function () {
    if (!window.AudioBuffer || !window.AudioBuffer.prototype.getChannelData) return;
    var _noisyBuffers = new WeakSet();
    var origGet = window.AudioBuffer.prototype.getChannelData;
    var wrappedGet = function () {
      var data = origGet.apply(this, arguments);
      try {
        if (data && typeof data.length === 'number' && !_noisyBuffers.has(data)) {
          _noisyBuffers.add(data);
          for (var i = 0; i < data.length; i += 137) data[i] = data[i] + audioNoise;
        }
      } catch (e) {}
      return data;
    };
    window.AudioBuffer.prototype.getChannelData = wrappedGet;
    patched.add(wrappedGet);
  })();

  var origResolved = Intl.DateTimeFormat.prototype.resolvedOptions;
  var wrappedResolved = function () {
    var r = origResolved.apply(this, arguments);
    r.timeZone = FP.locale.timezone;
    return r;
  };
  Intl.DateTimeFormat.prototype.resolvedOptions = wrappedResolved;
  patched.add(wrappedResolved);

  // Date.getTimezoneOffset 必须与 Intl 声明的时区一致，否则一眼穿帮。
  // 时区池当前只有免夏令时的 Asia/Shanghai；以后往池里加欧美时区时，
  // 固定偏移会在夏令时期间差一小时，需要改成按日期计算。
  (function () {
    var TZ_OFFSETS = {
      'Asia/Shanghai': -480, 'Asia/Hong_Kong': -480, 'Asia/Macau': -480,
      'Asia/Taipei': -480, 'Asia/Singapore': -480, 'Asia/Kuala_Lumpur': -480,
      'Asia/Manila': -480, 'Asia/Tokyo': -540, 'Asia/Seoul': -540,
      'Asia/Bangkok': -420, 'Asia/Jakarta': -420, 'Asia/Ho_Chi_Minh': -420,
      'Asia/Dubai': -240, 'Asia/Kolkata': -330, 'Asia/Colombo': -330,
      'UTC': 0, 'Etc/GMT': 0, 'Etc/UTC': 0, 'Europe/Lisbon': 0,
      // 以下有夏令时，池子里目前没有；仅作未知时区的兜底近似
      'Europe/London': 0, 'America/New_York': 300, 'America/Los_Angeles': 480,
      'Europe/Berlin': -60, 'Europe/Paris': -60,
    };
    var tz = FP.locale && FP.locale.timezone;
    var minutes = Object.prototype.hasOwnProperty.call(TZ_OFFSETS, tz) ? TZ_OFFSETS[tz] : -480;
    var wrappedOffset = function () { return minutes; };
    Date.prototype.getTimezoneOffset = wrappedOffset;
    patched.add(wrappedOffset);
  })();

  // ---- WebRTC 防护：按环境配置决定策略 ----
  (function () {
    if (!window.RTCPeerConnection) return;
    var mode = (FP.webrtc && FP.webrtc.mode) || 'proxy';
    var OrigRTC = window.RTCPeerConnection;

    // disabled：完全关闭，任何调用都抛错（等价于浏览器禁用 WebRTC）
    if (mode === 'disabled') {
      var DisabledRTC = function () {
        throw new Error('RTCPeerConnection is not supported');
      };
      DisabledRTC.prototype = OrigRTC.prototype;
      DisabledRTC.generateCertificate = OrigRTC.generateCertificate;
      window.RTCPeerConnection = DisabledRTC;
      patched.add(DisabledRTC);
      return;
    }

    // proxy：强制 relay，只能走代理返回的候选地址，不泄露本机内网 IP
    var SafeRTC = function (cfg, constraints) {
      var next;
      if (cfg && cfg.iceServers) {
        next = JSON.parse(JSON.stringify(cfg));
        next.iceTransportPolicy = 'relay';
      } else {
        next = { iceTransportPolicy: 'relay' };
      }
      return new OrigRTC(next, constraints);
    };
    SafeRTC.prototype = OrigRTC.prototype;
    SafeRTC.generateCertificate = OrigRTC.generateCertificate;
    window.RTCPeerConnection = SafeRTC;
    patched.add(SafeRTC);
  })();

  // ---- 字体枚举伪装 ----
  // 页面探测字体的手法：用待测字体渲染文本量 offsetWidth，与回退字体比较，
  // 宽度不同 = 该字体已安装。必须让「应缺失」的字体量出回退宽度，
  // 否则枚举说没装、宽度说装了，自相矛盾（旧实现两边返回同一值，等于没伪装）。
  (function () {
    var missing = (FP.fonts && FP.fonts.missing) || [];
    var extra = (FP.fonts && FP.fonts.extra) || [];
    if (!missing.length && !extra.length) return;

    function listHit(list, fam) {
      var f = String(fam || '').toLowerCase();
      for (var i = 0; i < list.length; i++) {
        if (f.indexOf(String(list[i]).toLowerCase()) >= 0) return true;
      }
      return false;
    }

    // 1) document.fonts.check：missing 返回 false，extra 返回 true
    if (document.fonts && typeof document.fonts.check === 'function') {
      var origCheck = document.fonts.check.bind(document.fonts);
      var wrappedCheck = function (font, text) {
        try {
          var spec = String(font || '');
          if (listHit(missing, spec)) return false;
          if (listHit(extra, spec)) return true;
        } catch (e) {}
        return origCheck(font, text);
      };
      document.fonts.check = wrappedCheck;
      patched.add(wrappedCheck);
    }

    // 2) offsetWidth 探测：命中「应缺失」字体的元素按不存在的字体重新测量。
    //    用一个必然不存在的哨兵字体取回退宽度，量完即移除探针元素，不改原元素。
    var SENTINEL = '__fp_font_not_installed__';
    var origOffsetWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth');
    if (origOffsetWidth && origOffsetWidth.get) {
      var baseGet = origOffsetWidth.get;
      Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
        get: function () {
          var el = this;
          var w = baseGet.call(el);
          try {
            if (el && el.style && el.style.fontFamily && el.parentNode
                && listHit(missing, el.style.fontFamily)) {
              var probe = el.cloneNode(true);
              probe.style.fontFamily = SENTINEL;
              el.parentNode.insertBefore(probe, el);
              w = baseGet.call(probe);
              el.parentNode.removeChild(probe);
            }
          } catch (e) {}
          return w;
        },
        configurable: true
      });
    }
  })();

  // ---- WebGL 参数微扰 ----
  (function () {
    var g = FP.gpu || {};
    var OVERRIDES = {};
    if (g.maxTextureSize) OVERRIDES[0x0D33] = g.maxTextureSize;      // MAX_TEXTURE_SIZE
    if (g.maxViewport) OVERRIDES[0x0D3A] = g.maxViewport;            // MAX_VIEWPORT_DIMS
    if (g.maxRenderbuffer) OVERRIDES[0x0D41] = g.maxRenderbuffer;    // MAX_RENDERBUFFER_SIZE
    if (g.maxVertexAttribs) OVERRIDES[0x8869] = g.maxVertexAttribs;  // MAX_VERTEX_ATTRIBS

    function patch(proto) {
      if (!proto || !proto.getParameter) return;
      var orig = proto.getParameter;
      var wrapped = function (p) {
        if (p === 37445) return g.vendor;
        if (p === 37446) return g.renderer;
        if (Object.prototype.hasOwnProperty.call(OVERRIDES, p)) {
          var v = OVERRIDES[p];
          if (p === 0x0D3A) {
            // MAX_VIEWPORT_DIMS 真实返回 Int32Array(2)；旧指纹可能是标量，统一补成二元组
            var pair = Array.isArray(v) ? v : [v, v];
            return new Int32Array([pair[0], pair[1]]);
          }
          return v;
        }
        return orig.apply(this, arguments);
      };
      proto.getParameter = wrapped;
      patched.add(wrapped);
    }
    patch(window.WebGLRenderingContext && window.WebGLRenderingContext.prototype);
    if (window.WebGL2RenderingContext) patch(window.WebGL2RenderingContext.prototype);
  })();

  // ---- AudioContext 采样率与噪声 ----
  (function () {
    var a = FP.audio || {};
    if (!window.AudioContext) return;
    var OrigAC = window.AudioContext;
    var PATCHED_AC = function (opts) {
      var next = opts ? Object.assign({}, opts) : {};
      if (a.sampleRate && !next.sampleRate) next.sampleRate = a.sampleRate;
      return new OrigAC(next);
    };
    PATCHED_AC.prototype = OrigAC.prototype;
    window.AudioContext = PATCHED_AC;
    patched.add(PATCHED_AC);
    if (window.webkitAudioContext) window.webkitAudioContext = PATCHED_AC;
  })();

  // ---- 媒体设备枚举伪装 ----
  (function () {
    var m = FP.media;
    if (!m || !navigator.mediaDevices || !navigator.mediaDevices.enumerateDevices) return;
    var orig = navigator.mediaDevices.enumerateDevices.bind(navigator.mediaDevices);

    function build(real) {
      real = real || [];
      var fake = [];
      function push(kind, count) {
        for (var i = 0; i < count; i++) {
          var found = null;
          for (var j = 0; j < real.length; j++) {
            if (real[j] && real[j].kind === kind) { found = real[j]; break; }
          }
          fake.push({
            deviceId: (found && found.deviceId) || (kind + '-dev-' + i),
            kind: kind,
            label: m.labelsHide ? '' : ((found && found.label) || ''),
            groupId: (found && found.groupId) || 'grp-' + i
          });
        }
      }
      push('audioinput', m.audioInputs);
      push('audiooutput', m.audioOutputs);
      push('videoinput', m.videoInputs);
      return fake;
    }

    var wrapped = function () {
      try {
        return orig().then(build, function () { return build([]); });
      } catch (e) {
        // 非安全上下文等异常情况：直接返回伪造列表
        return Promise.resolve(build([]));
      }
    };
    navigator.mediaDevices.enumerateDevices = wrapped;
    patched.add(wrapped);
  })();

  // ---- 语音合成音色伪装 ----
  (function () {
    if (!window.speechSynthesis || !window.speechSynthesis.getVoices) return;
    var orig = window.speechSynthesis.getVoices.bind(window.speechSynthesis);
    var wrapped = function () {
      var list = orig();
      if (!list || !list.length) return list;
      // 打乱顺序并截取子集，制造个体差异
      var arr = Array.prototype.slice.call(list);
      var n = FP.hardware.cores % 3;
      for (var i = arr.length - 1; i > 0; i--) {
        var j = (i * 7 + n) % (i + 1);
        var t = arr[i]; arr[i] = arr[j]; arr[j] = t;
      }
      return n === 0 ? arr : arr.slice(0, Math.max(1, arr.length - n));
    };
    window.speechSynthesis.getVoices = wrapped;
    patched.add(wrapped);
  })();

  // ---- ClientRects 噪声 ----
  // 元素布局矩形的亚像素值是最隐蔽的指纹源之一，原生 Chrome 在不同机器上
  // 因字体度量差异产生不同值。这里按环境注入稳定微扰。
  (function () {
    var cr = FP.clientRects;
    if (!cr || !cr.enabled) return;
    var eps = cr.noise;

    function jitterRect(r) {
      try {
        var dx = (Math.sin(r.left * 977 + r.top * 131) * eps) || 0;
        var dy = (Math.cos(r.width * 313 + r.height * 719) * eps) || 0;
        return {
          x: r.x + dx, y: r.y + dy,
          width: r.width, height: r.height,
          top: r.top + dy, left: r.left + dx,
          right: r.right + dx, bottom: r.bottom + dy
        };
      } catch (e) { return r; }
    }

    var origGetBCR = Element.prototype.getBoundingClientRect;
    var wrappedBCR = function () {
      var r = origGetBCR.apply(this, arguments);
      var j = jitterRect(r);
      try {
        Object.defineProperty(j, 'toJSON', {
          value: function () {
            return {x: this.x, y: this.y, width: this.width, height: this.height,
                    top: this.top, left: this.left, right: this.right, bottom: this.bottom};
          }, configurable: true
        });
      } catch (e) {}
      return j;
    };
    Element.prototype.getBoundingClientRect = wrappedBCR;
    patched.add(wrappedBCR);

    if (Element.prototype.getClientRects) {
      var origGCR = Element.prototype.getClientRects;
      var wrappedGCR = function () {
        var list = origGCR.apply(this, arguments);
        try {
          return Array.prototype.map.call(list, jitterRect);
        } catch (e) { return list; }
      };
      Element.prototype.getClientRects = wrappedGCR;
      patched.add(wrappedGCR);
    }
  })();

  // ---- 存储配额伪装 ----
  (function () {
    var st = FP.storage;
    if (!st || !navigator.storage || !navigator.storage.estimate) return;
    var orig = navigator.storage.estimate.bind(navigator.storage);
    var total = st.quotaGB * 1024 * 1024 * 1024;
    var wrapped = function () {
      return orig().then(function (q) {
        return {quota: total, usage: q && q.usage ? q.usage : 0};
      }, function () {
        return {quota: total, usage: 0};
      });
    };
    navigator.storage.estimate = wrapped;
    patched.add(wrapped);
  })();

  // ---- 端口扫描防护 ----
  // 页面常用手法：向 127.0.0.1 / localhost 的常见端口发 fetch、Image、script
  // 请求，靠响应时间或 onload/onerror 差异判断本机装了什么软件（如指纹浏览器、
  // 远控、调试端口）。这里统一阻断到内网地址的主动请求。
  (function () {
    var ps = FP.portScan;
    if (!ps || !ps.protect) return;

    // 本机与内网地址判定
    function isInternal(url) {
      try {
        var u = new URL(url, location.href);
        var h = (u.hostname || '').toLowerCase();
        if (!h) return false;
        if (h === 'localhost' || h === '127.0.0.1' || h === '[::1]' || h === '::1') return true;
        if (h === '0.0.0.0') return true;
        if (h.endsWith('.localhost')) return true;
        // IPv6：环回 / 链路本地 fe80::/10 / ULA fc00::/7
        if (h.indexOf(':') >= 0) {
          var v6 = h.replace(/^\[|\]$/g, '');
          if (v6 === '::' || /^fe[89ab]/.test(v6) || /^f[cd]/.test(v6)) return true;
        }
        // 私有网段
        if (/^10\./.test(h)) return true;
        if (/^192\.168\./.test(h)) return true;
        if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return true;
        if (/^169\.254\./.test(h)) return true;
        if (/^127\./.test(h)) return true;
        return false;
      } catch (e) {
        return false;
      }
    }

    // fetch
    var origFetch = window.fetch;
    if (origFetch) {
      var wrappedFetch = function (input) {
        var url = '';
        try {
          if (typeof input === 'string') url = input;
          else if (input instanceof URL) url = input.href;
          else if (input && input.url) url = String(input.url);
          else url = String(input || '');
        } catch (e) {}
        if (isInternal(url)) {
          return Promise.reject(new TypeError('Failed to fetch'));
        }
        return origFetch.apply(this, arguments);
      };
      window.fetch = wrappedFetch;
      patched.add(wrappedFetch);
    }

    // XMLHttpRequest
    var origOpen = XMLHttpRequest.prototype.open;
    var wrappedOpen = function (method, url) {
      if (isInternal(url)) {
        // 标记为被阻断，send 时直接触发 error
        this.__portScanBlocked = true;
      }
      return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.open = wrappedOpen;
    patched.add(wrappedOpen);

    var origSend = XMLHttpRequest.prototype.send;
    var wrappedSend = function () {
      if (this.__portScanBlocked) {
        var self = this;
        setTimeout(function () {
          try {
            self.dispatchEvent(new Event('error'));
            if (typeof self.onerror === 'function') self.onerror(new Event('error'));
          } catch (e) {}
        }, 0);
        return;
      }
      return origSend.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = wrappedSend;
    patched.add(wrappedSend);

    // Image / script / link 探测：改写 src/href 为该属性设值时的拦截
    function blockResource(proto, prop) {
      if (!proto) return;
      var desc = Object.getOwnPropertyDescriptor(proto, prop);
      if (!desc || !desc.set) return;
      var origSet = desc.set;
      var wrapper = {
        set: function (v) {
          if (isInternal(v)) {
            // 指向不可达地址，让探测判定为「端口关闭」
            return origSet.call(this, 'about:blank');
          }
          return origSet.call(this, v);
        },
        get: desc.get,
        configurable: true,
        enumerable: desc.enumerable
      };
      try {
        Object.defineProperty(proto, prop, wrapper);
      } catch (e) {}
    }
    blockResource(window.HTMLImageElement && HTMLImageElement.prototype, 'src');
    blockResource(window.HTMLScriptElement && HTMLScriptElement.prototype, 'src');
    blockResource(window.HTMLLinkElement && HTMLLinkElement.prototype, 'href');

    // WebSocket 到内网端口也要拦
    if (window.WebSocket) {
      var OrigWS = window.WebSocket;
      var SafeWS = function (url, protocols) {
        if (isInternal(url)) {
          throw new DOMException('WebSocket connection blocked', 'SecurityError');
        }
        return protocols !== undefined
          ? new OrigWS(url, protocols)
          : new OrigWS(url);
      };
      SafeWS.prototype = OrigWS.prototype;
      ['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach(function (k) {
        SafeWS[k] = OrigWS[k];
      });
      window.WebSocket = SafeWS;
      patched.add(SafeWS);
    }

    // sendBeacon：内网目标直接返回 false（端口存活会让它返回 true）
    if (navigator.sendBeacon) {
      var origBeacon = navigator.sendBeacon.bind(navigator);
      var wrappedBeacon = function (url) {
        if (isInternal(url)) return false;
        return origBeacon.apply(navigator, arguments);
      };
      navigator.sendBeacon = wrappedBeacon;
      patched.add(wrappedBeacon);
    }

    // EventSource（SSE）与 WebSocket 同类
    if (window.EventSource) {
      var OrigES = window.EventSource;
      var SafeES = function (url, cfg) {
        if (isInternal(url)) {
          throw new DOMException('EventSource connection blocked', 'SecurityError');
        }
        return cfg !== undefined ? new OrigES(url, cfg) : new OrigES(url);
      };
      SafeES.prototype = OrigES.prototype;
      ['CONNECTING', 'OPEN', 'CLOSED'].forEach(function (k) {
        SafeES[k] = OrigES[k];
      });
      window.EventSource = SafeES;
      patched.add(SafeES);
    }

    // iframe.src / form.action：指向内网时改写为空白页
    blockResource(window.HTMLIFrameElement && HTMLIFrameElement.prototype, 'src');
    blockResource(window.HTMLFormElement && HTMLFormElement.prototype, 'action');

    // window.open 打开内网地址
    var origWindowOpen = window.open;
    if (origWindowOpen) {
      var wrappedOpenWin = function (url) {
        if (isInternal(url)) return null;
        return origWindowOpen.apply(window, arguments);
      };
      window.open = wrappedOpenWin;
      patched.add(wrappedOpenWin);
    }
  })();

  // ---- 插件列表伪装 ----
  // 现代 Chrome 的 navigator.plugins 固定为 PDF 相关几项。按环境裁剪数量，
  // 同时同步 mimeTypes 与 pdfViewerEnabled，避免三者互相矛盾。
  (function () {
    var pg = FP.plugins;
    if (!pg || !pg.enabled) return;

    var names = (pg.names || []).slice(0, Math.max(0, Math.min(5, pg.count || 5)));
    if (!names.length) return;

    // 构造类 Plugin 对象
    var fakePlugins = names.map(function (name, i) {
      var p = {
        name: name,
        filename: 'internal-pdf-viewer',
        description: 'Portable Document Format',
        length: 2
      };
      p.item = function (idx) { return idx === 0 || idx === 1 ? {type: 'application/pdf'} : null; };
      p.namedItem = function (n) {
        return (n === 'application/pdf' || n === 'text/pdf') ? {type: n} : null;
      };
      return p;
    });

    try {
      Object.defineProperty(navigator, 'plugins', {
        get: function () {
          var arr = fakePlugins.slice();
          arr.item = function (i) { return arr[i] || null; };
          arr.namedItem = function (n) {
            for (var i = 0; i < arr.length; i++) {
              if (arr[i].name === n) return arr[i];
            }
            return null;
          };
          arr.refresh = function () {};
          return arr;
        },
        configurable: true
      });
    } catch (e) {}

    // mimeTypes 与插件数量保持自洽
    try {
      Object.defineProperty(navigator, 'mimeTypes', {
        get: function () {
          var list = [
            {type: 'application/pdf', suffixes: 'pdf', description: 'Portable Document Format'},
            {type: 'text/pdf', suffixes: 'pdf', description: 'Portable Document Format'}
          ];
          list.item = function (i) { return list[i] || null; };
          list.namedItem = function (n) {
            for (var i = 0; i < list.length; i++) {
              if (list[i].type === n) return list[i];
            }
            return null;
          };
          return list;
        },
        configurable: true
      });
    } catch (e) {}

    // PDF 查看器开关与插件存在性一致
    try {
      Object.defineProperty(navigator, 'pdfViewerEnabled', {
        get: function () { return true; },
        configurable: true
      });
    } catch (e) {}
  })();

  // ---- WebGPU 伪装 ----
  // WebGPU 是 Chrome 113+ 新增的指纹面：requestAdapter 返回的 info 里带
  // vendor / architecture / device / description。三家商业指纹浏览器都已覆盖，
  // 这里按环境配置改写，且必须与 WebGL 的 GPU 厂商保持一致。
  (function () {
    var wg = FP.webgpu;
    if (!wg || !wg.enabled) return;
    if (!navigator.gpu || !navigator.gpu.requestAdapter) return;

    var origRequest = navigator.gpu.requestAdapter.bind(navigator.gpu);

    function patchAdapter(adapter) {
      if (!adapter) return adapter;
      try {
        // adapter.info 是只读对象，用 defineProperty 覆盖
        var fakeInfo = {
          vendor: wg.vendor || '',
          architecture: wg.architecture || '',
          device: wg.device || '',
          description: wg.description || ''
        };
        Object.defineProperty(adapter, 'info', {
          get: function () { return fakeInfo; },
          configurable: true
        });
      } catch (e) {}

      // requestAdapterInfo 是旧版 API，一并覆盖
      if (typeof adapter.requestAdapterInfo === 'function') {
        var origInfo = adapter.requestAdapterInfo.bind(adapter);
        var wrappedInfo = function () {
          return origInfo().then(function () {
            return {
              vendor: wg.vendor || '',
              architecture: wg.architecture || '',
              device: wg.device || '',
              description: wg.description || ''
            };
          }, function () {
            return {
              vendor: wg.vendor || '',
              architecture: wg.architecture || '',
              device: wg.device || '',
              description: wg.description || ''
            };
          });
        };
        adapter.requestAdapterInfo = wrappedInfo;
        patched.add(wrappedInfo);
      }
      return adapter;
    }

    var wrappedRequest = function () {
      return origRequest.apply(navigator.gpu, arguments).then(patchAdapter);
    };
    navigator.gpu.requestAdapter = wrappedRequest;
    patched.add(wrappedRequest);
  })();
})();
"""

# 标签页标题锁定脚本：插入到注入模板的 __TITLE_LOCK__ 位置
_TITLE_LOCK_JS = r"""
  // ---- 标签页标题锁定 ----
  // 页面自己会不断改 document.title（淘宝会写「淘宝网 - 淘！我喜欢」），
  // 因此用定时器持续把环境名前缀写回去，保证标签页始终能分辨是哪个环境。
  (function () {
    var PREFIX = __TITLE_PREFIX__;
    var applying = false;
    function lock() {
      if (applying) return;
      var cur = '';
      try { cur = document.title || ''; } catch (e) { return; }
      if (cur.indexOf(PREFIX) === 0) return;
      applying = true;
      try {
        document.title = cur ? PREFIX + ' · ' + cur : PREFIX;
      } catch (e) {}
      applying = false;
    }
    try {
      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', lock);
      }
    } catch (e) {}
    lock();
    setInterval(lock, 1200);
  })();
"""
