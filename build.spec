# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置。

用法（在本目录执行）：
    pyinstaller build.spec

产物：
    dist/多账号环境管理器.exe
"""

import sys
from pathlib import Path

ROOT = Path(SPECPATH).resolve()

block_cipher = None

added = []
for src, dst in [(ROOT / "web", "web"), (ROOT / "manager", "manager")]:
    if src.exists():
        added.append((str(src), dst))

hidden = [
    "manager.paths",
    "manager.layout",
    "manager.webdav",
    "manager.members",
    "manager.store",
    "manager.node_pool",
    "manager.subscription",
    "manager.fingerprint",
    "manager.browser",
    "manager.proxy",
    "manager.nodes",
    "manager.syncer",
    "manager.config_io",
    "manager.bidi",
    "manager.backends",
    "manager.firefox_kernel",
    "manager.kernels",
    "manager.cookies",
    "manager.dynamic_ip",
    "manager.excel_io",
    "openpyxl",
    "websocket",
]

excludes = [
    "tkinter", "matplotlib", "numpy", "pandas",
    "scipy", "PIL", "pytest", "IPython", "notebook",
]

a = Analysis(
    [str(ROOT / "app.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=added,
    hiddenimports=hidden,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="多账号环境管理器",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
