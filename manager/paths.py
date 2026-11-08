"""统一的数据目录解析。

源码运行时数据放在项目目录；打包成 EXE 后数据必须放在 EXE 旁边，
否则 PyInstaller 的临时解包目录一关就丢。

所有需要持久化的模块从这里取目录，不再各自用 __file__ 推导。
"""

import os
import pathlib
import sys


def data_root():
    """返回可写的数据根目录（会自动创建）。"""
    override = os.environ.get("ENV_MANAGER_DATA")
    if override:
        p = pathlib.Path(override).resolve()
    elif getattr(sys, "frozen", False):
        # EXE 运行：数据放在 exe 同级目录的 data/
        p = pathlib.Path(sys.executable).resolve().parent / "data"
    else:
        # 源码运行：数据放在项目目录的 data/
        p = pathlib.Path(__file__).resolve().parent.parent / "data"

    p.mkdir(parents=True, exist_ok=True)
    return p


def data_file(name):
    """返回数据目录下的某个文件路径。"""
    return data_root() / name


def atomic_write_text(path, text):
    """原子写文本文件：先写同目录临时文件，再 os.replace 原子替换。

    进程崩溃 / 断电时最多丢最后一次写入，不会留下半截 JSON；
    并发读也只会读到完整的旧内容或完整的新内容。
    """
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name("%s.tmp-%d" % (p.name, os.getpid()))
    tmp.write_text(text, encoding="utf-8")
    os.replace(str(tmp), str(p))
