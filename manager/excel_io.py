"""Excel 批量导入环境。

支持 .xlsx / .xlsm（openpyxl）与 .csv 三种格式。
表头识别中英文，列顺序无所谓；缺省列用默认值。

必需列：环境编号（id / 编号 / 环境 / 账号编号）
可选列：名称、平台、备注、分组、标签、启动网址、
        节点名 / 节点名称、代理协议、代理服务器、代理端口、代理账号、代理密码、
        动态IP链接

一个文件里的节点如果不存在于节点池，会自动创建后再绑定到环境。
"""

import csv
import io

MAX_ROWS = 2000
MAX_COLS = 40


class ExcelError(Exception):
    pass


# 表头别名：把各种写法归一化到内部字段名
HEADER_ALIASES = {
    "id": ("id", "环境编号", "编号", "环境", "账号编号", "环境id", "envid", "env_id"),
    "name": ("name", "名称", "环境名称", "备注名", "店铺名"),
    "platform": ("platform", "平台"),
    "remark": ("remark", "备注", "说明", "描述"),
    "group": ("group", "分组", "组", "分组名"),
    "tags": ("tags", "标签", "tag"),
    "startUrl": ("starturl", "启动网址", "网址", "start_url", "主页", "起始页"),
    "nodeName": ("nodename", "节点名", "节点名称", "节点"),
    "protocol": ("protocol", "代理协议", "协议", "代理类型"),
    "server": ("server", "代理服务器", "服务器", "代理ip", "代理地址", "ip"),
    "port": ("port", "代理端口", "端口"),
    "username": ("username", "代理账号", "账号", "用户名"),
    "password": ("password", "代理密码", "密码"),
    "dynamicIpUrl": ("dynamicipurl", "动态ip链接", "动态ip", "ip提取链接", "dynamic_ip_url"),
    "browserBackend": ("browserbackend", "浏览器后端", "浏览器内核", "内核", "backend"),
    "kernelVersion": ("kernelversion", "内核版本", "firefox版本", "浏览器版本"),
}


def _normalize_header(cell):
    """把表头单元格归一化成内部字段名。"""
    if cell is None:
        return None
    text = str(cell).strip().lower()
    # 去掉 BOM、空格、下划线做宽松匹配
    compact = text.replace(" ", "").replace("_", "").replace("\ufeff", "")
    for field, aliases in HEADER_ALIASES.items():
        for alias in aliases:
            if compact == alias.replace(" ", "").replace("_", "").lower():
                return field
    return None


def parse_file(path):
    """解析文件，返回 (rows, error)。rows 是 dict 列表。"""
    lower = path.lower()
    if lower.endswith(".csv"):
        return _parse_csv(path)
    if lower.endswith(".xlsx") or lower.endswith(".xlsm"):
        return _parse_xlsx(path)
    raise ExcelError("只支持 .xlsx / .xlsm / .csv 文件")


def _parse_csv(path):
    raw = None
    for encoding in ("utf-8-sig", "utf-8", "gbk"):
        try:
            with open(path, "r", encoding=encoding, newline="") as f:
                raw = f.read()
            break
        except (UnicodeDecodeError, OSError):
            continue
    if raw is None:
        raise ExcelError("无法读取文件（编码不支持）")

    reader = csv.reader(io.StringIO(raw))
    grid = [row for row in reader if any((c or "").strip() for c in row)]
    return _grid_to_rows(grid, "csv")


def _parse_xlsx(path):
    try:
        from openpyxl import load_workbook
    except ImportError:
        raise ExcelError("缺少 openpyxl，无法解析 Excel")

    try:
        wb = load_workbook(path, read_only=True, data_only=True)
    except Exception as e:
        raise ExcelError("打开 Excel 失败: %s" % e)

    try:
        ws = wb[wb.sheetnames[0]] if wb.sheetnames else None
        if ws is None:
            raise ExcelError("文件里没有工作表")

        grid = []
        for row in ws.iter_rows(values_only=True):
            if len(grid) >= MAX_ROWS:
                break
            cells = list(row[:MAX_COLS])
            if any((c is not None and str(c).strip()) for c in cells):
                grid.append(cells)
        return _grid_to_rows(grid, "xlsx")
    finally:
        try:
            wb.close()
        except Exception:
            pass


def _grid_to_rows(grid, kind):
    """把二维表转成 dict 列表。"""
    if not grid:
        raise ExcelError("文件内容为空")

    header_cells = grid[0]
    columns = {}
    for idx, cell in enumerate(header_cells):
        field = _normalize_header(cell)
        if field and field not in columns:
            columns[field] = idx

    if "id" not in columns:
        raise ExcelError("缺少「环境编号」列（可用表头：环境编号 / 编号 / id）")

    rows = []
    skipped = 0
    for raw in grid[1:]:
        env_id = _cell_text(raw, columns.get("id"))
        if not env_id:
            skipped += 1
            continue
        rows.append({
            "id": env_id,
            "name": _cell_text(raw, columns.get("name")),
            "platform": _cell_text(raw, columns.get("platform")),
            "remark": _cell_text(raw, columns.get("remark")),
            "group": _cell_text(raw, columns.get("group")),
            "tags": _split_tags(_cell_text(raw, columns.get("tags"))),
            "startUrl": _cell_text(raw, columns.get("startUrl")),
            "nodeName": _cell_text(raw, columns.get("nodeName")),
            "protocol": _cell_text(raw, columns.get("protocol")),
            "server": _cell_text(raw, columns.get("server")),
            "port": _cell_text(raw, columns.get("port")),
            "username": _cell_text(raw, columns.get("username")),
            "password": _cell_text(raw, columns.get("password")),
            "dynamicIpUrl": _cell_text(raw, columns.get("dynamicIpUrl")),
            "browserBackend": _cell_text(raw, columns.get("browserBackend")),
            "kernelVersion": _cell_text(raw, columns.get("kernelVersion")),
        })

    return rows, ("共 %d 行，跳过空行 %d 行" % (len(rows), skipped))


def template_rows():
    """生成模板用的示例行（供前端下载）。"""
    header = [
        "环境编号", "名称", "平台", "备注", "分组", "标签", "启动网址",
        "代理协议", "代理服务器", "代理端口", "代理账号", "代理密码",
        "节点名", "动态IP链接", "浏览器后端", "内核版本",
    ]
    sample = [
        "taobao-01", "店铺A", "淘宝", "主账号", "示例分组", "主力,已认证",
        "https://www.taobao.com", "socks5", "1.2.3.4", "1080", "user", "pass",
        "香港节点01", "", "firefox", "150.0",
    ]
    return header, sample


# ---------- 工具 ----------

def _cell_text(row, idx):
    if idx is None or idx >= len(row):
        return ""
    v = row[idx]
    if v is None:
        return ""
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v).strip()


def _split_tags(text):
    if not text:
        return []
    out = []
    for part in text.replace("，", ",").replace(";", ",").replace("、", ",").split(","):
        t = part.strip()
        if t and t not in out:
            out.append(t)
    return out[:8]
