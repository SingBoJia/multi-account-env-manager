# 多账号环境管理器 TRD

> 产品代号：Taobao Env Manager  
> 文档版本：v1.0（Draft）  
> 日期：2026-11-08  
> 状态：待评审  
> 关联文档：[PRD](./PRD.md)

---

## 1. 设计目标与约束

### 1.1 目标

1. 在 Windows 本机运行，默认只监听 `127.0.0.1`。
2. 每个环境拥有独立浏览器 profile、独立指纹配置、独立代理出口。
3. 内置本地 Firefox 147/150/151 与本地 Chrome 多内核，不依赖 AdsPower 等外部服务。
4. 环境、节点、订阅、成员、备份等状态可持久化，进程重启不丢。
5. 可打包成单文件 EXE；浏览器内核作为外部资源，支持在线下载安装。
6. 关键操作有权限控制、环境锁和错误提示。

### 1.2 约束

- 运行平台：Windows 10/11 x64。
- 后端：Python 3 + Flask，单进程多线程。
- 前端：原生 HTML/CSS/JavaScript，无构建链。
- 浏览器控制：
  - Chrome：CDP
  - Firefox 多版本：W3C WebDriver BiDi
- 代理：本地 sing-box 进程。
- 存储：JSON 文件 + 浏览器 profile 目录。
- 打包：PyInstaller onefile。

## 2. 总体架构

```text
┌─────────────────────────────────────────────────────────────┐
│                        Browser (Web UI)                     │
│  envs / kernels / nodes / subs / sync / members / cloud     │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTP / JSON (127.0.0.1)
┌───────────────────────────▼─────────────────────────────────┐
│                         Flask app.py                        │
│  auth guard · member gate · env APIs · kernel APIs · import │
└───────┬───────────────┬───────────────┬─────────────────────┘
        │               │               │
┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼─────────────┐
│ Environment  │ │  Backends   │ │   KernelManager    │
│ Store        │ │ local / fx  │ │ status/download    │
└───────┬──────┘ └──────┬──────┘ └──────┬─────────────┘
        │               │               │
┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼─────────────┐
│ JSON files   │ │ Chrome CDP  │ │ Firefox 多版本 + BiDi │
│ data/*.json  │ │ sing-box    │ │ profile + user.js  │
└──────────────┘ └─────────────┘ └────────────────────┘
```

### 2.1 进程模型

- 一个 Flask 主进程，`threaded=True`。
- 每个浏览器环境一个浏览器进程组。
- 每个使用代理的环境一个 sing-box 子进程。
- 内核下载使用后台线程，任务状态保存在内存中。

### 2.2 数据流

1. 前端调用 `/api/*`。
2. Flask 先做本机 Host/Origin 校验，再做成员鉴权与环境范围校验。
3. 环境操作读写 `data/environments.json`，指纹读写 `data/fingerprints.json`。
4. 启动环境时：
   - 按需启动 sing-box，得到本地代理端口。
   - 调用 `BrowserBackends.start()` 分流到 Chrome 或 Firefox。
   - 浏览器进程与状态写入 `data/state` / `data/firefox-state`。
5. 停止环境时停止浏览器与 sing-box，清理端口和状态。

## 3. 技术栈

| 层 | 技术 |
|---|---|
| Web 框架 | Flask |
| 前端 | 原生 HTML/CSS/JS |
| 数据存储 | JSON + 文件目录 |
| Chrome 控制 | CDP / WebSocket |
| Firefox 控制 | WebDriver BiDi / WebSocket |
| 代理 | sing-box |
| 密码哈希 | PBKDF2, 200,000 轮 |
| 打包 | PyInstaller onefile |
| 解压内核 | 7-Zip (`7z.exe`) |

## 4. 目录结构

```text
taobao_env/
├─ app.py                     # Flask 入口、路由、启动流程
├─ build.spec                 # PyInstaller 配置
├─ README.md
├─ docs/
│  ├─ PRD.md
│  └─ TRD.md
├─ web/
│  └─ index.html              # 单页控制台
├─ manager/
│  ├─ paths.py                # 数据目录解析
│  ├─ store.py                # 环境元数据
│  ├─ fingerprint.py          # 指纹生成/持久化
│  ├─ browser.py              # 本地 Chrome 启动器（CDP）
│  ├─ firefox_kernel.py       # 本地 Firefox 多版本启动器（BiDi）
│  ├─ bidi.py                 # WebDriver BiDi 客户端
│  ├─ backends.py             # local/firefox 路由
│  ├─ kernels.py              # 内核状态/下载/校验/解压
│  ├─ proxy.py                # sing-box 进程管理
│  ├─ nodes.py                # 节点解析
│  ├─ node_pool.py            # 节点池
│  ├─ subscription.py         # 代理订阅
│  ├─ dynamic_ip.py           # 动态 IP 提取
│  ├─ cookies.py              # Chrome Cookie 读写
│  ├─ syncer.py               # 窗口同步（CDP）
│  ├─ layout.py               # 窗口布局
│  ├─ config_io.py            # 配置导入导出
│  ├─ excel_io.py             # Excel 模板/导入
│  ├─ members.py              # 成员/角色/环境范围
│  ├─ webdav.py               # WebDAV 备份
│  └─ ssrf_guard.py           # URL 安全检查
├─ kernels/
│  └─ firefox/
│     ├─ 147.0.4/extract/core/firefox.exe
│     ├─ 150.0/extract/core/firefox.exe
│     └─ 151.0/extract/core/firefox.exe
└─ data/                      # 运行时数据（EXE 模式在 exe 同级）
   ├─ environments.json
   ├─ fingerprints.json
   ├─ nodes.json
   ├─ subscriptions.json
   ├─ members.json
   ├─ profiles/
   ├─ firefox-state/
   ├─ singbox/
   └─ state/
```

## 5. 模块设计

### 5.1 `app.py`

职责：

- 创建 Flask app 与全局管理器实例。
- 注册环境、节点、订阅、内核、成员、云端同步等 API。
- 本机 Host/Origin 防护与成员权限网关。
- 环境启动编排 `_start_one()`：准备代理 → 调后端启动。
- 静态页面服务与 EXE 启动入口。

关键点：

- `DATA_ROOT = manager.paths.data_root()`，源码/EXE/测试共用同一套数据目录解析。
- `_pick_port()` 通过连接探测判断端口是否被占用，避免两个实例同时绑定 8787。
- `_start_one()` 不再有外部指纹浏览器分支，只走代理 + `BrowserBackends.start()`。
- 所有 API 返回 `{ok: bool, ...}`；错误统一 `{ok: false, error: "..."}`。

### 5.2 `manager/paths.py`

```python
def data_root():
    if ENV_MANAGER_DATA: return that
    if frozen: return exe_dir / "data"
    return project_dir / "data"
```

所有持久化模块通过 `data_file()` 取路径，避免各自用 `__file__` 推导。

### 5.3 `manager/store.py`

环境元数据存储，单文件 `environments.json`。

字段：

| 字段 | 类型 | 说明 |
|---|---|---|
| id | str | 环境编号，主键 |
| name | str | 显示名 |
| platform | str | 平台，默认淘宝 |
| remark | str | 备注 |
| proxy | object | 单节点代理 |
| nodeId | str | 节点池节点 ID |
| chain | list[str] | 多级代理链 |
| startUrl | str | 启动网址 |
| browserBackend | `firefox`/`local` | 浏览器内核 |
| kernelVersion | `147.0.4`/`150.0`/`151.0`/`system` | 具体内核版本 |
| group/tags | str/list | 分组与标签 |
| dynamicIp | object | 动态 IP 配置 |
| fpMode | `stable`/`random` | 指纹模式 |
| allowDirect | bool | 是否允许无代理直连 |
| locked/lockHash/lockSalt | bool/str | 环境锁 |
| deleted/deletedAt | bool/str | 回收站 |

实现细节：

- 所有读改写用可重入锁串行化。
- 写入使用临时文件 + `os.replace` 原子替换。
- 旧数据 `browserBackend=ads` 统一映射为 `firefox`，不再保存 `adsUserId`。

### 5.4 `manager/fingerprint.py`

职责：

- 为每个环境生成一次设备身份，稳定模式永久复用。
- 随机模式每次启动前重新生成。
- 字段：屏幕、DPR、CPU 核心、内存、GPU、Canvas 噪声、Audio 噪声、字体、媒体设备、语言、时区、UA。
- 提供克隆/对比/摘要。

指纹不直接等于“安全”，只是降低环境间关联概率。

### 5.5 `manager/browser.py`（本地 Chrome）

启动流程：

1. 定位 `chrome.exe`。
2. 创建 `profiles/env-<id>`。
3. 分配 CDP 端口（9333 起）。
4. 启动 Chrome：
   - `--user-data-dir`
   - `--remote-debugging-port`
   - `--user-agent`
   - `--lang`
   - `--window-size`
   - `--proxy-server=127.0.0.1:<sing-box 端口>`
5. 通过 CDP 在 `document_start` 注入指纹脚本。
6. 保存端口/进程/状态。

停止：

- 关闭 CDP 连接。
- 终止 Chrome 进程组。
- 清理状态。

### 5.6 `manager/firefox_kernel.py`（本地 Firefox 多版本）

启动流程：

1. 从环境配置读取 `kernelVersion`；未指定时取已安装最高版本。
2. 定位 `kernels/firefox/<version>/extract/core/firefox.exe`（兼容旧 `firefox-150`）。
3. 创建 `profiles/fx<version>-<id>`。
4. 生成 `user.js`：
   - `general.useragent.override`
   - `intl.accept_languages`
   - `dom.maxHardwareConcurrency`
   - `layout.css.devPixelsPerPx`
   - `network.proxy.*`
   - `media.peerconnection.enabled=false`
5. 分配空闲端口。
6. 启动：
   ```text
   firefox.exe -profile <dir> -no-remote -new-instance
     --remote-debugging-port <port> -width <w> -height <h> <url>
   ```
7. 等待 TCP 端口可连接。
8. 连接 `ws://127.0.0.1:<port>/session`，执行 `session.new`。
9. 通过 `browsingContext.getTree` 获取标签页，导航到启动网址。
10. 保存 `data/firefox-state/<env>.json`（含 kernelVersion）。

停止：

- 尝试 BiDi `browser.close`。
- 终止进程；必要时 `taskkill /T /F`。
- 更新状态文件 `running=false`。

限制：

- Firefox 单 BiDi 会话，不能让两个客户端同时 `session.new`。
- `user.js` 无法覆盖时区/Canvas/WebGL 深层信号，需要 WebExtension 扩展。

### 5.7 `manager/bidi.py`

最小 BiDi 客户端：

- `session.new`
- `browsingContext.getTree/create/navigate/close`
- `script.evaluate`
- `storage.getCookies/setCookie/deleteCookies`

连接时 `suppress_origin=True`，兼容 Firefox Remote Agent 的握手要求。

### 5.8 `manager/backends.py`

只保留两路：

```python
def backend(env_id):
    b = meta.get("browserBackend") or "local"
    if b == "ads": return "firefox"   # 旧数据迁移
    return b if b in ("local", "firefox") else "local"
```

- `start()`：firefox → `FirefoxKernel.start()`；local → `BrowserLauncher.start()`。
- `stop/stop_all/forget`：同时清理两套后端。
- `page_targets()`：Firefox 直接拒绝，因为不是 CDP。

### 5.9 `manager/kernels.py`

内核状态：

- Firefox 多版本：扫描 `kernels/firefox/*/extract/core/firefox.exe`，版本读 `application.ini`；同时兼容旧 `firefox-<major>` 目录。
- Chrome：路径、版本（读 `Application/<version>/`）。

下载任务：

```text
state: idle → downloading → verifying → extracting → done/error
progress: 0..100
```

安全约束：

- 只允许 `FIREFOX_CATALOG` 中的官方版本（147.0.4 / 150.0 / 151.0），URL 固定。
- 下载后校验官方 `SHA256SUMS`。
- 只允许解压到 `kernels/firefox/<version>/extract`。
- 使用 `.part` 临时文件，完成后 `os.replace`。

#### 5.9.1 对齐 AdsPower 的内核模型

AdsPower 的 profile 里保存的是：

```json
{"browser_kernel_config": {"type": "firefox", "version": "147"}}
```

启动时通过 `getBrowserPath(type, version)` 解析：

```text
firefox -> <BASE_DIR>/flower_<version>/FlowerBrowser.exe
chrome  -> <BASE_DIR>/chrome_<version>/SunBrowser.exe
```

本项目的对应实现：

| AdsPower | 本项目 |
|---|---|
| `browser_kernel_config.type` | `browserBackend`（`firefox` / `local`） |
| `browser_kernel_config.version` | `kernelVersion`（`147.0.4` / `150.0` / `151.0` / `system`） |
| `flower_<version>` | `kernels/firefox/<version>/extract/core/firefox.exe` |
| `chrome_<version>` | `kernels/chrome/<version>/chrome.exe`（预留）或系统 Chrome |
| `getBrowserPath(type, version)` | `resolve_firefox_kernel(version)` |

关键点：

- 多个版本并存在磁盘上，环境只保存 type/version。
- 切换版本不改环境编号，但会使用新的 profile：`profiles/fx<version>-<env>`。
- 内核包独立下载/校验/解压，不要求重新打包 EXE。

### 5.10 代理相关模块

| 模块 | 职责 |
|---|---|
| `proxy.py` | 启动/停止 sing-box，分配本地端口 |
| `nodes.py` | 解析协议、地址、端口、认证信息 |
| `node_pool.py` | 节点池 CRUD、分组 |
| `subscription.py` | 拉取订阅、解析节点、去重 |
| `dynamic_ip.py` | 从提取链接获取新 IP |

启动环境时优先级：

```text
代理链 > 动态 IP > 单节点 > allowDirect 直连
```

未配置代理且未开启 `allowDirect` → 拒绝启动。

### 5.11 其他模块

| 模块 | 职责 |
|---|---|
| `cookies.py` | Chrome profile Cookie SQLite 读写、Netscape 转换 |
| `syncer.py` | Chrome 窗口同步（CDP 输入事件） |
| `layout.py` | 窗口布局计算 |
| `config_io.py` | 配置 JSON 导入/导出、脱敏 |
| `excel_io.py` | Excel 模板、批量导入解析 |
| `members.py` | 成员、角色、环境范围、密码哈希 |
| `webdav.py` | WebDAV 上传/下载/列表 |
| `ssrf_guard.py` | 订阅/WebDAV URL 内网地址拦截 |

## 6. 数据模型

### 6.1 `environments.json`

```json
{
  "taobao-01": {
    "id": "taobao-01",
    "name": "店铺A",
    "platform": "淘宝",
    "browserBackend": "firefox",
    "kernelVersion": "150.0",
    "startUrl": "https://www.taobao.com",
    "nodeId": "node-xxx",
    "chain": [],
    "group": "示例分组",
    "tags": ["主力"],
    "fpMode": "stable",
    "allowDirect": false,
    "deleted": false
  }
}
```

### 6.2 `fingerprints.json`

```json
{
  "taobao-01": {
    "version": 5,
    "screen": {"width": 1920, "height": 1080, "dpr": 1.0},
    "hardware": {"cores": 8, "memory": 16},
    "gpu": {"vendor": "NVIDIA", "renderer": "...", "webglNoise": 123},
    "canvas": {"noise": 456, "textNoise": 789},
    "audio": {"noise": 0.003},
    "locale": {"language": "zh-CN", "languages": ["zh-CN", "zh"], "timezone": "Asia/Shanghai"},
    "ua": {"userAgent": "..."}
  }
}
```

### 6.3 `members.json`

```json
{
  "admin": {
    "username": "admin",
    "displayName": "老板",
    "role": "admin",
    "enabled": true,
    "salt": "...",
    "passwordHash": "...",
    "envScope": [],
    "createdAt": "2026-10-31 02:10:39"
  }
}
```

自助注册的待授权账号使用 `envScope=["__none__"]`，不匹配任何真实环境。

### 6.4 状态目录

| 目录 | 内容 |
|---|---|
| `data/profiles/env-*` | Chrome 用户数据 |
| `data/profiles/fx<version>-*` | Firefox 多版本用户数据 |
| `data/firefox-state/*.json` | Firefox 端口/PID/profile/版本 |
| `data/state/*.json` | Chrome 端口/进程/标签页 |
| `data/singbox/` | sing-box 配置与日志 |
| `data/ui-profile*/` | 控制台浏览器 profile |

## 7. API 设计

### 7.1 约定

- 所有接口返回 JSON，成功 `{"ok": true, ...}`，失败 `{"ok": false, "error": "..."}`。
- 成员系统启用后，除 `/api/auth/*` 外需要 `Authorization: Bearer <token>`。
- 环境级权限由 `envScope` 校验。
- 时间格式：`YYYY-MM-DD HH:MM:SS`。

### 7.2 主要接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | `/api/envs` | 环境列表 / 创建 |
| PATCH/DELETE | `/api/envs/<id>` | 修改 / 移入回收站 |
| POST | `/api/envs/<id>/start` | 启动 |
| POST | `/api/envs/<id>/stop` | 停止 |
| POST | `/api/start-all` | 全部启动 |
| POST | `/api/stop-all` | 全部停止 |
| PATCH | `/api/envs/<id>/meta` | 分组/标签/指纹模式/内核 |
| GET | `/api/envs/<id>/fingerprint` | 读取指纹 |
| POST | `/api/envs/<id>/fingerprint/regenerate` | 重新生成（仅 Chrome） |
| GET/POST | `/api/envs/<id>/cookies` | 导出 / 导入 Cookie |
| GET | `/api/envs/<id>/proxy/test` | 单节点测速 |
| POST | `/api/envs/<id>/chain/test` | 代理链测速 |
| GET | `/api/kernels` | 内核状态 |
| POST | `/api/kernels/download` | 下载指定 Firefox 版本（body: type/version） |
| GET | `/api/kernels/job` | 下载任务状态 |
| GET | `/api/auth/status` | 登录状态/管理员列表 |
| POST | `/api/auth/login` | 登录 |
| POST | `/api/auth/register` | 首次管理员/待授权只读注册 |
| POST | `/api/auth/recover` | 本机重置管理员密码 |
| GET/POST | `/api/members` | 成员列表/添加 |
| PATCH/DELETE | `/api/members/<username>` | 编辑/删除 |
| GET | `/api/nodes` | 节点池 |
| POST | `/api/nodes/import` | 批量导入节点 |
| GET/POST | `/api/subscriptions` | 订阅 |
| POST | `/api/sync/start` | 窗口同步 |
| POST | `/api/layout/apply` | 窗口布局 |
| POST | `/api/envs/import-excel` | Excel 导入 |
| GET | `/api/envs/import-excel/template` | 下载模板 |
| GET | `/api/export` | 配置导出 |
| POST | `/api/import` | 配置导入 |
| WebDAV | `/api/cloud/*` | 备份/恢复 |

### 7.3 示例：创建默认环境

```http
POST /api/envs
Content-Type: application/json

{
  "id": "taobao-06",
  "name": "店铺06",
  "platform": "淘宝",
  "startUrl": "https://www.taobao.com"
}
```

响应：

```json
{
  "ok": true,
  "env": {
    "id": "taobao-06",
    "browserBackend": "firefox",
    "kernelVersion": "150.0"
  }
}
```

### 7.4 示例：启动内核下载

```http
POST /api/kernels/download
```

```json
{
  "ok": true,
  "started": true,
  "message": "已开始下载",
  "job": {"state": "downloading", "progress": 0}
}
```

轮询 `GET /api/kernels/job`，直到 `state=done/error`。

## 8. 浏览器生命周期

### 8.1 Firefox 多版本

```text
检查内核 → 创建 profile → 写 user.js → 选空闲端口 → 启动 firefox.exe
→ 等待端口可连接 → BiDi session.new → getTree
→ 复用/创建标签页 → navigate → 保存 state → 返回端口
```

停止：

```text
BiDi browser.close → 等待进程退出 → taskkill 兜底
→ 更新 state.running=false
```

### 8.2 Chrome

```text
检查 chrome.exe → 创建 profile → 选 CDP 端口 → 启动
→ 等待 /json/version → 连接 CDP → 注入指纹
→ 导航 → 保存 state → 返回端口
```

停止：

```text
关闭 CDP → 终止进程 → 清理 state
```

### 8.3 端口分配

- Chrome：`CDP_PORT_BASE=9333`，向后探测 400 个端口。
- Firefox：`_free_port()` 绑定 `127.0.0.1:0` 获取系统空闲端口。
- 端口与 envId 绑定，状态文件记录 PID，停止时只操作自己的进程。

## 9. 指纹设计

### 9.1 通用字段

- 屏幕：宽、高、可用高度、DPR
- 硬件：CPU 核心、内存
- GPU：厂商、渲染器、WebGL 参数、噪声
- Canvas：像素噪声、文字噪声
- Audio：采样噪声
- 字体：额外/缺失字体
- 媒体设备：摄像头/麦克风/扬声器数量
- 语言/时区/UA

### 9.2 Firefox 多版本当前实现

通过 `user.js` 写入：

| 项 | 实现 |
|---|---|
| UA | `general.useragent.override` |
| 语言 | `intl.accept_languages` |
| CPU | `dom.maxHardwareConcurrency` |
| DPR | `layout.css.devPixelsPerPx` |
| 代理 | `network.proxy.*` |
| WebRTC | `media.peerconnection.enabled=false` |

限制：

- 时区仍为系统时区。
- Canvas/WebGL/字体枚举未做深层注入。
- 需通过 WebExtension 在 `document_start` 修改 `window.wrappedJSObject` 或注入页面脚本。

### 9.3 Chrome

通过 CDP `Page.addScriptToEvaluateOnNewDocument` 注入，覆盖：

- `navigator`、UA-CH
- screen/DPR
- WebGL vendor/renderer/parameters
- Canvas getImageData/toDataURL
- AudioBuffer
- 语言/时区

## 10. 安全设计

### 10.1 本机防护

- `app.run(host="127.0.0.1")`。
- `_local_guard` 校验 Host 和 Origin 必须是本机。
- 防止 DNS rebinding 与恶意网页 `no-cors` 请求。

### 10.2 认证与权限

- 密码使用 PBKDF2，200,000 轮，随机盐。
- 登录 token 随机 24 字节，内存保存，TTL 2 小时。
- 角色：admin / manager / operator / viewer。
- `envScope` 环境级授权；空数组=全部。
- 自助注册默认 `viewer` + `envScope=["__none__"]`，待管理员授权。
- 首个成员强制 admin，避免锁死。
- 管理员密码重置仅允许 `127.0.0.1/::1`，旧 token 全部失效。

### 10.3 环境锁

- 锁密码单独哈希保存。
- 修改/删除/导出 Cookie 前校验。
- 忘记锁密码只能通过删除环境或管理员操作，属于后续改进点。

### 10.4 内核下载

- 只允许内置 `FIREFOX_CATALOG` 中的版本，不接受用户输入 URL。
- 每个版本使用官方 SHA256 校验。
- 只解压到固定目录。
- 失败保留 `.part`，下次覆盖重试。

### 10.5 代理/订阅

- 订阅 URL 只允许 http/https。
- 拒绝 localhost、环回、保留地址，避免 SSRF。
- WebDAV 同样做 URL 检查。

## 11. 并发与可靠性

- 环境存储：`RLock` 串行读改写。
- 指纹存储：`RLock`，克隆时整体复制。
- 端口集合：`_PORT_LOCK` + `_PORT_TAKEN`。
- 状态文件：原子写入。
- 启动失败：回收代理进程，避免残留 sing-box。
- 停止：先优雅关闭，再强制终止，避免端口占用。
- 下载任务：单任务状态机，重复点击返回“已在运行”。

## 12. 打包与部署

### 12.1 PyInstaller

`build.spec`：

- `datas`: `web/`、`manager/`
- `hiddenimports`: 各 manager 模块、openpyxl、websocket
- `console=True`
- onefile

构建：

```powershell
python -m PyInstaller --noconfirm build.spec
```

产物：

```text
dist/多账号环境管理器.exe
```

### 12.2 外部资源

- `kernels/firefox/<version>/extract/core/firefox.exe` 不打进 EXE。
- 发布时把 `kernels` 放在 EXE 同级，或保留在上一级开发目录。
- 代码会依次查找：
  1. `FIREFOX150_PATH` 环境变量
  2. `<exe_dir>/kernels/firefox/<version>/...`
  3. `<exe_dir>/../kernels/firefox/<version>/...`

### 12.3 数据目录

- EXE：`<exe_dir>/data`
- 源码：`<project>/data`
- 测试：`ENV_MANAGER_DATA=<temp>` 覆盖

### 12.4 依赖

- 7-Zip：内核下载安装需要。
- sing-box：代理功能需要；未安装时仅直连环境可用。
- Chrome：使用 `local` 内核时需要；Firefox 多版本不需要 Chrome。

## 13. 迁移设计

### 13.1 移除 AdsPower

- 运行时代码中不再有 AdsPower 客户端/启动器。
- `manager/ads.py`、`manager/ads_browser.py` 已移至备份目录，不参与打包。
- `/api/ads/status`、`/api/ads/verify` 已删除。
- UI 不再出现 AdsPower 选项、环境 ID、ADS 状态按钮。

### 13.2 数据迁移

- `browserBackend=ads` → `firefox`。
- `adsUserId` 不再写出，读取时忽略。
- 旧配置导入时同样映射。
- 迁移不改变 profile 数据；原 AdsPower profile 仍留在 AdsPower 目录，但本软件不再读取。

## 14. 测试策略

### 14.1 单元测试

- 指纹生成稳定性/随机性。
- 环境存储原子写入。
- 成员密码校验、角色权限、envScope。
- 配置导入导出脱敏。
- 内核 SHA256 解析。

### 14.2 API 测试

- 创建默认环境 → `firefox/150`。
- 旧 `ads` 后端 → `firefox/150`。
- 启动/停止 Firefox 147.0.4 / 150.0。
- Cookie 导入导出。
- 成员注册/重置密码。
- 内核状态/下载任务。

### 14.3 冒烟测试

- 源码启动 → 页面加载。
- EXE 启动 → 页面/API。
- Firefox 147/150 启动 → BiDi → 停止。
- Chrome 启动 → CDP → 停止。
- 内核下载空目录 → 安装完成。

### 14.4 已验证记录

- Firefox 150.0 直接启动：`VERSION=150.0`；Firefox 147.0.4 启动：`VERSION=147.0.4`。
- API 创建默认环境：`firefox/150`。
- 内核空目录下载安装：约 13 秒完成，SHA256 通过。
- EXE 启动：页面正常，内核页存在。
- 移除 AdsPower 后：`/api/kernels` 仅 `firefox150/chrome`。

## 15. 性能目标

| 指标 | 目标 |
|---|---|
| 100 环境列表 | < 1s |
| 单环境 Firefox 启动 | < 10s |
| 单环境 Chrome 启动 | < 8s |
| 内核下载 87MB | 正常网络 < 60s |
| 页面首屏 | < 2s（本机） |

## 16. 风险与技术债

| 项 | 说明 | 计划 |
|---|---|---|
| Firefox 深层指纹 | 仅 user.js，时区/Canvas/WebGL 弱 | V1.2 WebExtension |
| Firefox 单 BiDi 会话 | 不能多客户端同时控制 | 管理器内复用单一 session |
| 7-Zip 依赖 | 无 7z 无法安装内核 | 后续内置解压或自带 7z |
| EXE onefile 启动慢 | 每次解包 | 后续可切 onedir |
| Chrome 下载目录未隔离 | 多环境共用系统 Downloads | V1.2 独立下载目录 |
| 成员密码重置 | 本机无旧密码可重置 | 后续恢复码/二次确认 |
| 环境锁找回 | 无找回流程 | 后续管理员解锁 |

## 17. 架构决策记录（ADR）

### ADR-001：内置内核而非依赖外部指纹浏览器

- 决策：使用本地 Firefox 147/150/151 + 本地 Chrome。
- 原因：可控、无外部订阅、可打包、符合“自研内置”要求。
- 代价：需要自己维护指纹与内核升级。

### ADR-002：Firefox 多版本注册表，默认 150.0

- 决策：`browserBackend` 默认 `firefox`，`kernelVersion=150.0`；环境可选 147.0.4 / 151.0。
- 原因：用户明确要求默认不依赖 AdsPower，且 Firefox 多版本是内置能力。
- 代价：Firefox 深层指纹弱于 Chrome CDP，需要后续扩展。

### ADR-003：完全移除 AdsPower 运行时

- 决策：删除导入、实例、API、UI、打包项；旧数据映射到 Firefox。
- 原因：用户要求“自己内置”，不允许直接使用外部软件。
- 代价：旧 AdsPower profile 不能直接复用登录态。

### ADR-004：内核文件放在 EXE 外部

- 决策：`kernels/` 不打进 onefile。
- 原因：345MB+ 内核会使 EXE 过大、启动更慢。
- 代价：分发时需带 `kernels` 目录。

## 18. 附录

### 18.1 环境状态机

```text
停止 --start--> 启动中 --成功--> 运行中
  ^                |                 |
  |                +--失败--> 停止   |
  +---------------- stop ------------+
```

### 18.2 内核下载状态机

```text
idle → downloading → verifying → extracting → done
  ↑         |             |            |
  +--------- error ←-------+------------+
```

### 18.3 关键文件责任

| 文件 | 责任 |
|---|---|
| `app.py` | 路由、鉴权、启动编排 |
| `manager/store.py` | 环境元数据 |
| `manager/fingerprint.py` | 指纹 |
| `manager/browser.py` | Chrome |
| `manager/firefox_kernel.py` | Firefox 多版本 |
| `manager/bidi.py` | BiDi |
| `manager/backends.py` | 内核路由 |
| `manager/kernels.py` | 内核下载 |
| `manager/proxy.py` | sing-box |
| `manager/members.py` | 成员权限 |
| `web/index.html` | 控制台 |

---

## 附：评审检查表

- [ ] 是否还有外部指纹浏览器依赖
- [ ] 默认内核是否为 Firefox 150.0
- [ ] 新环境是否无需外部 ID
- [ ] 内核下载是否校验 SHA256
- [ ] 运行中是否禁止切换内核
- [ ] 成员权限是否覆盖所有写操作
- [ ] 日志是否避免输出敏感信息
- [ ] EXE 是否携带/能找到 `kernels`
