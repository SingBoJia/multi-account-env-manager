# 多账号环境管理器

每个环境一套独立的浏览器指纹 + 独立代理出口 + 独立登录态，用于淘宝等多账号运营。

> 本项目用于自有或已授权账号的环境隔离、自动化测试与隐私研究；请遵守目标平台规则及当地法律，不用于未授权访问、欺诈或其他违法用途。

## 文档

- [产品需求文档 PRD](docs/PRD.md)
- [技术设计文档 TRD](docs/TRD.md)

## 浏览器后端：本地 Firefox 多版本 / 本地 Chrome

管理器只使用内置内核，不依赖任何外部指纹浏览器：

| 后端 | 浏览器 | 指纹 | 代理 | 控制协议 |
|---|---|---|---|---|
| `firefox`（新建默认） | 本地 Firefox 147.0.4 / 150.0 / 151.0 | 管理器 user.js + 独立 profile | 管理器节点池 / sing-box | WebDriver BiDi |
| `local` | 本机 Google Chrome | 管理器 JS 注入 + CDP | 管理器节点池 / sing-box | CDP |

新建环境默认使用 **Firefox 150.0**，不需要填写任何外部环境 ID；在环境设置里可以切换 147.0.4 / 150.0 / 151.0。

### Firefox 多版本内核

- 目录结构（对齐 AdsPower 的 `browser_kernel_config{type,version}`）：
  `kernels/firefox/<version>/extract/core/firefox.exe`
- 兼容旧目录：`kernels/firefox-150/extract/core/firefox.exe`
- 每个环境独立 profile：`profiles/fx<version>-<环境编号>`
- 启动时按环境的 `kernelVersion` 解析具体内核，例如 147.0.4、150.0、151.0
- 已写入：对应版本 UA、语言、CPU 核心、DPR、代理、禁用 WebRTC
- 控制走 WebDriver BiDi：`ws://127.0.0.1:<端口>/session`
- 打包 EXE 后，把整个 `kernels` 目录放到 `多账号环境管理器.exe` 同级目录
- 说明：本地内核不改 Firefox 源码，Canvas/WebGL/时区等深层指纹不如商业指纹浏览器完整；后续可以加 WebExtension 注入来补强

### 内核管理页

- 顶部「内核」标签页会列出所有已安装/可安装的 Firefox 版本和本地 Chrome。
- 未安装的 Firefox 版本显示「下载并安装」：
  - 从 Mozilla 官方对应版本下载 win64 安装包
  - 使用官方 SHA256 校验
  - 调用 7-Zip 解压到 `kernels/firefox/<version>/extract/core`
  - 页面显示下载/校验/解压进度，失败可重试
- 已安装时不重复下载；只显示版本与路径。
- 说明：下载安装需要本机有 7-Zip（`7z.exe`）；没有 7-Zip 会明确报错。

### 相关文件

- `manager/firefox_kernel.py`：Firefox 多版本启动器（按版本解析、profile、user.js、BiDi）
- `manager/bidi.py`：最小 WebDriver BiDi 客户端（标签页、导航、Cookie）
- `manager/kernels.py`：内核注册表、Firefox 多版本下载/校验/解压
- `manager/backends.py`：按环境把请求分流到 `firefox` 或 `local`

## 登录 / 成员

- **首次使用**：登录页点「注册新用户」，第一个账号自动成为管理员。
- **已有成员**：自助注册的账号是「待授权只读」，登录后看不到环境数据；
  管理员在「成员」页给它分配环境范围后才会生效。
- **忘记管理员密码**：登录页点「忘记管理员密码？」，
  只在运行管理器的本机可用；输入管理员用户名和新密码即可重置，不需要旧密码。
- 密码不会以明文保存，程序/接口都不会回显原密码。
- 首个成员（无论通过注册还是「添加成员」）都会被强制设为管理员，避免初始化后锁死。

## 两种运行方式

**方式一：EXE 直接运行（推荐）**

```
双击  dist\多账号环境管理器.exe
```

- 无需安装 Python
- 自动打开浏览器界面
- 数据保存在 EXE 同级的 `data/` 目录，关掉程序不会丢
- 首次运行会自动创建 `data/` 目录

**方式二：源码运行**

```bash
cd taobao_env
python app.py
```

浏览器打开 http://127.0.0.1:8787

## 重新打包 EXE

```bash
python -m PyInstaller --noconfirm --clean --onefile --console \
  --name "多账号环境管理器" --distpath dist --workpath build --specpath . \
  --add-data "web;web" --add-data "manager;manager" \
  --hidden-import manager.paths --hidden-import manager.store \
  --hidden-import manager.node_pool --hidden-import manager.subscription \
  --hidden-import manager.fingerprint --hidden-import manager.browser \
  --hidden-import manager.proxy --hidden-import manager.nodes \
  --hidden-import manager.syncer --hidden-import manager.config_io \
--hidden-import manager.bidi --hidden-import manager.backends \
--hidden-import manager.firefox_kernel --hidden-import manager.kernels \
  --hidden-import manager.cookies --hidden-import manager.dynamic_ip \
  --hidden-import manager.excel_io --hidden-import openpyxl --hidden-import websocket \
  --exclude-module tkinter --exclude-module matplotlib --exclude-module numpy \
  --exclude-module pandas --exclude-module scipy --exclude-module PIL \
  --exclude-module pytest --exclude-module IPython --exclude-module notebook app.py
```

产物约 18-19 MB，单文件。

**依赖**：代理功能需要本机装有 sing-box（`scoop install sing-box`），指纹功能需要 Chrome。

## 面板

## 环境管理（表格视图）

一行一个环境，支持勾选批量操作：

- 勾选后批量：启动 / 停止 / 换指纹 / 对比指纹 / 设分组 / 导出 Cookie / 移入回收站
- 单行操作：启动、停止、分组、Cookie、动态IP、链条、测速、上锁、克隆、回收
- **筛选栏**：按名称/编号/备注搜索，按分组、标签、状态（运行/停止/上锁/未配节点）过滤
- 顶部统计：环境总数、运行数、已配节点、无节点数

**分组与标签**：给环境分类（如「店铺组A」「店铺组B」）和打标签（如「主力」「已认证」）。分组和标签都可作为筛选条件。

**克隆环境**：复制源环境的设备身份（屏幕、硬件、显卡、语言、时区、UA）和节点配置。默认开启「噪声独立」，此时 Canvas / Audio / ClientRects 噪声会重新生成，避免两个环境被识别为同一台设备。

**对比指纹**：勾选 2 个以上环境点「对比指纹」，会列出 15 个维度并标红所有取值相同的维度。

### 节点池

集中管理所有代理节点，与环境解耦：

- **批量导入**：粘贴分享链接（每行一条）、整段 base64 订阅内容、或订阅 URL
- **导入即分配**：可选「同时自动分配给空闲环境」
- **单节点测速**：临时起一个 sing-box 实例查出口 IP
- **全部测速**：逐个验证所有节点
- **批量分配**：手动选择「哪些环境 ↔ 哪些节点」，按顺序一一对应
- **分组标签**：导入时可打组（如「香港」「住宅」），便于筛选

### 订阅

代理订阅管理，主流指纹浏览器都没有的能力：
- 添加订阅地址后立即同步一次
- **增量更新**：按节点内容哈希比对
  - 新增节点自动加入池
  - 内容变化的节点**原地更新，节点 ID 不变**（环境绑定不会断）
  - 订阅里已删除的节点从池中移除
- **手动导入的节点完全不受影响**
- 单个同步 / 全部同步 / 停用 / 删除（删除时连带移除它引入的节点）
- 订阅地址 token 在界面上打码显示
- 拉取失败保留上次结果，不影响现有节点

订阅地址只允许 http/https，并拒绝 localhost、环回、私有、保留地址、云元数据地址（`169.254.169.254` 等），实测 7 类恶意地址全部拦截。

### 窗口同步

在一个窗口里的操作实时同步到其他窗口。这是比特浏览器在主流指纹浏览器里独有的功能，本工具已实现。

**同步内容**（可分别开关）：

| 动作 | 实现方式 | 实测 |
|---|---|---|
| 导航 | 监听主窗口 URL 变化，从窗口跳转到同一地址 | 通过 |
| 滚动 | 上报滚动坐标，从窗口 `scrollTo` 到同一位置 | 通过（主 46 → 从 46） |
| 点击 | 用 CSS 选择器定位元素后 `.click()`，找不到时按坐标兜底 | 通过 |
| 输入 | 定位元素后填值并派发 `input` / `change` 事件 | 通过 |
| 按键 | 同步 Enter / Escape / Tab | 通过 |

**同步延迟**：可在界面设置每个从窗口之间的间隔（默认 120ms），避免同时发起请求触发风控。

**实现要点**：Chrome 155 的 `Runtime.bindingCalled` 在本环境不投递（实测收不到事件），因此改用「页面队列 + CDP 轮询拉取」。选择器定位而非坐标回放，保证不同分辨率窗口也能对准同一元素。

**使用前提**：各窗口需处于同一站点、页面结构一致。

## 回收站

删除环境不再直接销毁，改为「移入回收站」：

- 列表页的「回收」「移入回收站」都是软删除，环境从主表格消失但数据完整保留
- 回收站标签页可查看、恢复、或彻底删除
- **彻底删除**会连带删除浏览器数据目录，且必须二次确认（前端弹确认框 + 后端要求 `confirm=true`）

## Cookie 导入导出

**导出**（环境必须先停止，Chrome 会锁住 cookie 库）：

- JSON 格式：完整字段（域名、名称、值、路径、过期时间、secure、httpOnly、sameSite）
- Netscape 格式：兼容 curl / wget / 大部分工具
- 支持按域名过滤，例如只导出 `taobao.com` 的 cookie
- 批量导出：勾选多个环境一次导出到一个文件

**导入**：支持 JSON 数组和 Netscape 格式。写入前会删除同名同路径的旧 cookie，避免冲突。

**说明**：Chrome 用 DPAPI 加密 cookie 值。本工具导出时能读出明文的部分会正常显示；加密且读不出的会标记为「已加密」。跨机器迁移请走「导出明文 → 目标机导入明文」，因为加密值与机器绑定。

## 动态 IP 提取器

借鉴比特浏览器的 `dynamicIpUrl`。很多代理服务商提供「提取链接」，每请求一次返回一个可用 IP。

**配置**：环境行点「动态IP」，填提取链接并启用。之后每次启动环境都会先拉一个新 IP 再用。

**支持的返回格式**：

```
1.2.3.4:8080
1.2.3.4:8080:user:pass
user:pass@1.2.3.4:8080
1.2.3.4 3128
{"data":[{"ip":"1.2.3.4","port":8080,"username":"u","password":"p"}]}
["1.2.3.4:8080"]
```

解析出的 IP 按 SOCKS5 处理（多数提取服务返回的都是 socks5 代理）。

**SSRF 防护**（硬性约束）：提取链接只允许 http / https，拉取前解析主机名并拒绝 localhost、环回、私有、链路本地、保留地址、云元数据地址（`169.254.169.254`）。实测 7 类内网地址全部拦截。响应体限制 256 KB。

**失败处理**：提取失败时记录日志并回退到该环境的固定节点，不会导致环境起不来。

## Excel 批量导入

批量创建环境的最快方式。

**支持格式**：`.xlsx` / `.xlsm` / `.csv`

**表头**（中英文皆可，列顺序随意）：

| 列 | 必需 | 说明 |
|---|---|---|
| 环境编号 / 编号 / id | 是 | 环境唯一标识 |
| 名称 / 环境名称 | 否 | 显示名 |
| 平台 | 否 | 默认淘宝 |
| 备注 / 说明 | 否 | |
| 分组 / 组 | 否 | 自动建立分组 |
| 标签 / tag | 否 | 逗号分隔，最多 8 个 |
| 启动网址 / 网址 | 否 | 默认 https://www.taobao.com |
| 代理协议 / 协议 | 否 | socks5 / http / vless / vmess / trojan / hysteria2 / ssh |
| 代理服务器 / 服务器 / ip | 否 | |
| 代理端口 / 端口 | 否 | |
| 代理账号 / 用户名 | 否 | |
| 代理密码 / 密码 | 否 | |
| 节点名 / 节点名称 | 否 | 同名节点复用，否则按服务器信息新建 |
| 动态IP链接 / 动态ip | 否 | 自动配置动态 IP 提取器 |

**行为**：

- 已存在的环境编号会跳过，不会覆盖
- 填了代理服务器但节点池没有同名节点时，自动创建节点并绑定
- 填了动态IP链接会自动校验并启用（内网地址会被拒绝）

界面上点「Excel导入」→「下载模板」可拿到标准模板。

### 导入导出

配置备份与迁移：

- **导出**：点「导出配置」会询问是否包含凭据
  - 确定 = 完整配置（含代理密码、UUID、REALITY 公钥），妥善保管
  - 取消 = 脱敏版本（凭据替换为 `***`），适合分享排查
- **导入**：支持选文件或粘贴 JSON，已存在的环境/节点/订阅默认跳过
- **指纹保护**：导入时只补缺失的指纹，已有环境的设备身份不会被改动（避免平台触发验证）

实测往返：删除 2 个环境后导入备份，环境与指纹完整还原。

## 环境锁

给单个环境上锁，防止别人改你的配置。适合把机器借给别人、或团队协作时保护重要账号环境。
**上锁后以下操作都需要密码**：修改配置、启动、停止、换指纹、删除、改代理链。

**实现方式**：

- 密码用 **PBKDF2-HMAC-SHA256**（20 万次迭代 + 16 字节随机盐）派生后存储，配置文件里只有哈希，不存明文
- 校验用 `secrets.compare_digest` 常量时间比较，避免时序侧信道
- 密码可通过请求体 `password` 字段或 `X-Env-Password` 请求头传入
- 批量操作时，已上锁且未给密码的环境会跳过并在返回的 `locked` 列表里报告

**实测**：无密码修改、启动、换指纹全部被 403 拦截；错误密码同样拦截；正确密码和密码头方式都能通过。

**注意**：这是本地防护，不是加密。浏览器数据目录本身没有加密，能直接访问文件系统的人仍可绕过。防的是「用这个界面的人」，不是拿到机器的人。

## 多级代理链

流量经过多个代理节点中转，用于隐藏真实出口链路。最多 3 级。

**配置方式**：环境行点「链条」，按顺序添加节点。

**顺序含义**：第一个是**最终出口**，后面依次是前置中转。

```
浏览器 → 中转2 → 中转1 → 出口 → 目标网站
```

例如设 3 级 `[香港, 日本, 美国]`：流量先到美国节点，再到日本，再到香港，最后访问淘宝——淘宝看到的是香港 IP。

**实现**：用 sing-box 的 `detour` 字段串联 outbound：

```
hop2.detour = hop1
hop1.detour = hop0
route.final = hop2   ← 入口
```

三级混合协议（vless + socks5 + http）配置已通过 `sing-box check` 校验。

**保护规则**：

- 链中不能有重复节点
- 最多 3 级
- 设置了代理链时，单节点配置被忽略（链条优先）
- 点「测试连通」会临时起实例探测，返回最终出口 IP

**注意**：链条越长延迟越高，且任一环节不通整条链就断。建议先用「测试连通」确认再启动环境。

## 窗口布局管理

勾选多个已启动的环境，一键按预设方式排列窗口。用 CDP 的 `Browser.setWindowBounds` 控制，不需要额外依赖。

| 布局 | 效果 |
|---|---|
| 网格 | 自动算行列，尽量接近正方形 |
| 横向平铺 | 一行排开 |
| 纵向平铺 | 一列排开 |
| 层叠 | 每个窗口偏移 34px 叠放 |
| 聚焦 | 主窗口占满，其余最小化 |

位置基于屏幕工作区（自动扣除任务栏），最小单元 320x240 防止挤成一团。

## 成员与权限

启用后所有 API 都需要登录（Bearer token，2 小时有效）。未添加任何成员时为单用户模式，全部放行。

**角色**：

| 角色 | 能做 |
|---|---|
| 管理员 | 全部权限，可管理成员 |
| 运维 | 管理环境与节点，不能管理成员 |
| 操作员 | 启动/停止/窗口排列/云端同步 |
| 只读 | 仅查看 |

**环境级授权**：非管理员可以限定「只能操作哪些环境」，范围外一律 403。

**保护机制**：

- 密码 PBKDF2 存储（20 万次迭代），登录接口返回 token，不传密码
- 最后一个管理员不能被降级、停用或删除
- 成员被停用或删除时，其会话立即失效
- 权限在 Flask `before_request` 统一拦截，HTTP 方法 + 路径自动映射到动作

**实测**：viewer 启动环境 403、添加成员 403；admin 全部通过；登录死锁（login 被自己的权限钩子拦截）已修复。

## 云端同步（WebDAV）

把配置备份到任意 WebDAV 服务器（坚果云、群晖、Nextcloud 等）。用标准库 `http.client` 实现 PUT/GET/PROPFIND/MKCOL，零第三方依赖。

**操作**：

- 保存配置 → 测试连接 → 立即备份（文件名 `backup-时间戳.json`，同时维护 `latest.json` 指针）
- 备份列表 → 一键恢复（已有环境不覆盖，指纹保持不变，与本地导入导出同一套保护逻辑）

**安全**：

- 只允许 http/https
- 默认拒绝内网地址；NAS 在内网时打开「允许内网地址」开关
- 密码在界面打码显示，恢复接口的文件名做白名单校验防路径穿越

## 支持的协议

由本机 sing-box 1.13.19 承接，每个环境一个独立进程、独立本地端口（20000-20100）：

| 协议 | 分享链接格式 | 特性支持 |
|---|---|---|
| VLESS | `vless://uuid@host:port?params#name` | REALITY、uTLS 指纹、ws / grpc / http 传输、flow |
| VMess | `vmess://base64(json)` | TLS、ws / grpc 传输、加密方式、AlterID |
| Trojan | `trojan://password@host:port?params#name` | TLS、ws / grpc 传输、SNI |
| Hysteria2 | `hysteria2://password@host:port?params#name` | TLS、SNI、obfs |
| SOCKS5 | `socks5://user:pass@host:port#name` | 用户名密码认证 |
| HTTP | `http://user:pass@host:port#name` | 用户名密码认证 |
| **SSH** | `ssh://user:pass@host:22#name` | 账号密码或私钥登录、本地 socks 转发 |

SSH 走 sing-box 的 `ssh` outbound，可填 `username` / `password` / `privateKey` / `hostKey`。

订阅支持整体 base64 编码和明文多行两种形式。订阅 URL 只允许 http/https，且会拒绝 localhost、环回、私有、保留地址（防 SSRF）。

REALITY 公钥会做格式校验（必须是 43 位 base64url 的 x25519 公钥），填错会立即报明确错误而不是等 sing-box 启动失败。

## 指纹覆盖范围

每个环境独立随机且永久稳定（同一环境每次启动一致）：

**基础维度**
- 屏幕分辨率与 DPR（互相匹配，不出现矛盾组合）
- CPU 核心数、设备内存
- 显卡厂商与型号（WebGL UNMASKED 值）
- 语言列表、时区
- User-Agent 与 UA-CH brands
- `navigator.webdriver` 伪装为 false

**Canvas / Audio 噪声**
- Canvas `getImageData` 像素噪声 + `toDataURL` 第二重噪声
- AudioContext 指纹噪声、采样率（44100 / 48000）

**v2 新增维度**
- WebGL 参数：MAX_TEXTURE_SIZE、MAX_VERTEX_ATTRIBS、MAX_RENDERBUFFER_SIZE（每环境不同）
- 字体枚举：随机隐藏部分字体（Wingdings / Garamond / Comic Sans 等），让字体指纹有差异
- 媒体设备：摄像头 / 麦克风 / 扬声器的枚举数量与标签（伪装后 `enumerateDevices` 仍显示为 native code）
- 语音合成音色：`getVoices()` 返回的子集和顺序按环境变化

**v3 新增维度**
- ClientRects 噪声：`getBoundingClientRect` 的亚像素微扰，这是最隐蔽的指纹源之一
- 存储配额伪装：`navigator.storage.estimate()` 返回的 quota 按环境变化（120/256/512/1000 GB）
- WebRTC 四态：`proxy`（强制 relay，不泄露内网 IP）/ `disabled`（完全关闭，调用即抛错）

**v4 新增维度**
- **WebGPU 伪装**：改写 `navigator.gpu.requestAdapter()` 返回的 `adapter.info`（Chrome 113+ 新增指纹面，三家商业浏览器均已覆盖）。厂商/架构强制与 WebGL 的 GPU 厂商一致——两者矛盾是最容易被识破的破绽。实测 8/8 环境全部一致
- **端口扫描防护**：阻断页面对本机/内网端口的所有探测（`fetch` / `XMLHttpRequest` / `WebSocket` / `img.src` / `script.src` / `link.href`）。防的是页面通过探测 127.0.0.1 常见端口来判断你本机装了什么软件（指纹浏览器、远控、调试端口）。实测内网请求全部 blocked，外网正常 reached，无误伤

**v5 新增维度**
- **插件列表伪装**：按环境裁剪 `navigator.plugins` 的数量（3~5 个），同时同步 `mimeTypes` 与 `pdfViewerEnabled`，避免三者互相矛盾

**隐私保护**
- WebRTC 按环境策略生效，默认不泄露内网 IP
- 无代理时禁用非代理 UDP

## 关于 Chrome 命令行警告

如果你之前看到过「**您使用的是不受支持的命令行标记: --disable-blink-features=AutomationControlled**」：

这个标记在 Chrome 121 之后已被移除支持，Chrome 会忽略并弹警告。本工具已移除该标记，改用注入脚本覆盖 `navigator.webdriver = false`，效果完全一样且不会触发警告。

启动参数里现在不含任何已废弃的标记。

## 目录结构

```
taobao_env/
├── app.py                  Flask 服务入口
├── manager/
│   ├── fingerprint.py      指纹生成与注入脚本（v5）
│   ├── proxy.py            sing-box 配置与进程管理（支持多级链 + SSH）
│   ├── browser.py          Chrome 启动与 CDP 注入
│   ├── nodes.py            分享链接 / 订阅解析器
│   ├── node_pool.py        节点池存储
│   ├── subscription.py     订阅管理与增量同步
│   ├── syncer.py           窗口同步器
│   ├── config_io.py        配置导入导出
│   ├── cookies.py          Cookie 导入导出
│   ├── dynamic_ip.py       动态 IP 提取器（含 SSRF 防护）
│   ├── excel_io.py         Excel 批量导入
│   ├── paths.py            数据目录解析（源码 / EXE 通用）
│   └── store.py            环境配置存储（分组/标签/回收站/环境锁）
├── web/
│   └── index.html          管理界面
├── dist/
│   └── 多账号环境管理器.exe  打包产物（双击即用）
├── data/                   运行时数据（配置、浏览器 profile）
│   ├── environments.json
│   ├── fingerprints.json
│   ├── nodes.json
│   ├── subscriptions.json
│   ├── profiles/           各环境浏览器数据
│   └── singbox/            临时 sing-box 配置
├── verify_all.py           基础指纹验收
├── verify_v2.py            v2 维度验收
├── verify_v3.py            v3 维度验收
├── verify_v4.py            v4 维度验收（WebGPU / 端口防护）
├── selftest.py             基础端到端自检
├── selftest_v2.py          节点导入 / 分配 / 批量启动自检
├── selftest_sub.py         订阅 SSRF 防护自检
├── test_sub_sync.py        订阅增量同步验证
├── test_sync.py            窗口同步器实测
├── test_lock_chain.py      环境锁与代理链实测
└── test_features.py        7 项新功能端到端实测
```

## 验证

基础指纹（需先启动环境）：

```bash
python verify_all.py 9333 9334 9335 9336 9337
```

新维度指纹：

```bash
python verify_v2.py 9333 9334
```

节点导入与批量分配：

```bash
python selftest_v2.py
```

## 实测记录（2026-10-27）

5 个环境同时启动，全部 `injected=True`：

- 屏幕分辨率 **5/5 全不同**
- 硬件配置（核心+内存）**5/5 全不同**
- 显卡 4/5 不同
- UA 4/5 不同
- Canvas 哈希 5/5 全不同
- 音频噪声 5/5 全不同
- ClientRects 噪声 5/5 全不同
- 存储配额 4/5 不同
- 语言列表 5/5 不同

生成时会自动避开已有环境的「分辨率+核心+内存+显卡+UA」组合，保证多环境画像不撞车。同时内存与核心数按真实配置比例搭配，不会出现「8 核 + 2G」这类现实中不存在的组合。

## 稳定性设计

- **端口分配无竞态**：进程内已分配集合 + 实际监听探测双重保护，批量启动 5 个环境可稳定拿到 9333~9337 连续端口
- **服务重启状态不失同步**：每个环境启动时写状态文件（端口 + PID），服务重启后通过探测端口自动恢复"运行中"状态，不会出现"界面显示停止但浏览器还开着"
- **注入失败会记录**：启动日志输出 `injected=True/False`，失败时界面可查原因

## 已知限制

1. **Canvas/WebGL 是噪声级伪装**。本地 Chrome 用同一块 GPU 渲染，底层像素仍来自真实硬件。专业级检测（如 CreepJS 的多维交叉校验）有可能识别噪声模式。要完全隔离需要反检测浏览器内核（Chromium 定制版）。
2. **TLS 指纹（JA3/JA4）未修改**。Chrome 的 TLS 握手特征仍是本机特征。淘宝目前主要看 IP 和 Canvas，但深度检测可感知。
3. **字体伪装是探测层**。我们拦截的是「字体是否存在」的判断，没有真的改系统字体，专业的字体度量检测仍可能看出来。
4. **代理必须自备**。没有节点时所有环境共用本机出口 IP，这是最强的关联信号。务必每个环境配不同 IP，优先住宅或静态 IP。
5. **节点是测试数据时页面打不开**。验证代理链路是否可用请用「测代理」，节点不通时页面会显示 chrome-error。
