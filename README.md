# CCGait · Claude 客户端环境闸门

给 Claude Code CLI 与 Claude Desktop 装一道闸门：**只有出口 IP / 国家命中白名单时，这两个客户端才能启动、才能联网**。出口不对时，闸门会结束正在运行的客户端，并在内核层按程序阻断它们的出站流量。

设计目标是「**宁可拦住自己，也不让客户端在错误的环境里跑**」。它只做检测与拦截，**不做**任何伪装。

---

## 它做什么 / 不做什么

| 做的事 | 说明 |
| --- | --- |
| 出口身份核验 | 4 个数据源（Cloudflare trace / ip-api / ipinfo / ip.sb）交叉比对出口 IP、国家、ASN、机房标记；多源不一致即视为可疑 |
| 白名单判定 | IP、CIDR、国家、ASN 四项可任意组合；任一不命中即拦截 |
| 进程执法 | 每 2 秒巡检，发现 Claude 客户端且判定不通过 → 立即终止（含子进程） |
| 网络阻断（第一层） | WFP 内核过滤器按可执行文件阻断出站，**不依赖系统防火墙是否开启** |
| 网络阻断（第二层） | Windows 防火墙「出站阻断」规则；需要管理员权限，闸门会自动开启防火墙配置文件（否则规则不生效） |
| 环境特征检测 | 系统时区、界面语言、中文字体、Emoji 国旗渲染、DNS 服务器、系统代理 —— 判定口径对齐 [ippure 的 Claude 检测](https://ippure.com/claude.html) |
| Claude 域名解析 | 解析 claude.ai / claude.com / api.anthropic.com 并反查落地归属地，识别解析被污染 |
| 分流支持 | 可让检测与客户端都走指定代理，避免 CLI 直连暴露物理网卡出口 |

**什么算硬门槛，什么只提示**

| 类别 | 项目 | 不满足的后果 |
| --- | --- | --- |
| 硬门槛（block） | 出口白名单：IP / CIDR / 国家 / ASN / 要求住宅出口；多源一致性与 failClosed；Claude 域名解析落地 | **打不开客户端，且上不了网** |
| 只提示（warn） | 系统时区、界面语言、国内字体、Emoji 国旗渲染、本机 DNS 服务器、系统代理/分流覆盖 | 只在报告里列出，**不拦截、不门控** |

中文用户环境这几项之所以不门控：它们衡量的是"这台机器的特征"，而改时区、删系统字体属于改系统设置 —— 不该由闸门替你决定能不能用。要更严就把 `checks.<项>.severity` 改成 `block`（界面上「检查项严重度」面板可以逐项切换）。

| 不做的事 | 原因 |
| --- | --- |
| 不伪造时区 / 语言 / 地区 | 那是规避服务方的区域识别，不是配置卫生；发现不一致时只报告，改不改由你决定 |
| 不改设备指纹、不 patch 客户端 | 同上 |
| 不做 IP 信誉、TLS 指纹（JA4）伪装 | 超出「配置闸门」的范围 |

> 一句话：CCGait 让你**在错误的环境里跑不起来**，而不是帮你**看起来没问题**。

---

## 两道阻断，为什么不只用防火墙

Windows 防火墙规则**只在对应配置文件启用时才生效**——实测把三个 profile 全关掉后，规则被完全忽略，客户端照样能联网。所以第一层阻断不放在防火墙上，而是用 Windows 过滤平台（WFP）在 `ALE_AUTH_CONNECT` 层挂会话级过滤器：

| | WFP 内核过滤器（第一层） | Windows 防火墙规则（第二层） |
| --- | --- | --- |
| 需要防火墙开启 | 不需要 | 需要；`enableFirewallProfiles=true` 时闸门会自己打开三个 profile |
| 作用域 | 只拦指定可执行文件的出站连接 | 只拦指定可执行文件 |
| 持久化 | 不持久化：宿主进程一退出，过滤器自动消失 | 写进系统规则，需显式删除 |
| 恢复方式 | 宿主退出即恢复 | `ccgait firewall off` |

两层默认都开（`blockNetwork: true` + `firewallRules: true`）。都是**按程序**拦截，不会影响机器上其它软件联网。生命周期刻意做成「进程即策略」：宿主活着就拦，宿主一退出就恢复，不会给机器留下"莫名其妙上不了网"的状态。

这里有一个必须写清楚的实现要点：**WFP 会话必须是动态会话（`FWPM_SESSION_FLAG_DYNAMIC`）**。早期版本用普通会话加非持久过滤器，看起来"进程退出就该自动清理"，但实测宿主被**硬杀**（任务管理器结束进程、或按进程名清扫）时过滤器会**永久留在内核里**：机器上某个程序从此连不上网，而进程列表里看不到任何宿主，排查起来毫无头绪。本机就因此留下过 30 条过滤器，覆盖 15 个可执行文件（包括 `System32\curl.exe`）。改成动态会话后，会话一结束对象由 BFE 自动回收，硬杀也不会残留。

```bash
node src/cli.js wfp on      # 对发现的所有 Claude 客户端建立阻断
node src/cli.js wfp status  # 看当前是否生效
node src/cli.js wfp off     # 解除（会按进程名扫干净，不留孤儿宿主）
node src/cli.js wfp purge   # 兜底：删掉本工具遗留在内核里的所有过滤器
```

`wfp on` 需要管理员权限；`guard` 常驻执法时会自动管理这道阻断，不需要手动执行。若升级前用过旧版本、怀疑某个程序"莫名其妙上不了网"，跑一次 `wfp purge` 即可（会报告删掉几条）。

**界面上怎么看出当前状态**：操作面板顶部有一条状态条，直接写「闸门 运行中/未运行 · 网络阻断 生效中/未生效 · 系统防火墙 已开/已关」；按钮本身也带状态 —— 已经在生效的动作会变成实心绿底的「已阻断网络（N 个程序）」并置灰（再点没有意义），而「解除阻断」在没有阻断时是禁用状态。这两处都是从 `/api/status` 的 `networkBlock` 字段读的实时值（WFP 与防火墙规则任一层在生效就算生效中），不是界面自己猜的。

**「Claude 客户端现状」面板**回答两个最直接的问题，并附带拦截记录：

| 结论 | 怎么算出来的 |
| --- | --- |
| 能否打开 Claude | 闸门是否在执法 + 判定是否通过 + 是否配置了「终止客户端进程」。闸门没在跑时会如实写"没有执法在生效"，避免误以为有闸门在保护 |
| 能否访问网络 | 只看当前有没有生效中的阻断（WFP 或防火墙规则）—— 它与判定无关：即使闸门没跑，之前手动建的阻断依然会让它连不上网 |

两个结论都由服务端算好（`/api/status` 的 `claudeAccess`），界面只负责显示 —— 否则"界面显示可以打开、闸门却在杀进程"这种事迟早会发生。

**拦截记录**直接复用日志文件：`block`/`warn` 级别的条目就是"发生过拦截或被拦下的动作"，界面启动时从 `.ccgait/ccgait-*.log` 回填最近 80 条，之后实时追加（闸门内部的执法动作也经同一个日志漏斗登记）。所以它是**跨重启保留**的，不需要另建一套存储。

---

## Windows 客户端与安装包

打包好的客户端是**单个安装程序**，双击即可：

```
dist\CCGaitSetup.exe        安装程序（341 KB，内嵌全部运行时文件）
dist\CCGaitClient.exe       客户端本体（安装时一并部署）
```

安装程序做的事：

| 步骤 | 说明 |
| --- | --- |
| 解包 | 29 个运行时文件写入 `%LOCALAPPDATA%\Programs\CCGait`（**按用户安装，不需要管理员 / 不弹 UAC**） |
| 配置 | 首次安装从示例生成 `config.json`（默认只允许英国、要求住宅出口）；已存在则不覆盖 |
| 快捷方式 | 开始菜单 + 桌面 `CCGait.lnk`（勾选项可取消桌面） |
| 开机自启 | **默认勾选**：写 HKCU 的 Run 项，登录后自动启动托盘；可在「任务管理器 → 启动应用」里随时关闭 |
| 卸载项 | 注册到 HKCU 卸载表，出现在「设置 → 应用 → 已安装的应用」，卸载程序随安装部署并支持自删除 |
| 自检 | 检测 Node.js（需要 20+），缺失时给出提示与下载地址 |

客户端两种形态（同一个 exe）：

- `CCGaitClient.exe` —— 启动本地服务并打开**应用窗口**（Edge/Chrome 的 APP 模式：无地址栏、无标签页、独立任务栏图标，关闭窗口不影响闸门）
- `CCGaitClient.exe tray` —— **托盘常驻**：图标显示判定与出口、右键菜单（立即检测 / 启停闸门 / 阻断网络 / 终止进程 / 开机自启开关 / 打开界面 / 打开配置）、只有「放行 → 拦截」翻转时弹气泡
- `CCGaitClient.exe startup on|off|status` —— 脚本化控制开机自启（退出码即状态）

界面风格与 MoA Studio 一致：左侧导航栏 + 白色卡片 + 圆角药丸徽章 + 深色主按钮。

### 从源码运行（开发用，不需要打包）

```bash
node src/cli.js desktop      # 应用窗口
node src/cli.js tray         # 托盘（PowerShell 版，开发时用）
node src/cli.js ui           # 只在浏览器里打开
```

### 重新打包

```bash
node src/cli.js build-installer      # 或 node --input-type=module -e "..." 见 src/win/build.js
```

打包链路**不依赖任何外部工具链**：编译器用 .NET Framework 自带的 `csc.exe`，
图标由 `src/win/icon.js` 手写 PNG/ICO 编码器生成，载荷用自定义文本格式内嵌。

## 安装与快速开始

无需依赖，只用 Node 内置模块（Node ≥ 20，本机 Node 24 可直接跑）：

```bash
cd D:\CCGait
node src/cli.js init          # 从 config.example.json 生成 config.json
# 编辑 config.json：填 whitelist.ips / countries
node src/cli.js check         # 只读检测：看当前出口与环境特征，给出判定
node src/cli.js guard         # 常驻执法（前台运行，Ctrl+C 退出时会撤掉阻断）
```

做成开机常驻（推荐，否则只在手动运行时生效）：

```bash
# 以管理员身份运行一次，注册登录自启（计划任务，ONLOGON + 最高权限 + 延迟 30 秒）
node src/cli.js install-startup
node src/cli.js status        # 查看闸门/规则/自启状态
node src/cli.js uninstall-startup
```

---

## 命令一览

| 命令 | 作用 |
| --- | --- |
| `check [--json] [--proxy <url>] [--no-proxy]` | 只读检测 + 判定；`--proxy` 用别的出口试算，不写配置 |
| `guard [--once] [--keep-blocks]` | 常驻执法；`--once` 跑一轮就退出 |
| `status [--json]` | 闸门进程、防火墙规则、发现的客户端路径、自启状态、最近判定 |
| `targets` | 列出发现的所有 Claude 可执行文件（含 MSIX/Squirrel/npm 各种安装方式） |
| `kill` | 立即终止正在运行的 Claude 客户端 |
| `firewall on\|off\|list` | 手动建立 / 解除 / 查看 CCGait 的阻断规则 |
| `firewall enable-profiles` | 打开 Windows 防火墙的三个配置文件（仅 `enforcement.firewallRules` 需要） |
| `wfp on\|off\|status` | 手动建立 / 解除 / 查看 WFP 内核过滤器阻断（**不依赖防火墙**） |
| `run cli\|desktop [args]` | 判定通过才启动客户端，并注入分流代理 |
| `install-startup` / `uninstall-startup` | 注册 / 移除登录自启 |

退出码：`0` = 放行，`2` = 拦截，`1` = 执行出错。可以直接用在脚本里做前置判断。

---

## 配置说明（config.json）

```jsonc
{
  "whitelist": {
    "ips": [],                 // 固定出口 IP；非空时换个 IP 就被拦
    "cidrs": [],               // 网段，如 "203.0.113.0/24"
    "countries": ["HK", "SG"], // 允许的国家/地区（ISO 两位代码）
    "asns": [],                // 允许的 ASN，如 "AS15169"
    "requireResidential": true // 默认开启：机房/代理出口也算不通过
  },
  "checks": {
    // enabled 控制是否检测；severity = "block" 不通过即拦截，"warn" 只报告
    "egressIp":     { "enabled": true, "severity": "block" },
    "claudeDns":    { "enabled": true, "severity": "block", "deniedCountries": ["CN"] },
    "timezone":     { "enabled": true, "severity": "warn" },
    "language":     { "enabled": true, "severity": "warn" },
    "fonts":        { "enabled": true, "severity": "warn" },
    "dnsServers":   { "enabled": true, "severity": "warn" },
    "proxyEnvLeak": { "enabled": true, "severity": "warn" }
  },
  "enforcement": {
    "killProcesses": true,     // 终止客户端进程
    "blockNetwork": true,      // 判定不通过就断它的网（走 WFP 内核过滤器，不需要防火墙）
    "firewallRules": false,    // 是否额外写 Windows 防火墙规则（需管理员 + 防火墙开启）
    "failClosed": true,        // 判定不出结果也拦（更安全）
    "pollIntervalMs": 2000,    // 进程巡检间隔
    "recheckIntervalMs": 30000 // 网络复检间隔
  },
  "network": {
    "proxy": { "enabled": true, "url": "http://127.0.0.1:7890", "required": false }
  },
  "runtime": { "stateDir": "", "logRetentionDays": 7 }
}
```

`$comment*` 键会被忽略，可以随便写说明。

**判定语义**

- 白名单为空 → 任何出口都不通过（配置校验会提示）。
- `countries` 只写国家 → 出口在该国家就通过（IP 会变也不影响）。
- `ips` / `cidrs` 一旦非空 → 出口必须落在其中，否则拦截。**这才是「固定 IP」的真正开关**。
- `failClosed: true` 时，查询失败或 4 个数据源互相矛盾都按拦截处理。

---

## 本机实测结论（重要）

首次运行 `check` 得到的真实情况：

| 维度 | 实测值 | 含义 |
| --- | --- | --- |
| 直连出口 | `111.0.116.114` · CN · 中国移动 · 移动网络 | 物理网卡出口在国内。**Claude Code CLI 默认不走系统代理**，所以不给它指定代理时会以这个 IP 出去 |
| 经 `127.0.0.1:7890` 出口 | 先 `50.7.250.107`(HK)，后 `66.90.98.106`(SG)，均为 FDCservers 机房 | 代理在**节点间轮换**，不是固定 IP；且都是机房 IP |
| Claude 域名解析 | 三个域名都解析到 `160.79.104.10`(US) | 解析未被污染 |
| 系统时区 | Europe/London | 已经是非国内时区 |
| 界面语言 | en-US、zh-Hans-SG | 列表里仍有中文 |
| 中文字体 | 等线 DengXian ×3、MiSans | 命中"国内专有字体" |
| DNS 服务器 | 119.29.29.29（腾讯）等 | 解析走国内服务器 |
| 系统代理 | 127.0.0.1:7890 已开启 | 系统代理只覆盖走 WinINET 的程序，**CLI 不在其列** |
| Windows 防火墙 | Domain/Private/Public **全部关闭** | 防火墙规则不会生效 —— 所以第一层走 WFP，不依赖这个开关；第二层打开时闸门会自动把 profile 打开 |

所以当前配置做了两件事：`network.proxy.enabled = true`（让检测和 `ccgait run` 都走你的代理），白名单按 HK+SG 放行。**要真正"固定 IP"，需要先在代理里锁定单一节点**，再把该 IP 填进 `whitelist.ips`。

**一个真实踩过的坑（"网站通过了，闸门却不过"）**：配置里写了走 `127.0.0.1:7890` 代理，但代理进程后来关了 —— 浏览器直连照样能上网（出口仍是英国 IP），而闸门的探针坚持走那条死代理，于是四个数据源全部 `ECONNREFUSED`，被判"出口未知"并按 failClosed 拦截。看起来像"策略判错了"，其实是**探针走了死路**。

现在的处理：
- `network.proxy.required = false` 时代理连不上会**回退直连**，并按真实出口判定，同时在报告里明确写出"代理连不上，本次按直连出口判定"（这条语义以前只在配置注释里写着，代码没实现，已修）；
- `required = true` 时不回退：拿不到代理就按拦截处理，符合"必须走代理"的预期；
- 界面在出口查不到时会直接点名"配置的代理 X 连不上"，而不是只丢一个"未通过"。

**拦截能力的实测证据**（真跑出来的，不是推断）：

| 断言 | 实测结果 |
| --- | --- |
| 防火墙三个 profile 全关时，规则是否还有效 | **无效**。规则在，程序照样联网 —— 这是不把阻断放在防火墙上的直接原因 |
| WFP 过滤器在防火墙全关时能否断网 | **能**。同一个程序：加阻断前 `HTTP 200` → 阻断中连接失败（curl 退出码 7）→ 解除后 `HTTP 200` |
| 阻断期间宿主是否必须存活 | **必须**。过滤器随会话消失，宿主一退出阻断立即失效，所以宿主被设计成常驻 |
| 能否识别并终止真实的 Claude 客户端 | **能**。用真实 Claude Code CLI 进程实测：识别为 `cli` → 终止 → 确认消失，机器上无残留客户端进程 |
| 解除后是否干净 | **干净**。宿主进程 0 个、pid/停止文件 0 个、防火墙规则 0 条、防火墙开关回到原状态 |
| 宿主被硬杀后是否残留 | **不残留**。动态会话下硬杀宿主，过滤器随会话消失，网络立即恢复（早期版本会永久残留 30 条，已修） |

对应的可复现脚本是 `tests/wfp.integration.mjs`（需管理员），断言链就是上面这几条；`tests/e2e-guard.mjs` 再补一条"真实客户端被杀 + 真断网 + 收尾复原"的完整链路。

---

## 建议的收紧顺序

1. **让 CLI 也走代理**：在代理客户端里打开 TUN 模式（或始终用 `ccgait run cli`）。否则 CLI 会暴露国内物理 IP。
2. **锁定单一节点**，把该 IP 填进 `whitelist.ips`，把 `requireResidential` 设为 `true`（治机房出口）。
3. **系统 DNS 换成非国内**（如 1.1.1.1 / 8.8.8.8），并把 `checks.dnsServers.severity` 提为 `"block"`。
4. **时区/语言/字体**：时区已经是欧洲，保持；语言列表里的 `zh-Hans-SG` 与中文字体属"环境特征"，如要一并拦截，把对应 `severity` 提为 `"block"`（CCGait 不会替你改系统设置）。
5. **恢复浏览器级别的一致性**：系统时区、浏览器语言、出口地区三者一致最稳。

---

## 安全与可逆性

- **只碰自己的东西**：防火墙规则名统一带前缀 `CCGait :: block :: `，删除时按前缀一次性清除，不会动用户自己的任何规则；WFP 过滤器只挂在 Claude 客户端的可执行文件上，且不持久化。`firewall off` / `wfp off` / `guard` 正常退出 / `uninstall-startup` 都会清理。
- **进程白名单是路径判定**：只终止「可执行文件位于 Claude 安装目录」或「命令行引用 claude-code 包」的进程，绝不按 `node.exe` 这类通用名批量杀进程；shell 与编辑器（bash / powershell / cmd / explorer / Code / Windows Terminal）即使命令行里出现过 claude-code 路径也不会被误判。
- **不留隐藏状态**：闸门只在运行时执法，退出时撤掉阻断（避免留下"莫名其妙上不了网"）；所有状态只写在 `.ccgait/` 下（`state.json` + 日志）。`wfp off` 会按进程名再扫一遍，确保没有孤儿宿主继续挂着过滤器。
- **失败不假装成功**：防火墙规则创建后会**回查系统实际状态**，只把真正生效的算作已阻断，失败逐条上报（这条是踩过 PowerShell 5.1 数组折叠坑之后加的）。

---

## 立项过程中踩到的 Windows 坑（都已修）

| 坑 | 现象 | 处理 |
| --- | --- | --- |
| PowerShell 5.1 数组折叠 | `$json \| ConvertFrom-Json` 把数组当成单个对象，循环只跑一轮 → 防火墙规则一条没建却报"已阻断 11 个程序" | 改用 `-InputObject` 且不套 `@()`；逐条 `-ErrorAction Stop`；**回查系统实际状态**后才算成功 |
| WFP 的 P/Invoke 默认 ANSI | `FwpmGetAppIdFromFileName0` 返回 `0x2`（找不到文件），中文路径全废 | 所有 P/Invoke 显式 `CharSet = CharSet.Unicode` |
| WFP 层与条件的 GUID 记错 | `FWP_E_LAYER_NOT_FOUND`（`0x80320004`），过滤器一条都建不上 | 从本机 SDK 头文件取权威 GUID，并用 `probe-layer` 自检层名 |
| 分离进程的 stdin 是 NUL | `hold` 里用 `Console.In.ReadLine()` 等停止信号，分离启动后立刻 EOF → 宿主秒退、过滤器随之消失（而探针还显示"在线"，看起来像拦截没生效） | 改成轮询停止文件 `--stop-file`，宿主常驻直到被明确要求退出 |
| 只 unref 不拆管道 | `ccgait wfp on` 打完日志不退出；管道接到 `head` 时会永久挂住 | detached 后先 `stdout/stderr.destroy()` 再 `unref()` |
| 非动态会话 + 硬杀 = 永久残留 | 宿主被任务管理器结束（或我方按名清扫）后过滤器留在内核里，某个程序从此连不上网，且看不到任何宿主进程 —— 本机留下 30 条、覆盖 15 个可执行文件，一开始误判成"网络故障" | 引擎改用动态会话（`FWPM_SESSION_FLAG_DYNAMIC`），对象随会话自动回收；另加 `wfp purge` 兜底清理旧版本残留 |
| 结构体偏移靠猜 | `FWPM_FILTER0` 里 `providerKey` 是指针、`filterId` 在 176 而不是 168，猜错导致 purge 一条都删不掉（还扫描了 294 条） | 偏移一律取自本机 SDK 头文件 `shared\fwpmtypes.h`，并加 `list-filters` 自检命令 |
| pid 文件与真实宿主不一致 | 两个宿主并存，`off` 只杀得掉一个，另一个继续挂着过滤器 | 建立前先按进程名扫掉孤儿；`off` 无论 pid 文件写了什么都再全量扫一遍 |
| 探针用 `claude doctor` 测进程发现 | 该命令不到 1 秒就退出，进程发现永远"失败"，是假阴性 | 用长驻的真实客户端进程（`mcp serve`）做断言目标 |
| 探针用 `System32\curl.exe` | 该路径可能被别的软件定向拦截，测试会误报成"网络故障" | 测试自己复制一份 curl 到 `.ccgait\probe-curl.exe` 当探针 |
| `Get-NetFirewallProfile` 的 Enabled 序列化成整数 | 该字段是 `GpoBoolean` 枚举，`ConvertTo-Json` 给的是 `1/0` 而不是 `true/false`，于是 `=== true` 永远为假：**防火墙关着时读数正确、一打开就报"已关"** | 归一化函数 + 单元测试钉住（`normalizeProfileEnabled`） |
| 报"已终止 0 个"却列着 PID | 进程在 taskkill 执行前已自行退出，被算成"没杀到" | 区分"我们杀掉的"和"本来就已退出的"，日志分别说明 |
| 探针走了死代理 | 配置指向 `127.0.0.1:7890` 但代理已关，四个数据源全 `ECONNREFUSED`，被判"出口未知"而拦截 —— 看起来像"策略判错" | 实现 `proxy.required=false` 的回退语义（回退直连并按真实出口判定），并在界面点名"配置的代理 X 连不上" |
| 日志框字体没有中文字形 | 安装程序日志框用 `Consolas`，它没有中文字形且 WinForms 不会自动回退，中文全渲染成 `□`（`GetGlyphIndicesW` 实测 4/4 缺字形） | 日志框改用 `Microsoft YaHei UI`（实测 0/4 缺），并把"产物里必须有雅黑、不能有 Consolas"写进 `verify-payload.mjs` |
| 升级安装被自己的进程挡住 | 安装时提示 `The process cannot access the file 'CCGaitWfp.exe' because it is being used by another process` —— .NET 的英文异常，用户完全不知道要做什么 | 安装前检测安装目录里正在运行的进程，弹框说明"需要先结束它（托盘会消失、生效中的阻断会被撤掉）"并询问；同意后先走 CLI 的 `guard-stop` 收尾再结束进程，写入失败还会重试并给出中文可操作提示 | `/api/status` 一次要 **14 秒**：`Get-NetFirewallRule` 会把全部防火墙规则拉出来在 PowerShell 侧过滤（单项 13.7 秒）。界面每次刷新都调它，于是永远显示过期状态 —— 用户看到"可以访问网络"而实际已被断网 | 规则枚举改用 COM（`HNetCfg.FwPolicy2`，**0.46 秒**）、防火墙 profile 也改 COM（2.3 秒 → 0.43 秒），`/api/status` 降到 **1.6 秒**；轮询从 15 秒缩到 8 秒并去掉"后台标签页不轮询"的判断；再加服务端状态监视（6 秒）主动广播变化 |
| 阻断是别的实例建的，界面看不出来 | 安装版托盘的闸门建立的阻断不触发本界面的任何事件，界面只能靠轮询发现；用户点「解除阻断」会被对方立刻重建，看起来像"点了没反应" | 状态里区分"本界面建立的阻断"与外部阻断，卡片直接写明"这个阻断不是本界面建立的（很可能是安装版托盘的闸门在维持）" |
| 打包中途失败留下混合版本 | 构建脚本开头就清空 `dist/build`，exe 被运行中的宿主占用而编译失败时，`dist` 会留下"新客户端 + 旧安装包（内嵌旧载荷）" | 全部产物先编到暂存目录，全部成功后才一次性发布；失败时 dist 原样不动并提示是谁占用 |
| `listWfpHosts` 把一次性调用当常驻宿主 | `purge`/`check` 也叫 `CCGaitWfp.exe`，按名匹配会误报"阻断生效中"，还可能让清扫杀掉正在跑的 purge | 按命令行里是否有 `hold` 判定常驻宿主，另留 `listWfpProcesses` 用于排查 |
| 非 Unicode 程序语言（本机 ACP=1252） | 含中文的 `.lnk` 经 WScript.Shell 创建时中文变 `?`，`Save()` 抛 FileNotFoundException | 快捷方式名与描述一律 ASCII；中文只出现在 Unicode 的界面里 |
| csc 读源码的默认编码 | 按 ANSI 解析会毁掉界面里的中文 | 编译前把源码写成带 UTF-8 BOM 的副本再交给 csc |
| 卸载程序自删除 | 运行中的 exe 删不掉自己，残留 341 KB | 交给延迟 2 秒的 `cmd` 在进程退出后删除，`rmdir` 只在目录空时生效 |
| 托盘/闸门文件占用 | 卸载时提示"文件被占用" | 卸载先结束自家客户端进程，再按 CLI 语义停止闸门（撤掉防火墙阻断） |
| 操作按钮重建丢点击 | 状态每次刷新销毁重建按钮，点击落在重建瞬间会丢 | 按钮只创建一次，之后仅更新文案/禁用/加载态 |

## 目录结构

```
D:\CCGait\
├─ config.json / config.example.json   白名单与策略
├─ src\
│  ├─ cli.js            命令行入口
│  ├─ config.js         配置加载/校验 + IP、CIDR 工具
│  ├─ providers.js      出口身份多源核验 + Claude 域名解析落地
│  ├─ environment.js    时区/语言/字体/DNS/系统代理 检测
│  ├─ verdict.js        白名单判定引擎
│  ├─ claude-targets.js Claude 可执行文件发现 + 进程归类
│  ├─ process-guard.js  进程枚举与终止
│  ├─ firewall.js       Windows 防火墙按程序阻断（含回查）
│  ├─ guard.js           守护循环 + 状态文件
│  ├─ startup.js        登录自启（计划任务 + 隐藏启动器）
│  ├─ win\
│  │  ├─ wfp.js          WFP 阻断的生命周期管理
│  │  └─ native\CCGaitWfp.cs   WFP 内核过滤器宿主（C#）
│  └─ log.js            日志
├─ tests\
│  ├─ core.test.js              单测（node --test）
│  ├─ ui.test.js / windows-client.test.js
│  ├─ wfp.integration.mjs       可选集成测试（需管理员，会真实挂/撤过滤器）
│  ├─ firewall.integration.mjs  可选集成测试（需管理员，会真实建/删规则）
│  └─ e2e-guard.mjs             可选端到端测试（需管理员，会终止真实客户端进程）
└─ .ccgait\                     运行状态与日志（自动创建）
```

## 测试

```bash
node --test                             # 单元测试，无需权限
node tests/verify-payload.mjs           # 安装包完整性：载荷与 exe 是否含最新修复，无需权限
node tests/wfp.integration.mjs          # WFP 拦截集成测试，需管理员
node tests/firewall.integration.mjs     # 防火墙集成测试，需管理员
node tests/e2e-guard.mjs                # 端到端：真实客户端被杀 + 真断网 + 收尾复原，需管理员
```

`verify-payload.mjs` 值得单独说一句：载荷里的文件内容是 base64 的，所以"直接在载荷里 grep 源码字符串"永远查不到东西，会误判成缺失。这个脚本解码后核对 JS 源码、**编译后的 exe**（.NET 字符串是 UTF-16）和 README，专门防"改了源码忘了重新打包"。

三个集成测试都会**真的改变机器状态**（挂过滤器 / 建规则 / 终止进程），所以不放进 `node --test`。它们跑完都会把状态恢复干净，并在恢复失败时明确报错，而不是假装通过。

`e2e-guard.mjs` 会终止本机正在运行的 Claude 客户端进程，跑之前请先保存 Claude Code / Claude Desktop 里的工作。它最近一次在本机的运行结果是 **15/15 项通过**。
