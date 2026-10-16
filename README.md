# CCGait · Claude 客户端环境闸门

给 Claude Code CLI 与 Claude Desktop 装一道闸门：**只有出口 IP / 国家命中白名单时，这两个客户端才能启动、才能联网**。出口不对时，闸门会结束正在运行的客户端，并在 Windows 防火墙层面按程序阻断它们的出站流量。

设计目标是「**宁可拦住自己，也不让客户端在错误的环境里跑**」。它只做检测与拦截，**不做**任何伪装。

---

## 它做什么 / 不做什么

| 做的事 | 说明 |
| --- | --- |
| 出口身份核验 | 4 个数据源（Cloudflare trace / ip-api / ipinfo / ip.sb）交叉比对出口 IP、国家、ASN、机房标记；多源不一致即视为可疑 |
| 白名单判定 | IP、CIDR、国家、ASN 四项可任意组合；任一不命中即拦截 |
| 进程执法 | 每 2 秒巡检，发现 Claude 客户端且判定不通过 → 立即终止（含子进程） |
| 网络阻断 | 用 Windows 防火墙给每个 Claude 可执行文件加「出站阻断」规则，判定通过时自动撤掉 |
| 环境特征检测 | 系统时区、界面语言、中文字体、DNS 服务器、系统代理 —— 这些是"环境与账号地区不一致"的公开特征 |
| Claude 域名解析 | 解析 claude.ai / claude.com / api.anthropic.com 并反查落地归属地，识别解析被污染 |
| 分流支持 | 可让检测与客户端都走指定代理，避免 CLI 直连暴露物理网卡出口 |

| 不做的事 | 原因 |
| --- | --- |
| 不伪造时区 / 语言 / 地区 | 那是规避服务方的区域识别，不是配置卫生；发现不一致时只报告，改不改由你决定 |
| 不改设备指纹、不 patch 客户端 | 同上 |
| 不做 IP 信誉、TLS 指纹（JA4）伪装 | 超出「配置闸门」的范围 |
| 不替你打开系统防火墙 | 那是全机安全设置，只提供显式命令并提示 |

> 一句话：CCGait 让你**在错误的环境里跑不起来**，而不是帮你**看起来没问题**。

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
| `firewall enable-profiles` | 打开 Windows 防火墙的三个配置文件（**网络阻断生效的前提**） |
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
    "blockNetwork": true,      // 防火墙按程序阻断出站（需管理员 + 防火墙开启）
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
| Windows 防火墙 | Domain/Private/Public **全部关闭** | 规则不会生效，必须先 `firewall enable-profiles` |

所以当前配置做了两件事：`network.proxy.enabled = true`（让检测和 `ccgait run` 都走你的代理），白名单按 HK+SG 放行。**要真正"固定 IP"，需要先在代理里锁定单一节点**，再把该 IP 填进 `whitelist.ips`。

---

## 建议的收紧顺序

1. **让 CLI 也走代理**：在代理客户端里打开 TUN 模式（或始终用 `ccgait run cli`）。否则 CLI 会暴露国内物理 IP。
2. **锁定单一节点**，把该 IP 填进 `whitelist.ips`，把 `requireResidential` 设为 `true`（治机房出口）。
3. **系统 DNS 换成非国内**（如 1.1.1.1 / 8.8.8.8），并把 `checks.dnsServers.severity` 提为 `"block"`。
4. **时区/语言/字体**：时区已经是欧洲，保持；语言列表里的 `zh-Hans-SG` 与中文字体属"环境特征"，如要一并拦截，把对应 `severity` 提为 `"block"`（CCGait 不会替你改系统设置）。
5. **恢复浏览器级别的一致性**：系统时区、浏览器语言、出口地区三者一致最稳。

---

## 安全与可逆性

- **只碰自己的东西**：防火墙规则名统一带前缀 `CCGait :: block :: `，删除时按前缀一次性清除，不会动用户自己的任何规则；`firewall off` / `guard` 正常退出 / `uninstall-startup` 都会清理。
- **进程白名单是路径判定**：只终止「可执行文件位于 Claude 安装目录」或「命令行引用 claude-code 包」的进程，绝不按 `node.exe` 这类通用名批量杀进程。
- **不留隐藏状态**：闸门只在运行时执法，退出时撤掉阻断（避免留下"莫名其妙上不了网"）；所有状态只写在 `.ccgait/` 下（`state.json` + 日志）。
- **失败不假装成功**：防火墙规则创建后会**回查系统实际状态**，只把真正生效的算作已阻断，失败逐条上报（这条是踩过 PowerShell 5.1 数组折叠坑之后加的）。

---

## 立项过程中踩到的 Windows 坑（都已修）

| 坑 | 现象 | 处理 |
| --- | --- | --- |
| PowerShell 5.1 数组折叠 | `$json \| ConvertFrom-Json` 把数组当成单个对象，循环只跑一轮 → 防火墙规则一条没建却报"已阻断 11 个程序" | 改用 `-InputObject` 且不套 `@()`；逐条 `-ErrorAction Stop`；**回查系统实际状态**后才算成功 |
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
│  └─ log.js            日志
├─ tests\
│  ├─ core.test.js              单测（node --test，23 项）
│  └─ firewall.integration.mjs  可选集成测试（需管理员，会真实建/删规则）
└─ .ccgait\                     运行状态与日志（自动创建）
```

## 测试

```bash
node --test                                # 单元测试，无需权限
node tests/firewall.integration.mjs        # 防火墙集成测试，需管理员
```
