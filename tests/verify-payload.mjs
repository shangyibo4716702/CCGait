#!/usr/bin/env node
/**
 * 安装包完整性检查（无需管理员）：
 *   node tests/verify-payload.mjs
 *
 * 为什么需要它：`dist/build/payload.txt` 里文件内容是 **base64** 的，所以"用 grep 在载荷里
 * 搜源码字符串"本身查不到东西（看起来像"缺失"，其实是查法错了）。这个脚本解码后再核对，
 * 用来防一类很容易发生的事故：改了源码但忘了重新打包，装出来的还是旧版本。
 *
 * 检查三类东西：
 *   1. JS 源码 → 解码后按文本核对关键实现；
 *   2. C# 客户端 / WFP 助手 → 核对**编译后的 exe**（.NET 字符串是 UTF-16，要按 UTF-16 搜）；
 *      .cs 源文件本来就不进载荷，它们被编进 exe 了。
 *   3. README → 核对文档里的关键说明。
 */
import { existsSync, readFileSync } from 'node:fs'

const payloadPath = new URL('../dist/build/payload.txt', import.meta.url)
if (!existsSync(payloadPath)) {
  console.log('跳过：没有 dist/build/payload.txt（先执行 node src/cli.js build-installer）')
  process.exit(0)
}

const raw = readFileSync(payloadPath, 'utf8')
const files = new Map()
let current = null
let buffer = []
const flush = () => {
  if (current) files.set(current, Buffer.from(buffer.join(''), 'base64'))
  buffer = []
}
for (const line of raw.split(/\r?\n/)) {
  if (line.startsWith('##FILE ')) {
    flush()
    current = line.slice(7).trim()
    continue
  }
  if (current && line.trim()) buffer.push(line.trim())
}
flush()

const textHas = (name, needle) => Boolean(files.get(name)?.toString('utf8').includes(needle))
const binaryHas = (name, needle) => {
  const data = files.get(name)
  if (!data) return false
  // .NET 字符串字面量是 UTF-16LE；中文与 ASCII 都按 UTF-16 查。
  return data.includes(Buffer.from(needle, 'utf16le'))
}

const checks = [
  ['src/firewall.js', 'normalizeProfileEnabled', '防火墙状态读数修复（GpoBoolean 被序列化成 1）'],
  ['src/firewall.js', 'HNetCfg.FwPolicy2', '规则枚举改用 COM（13.7 秒 → 0.9 秒）'],
  ['src/ui/session.js', 'startWatching', '阻断状态变化主动广播（不等轮询）'],
  ['src/ui/session.js', 'externalBlock', '界面：说明阻断来自别的实例'],
  ['src/ui/public/app.js', '!visibilityState', '界面：后台标签页也要轮询（不该有这个判断）'],
  ['src/config.js', "dnsServers: 'warn'", '本机 DNS（配置口径）默认只提示、不参与拦截'],
  ['src/config.js', 'enableFirewallProfiles', '第二层防火墙规则自动开启 profile'],
  ['src/config.js', 'emojiFlags', 'Emoji 国旗渲染检查项'],
  ['src/providers.js', 'proxyFallback', '代理连不上时回退直连'],
  ['src/providers.js', 'probeResolverEgress', '解析出口（实测）：与参考网站 DNS LEAK 对齐的硬门槛'],
  ['src/verdict.js', 'resolver-egress-denied', '解析出口落在被禁地区即拦截'],
  ['src/guard.js', '已开启 Windows 防火墙配置文件', '闸门开启防火墙 profile'],
  ['src/guard.js', '已处理 ', '进程处理日志（不再报"已终止 0 个"）'],
  ['src/verdict.js', 'emoji-flags-suspect', 'Emoji 判定规则'],
  ['src/environment.js', 'probeEmojiFont', 'Emoji 字体资产探测'],
  ['src/environment.js', 'isPublicDnsAddress', 'DNS 检查：只统计已连接网卡的公共解析器（IPv4+IPv6）'],
  ['src/firewall.js', 'firewallRulesUpToDate', '第二层：规则齐全时不重写（省掉每轮十几秒）'],
  ['src/guard.js', 'checking', '一轮判定串行执行（避免并发起多个 WFP 宿主）'],
  ['src/win/wfp.js', 'purgeWfpFilters', '遗留过滤器清理'],
  ['src/win/wfp.js', 'listWfpProcesses', '区分常驻宿主与一次性调用'],
  ['src/cli.js', 'WFP 内核阻断：', 'CLI firewall on/off 同时管理两层'],
  ['src/cli.js', 'guard-start', '启动闸门改由常驻界面服务进程承担'],
  ['src/guard.js', 'guard-start.request', '启动请求文件（与停止请求对称）'],
  ['src/guard.js', 'blockFirst', '判定前先挂 WFP 过滤器（block-first，关掉"还没出结果"的空窗）'],
  ['config.example.json', 'blockFirst', '配置示例：block-first 开关'],
  ['src/ui/session.js', 'guardStartRequestPath', '服务进程巡检启动请求并建自己的闸门'],
  ['src/ui/session.js', 'wfpOrphan', '界面：宿主与 pid 记录不一致时可见'],
  ['src/ui/session.js', 'stopWfpBlock', '界面：解除阻断同时撤掉 WFP'],
  ['src/ui/public/app.js', '白名单比对', '界面：白名单逐项命中'],
  ['src/ui/public/app.js', 'tag-detail', '界面：每格结论标签带判定原文'],
  ['src/ui/public/app.js', 'detail-card', '界面：环境逐条明细卡片（对齐参考站分区样式）'],
  ['src/ui/public/app.js', '解析服务器归属地', '界面：解析出口逐条列出 IP + 归属地'],
  ['src/ui/public/styles.css', 'env-section', '界面：环境分区样式'],
  ['src/ui/public/app.js', 'proxyFallback', '界面：代理回退说明'],
  ['src/ui/public/app.js', 'renderStateStrip', '界面：操作面板状态条'],
  ['src/ui/public/app.js', '已阻断网络', '界面：按钮显示阻断状态'],
  ['src/ui/public/app.js', 'renderClaudeAccess', '界面：客户端现状（能否打开/联网）'],
  ['src/ui/public/app.js', 'interception-list', '界面：拦截记录列表'],
  ['src/ui/session.js', 'buildClaudeAccess', '服务端：客户端可用性结论'],
  ['src/ui/server.js', 'favicon', '应用窗口任务栏图标（页面图标，APP 模式窗口用）'],
  ['src/win/icon.js', 'distanceToPolyline', '图标：白色描边盾牌（线稿风格、小尺寸不糊）'],
  ['src/win/icon.js', 'strokeProfile', '图标：按尺寸分档给线宽（小尺寸更粗，才不发虚）'],
  ['src/win/icon.js', 'buildFaviconIco', '页面 favicon：只给小档以上的图，避免任务栏放大发糊'],
  ['src/win/icon.js', 'supersample', '图标：抗锯齿强度按尺寸分档（小尺寸 2×，避免灰边糊开）'],
  ['src/ui/session.js', 'launchClaudeDesktop', '服务端：门控启动（先判定后启动）'],
  ['src/ui/public/index.html', 'launch-desktop', '界面：启动 Claude Desktop 按钮'],
  ['src/ui/session.js', 'checkInternal', '门控启动复用检测（避免串行队列死锁）'],
  ['src/ui/session.js', 'readInterceptionsFromLog', '拦截记录跨重启回填'],
  ['src/ui/public/index.html', 'sec-access', '界面：客户端现状面板'],
  ['src/guard.js', 'isDefiniteViolation', '只有"确认违规"才终止进程（抖动只断网）'],
  ['src/guard.js', 'violationSignature', '同一违规原因连续出现才累计（换原因清零）'],
  ['src/guard.js', 'KILL_CONFIRM_ROUNDS', '终止进程要求连续确认多轮'],
  ['src/guard.js', 'KILL_WORTHY_REASON_IDS', '只有出口身份不符才杀进程（DNS/代理问题只断网）'],
  ['src/guard.js', 'Claude 未运行，浏览器暂不纳入管控', '浏览器只在 Claude 运行时才断网'],
  ['src/win/wfp.js', 'shouldReuseWfpHost', '宿主复用前核对浏览器管控状态'],
  ['src/sessions-sync.js', 'copySessions', '会话同步：只搬索引，正文留在共享区'],
  ['src/proxy-mode.js', 'probeProxyMode', '代理全局模式检查：识别规则模式下的直连泄露'],
  ['src/proxy-mode.js', 'judgeProxyMode', '代理模式判定（unknown 不拦，避免误杀）'],
  ['src/proxy-mode.js', 'readProxySettings', '代理 IPv6 / DNS 覆写开关读取'],
  ['src/proxy-mode.js', 'judgeProxySettings', '代理开关三项判定'],
  ['src/providers.js', 'probeResolverEgressSampled', '解析出口采样探测（抓间歇性泄露）'],
  ['src/sessions-sync.js', 'listSessionGroups', '会话同步：按账号/组织定位索引目录'],
  ['src/ui/public/index.html', 'sync-modal', '界面：会话同步弹层（手动勾选）'],
  ['src/accounts.js', 'locateDesktopProfile', '账号切换：定位 MSIX 容器里的 Desktop profile'],
  ['src/accounts.js', 'PROFILE_EXCLUDES', '账号切换：缓存与 CLI 二进制不跟着账号走'],
  ['src/ui/public/index.html', 'side-accounts', '界面：侧栏账号面板'],
  ['src/ui/public/app.js', 'switchToAccount', '界面：切号动作'],
  ['src/ui/session.js', 'networkBlock', '接口：暴露网络阻断实时状态'],
  ['src/ui/public/index.html', 'action-state', '界面：状态条容器'],
  ['src/ui/public/styles.css', 'state-cell', '界面：状态条样式'],
  ['src/ui/public/styles.css', 'button.action.active', '界面：激活态按钮样式'],
  ['README.md', '不拦截、不门控', '文档：环境项只提示'],
  ['README.md', 'Emoji 国旗渲染', '文档：Emoji 检查项'],
  ['README.md', '界面上怎么看出当前状态', '文档：状态标识说明'],
]

const binaryChecks = [
  ['CCGaitClient.exe', '启动时自动开闸门', '托盘启动即开闸门'],
  ['CCGaitClient.exe', 'AutoStartGuard', '自动开闸门开关'],
  ['CCGaitClient.exe', '常驻界面服务', '执法由常驻界面服务进程承担（不再另起 guard 进程）'],
  ['CCGaitWfp.exe', 'PURGED', 'purge 模式'],
  ['CCGaitWfp.exe', '--stop-file', '宿主常驻与停止信号'],
  ['CCGaitWfp.exe', 'list-filters', '过滤器自检'],
  ['CCGaitWfp.exe', 'WARN-EXEMPT', 'IPv6 回环豁免建不起来时退回全封'],
]

console.log(`载荷文件数：${files.size}\n`)
let missing = 0
for (const [file, rawNeedle, why] of checks) {
  // 以 ! 开头的条目表示"这个字符串不该出现"（用于钉住已经修掉的写法别被改回来）。
  const absent = rawNeedle.startsWith('!')
  const needle = absent ? rawNeedle.slice(1) : rawNeedle
  const present = textHas(file, needle)
  const ok = absent ? !present : present
  if (!ok) missing++
  console.log(`  ${ok ? '有' : '缺'}  ${file} ← ${absent ? '不含 ' : ''}${needle}　（${why}）`)
}

console.log('\n编译产物（.cs 源不进载荷，功能在 exe 里）：')
for (const [file, needle, why] of binaryChecks) {
  const ok = binaryHas(file, needle)
  if (!ok) missing++
  console.log(`  ${ok ? '有' : '缺'}  ${file} ← ${needle}　（${why}）`)
}

// 安装程序本体不在载荷里（它是内嵌载荷的那个 exe），单独查 dist 下的产物。
// 这条针对一个真实事故：日志框用了 Consolas，而它没有中文字形（实测 4/4 缺），
// 于是界面中文全渲染成方块 —— 字体名必须能在产物里查到。
const setupExePath = new URL('../dist/CCGaitSetup.exe', import.meta.url)
if (existsSync(setupExePath)) {
  const setupData = readFileSync(setupExePath)
  const hasYaHei = setupData.includes(Buffer.from('Microsoft YaHei UI', 'utf16le'))
  const hasConsolas = setupData.includes(Buffer.from('Consolas', 'utf16le'))
  if (!hasYaHei) missing++
  if (hasConsolas) missing++
  console.log('\n安装程序本体（dist/CCGaitSetup.exe）：')
  console.log(`  ${hasYaHei ? '有' : '缺'}  Microsoft YaHei UI　（日志框字体，有中文字形）`)
  console.log(`  ${hasConsolas ? '仍含' : '无'}  Consolas　（没有中文字形，出现在日志框会导致方块乱码）`)
}

console.log(`\n结论：${missing === 0 ? '载荷与编译产物均包含全部关键修复' : `有 ${missing} 项缺失 —— 很可能改了源码但没重新打包`}`)
process.exitCode = missing === 0 ? 0 : 1
