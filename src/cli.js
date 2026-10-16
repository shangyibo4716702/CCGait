#!/usr/bin/env node
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { spawn } from 'node:child_process'
import {
  CONFIG_PATH,
  PROJECT_ROOT,
  initConfig,
  loadConfig,
  resolveStateDir,
  validateConfig,
} from './config.js'
import { createLogger, defaultLogFile } from './log.js'
import {
  applyBlockForPaths,
  enableProfiles,
  firewallProfileState,
  isElevated,
  listManagedRules,
  removeAllBlocks,
} from './firewall.js'
import {
  claudeDiscovery,
  claudeExecutablePaths,
  killAllClaudeProcesses,
  listClaudeProcesses,
} from './process-guard.js'
import {
  clearGuardStopRequest,
  createGuard,
  enforce,
  formatCheckReport,
  processAlive,
  readGuardPid,
  requestGuardStop,
  runChecks,
  stateFilePath,
} from './guard.js'
import { writeLastCheck } from './win/status.js'
import { installStartup, startupStatus, uninstallStartup } from './startup.js'
import { createUiSession } from './ui/session.js'
import { createUiServer } from './ui/server.js'
import { DEFAULT_UI_PORT, openDesktopClient } from './win/desktop.js'
import { writeIconFiles } from './win/icon.js'
import { installShortcuts, uninstallShortcuts } from './win/shortcuts.js'
import { buildInstaller } from './win/build.js'

/**
 * CCGait 命令行入口。
 *
 *   ccgait check              检测当前环境并给出判定（只读，不改任何东西）
 *   ccgait guard              常驻执法：不满足白名单就终止客户端并阻断其网络
 *   ccgait status             查看闸门状态、防火墙规则与发现的客户端路径
 *   ccgait run cli|desktop    通过闸门启动客户端（可注入分流代理）
 *   ccgait firewall on|off    手动建立/解除防火墙阻断
 *   ccgait install-startup    注册开机自启（需要管理员）
 */

function printUsage() {
  console.log(`CCGait · Claude 客户端环境闸门

用法：
  ccgait init                    生成 config.json（从 config.example.json 复制）
  ccgait check [--json]          检测出口 IP/国家/环境特征并给出判定
         [--proxy <url>]         本次检测走该代理（用于确认分流后的出口）
         [--no-proxy]            本次检测强制直连
  ccgait guard [--once]          常驻执法；--once 只跑一轮后退出
         [--keep-blocks]         停止时保留防火墙规则（默认会撤掉）
  ccgait guard-stop              请求正在运行的闸门优雅停止（会撤掉防火墙阻断）
  ccgait status [--json]         查看状态：闸门进程、防火墙规则、客户端路径
  ccgait targets                 列出发现的 Claude 可执行文件
  ccgait kill                    立即终止正在运行的 Claude 客户端
  ccgait firewall on|off|list|enable-profiles
                                 手动建立 / 解除 / 查看阻断规则；enable-profiles 打开系统防火墙
  ccgait run cli|desktop [args]  判定通过才启动客户端（会注入分流代理）
  Windows 客户端：
  ccgait desktop [--port N]     应用窗口（无地址栏；关窗口不影响闸门）
  ccgait tray                   托盘客户端（状态图标 + 右键菜单）
  ccgait build-installer        编译 Windows 客户端与安装包（输出到 dist/）
  ccgait install-shortcut [--desktop]
                                 安装开始菜单（可选桌面）快捷方式
  ccgait uninstall-shortcut     移除快捷方式

  Web 界面：
  ccgait ui [--port N] [--no-open]
                                 启动本地 Web 界面（默认 17890 端口，自动打开浏览器）
  ccgait install-startup         注册登录自启（管理员）
  ccgait uninstall-startup       移除登录自启

配置文件：${CONFIG_PATH}
`)
}

async function loadOrExit() {
  const loaded = loadConfig()
  const logger = createLogger()
  if (!loaded.exists) {
    logger.warn('未找到 config.json', `执行 ccgait init 可从示例生成：${CONFIG_PATH}`)
  }
  const problems = validateConfig(loaded.config)
  if (problems.length > 0) {
    for (const problem of problems) logger.warn('配置问题', problem)
  }
  return loaded
}

async function commandInit() {
  const result = initConfig()
  console.log(
    result.created
      ? `已生成配置：${result.path}\n请编辑白名单（whitelist.ips / countries）后再运行 ccgait check。`
      : `配置已存在，未覆盖：${result.path}`,
  )
  return 0
}

/** 解析 --proxy <url> / --no-proxy，用于临时覆盖配置里的分流代理（不落盘）。 */
function applyProxyOverride(config, argv) {
  const index = argv.indexOf('--proxy')
  if (index !== -1) {
    const url = argv[index + 1]
    if (!url) throw new Error('--proxy 需要提供地址，例如 --proxy http://127.0.0.1:7890')
    return { ...config, network: { ...config.network, proxy: { enabled: true, url, required: false } } }
  }
  if (argv.includes('--no-proxy')) {
    return { ...config, network: { ...config.network, proxy: { enabled: false, url: '', required: false } } }
  }
  return config
}

async function commandCheck(argv) {
  const asJson = argv.includes('--json')
  const { config: loadedConfig } = await loadOrExit()
  const config = applyProxyOverride(loadedConfig, argv)
  const result = await runChecks(config)
  try {
    // 落盘供托盘/状态读取；写不进去不影响检测结果输出。
    writeLastCheck(resolveStateDir(config), result)
  } catch {
    // 忽略。
  }
  if (config !== loadedConfig) {
    process.stdout.write(
      `（本次检测走代理：${config.network.proxy.enabled ? config.network.proxy.url : '直连'}，未写入配置文件）
`,
    )
  }
  if (asJson) {
    console.log(JSON.stringify(result, null, 2))
    return result.verdict.allow ? 0 : 2
  }
  formatCheckReport(result, {
    info: (m, d) => console.log(`INFO  ${m}${d ? `：${d}` : ''}`),
    ok: (m, d) => console.log(`OK    ${m}${d ? `：${d}` : ''}`),
    warn: (m, d) => console.log(`WARN  ${m}${d ? `：${d}` : ''}`),
    block: (m, d) => console.log(`BLOCK ${m}${d ? `：${d}` : ''}`),
  })
  return result.verdict.allow ? 0 : 2
}

/** 给子进程注入分流代理（仅当配置开启且判定通过）。 */
function proxyEnvFor(config) {
  if (!config.network.proxy.enabled || !config.network.proxy.url) return {}
  const url = config.network.proxy.url
  return {
    HTTPS_PROXY: url,
    HTTP_PROXY: url,
    ALL_PROXY: url,
    https_proxy: url,
    http_proxy: url,
    all_proxy: url,
    NO_PROXY: '',
  }
}

async function commandRun(argv) {
  const target = argv[0]
  const rest = argv.slice(1)
  if (target !== 'cli' && target !== 'desktop') {
    console.error('用法：ccgait run cli|desktop [args...]')
    return 1
  }
  const { config } = await loadOrExit()
  const result = await runChecks(config)
  if (!result.verdict.allow) {
    console.error('闸门判定：拦截，已拒绝启动。原因：')
    for (const item of result.verdict.blockedBy) console.error(`  - ${item.title}：${item.detail}`)
    if (result.verdict.failedClosed) console.error('  - 出口身份无法确认（failClosed）')
    return 2
  }
  for (const item of result.verdict.warnings) {
    console.warn(`提示：${item.title} — ${item.detail}`)
  }

  const candidates = claudeExecutablePaths({
    localAppData: process.env.LOCALAPPDATA,
    appData: process.env.APPDATA,
    home: process.env.USERPROFILE,
  })
  const wanted = target === 'cli' ? /claude-code/i : /anthropicclaude|windowsapps|Claude/i
  const exe = candidates.find((item) => wanted.test(item))
  if (!exe) {
    console.error(`没有找到${target === 'cli' ? 'Claude Code CLI' : 'Claude Desktop'}的可执行文件`)
    return 1
  }

  const child = spawn(exe, rest, {
    env: { ...process.env, ...proxyEnvFor(config) },
    detached: true,
    stdio: 'ignore',
  })
  child.unref()
  console.log(`已启动：${exe}`)
  if (config.network.proxy.enabled) {
    console.log(`已注入分流代理：${config.network.proxy.url}`)
  }
  return 0
}

async function commandGuard(argv) {
  const once = argv.includes('--once')
  const keepBlocks = argv.includes('--keep-blocks')
  const { config } = await loadOrExit()
  const stateDir = resolveStateDir(config)
  const logger = createLogger({ logFile: defaultLogFile(stateDir) })

  const elevated = await isElevated()
  if (config.enforcement.blockNetwork && !elevated) {
    logger.warn(
      '当前不是管理员权限',
      '无法创建/删除防火墙规则；本轮只会终止进程，网络阻断不会生效。请以管理员身份运行。',
    )
  }

  if (once) {
    const result = await runChecks(config)
    formatCheckReport(result, logger)
    const enforcement = await enforce(config, result.verdict, { logger, stateDir })
    if (enforcement.errors.length > 0) {
      for (const item of enforcement.errors) logger.warn('执行提示', item)
    }
    logger.info('单轮执行完成', `状态文件：${stateFilePath(stateDir)}`)
    return result.verdict.allow ? 0 : 2
  }

  let guard
  const shutdown = async (signal) => {
    logger.info('收到退出信号', signal)
    await guard?.stop({ keepBlocks })
    process.exit(0)
  }
  guard = createGuard({
    config,
    stateDir,
    logger,
    // 外部（托盘 / ccgait guard-stop）请求停止时走同一条收尾路径：
    // 撤掉防火墙阻断 → 清理状态 → 退出。
    onStopRequest: () => void shutdown('stop-request'),
  })
  process.on('SIGINT', () => void shutdown('SIGINT'))
  process.on('SIGTERM', () => void shutdown('SIGTERM'))
  await guard.start()

  // 常驻：保持事件循环存活，同时让巡检定时器继续跑。
  await new Promise(() => {})
  return 0
}

async function commandGuardStop() {
  const { config } = await loadOrExit()
  const stateDir = resolveStateDir(config)
  const pid = readGuardPid(stateDir)
  if (!pid || !processAlive(pid)) {
    console.log('没有正在运行的闸门（未找到活跃的 guard.pid）')
    return 0
  }
  requestGuardStop(stateDir)
  console.log(`已请求闸门（PID ${pid}）停止：它会在下一轮巡检收尾（撤掉防火墙阻断后退出）`)
  for (let attempt = 0; attempt < 20; attempt += 1) {
    await new Promise((resolve) => setTimeout(resolve, 500))
    if (!processAlive(readGuardPid(stateDir) ?? pid)) {
      console.log('闸门已停止')
      return 0
    }
  }
  console.log('闸门尚未退出（可能正在执行检测），稍后可再用 ccgait status 查看')
  return 0
}

async function commandStatus(argv) {
  const asJson = argv.includes('--json')
  const { config } = await loadOrExit()
  const stateDir = resolveStateDir(config)
  let state
  try {
    state = JSON.parse(readFileSync(stateFilePath(stateDir), 'utf8'))
  } catch {
    state = undefined
  }
  const rules = await listManagedRules()
  const profile = await firewallProfileState()
  const targets = claudeExecutablePaths({
    localAppData: process.env.LOCALAPPDATA,
    appData: process.env.APPDATA,
    home: process.env.USERPROFILE,
  })
  const processes = await listClaudeProcesses()
  const startup = await startupStatus()
  const elevated = await isElevated()

  const summary = { state, rules, firewallProfile: profile, targets, processes, startup, elevated }
  if (asJson) {
    console.log(JSON.stringify(summary, null, 2))
    return 0
  }

  console.log(`配置：${CONFIG_PATH}`)
  console.log(`管理员权限：${elevated ? '有' : '无（无法建立防火墙阻断）'}`)
  console.log(
    `Windows 防火墙：${profile.anyEnabled ? '已开启' : '全部关闭（规则不会生效）'}`,
  )
  console.log(
    `登录自启：${startup.installed ? `已注册${startup.state ? `（${startup.state}）` : ''}` : '未注册'}`,
  )
  console.log(`发现的客户端（${targets.length}）：`)
  for (const item of targets) console.log(`  - ${item}`)
  const guardPid = readGuardPid(stateDir)
  console.log(`闸门进程：${processAlive(guardPid) ? `运行中（PID ${guardPid}）` : '未运行'}`)
  console.log(`运行中的 Claude 进程：${processes.length}`)
  for (const item of processes) console.log(`  - ${item.name}#${item.pid} [${item.kind}] ${item.exePath}`)
  console.log(`CCGait 防火墙规则：${rules.length}`)
  for (const rule of rules) console.log(`  - ${rule.enabled ? '启用' : '停用'} ${rule.program}`)
  if (state) {
    console.log(`最近一次判定：${state.allow ? '放行' : '拦截'}（${state.updatedAt}，来源 ${state.reason}）`)
    if (state.egress) {
      console.log(`  出口：${state.egress.ip ?? '未知'} · ${state.egress.country ?? '??'} · ${state.egress.org ?? ''}`)
    }
    for (const item of state.blocked ?? []) console.log(`  拦截原因：${item.title}`)
    for (const item of state.warnings ?? []) console.log(`  提示：${item.title}`)
  } else {
    console.log('最近一次判定：无记录（尚未运行过 guard）')
  }
  return 0
}

async function commandTargets() {
  const discovery = claudeDiscovery({
    localAppData: process.env.LOCALAPPDATA,
    appData: process.env.APPDATA,
    home: process.env.USERPROFILE,
  })
  if (discovery.entries.length === 0) {
    console.log('没有发现 Claude Code CLI 或 Claude Desktop 的可执行文件')
  }
  for (const item of discovery.entries) {
    console.log(`[${item.kind}] ${item.path}`)
    console.log(`      ${item.label}`)
  }
  for (const note of discovery.notes) console.log(`注意：${note}`)
  return 0
}

async function commandKill() {
  const processes = await listClaudeProcesses()
  if (processes.length === 0) {
    console.log('没有正在运行的 Claude 客户端进程')
    return 0
  }
  const killed = await killAllClaudeProcesses()
  for (const item of killed) {
    console.log(`${item.killed ? '已终止' : '未终止'} ${item.name}#${item.pid} ${item.error ?? ''}`)
  }
  return 0
}

async function commandFirewall(argv) {
  const action = argv[0]
  if (action === 'list') {
    const rules = await listManagedRules()
    if (rules.length === 0) {
      console.log('当前没有 CCGait 防火墙规则')
      return 0
    }
    for (const rule of rules) console.log(`${rule.enabled ? '启用' : '停用'} ${rule.program}`)
    return 0
  }
  if (action === 'off') {
    const result = await removeAllBlocks()
    if (result.error) {
      console.error(`解除阻断失败：${result.error}`)
      return 1
    }
    console.log(`已移除 ${result.removed} 条 CCGait 防火墙规则`)
    return 0
  }
  if (action === 'on') {
    const targets = claudeExecutablePaths({
      localAppData: process.env.LOCALAPPDATA,
      appData: process.env.APPDATA,
      home: process.env.USERPROFILE,
    })
    if (targets.length === 0) {
      console.error('没有发现 Claude 客户端，无法建立阻断')
      return 1
    }
    const result = await applyBlockForPaths(targets)
    if (result.error) {
      console.error(`建立阻断失败：${result.error}`)
      return 1
    }
    console.log(`已阻断：${result.verified.length}/${targets.length} 个程序`)
    for (const item of result.failed) {
      console.error(`  失败：${item.path} —— ${item.error}`)
    }
    return result.failed.length === 0 ? 0 : 1
  }
  if (action === 'enable-profiles') {
    const result = await enableProfiles()
    if (!result.ok) {
      console.error(`启用防火墙配置文件失败：${result.error}`)
      return 1
    }
    console.log('已启用 Windows 防火墙配置文件：')
    for (const item of result.profiles) {
      console.log(`  ${item.name}: ${item.enabled ? '启用' : '停用'}`)
    }
    console.log('现在按程序阻断规则才会真正生效。')
    return 0
  }
  console.error('用法：ccgait firewall on|off|list|enable-profiles')
  return 1
}

async function commandStartup(argv) {
  const { config } = await loadOrExit()
  const stateDir = resolveStateDir(config)
  if (argv[0] === 'status') {
    const status = await startupStatus()
    console.log(status.installed ? `已注册（状态 ${status.state ?? '未知'}）` : '未注册登录自启')
    return 0
  }
  const result = await installStartup(stateDir)
  if (!result.ok) {
    console.error(`注册登录自启失败：${result.error}`)
    return 1
  }
  console.log(`已注册登录自启（计划任务 ${result.taskName}，登录后延迟 30 秒以隐藏窗口方式启动）`)
  console.log(`启动器：${result.launcher}`)
  return 0
}

async function commandUninstallStartup() {
  const { config } = await loadOrExit()
  const stateDir = resolveStateDir(config)
  const result = await uninstallStartup(stateDir)
  console.log(
    `已移除登录自启（计划任务${result.removedTask ? '已删除' : '不存在'}；启动器${result.removedLauncher ? '已删除' : '不存在'}）`,
  )
  return 0
}

async function commandUi(argv) {
  const portIndex = argv.indexOf('--port')
  const port = portIndex === -1 ? 17890 : Number(argv[portIndex + 1])
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error('--port 需要一个有效端口号')
    return 1
  }
  const shouldOpen = !argv.includes('--no-open')
  const { config } = await loadOrExit()
  const stateDir = resolveStateDir(config)
  const logger = createLogger({ logFile: defaultLogFile(stateDir) })
  const session = createUiSession({ configPath: CONFIG_PATH, logger })
  const ui = createUiServer({ session, logger })

  let address
  try {
    address = await ui.listen(port)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    console.error(
      /EADDRINUSE/i.test(message)
        ? `端口 ${port} 已被占用：换一个端口，例如 ccgait ui --port ${port + 1}`
        : `启动界面失败：${message}`,
    )
    return 1
  }

  const url = `http://127.0.0.1:${address.port}/`
  console.log(`CCGait 界面已启动：${url}`)
  console.log('（只监听本机回环地址；所有操作都需要页面内的会话令牌）')
  const elevated = await isElevated()
  if (!elevated) {
    console.log('提示：当前不是管理员，网络阻断相关操作会失败；需要时请以管理员身份重新运行。')
  }
  if (shouldOpen && process.platform === 'win32') {
    spawn('cmd.exe', ['/c', 'start', '', url], { detached: true, stdio: 'ignore' }).unref()
  }

  const shutdown = async (signal) => {
    console.log(`
收到 ${signal}，正在收尾（停止闸门并撤掉阻断）…`)
    try {
      await session.dispose()
      await ui.close()
    } catch {
      // 退出流程不阻塞。
    }
    process.exit(0)
  }
  process.on('SIGINT', () => void shutdown('SIGINT'))
  process.on('SIGTERM', () => void shutdown('SIGTERM'))

  await new Promise(() => {})
  return 0
}

/**
 * 打开 Windows 应用窗口（Edge APP 模式）。服务不在就后台拉起；关掉窗口不影响闸门执法。
 */
async function commandDesktop(argv) {
  const portIndex = argv.indexOf('--port')
  const port = portIndex === -1 ? DEFAULT_UI_PORT : Number(argv[portIndex + 1])
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error('--port 需要一个有效端口号')
    return 1
  }
  const { config } = await loadOrExit()
  const stateDir = resolveStateDir(config)
  const result = await openDesktopClient({ port, stateDir })
  if (!result.windowOpened) {
    console.error(`打开窗口失败：${result.reason ?? '未找到 Microsoft Edge 或 Google Chrome'}`)
    return 1
  }
  console.log(`应用窗口已打开：${result.url}`)
  console.log(result.serverStarted ? `（后台服务已一并启动：端口 ${port}）` : '（复用已在运行的本地服务）')
  console.log('关闭窗口不会停止闸门；要停止请用托盘菜单或 ccgait guard-stop。')
  return 0
}

/** 启动 Windows 托盘客户端（状态图标 + 右键菜单）。 */
async function commandTray() {
  if (process.platform !== 'win32') {
    console.error('托盘客户端仅支持 Windows')
    return 1
  }
  const { config } = await loadOrExit()
  const stateDir = resolveStateDir(config)
  const { ico } = writeIconFiles(stateDir)
  const child = spawn(
    'powershell.exe',
    [
      '-NoProfile',
      '-NonInteractive',
      '-ExecutionPolicy',
      'Bypass',
      '-WindowStyle',
      'Hidden',
      '-File',
      join(PROJECT_ROOT, 'src', 'win', 'tray.ps1'),
      '-NodePath',
      process.execPath,
      '-CliPath',
      join(PROJECT_ROOT, 'src', 'cli.js'),
      '-StateDir',
      stateDir,
      '-IconPath',
      ico,
      '-ConfigPath',
      CONFIG_PATH,
      '-Port',
      String(DEFAULT_UI_PORT),
    ],
    { detached: true, stdio: 'ignore', windowsHide: true },
  )
  child.unref()
  console.log('托盘已启动：通知区域会出现 CCGait 盾牌图标')
  console.log('右键图标：立即检测 / 启停闸门 / 阻断网络 / 打开界面 / 退出托盘')
  return 0
}

/** 安装开始菜单（可选桌面）快捷方式。 */
async function commandInstallShortcut(argv) {
  const { config } = await loadOrExit()
  const stateDir = resolveStateDir(config)
  const { ico } = writeIconFiles(stateDir)
  const result = await installShortcuts({
    stateDir,
    iconPath: ico,
    alsoDesktop: argv.includes('--desktop'),
  })
  if (!result.ok) {
    console.error(result.error)
    return 1
  }
  for (const item of result.created) console.log(`已创建${item.label}快捷方式：${item.path}`)
  console.log('双击快捷方式即可启动后台服务并打开应用窗口。')
  return 0
}

async function commandUninstallShortcut() {
  const { config } = await loadOrExit()
  const stateDir = resolveStateDir(config)
  const result = await uninstallShortcuts({ stateDir })
  if (result.removed.length === 0) console.log('没有找到 CCGait 快捷方式')
  else for (const path of result.removed) console.log(`已删除：${path}`)
  return 0
}

async function commandBuildInstaller() {
  console.log('正在编译 Windows 客户端与安装包…')
  const result = await buildInstaller()
  for (const line of result.log ?? []) console.log('  ' + line)
  if (!result.ok) {
    console.error(result.error)
    return 1
  }
  console.log('')
  console.log('安装包就绪：' + result.setupExe + '（' + Math.round(result.sizeBytes / 1024) + ' KB）')
  console.log('双击即可安装；卸载程序随安装部署，会出现在「已安装的应用」里。')
  return 0
}

async function main() {
  const [command, ...argv] = process.argv.slice(2)
  switch (command) {
    case 'init':
      return commandInit()
    case 'check':
      return commandCheck(argv)
    case 'guard':
      return commandGuard(argv)
    case 'guard-stop':
      return commandGuardStop()
    case 'status':
      return commandStatus(argv)
    case 'targets':
      return commandTargets()
    case 'kill':
      return commandKill()
    case 'firewall':
      return commandFirewall(argv)
    case 'run':
      return commandRun(argv)
    case 'ui':
      return commandUi(argv)
    case 'desktop':
      return commandDesktop(argv)
    case 'build-installer':
      return commandBuildInstaller()
    case 'tray':
      return commandTray()
    case 'install-shortcut':
      return commandInstallShortcut(argv)
    case 'uninstall-shortcut':
      return commandUninstallShortcut()
    case 'install-startup':
      return commandStartup(argv)
    case 'uninstall-startup':
      return commandUninstallStartup()
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      printUsage()
      return 0
    default:
      console.error(`未知命令：${command}`)
      printUsage()
      return 1
  }
}

main()
  .then((code) => {
    process.exitCode = code ?? 0
  })
  .catch((error) => {
    console.error(`执行失败：${error instanceof Error ? error.message : String(error)}`)
    process.exitCode = 1
  })
