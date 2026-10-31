import { existsSync, lstatSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { execFile, execFileSync, spawn } from 'node:child_process'
import { promisify } from 'node:util'
import { CONFIG_PATH, loadConfig, normalizeConfig, resolveStateDir, validateConfig } from '../config.js'
import {
  clearGuardStartRequest,
  createGuard,
  guardStartRequestPath,
  processAlive,
  readGuardPid,
  runChecks,
} from '../guard.js'
import {
  applyBlockForPaths,
  enableProfiles,
  firewallProfileState,
  isElevated,
  listManagedRules,
  removeAllBlocks,
} from '../firewall.js'
import { claudeDiscovery, killAllClaudeProcesses, killClaudeProcessesByKind, listClaudeProcesses } from '../process-guard.js'
import {
  accountsRoot,
  listAccounts,
  locateDesktopProfile,
  nextAccountName,
  readAccountInsights,
  readAccountUuid,
  matchLiveAccount,
  readCurrentAccount,
  assertAccountName,
  recoverInterruptedSwitch,
  removeAccount,
  createEmptyAccount,
  accountDir,
  saveAccount,
  switchAccount,
  writeCurrentAccount,
} from '../accounts.js'
import {
  claudeProjectsDir,
  copySessions,
  listSessionGroups,
  listSessions,
  projectFolderFor,
  sessionBodyExists,
} from '../sessions-sync.js'
import {
  CORE_PROCESS_NAMES,
  applyClashFix,
  applyClaudeRules,
  claudeRuleCoverage,
  judgeDnsUpstreams,
  judgeProxySettings,
  needsClashFix,
  probeProxyMode,
  readClashRules,
  readProxySettings,
  writeProxyMode,
} from '../proxy-mode.js'
import { verifyClaudeRouting } from '../proxy-connections.js'
import { repairSystemDns } from '../win/system-dns.js'
import { startupStatus } from '../startup.js'
import { isWfpBlocking, listWfpHosts, readWfpPid, startWfpBlock, stopWfpBlock } from '../win/wfp.js'

const promisifiedExecFile = promisify(execFile)

/**
 * UI 会话层：把 CLI 已有的能力包成一组可调用的动作 + 一个事件流，供 Web 前端使用。
 *
 * 关键设计：
 * - **单一真相**。配置、闸门实例、最近一次检测结果、日志都在这里，UI 只是它的视图。
 * - **动作串行化**。启动/停止闸门、改配置都会互相影响，用一个内部的 promise 队列保证
 *   同一时刻只有一个动作在跑，避免"边启动边改配置"导致状态错乱。
 * - **可注入依赖**。检测、闸门工厂、防火墙操作都可以替换，方便在没有管理员权限、
 *   或不想动系统状态的情况下测试。
 */

const LOG_RING_SIZE = 500
const INTERCEPTION_RING_SIZE = 80

/**
 * 从日志文件里回填拦截记录。
 *
 * 为什么要读文件而不是只留内存：拦截记录的价值在于"事后回看"，
 * 而界面进程重启后内存里的东西就没了。日志文件本来就有 ISO 时间戳与级别，
 * 直接复用即可，不需要另建一套存储。
 */
function readInterceptionsFromLog(stateDir, limit = INTERCEPTION_RING_SIZE) {
  try {
    const dir = stateDir
    if (!existsSync(dir)) return []
    const files = readdirSync(dir)
      .filter((name) => name.startsWith('ccgait-') && name.endsWith('.log'))
      .sort()
    const picked = []
    for (const name of files.slice(-2)) {
      const text = readFileSync(join(dir, name), 'utf8')
      for (const line of text.split(/\r?\n/)) {
        // 形如：2026-10-17T01:52:08.144Z BLOCK 已阻断网络（防火墙出站） 11/11 个程序已生效
        const match = /^(\S+) (OK|WARN|BLOCK|INFO|ERR)\s+(.*)$/.exec(line.trim())
        if (!match) continue
        const [, at, tag, rest] = match
        const level = tag === 'BLOCK' ? 'block' : tag === 'WARN' ? 'warn' : tag === 'ERR' ? 'error' : tag === 'OK' ? 'ok' : 'info'
        if (level !== 'block' && level !== 'warn') continue
        picked.push({ at, level, message: rest })
      }
    }
    return picked.slice(-limit)
  } catch {
    return []
  }
}

function nowIso() {
  return new Date().toISOString()
}

/** 只取可写入配置的字段，并做一次规范化：UI 传什么都不会把配置写坏。 */
export function applyConfigPatch(current, patch) {
  const merged = {
    whitelist: { ...current.whitelist, ...(patch.whitelist ?? {}) },
    checks: { ...current.checks },
    enforcement: { ...current.enforcement, ...(patch.enforcement ?? {}) },
    network: {
      proxy: { ...current.network.proxy, ...(patch.network?.proxy ?? {}) },
    },
    runtime: { ...current.runtime, ...(patch.runtime ?? {}) },
  }
  for (const [name, value] of Object.entries(patch.checks ?? {})) {
    if (!value || typeof value !== 'object') continue
    const base = current.checks[name] ?? { enabled: true, severity: 'warn' }
    merged.checks[name] = { ...base, ...value }
  }
  return normalizeConfig(merged)
}

/**
 * Claude 客户端此刻的可用性结论。
 *
 * 三态，而不是两态 —— 因为"判定不通过但没人拦"和"判定通过"是完全不同的处境，
 * 都显示绿色"可以"会掩盖风险（实测用户就因为它误以为一切正常）：
 *   allow      → 可以
 *   deny       → 不可以（有执法在生效，且判定不通过）
 *   unguarded  → 未被拦截（判定不通过，但闸门没在跑，所以此刻确实能开/能联网）
 */
export function buildClaudeAccess({ check, ownGuard, externalGuards, networkBlocked, networkLayers, externalBlock, config }) {
  const killEnabled = config?.enforcement?.killProcesses !== false
  const enforcing = Boolean(ownGuard) || externalGuards.length > 0
  // 说"谁在执法"时不要写死成"托盘"：托盘、应用窗口、另一个界面都可能起闸门（它们都是
  // 独立的 `cli.js guard` 进程），写错了只会让人去错的地方找。
  const who = ownGuard ? '本界面' : externalGuards.length > 0 ? '另一个 CCGait 进程' : undefined
  const verdictKnown = Boolean(check)
  const deny = verdictKnown && check.allow === false
  const blockedTitles = (check?.blocked ?? []).map((item) => item.title).join('；')

  let launchState
  let launchReason
  if (enforcing && deny && killEnabled) {
    launchState = 'deny'
    launchReason = `判定不通过，启动就会被终止（执行者：${who}启动的闸门）：${blockedTitles || '见下方拦截记录'}`
  } else if (enforcing && deny && !killEnabled) {
    launchState = 'allow'
    launchReason = '判定不通过，但配置里关闭了「终止客户端进程」，所以不会被终止'
  } else if (enforcing) {
    launchState = 'allow'
    launchReason = verdictKnown
      ? `闸门在运行（${who}启动的闸门）且判定通过，可以正常启动`
      : `闸门在运行（${who}启动的闸门），但还没跑过检测；点「立即检测」后才有结论`
  } else if (deny) {
    launchState = 'unguarded'
    launchReason = '判定不通过，但当前没有拦截在生效（闸门没在运行）—— 此刻它确实能打开。点「启动闸门」立即接管。'
  } else {
    launchState = 'allow'
    launchReason = verdictKnown ? '闸门未运行；当前环境判定通过' : '闸门未运行，没有执法在生效'
  }

  let networkState
  let networkReason
  if (networkBlocked) {
    networkState = 'deny'
    networkReason =
      `已被阻断，连不上网（${networkLayers.join(' + ') || '阻断生效中'}）` +
      (externalBlock ? '。这个阻断不是本界面建立的（很可能是安装版托盘的闸门在维持），点「解除阻断」后可能被它立刻重建 —— 要彻底解除，请先在托盘里停止闸门。' : '')
  } else if (deny) {
    networkState = 'unguarded'
    networkReason = '判定不通过，但当前没有生效中的阻断 —— 此刻它确实能联网。点「启动闸门」立即拦截。'
  } else {
    networkState = 'allow'
    networkReason = '当前没有生效中的阻断，网络可用'
  }

  return {
    launchState,
    launchReason,
    networkState,
    networkReason,
    // 兼容旧字段名（界面与测试可能仍在读）
    canLaunch: launchState === 'deny' ? false : true,
    canNetwork: networkState === 'deny' ? false : true,
    externalBlock: Boolean(externalBlock),
    externalGuard: externalGuards.length > 0,
    verdict: verdictKnown ? (check.allow ? 'allow' : 'deny') : 'unknown',
    guardRunning: enforcing,
    enforcedBy: who,
  }
}

/**
 * 闸门进程写下 `state.json` 的文件名（与 `src/guard.js` 的 STATE_FILE 一致）。
 * 界面和闸门常常不是同一个进程（托盘起的是另一个 `cli.js guard`），这个文件是它们之间
 * 唯一共同的事实来源。
 */
const GUARD_STATE_FILE = 'state.json'

/**
 * 读闸门自己算出的最近一次判定，作为界面的起点。
 *
 * 为什么界面要读它：界面进程只知道自己这边的检测。装在托盘里的闸门是**另一个进程**，
 * 它判定不通过、正在终止 Claude 与断网时，刚打开界面的用户看到的却是"尚未检测"和绿色的
 * "可以打开" —— 界面说可以，闸门在杀进程。判定明明就在状态文件里，读一下就不会对不上。
 *
 * 状态文件里的字段比一次完整检测少（没有 DNS/环境特征/白名单明细），所以它只当兜底：
 * 界面自己跑过检测时以自己那份为准。
 */
export function readGuardCheck(stateDir) {
  try {
    const state = JSON.parse(readFileSync(join(stateDir, GUARD_STATE_FILE), 'utf8'))
    if (typeof state.allow !== 'boolean') return null
    return {
      at: state.updatedAt ?? null,
      allow: state.allow,
      blocked: state.blocked ?? [],
      warnings: state.warnings ?? [],
      egress: state.egress ?? {},
      failedClosed: Boolean(state.failedClosed),
      durationMs: state.durationMs,
      from: 'guard',
    }
  } catch {
    // 没有状态文件、或内容读不懂（写到一半被中断）时按"没检测过"处理。
    return null
  }
}

/**
 * 检测"别的 CCGait 实例正在执法"（例如另一个界面服务进程内的闸门、或手工起的 `ccgait guard`）。
 *
 * 为什么需要：界面里的闸门对象只代表**本进程**启动的那个。执法现在跑在常驻界面服务进程内，
 * 也就是另一个进程里；如果界面只按"自己的闸门在不在跑"来回答"能否打开"，就会给出"可以"
 * 这种与实际相反的结论。两个信号合起来看：
 * 1. `guard.pid` 指向的进程不是本进程且还活着 —— 覆盖"闸门跑在另一个界面服务进程里"；
 * 2. 命令行里带 `guard` 的 `cli.js` 进程 —— 覆盖手工起的独立闸门进程。
 */
async function detectExternalGuard(stateDir) {
  const found = new Set()
  const pid = stateDir ? readGuardPid(stateDir) : undefined
  if (pid && pid !== process.pid && processAlive(pid)) found.add(pid)
  if (process.platform !== 'win32') return [...found]
  try {
    const { execFile } = await import('node:child_process')
    const { promisify } = await import('node:util')
    const run = promisify(execFile)
    const { stdout } = await run(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        // 末尾的 (?![-\\w]) 是为了不把 `guard-stop` 这类同前缀的短命进程算进来。
        "Get-CimInstance Win32_Process -Filter \"Name='node.exe'\" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match 'cli\\.js[\" ]+guard(?![-\\w])' } | Select-Object -ExpandProperty ProcessId",
      ],
      { windowsHide: true, timeout: 10_000 },
    )
    for (const line of stdout.split(/\r?\n/)) {
      const value = Number(line.trim())
      if (Number.isInteger(value) && value > 0 && value !== process.pid) found.add(value)
    }
  } catch {
    // 查不到就当没有别的实例（本进程自己的闸门状态不受影响）。
  }
  return [...found]
}

/**
 * 重启代理内核，让新写的 DNS 配置生效。
 *
 * 为什么不能直接 taskkill：本机实测内核（verge-mihomo）以 **SYSTEM** 身份由
 * `clash_verge_service` 托管，管理员权限执行 taskkill 也会被拒（Access denied），
 * 结果就是"配置改了但没生效"。正确做法是重启那个服务，由它重新拉起内核。
 *
 * 等不到新进程就返回 false —— 界面会提示用户手动重启，不谎报成功。
 */
async function restartProxyCore({ waitMs = 20_000 } = {}) {
  if (process.platform !== 'win32') return false

  const runPowerShell = (script, timeout = 25_000) =>
    execFileSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { windowsHide: true, timeout, encoding: 'utf8' },
    )

  const coreIds = () => {
    try {
      const out = runPowerShell(
        `Get-Process -Name ${CORE_PROCESS_NAMES.join(',')} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id; exit 0`,
        10_000,
      )
      return out
        .split(/\r?\n/)
        .map((line) => Number(line.trim()))
        .filter((id) => Number.isInteger(id) && id > 0)
    } catch {
      return []
    }
  }

  const before = coreIds()

  // 优先重启托管服务；服务不存在时（如 FlClash 用别的方式托管）再退回杀进程。
  let restartedService = false
  try {
    const services = runPowerShell(
      "Get-Service | Where-Object { $_.Name -match 'clash.*service|verge.*service' -and $_.Status -eq 'Running' } | Select-Object -ExpandProperty Name; exit 0",
      15_000,
    )
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean)
    for (const name of services) {
      try {
        runPowerShell(`Restart-Service '${name}' -Force -ErrorAction Stop`, 30_000)
        restartedService = true
      } catch {
        // 单个服务重启失败就继续试下一个
      }
    }
  } catch {
    restartedService = false
  }

  if (!restartedService) {
    for (const pid of before) {
      try {
        execFileSync('taskkill.exe', ['/PID', String(pid), '/F'], { windowsHide: true, timeout: 10_000 })
      } catch {
        // 杀不掉（SYSTEM 进程）就走下面的等待，最终返回 false
      }
    }
  }

  const deadline = Date.now() + waitMs
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 500))
    const now = coreIds()
    if (now.some((pid) => !before.includes(pid))) return true
  }
  return false
}

export function createUiSession(options = {}) {
  const configPath = options.configPath ?? CONFIG_PATH
  const logger = options.logger
/**
 * 等待 Claude Desktop 真正出现（进程集合里出现新 PID）。
 *
 * 为什么不看退出码：MSIX 别名走的是外壳激活，`start` 几乎立刻返回 0，
 * 与实际是否拉起应用无关。只有"多了新进程"才是可观测的证据。
 */
async function waitForNewClaudeProcess(beforeIds, { timeoutMs = 12_000, intervalMs = 500 } = {}) {
  const deadline = Date.now() + timeoutMs
  const { listClaudeProcesses } = await import('../process-guard.js')
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
    let running = []
    try {
      running = await listClaudeProcesses()
    } catch {
      continue
    }
    if (running.some((item) => !beforeIds.has(item.pid))) return true
  }
  return false
}

/**
 * 把 Claude Desktop 的窗口带到前台。
 *
 * 实测 Claude 启动后会以最小化状态缩在托盘，用户点完"启动"看不到任何变化，
 * 会以为没启动。这里用 WScript.Shell.AppActivate 激活它的主窗口 ——
 * 不依赖 Win32 P/Invoke，也不改应用本身任何设置。
 */
async function focusDesktopWindow() {
  const script = [
    "$p = Get-Process Claude -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1",
    'if ($p) { $sh = New-Object -ComObject WScript.Shell; $null = $sh.AppActivate($p.Id); "FOCUSED" }',
  ].join('; ')
  try {
    const { stdout } = await runPowerShellQuiet(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
    )
    return stdout.includes('FOCUSED')
  } catch {
    return false
  }
}

/** 静默跑一次 PowerShell 并取 stdout（超时 8s，输出上限 1MB）。 */
function runPowerShellQuiet(file, args) {
  return promisifiedExecFile(file, args, { windowsHide: true, timeout: 8000, maxBuffer: 1024 * 1024 })
}

/**
 * 找出 Claude Desktop 的启动入口。
 *
 * 为什么优先用 MSIX 别名而不是包目录里的 claude.exe：MSIX 应用的 exe 直接双击会被
 * 系统权限挡住，正常启动入口是 `%LOCALAPPDATA%\Microsoft\WindowsApps\claude-desktop.exe`
 * 这个别名（由 AppX 安装时注册，走的是正常激活路径）。
 *
 * 注意别用 existsSync 判断别名：它会**跟随符号链接**去访问 WindowsApps 里受保护的
 * 目标，结果是 false —— 别名明明存在却被判成"没装"。这里用 lstatSync，只看别名本身。
 *
 * 找不到别名时退回已发现的桌面版可执行文件：能启动就行，不追求"最漂亮"的入口。
 */
function resolveDesktopTarget() {
  const localAppData = process.env.LOCALAPPDATA ?? ''
  const aliasDir = join(localAppData, 'Microsoft', 'WindowsApps')
  const candidateNames = ['claude-desktop.exe', 'claude.exe', 'Claude.exe']
  for (const name of candidateNames) {
    const alias = join(aliasDir, name)
    try {
      // lstat：只验证这个再解析点存在，不去读受保护的目标。
      if (lstatSync(alias)) return { path: alias, label: 'MSIX 别名' }
    } catch {
      // 不存在或不可读：继续看下一个候选。
    }
  }

  const discovery = claudeDiscovery({
    localAppData,
    appData: process.env.APPDATA,
    home: process.env.USERPROFILE,
  })
  const desktop = discovery.entries.filter((entry) => entry.kind === 'desktop')
  // 优先纯 claude.exe（主程序），而不是 cowork-svc / ssh-proxy 这类辅助进程。
  const main =
    desktop.find((entry) => /\\claude\.exe$/i.test(entry.path)) ??
    desktop.find((entry) => /claude-desktop\.exe$/i.test(entry.path)) ??
    desktop[0]
  if (!main) return undefined
  return { path: main.path, label: main.label }
}

/** 给子进程注入分流代理（仅当配置开启）。与 CLI 的 run 命令保持一致。 */
function proxyEnvFor(config) {
  if (!config?.network?.proxy?.enabled || !config.network.proxy.url) return {}
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

/**
 * 真正把 Claude Desktop 拉起来。
 *
 * MSIX 版不能直接 CreateProcess：`WindowsApps\claude-desktop.exe` 是应用执行别名
 * （一个再解析点），直接 spawn 会得到 `EPERM`。
 *
 * 也不能用 `cmd /c start "" "<别名>"`：实测它**立即返回成功但什么也没启动**，
 * 于是按钮显示"已启动"而 Claude 根本没运行（用户实测报过这一点）。
 *
 * 正确做法是走 UWP 的标准激活路径 `shell:AppsFolder\<包族名>!<应用ID>`，
 * 交给 explorer 执行 —— 实测能稳定拉起 11 个进程。找不到 AUMID 时退回
 * PowerShell 的 Start-Process（同样经过 ShellExecute）。
 */
function launchDesktopProcess(target, env) {
  const isAlias = /[\\/]Microsoft[\\/]WindowsApps[\\/]/i.test(target.path)
  if (isAlias) {
    const aumid = resolveAppUserModelId()
    if (aumid) {
      const child = spawn('explorer.exe', [`shell:AppsFolder\\${aumid}`], {
        detached: true,
        stdio: 'ignore',
        windowsHide: true,
        env,
      })
      child.unref()
      return child.pid
    }
    const escaped = target.path.replace(/'/g, "''")
    const child = spawn(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', `Start-Process -FilePath '${escaped}'`],
      { detached: true, stdio: 'ignore', windowsHide: true, env },
    )
    child.unref()
    return child.pid
  }
  const child = spawn(target.path, [], {
    env,
    detached: true,
    stdio: 'ignore',
    windowsHide: false,
  })
  child.unref()
  return child.pid
}

let cachedAumid

/**
 * 解析 Claude Desktop 的 AppUserModelId（形如 Claude_xxx!Claude）。
 *
 * 从开始菜单条目里读，而不是拼一个写死的值 —— 包族名会随安装来源/版本变化。
 * 读一次就缓存：它不会在运行期间改变。
 */
function resolveAppUserModelId() {
  if (cachedAumid !== undefined) return cachedAumid
  try {
    const out = execFileSync(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command',
        "(Get-StartApps | Where-Object { $_.Name -eq 'Claude' } | Select-Object -First 1).AppID"],
      { encoding: 'utf8', timeout: 15000, windowsHide: true },
    ).trim()
    cachedAumid = /^[^\s!]+![^\s]+$/.test(out) ? out : undefined
  } catch {
    cachedAumid = undefined
  }
  return cachedAumid
}

  const deps = {
    runChecks: options.deps?.runChecks ?? runChecks,
    createGuard: options.deps?.createGuard ?? createGuard,
    applyBlockForPaths: options.deps?.applyBlockForPaths ?? applyBlockForPaths,
    removeAllBlocks: options.deps?.removeAllBlocks ?? removeAllBlocks,
    listManagedRules: options.deps?.listManagedRules ?? listManagedRules,
    firewallProfileState: options.deps?.firewallProfileState ?? firewallProfileState,
    isElevated: options.deps?.isElevated ?? isElevated,
    enableProfiles: options.deps?.enableProfiles ?? enableProfiles,
    listClaudeProcesses: options.deps?.listClaudeProcesses ?? listClaudeProcesses,
    killAllClaudeProcesses: options.deps?.killAllClaudeProcesses ?? killAllClaudeProcesses,
    killClaudeProcessesByKind: options.deps?.killClaudeProcessesByKind ?? killClaudeProcessesByKind,
    probeProxyMode: options.deps?.probeProxyMode ?? probeProxyMode,
    readProxySettings: options.deps?.readProxySettings ?? readProxySettings,
    judgeProxySettings: options.deps?.judgeProxySettings ?? judgeProxySettings,
    judgeDnsUpstreams: options.deps?.judgeDnsUpstreams ?? judgeDnsUpstreams,
    needsClashFix: options.deps?.needsClashFix ?? needsClashFix,
    applyClashFix: options.deps?.applyClashFix ?? applyClashFix,
    readClashRules: options.deps?.readClashRules ?? readClashRules,
    claudeRuleCoverage: options.deps?.claudeRuleCoverage ?? claudeRuleCoverage,
    applyClaudeRules: options.deps?.applyClaudeRules ?? applyClaudeRules,
    writeProxyMode: options.deps?.writeProxyMode ?? writeProxyMode,
    verifyClaudeRouting: options.deps?.verifyClaudeRouting ?? verifyClaudeRouting,
    repairSystemDns: options.deps?.repairSystemDns ?? repairSystemDns,
    restartProxyCore: options.deps?.restartProxyCore ?? restartProxyCore,
    accountsRoot: options.deps?.accountsRoot ?? accountsRoot,
    locateDesktopProfile: options.deps?.locateDesktopProfile ?? locateDesktopProfile,
    claudeProjectsDir: options.deps?.claudeProjectsDir ?? claudeProjectsDir,
    claudeDiscovery: options.deps?.claudeDiscovery ?? claudeDiscovery,
    startupStatus: options.deps?.startupStatus ?? startupStatus,
    isWfpBlocking: options.deps?.isWfpBlocking ?? isWfpBlocking,
    listWfpHosts: options.deps?.listWfpHosts ?? listWfpHosts,
    readWfpPid: options.deps?.readWfpPid ?? readWfpPid,
    startWfpBlock: options.deps?.startWfpBlock ?? startWfpBlock,
    stopWfpBlock: options.deps?.stopWfpBlock ?? stopWfpBlock,
    // 真正"拉起 Claude Desktop"这一步：单独可注入，测试才能验证门控逻辑
    // 而不在开发机上真的弹出应用。
    launchDesktop: options.deps?.launchDesktop ?? launchDesktopProcess,
    resolveDesktopTarget: options.deps?.resolveDesktopTarget ?? resolveDesktopTarget,
    // 启动后的"进程真的出现了吗"验证：同样可注入，否则测试会依赖本机真实进程状态。
    waitForDesktopProcess:
      options.deps?.waitForDesktopProcess ?? ((beforeIds) => waitForNewClaudeProcess(beforeIds)),
    focusDesktopWindow: options.deps?.focusDesktopWindow ?? focusDesktopWindow,
  }

  const listeners = new Set()
  const logs = []
  // 拦截记录：从日志文件里回填历史（跨重启保留），之后与 pushLog 同步增长。
  const interceptions = readInterceptionsFromLog(resolveStateDir(loadConfig(configPath).config, configPath))
  let loaded = loadConfig(configPath)
  let stateDir = resolveStateDir(loaded.config, configPath)
  let configProblems = validateConfig(loaded.config)
  let guard = null
  let guardStartedAt = undefined
  // 界面自己跑过检测时用自己那份；没跑过就用闸门写下的判定兜底（可能是另一个进程里的闸门）。
  let lastCheck = null
  let lastEnforcement = null
  let lastError = undefined
  let queue = Promise.resolve()
  let watchTimer = null
  let watchStartTimer = null
  let watchSignature = null

  const emit = (event) => {
    for (const listener of listeners) {
      try {
        listener(event)
      } catch {
        // 单个订阅者出错不能影响其它订阅者。
      }
    }
  }

  const pushLog = (level, message, detail) => {
    const entry = {
      at: nowIso(),
      level,
      message,
      ...(detail === undefined ? {} : { detail }),
    }
    logs.push(entry)
    if (logs.length > LOG_RING_SIZE) logs.splice(0, logs.length - LOG_RING_SIZE)
    // 拦截记录与日志走同一个漏斗：block/warn 级别就是"发生过拦截/被拦下的动作"，
    // 统一在这里登记，避免每个动作各写一遍而漏掉（闸门内部的执法也经 logger 落到这里）。
    if (level === 'block' || level === 'warn') {
      interceptions.push(entry)
      if (interceptions.length > INTERCEPTION_RING_SIZE) {
        interceptions.splice(0, interceptions.length - INTERCEPTION_RING_SIZE)
      }
      emit({ type: 'interception', entry })
    }
    emit({ type: 'log', entry })
    // 同时写文件，便于事后排查。
    logger?.[level]?.(message, detail)
    return entry
  }

  /** 串行执行动作：任何动作都在前一个动作完成后才开始。 */
  const serialize = (operation) => {
    const result = queue.then(operation, operation)
    queue = result.then(
      () => undefined,
      () => undefined,
    )
    return result
  }

  const clientDiscoveryOptions = () => ({
    localAppData: process.env.LOCALAPPDATA,
    appData: process.env.APPDATA,
    home: process.env.USERPROFILE,
  })

  /**
   * 给"几乎不会变"的探测加一个短 TTL 缓存。
   *
   * 为什么需要：界面每 8 秒轮询一次 /api/status，而每一项都要起一次 PowerShell
   * （实测 firewallProfileState 290ms、listManagedRules 300ms、listClaudeProcesses
   * 560ms…）。全部并行也有 600ms 以上，用户点开面板、切个账号都觉得"卡"。
   *
   * 缓存多久：管理员权限、防火墙规则、开机自启这几项只会在用户主动改设置时变化，
   * 而改设置的动作走的是本会话（会主动失效缓存）。3 秒足够挡住连续轮询的重复开销，
   * 又短到不会让界面显示过期状态。
   *
   * 刻意不缓存 listClaudeProcesses：它是"现在有没有 Claude 在跑"的唯一依据，
   * 缓存它会让"启动 Claude 后界面仍说没在跑"。
   */
  const TTL_MS = 3000
  const cache = new Map()
  const cached = (key, load) => {
    const now = Date.now()
    const hit = cache.get(key)
    if (hit && now - hit.at < TTL_MS) return Promise.resolve(hit.value)
    return Promise.resolve(load()).then((value) => {
      cache.set(key, { at: now, value })
      return value
    })
  }
  const invalidateCache = () => cache.clear()

  const getConfig = () => loaded.config

  /** 当前完整状态快照（UI 的主要数据源）。 */
  const getStatus = async () => {
    // WFP 宿主探测也并进 Promise.all：它本身是一次 WMI 查询（实测 471ms），
    // 之前排在后面串行执行，等于每轮白等半秒 —— 面板 8 秒轮询一次，
    // 累计下来就是用户感知到的"卡"。
    const [elevated, profile, rules, processes, startup, wfpHosts] = await Promise.all([
      cached('elevated', deps.isElevated),
      cached('firewallProfile', deps.firewallProfileState),
      cached('managedRules', deps.listManagedRules),
      // 进程列表不缓存：它是"现在有没有 Claude 在跑"的唯一依据。
      deps.listClaudeProcesses(),
      cached('startup', deps.startupStatus),
      cached('wfpHosts', deps.listWfpHosts),
    ])
    const discovery = deps.claudeDiscovery(clientDiscoveryOptions())

    // 网络阻断到底有没有生效：这是界面上最容易看不出来、也最该看出来的一个状态。
    // WFP 是第一层（不依赖防火墙开关），防火墙规则是第二层；任一层在生效就算"阻断中"。
    // WFP 用**实际在跑的宿主进程**为准，而不是只看 pid 文件 —— pid 文件可能被删掉，
    // 那时候只看文件会报"未生效"，而内核里其实还挂着过滤器（实测踩过）。
    const wfpPid = deps.readWfpPid(stateDir)
    const wfpOrphan = wfpHosts.length > 0 && !wfpHosts.includes(wfpPid)
    const activeRules = rules.filter((rule) => rule.enabled)
    // 别的实例是不是也在执法 —— 决定"能否打开 Claude"要怎么回答。
    // （自己的闸门在跑时不用查：guard.pid 就是本进程，答案必然是"没有别的"。）
    const externalGuards = guard === null ? await detectExternalGuard(stateDir) : []
    // 判定：界面自己的检测优先，没跑过就认闸门写下的那份（托盘起的闸门在另一个进程里，
    // 不读这个文件的话，界面会一边写着"尚未检测/可以打开"，一边被它终止进程）。
    const check = lastCheck ?? readGuardCheck(stateDir)

    return {
      at: nowIso(),
      configPath,
      stateDir,
      configExists: loaded.exists,
      config: getConfig(),
      configProblems,
      elevated,
      firewallProfile: profile,
      rules,
      processes,
      targets: discovery.entries,
      targetNotes: discovery.notes,
      startup,
      networkBlock: {
        blocked: wfpHosts.length > 0 || activeRules.length > 0,
        wfp: wfpHosts.length > 0,
        wfpHosts,
        wfpPid,
        wfpOrphan,
        firewallRules: activeRules.length,
        programs: discovery.entries.length,
      },
      // Claude 此刻能不能打开、能不能联网 —— 用户最关心的两个结论。
      // 由服务端按「判定结果 + 执法开关 + 实际阻断状态」算好，界面直接显示，不在前端猜。
      claudeAccess: buildClaudeAccess({
        check,
        ownGuard: guard !== null,
        externalGuards,
        networkBlocked: wfpHosts.length > 0 || activeRules.length > 0,
        networkLayers: [wfpHosts.length > 0 ? 'WFP 内核过滤器' : undefined, activeRules.length > 0 ? `防火墙规则 ${activeRules.length} 条` : undefined].filter(Boolean),
        // 阻断不是本界面建立的（例如安装版托盘的闸门在维持）：要说清楚，
        // 否则用户点「解除阻断」会被对方立刻重建，看起来像"点了没反应"。
        externalBlock: guard === null && (wfpHosts.length > 0 || activeRules.length > 0),
        config: getConfig(),
      }),
      interceptions: interceptions.slice(-INTERCEPTION_RING_SIZE).reverse(),
      guard: {
        // 以内存里的闸门对象为准（UI 自己启停的就是它）；另外给出 pid 一致性信号：
        // 闸门跑在本进程里时 pid 文件应当就是本进程 PID，对不上就说明状态可疑
        // （进程被任务管理器结束、或另有闸门在跑），界面据此提示而不是笼统显示"运行中"。
        running: guard !== null,
        pid: readGuardPid(stateDir),
        pidMatches: guard === null ? null : readGuardPid(stateDir) === process.pid,
        startedAt: guardStartedAt,
        lastState: guard?.lastState ?? null,
      },
      lastCheck: check,
      lastEnforcement,
      ...(lastError ? { lastError } : {}),
      logs: logs.slice(-LOG_RING_SIZE),
    }
  }

  /**
   * 跑一轮完整检测并广播。
   *
   * 拆成 Internal + 外层排队：门控启动（launchClaudeDesktop）本身已经在队列里执行，
   * 再调 checkNow 就会等一个由自己占用的队列 —— 直接死锁（实测：点按钮后界面一直
   * 停在"检测中…"，进程永不返回）。所有"在队列里还要检测"的场景都必须走 Internal。
   */
  const checkInternal = async () => {
    try {
      const result = await deps.runChecks(getConfig())
      lastCheck = {
        at: nowIso(),
        allow: result.verdict.allow,
        failedClosed: result.verdict.failedClosed,
        blocked: result.verdict.blockedBy.map((item) => ({ id: item.id, title: item.title, detail: item.detail })),
        warnings: result.verdict.warnings.map((item) => ({ id: item.id, title: item.title, detail: item.detail })),
        // 白名单原文：界面要拿它把"为什么通过/不通过"显示成可比对的一行，
        // 而不是只给一个孤零零的 GB 让人猜。
        whitelist: result.verdict.whitelistSummary,
        egress: result.egress,
        dns: result.dns,
        environment: result.environment,
      }
      lastError = undefined
      pushLog(
        result.verdict.allow ? 'ok' : 'block',
        result.verdict.allow ? '检测通过：环境命中白名单' : '检测未通过',
        result.verdict.blockedBy.map((item) => item.title).join('；') || undefined,
      )
      emit({ type: 'check', check: lastCheck })
      return lastCheck
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error)
      pushLog('error', '检测失败', lastError)
      throw error
    }
  }

  const checkNow = () => serialize(checkInternal)

  /**
   * 闸门启停有两层：Internal 是真正的动作，外层 serialize 负责排队。
   * saveConfig 本身已在队列里执行，必须调用 Internal —— 否则它会去等一个由自己
   * 占用的队列，直接死锁（这个坑被 tests/ui.test.js 抓到过）。
   */
  const startGuardInternal = async () => {
      if (guard) return { running: true, startedAt: guardStartedAt }
      const config = getConfig()
      guard = deps.createGuard({
        config,
        stateDir,
        logger: {
          ok: (m, d) => pushLog('ok', m, d),
          warn: (m, d) => pushLog('warn', m, d),
          block: (m, d) => pushLog('block', m, d),
          info: (m, d) => pushLog('info', m, d),
          error: (m, d) => pushLog('error', m, d),
        },
        onState: (state) => emit({ type: 'guard', state }),
        // 外部停止请求（托盘/CLI 的 guard-stop 写的就是这个请求文件）必须真的走一遍收尾：
        // 不接这个回调的话，闸门会停掉执法循环、但 pid 文件不清、guard 变量不为 null，
        // 界面就一直显示"运行中"而实际什么都没拦 —— 说的和做的不一致，最难发现。
        onStopRequest: () => {
          void stopGuard()
        },
      })
      guardStartedAt = nowIso()
      pushLog('info', '闸门已启动', `巡检 ${config.enforcement.pollIntervalMs}ms`)
      await guard.start()
      emit({ type: 'status' })
      return { running: true, startedAt: guardStartedAt }
  }

  const stopGuardInternal = async (stopOptions = {}) => {
      if (!guard) return { running: false }
      try {
        await guard.stop(stopOptions)
      } finally {
        guard = null
        guardStartedAt = undefined
      }
      pushLog('info', '闸门已停止')
      emit({ type: 'status' })
      return { running: false }
  }

  const startGuard = () => serialize(startGuardInternal)
  const stopGuard = (stopOptions = {}) => serialize(() => stopGuardInternal(stopOptions))

  const setFirewall = (enabled) =>
    serialize(async () => {
      // 会改动防火墙规则与 WFP 宿主：动作结束后清缓存（见函数末尾），
      // 否则界面在 TTL 内还会报旧状态。
      if (!enabled) {
        // 两层都要撤。只删防火墙规则会把 WFP 内核过滤器留在那里继续断网 ——
        // 界面显示"已解除"、程序却依然上不了网，是最难排查的一种残留。
        const wfp = await deps.stopWfpBlock({ stateDir, waitMs: 10_000 })
        const result = await deps.removeAllBlocks()
        if (result.error) {
          pushLog('error', '解除阻断失败', result.error)
          throw new Error(result.error)
        }
        pushLog(
          'warn',
          '已解除网络阻断',
          `防火墙规则 ${result.removed} 条；WFP ${wfp.stopped ? '宿主已退出' : '本就没有宿主'}${wfp.purged ? `，另清理遗留过滤器 ${wfp.purged} 条` : ''}`,
        )
        invalidateCache()
        emit({ type: 'status' })
        return { ...result, wfp }
      }
      const discovery = deps.claudeDiscovery(clientDiscoveryOptions())
      const targets = discovery.entries.map((item) => item.path)
      if (targets.length === 0) throw new Error('没有发现 Claude 客户端，无法建立阻断')

      // 第一层：WFP 内核过滤器（不依赖防火墙开关）。
      const wfp = await deps.startWfpBlock({ paths: targets, stateDir, detached: true })
      if (!wfp.ok) {
        pushLog('error', 'WFP 阻断建立失败', wfp.error)
      } else if (!wfp.alreadyRunning) {
        pushLog('block', '已建立 WFP 内核阻断', `${wfp.filters} 条过滤器生效（宿主 PID ${wfp.pid}）`)
      }

      // 第二层：防火墙规则。
      const result = await deps.applyBlockForPaths(targets)
      if (result.error) {
        pushLog('error', '建立阻断失败', result.error)
        throw new Error(result.error)
      }
      lastEnforcement = { at: nowIso(), kind: 'firewall-manual', verified: result.verified.length, failed: result.failed }
      pushLog('block', '已建立网络阻断', `${result.verified.length}/${targets.length} 个程序已生效`)
      for (const item of result.failed) pushLog('warn', '阻断未生效', `${item.path}：${item.error}`)
      invalidateCache()
      emit({ type: 'status' })
      return { ...result, wfp }
    })

  const killProcesses = () =>
    serialize(async () => {
      const running = await deps.listClaudeProcesses()
      if (running.length === 0) {
        pushLog('info', '没有正在运行的 Claude 客户端')
        return { killed: [] }
      }
      const killed = await deps.killAllClaudeProcesses()
      const ok = killed.filter((item) => item.killed).length
      pushLog(ok > 0 ? 'block' : 'warn', `已终止 ${ok} 个 Claude 进程`, killed.map((item) => `${item.name}#${item.pid}`).join('、'))
      emit({ type: 'status' })
      return { killed }
    })

  /**
   * 账号切换（只针对 Claude Desktop）。
   *
   * 边界：只动 Desktop 的 profile，不碰 CLI 的 `~/.claude` 与 `~/.claude.json`。
   * 切号换的是登录态与设备标识（Cookies / Local Storage / IndexedDB / ant-did），
   * 缓存和 CLI 二进制保持共享。
   */
  const accountsBase = deps.accountsRoot()
  const resolveProfile = () => deps.locateDesktopProfile()

  const readAccountsState = () => {
    const profile = resolveProfile()
    const recorded = readCurrentAccount(accountsBase)
    const accounts = listAccounts(accountsBase)

    // 谁是"真正在线的"必须按 uuid 判断，不能信 current.json 那个标签。
    //
    // 实测踩到的坑：current.json 写着 C，但现场 profile 的 lastKnownAccountUuid
    // 其实是 B 的。旧代码按标签把现场数据贴到 C 身上，结果 C 显示了 B 的邮箱 ——
    // 界面上就是"两个账号同一个邮箱"，用户根本没法分辨谁是谁。
    // 标签对不上时以现场为准，并把标签纠正过来。
    let liveName
    let liveMatched = false
    if (profile) {
      const liveUuid = readAccountUuid(profile)
      const match = matchLiveAccount(accounts, liveUuid)
      liveName = match.name
      liveMatched = match.matched
      if (liveName && liveName !== recorded) writeCurrentAccount(accountsBase, liveName)
    }

    // 在线账号的用量直接读当前 profile（plan-usage-history.json 是普通 JSON，
    // Desktop 运行中也读得到，而且它在持续追加 —— 这才是"最后一次记录"的本意）。
    // 邮箱所在的 IndexedDB 在运行中会被锁，读不到就沿用存档时记录的那个。
    if (profile && liveName) {
      const live = readAccountInsights(profile)
      const index = accounts.findIndex((item) => item.name === liveName)
      if (index >= 0) {
        accounts[index] = {
          ...accounts[index],
          ...(live.email ? { email: live.email } : {}),
          ...(live.usage ? { usage: live.usage } : {}),
          // 登录态以现场为准：存档里的值只代表保存那一刻，token 可能早过期了。
          ...(typeof live.signedIn === 'boolean' ? { signedIn: live.signedIn } : {}),
        }
      }
    }

    // 同一 uuid 有多份存档 = 同一个 Claude 账号被保存了好几次。标出来，
    // 否则用户会以为那是几个不同账号（A/D/E 现在就共用 28a11d61）。
    // 注意要按**所有**账号分组，不能只看现场匹配上的那一个 —— 重复账号往往
    // 恰好不是当前在线的那个。
    const byUuid = new Map()
    for (const account of accounts) {
      const uuid = readAccountUuid(account.dir)
      if (!uuid) continue
      if (!byUuid.has(uuid)) byUuid.set(uuid, [])
      byUuid.get(uuid).push(account.name)
    }
    for (const names of byUuid.values()) {
      if (names.length < 2) continue
      for (const account of accounts) {
        if (!names.includes(account.name)) continue
        account.sameAccountAs = names.filter((name) => name !== account.name)
      }
    }

    return {
      profile: profile ? { found: true, path: profile } : { found: false },
      accountsDir: accountsBase,
      current: liveName ?? recorded,
      liveMatched,
      accounts,
    }
  }

  /**
   * 代理设置现状：给「修正 Clash 设置」按钮上色用。
   *
   * 只读配置，不联网、不改系统。`needsFix` 为 true 时按钮显示红色。
   */
  const readProxyFixStateInternal = async () => {
    const probe = await deps.probeProxyMode()
    if (!probe.dir) return { found: false, needsFix: false, issues: [], mode: probe.mode }
    const settings = deps.readProxySettings(probe.dir)
    const issues = [
      ...deps.judgeProxySettings(settings),
      ...deps.judgeDnsUpstreams({ nameserver: settings.nameserver }),
    ]
    // 规则模式下，DNS 修好了也不够：Claude 的域名没被规则覆盖，照样会直连。
    const coverage =
      probe.mode === 'rule' ? deps.claudeRuleCoverage(deps.readClashRules(probe.dir)) : null
    if (coverage && !coverage.ok) issues.push(...coverage.issues)
    return {
      found: true,
      dir: probe.dir,
      client: probe.client,
      mode: probe.mode,
      settings,
      coverage,
      issues,
      needsFix: deps.needsClashFix(settings) || Boolean(coverage && !coverage.ok),
    }
  }

  const getProxyFixState = () => serialize(readProxyFixStateInternal)

  /**
   * 一键修正 Clash 设置：把 DNS 上游里的国内解析器去掉。
   *
   * 改完必须重启内核才生效（内核只在启动时读配置）。Verge GUI 常驻时会自动把内核
   * 重新拉起 —— 实测如此；这里等新进程出现再返回，避免界面报"已修正"但实际没生效。
   */
  const fixClashSettings = () =>
    serialize(async () => {
      const probe = await deps.probeProxyMode()
      if (!probe.dir) throw new Error('没找到受支持的代理客户端配置，无法自动修正')
      const outcome = deps.applyClashFix(probe.dir)
      const changedFiles = outcome.results.filter((item) => item.changed)
      // 规则模式下再补一手：把 Claude 的域名写进规则增强文件（订阅更新不会覆盖）。
      const ruleFix = probe.mode === 'rule' ? deps.applyClaudeRules(probe.dir) : { changed: false }
      if (changedFiles.length === 0 && ruleFix.changed !== true) {
        pushLog(
          'info',
          '代理设置无需修正',
          [...outcome.results.map((item) => item.reason), ruleFix.reason]
            .filter(Boolean)
            .join('；'),
        )
        emit({ type: 'status' })
        return { changed: 0, restarted: false, ...(await readProxyFixStateInternal()) }
      }
      if (ruleFix.changed === true) {
        pushLog(
          'info',
          '已把 Claude 规则写进规则增强文件',
          `${ruleFix.file?.split(/[\\/]/).pop() ?? ''}：${(ruleFix.after ?? []).join(', ')}`,
        )
      }
      pushLog(
        'info',
        `已修正 ${changedFiles.length} 个配置文件`,
        changedFiles
          .map(
            (item) =>
              `${item.file.split(/[\\/]/).pop()}：${(item.before ?? []).join(',')} → ${(item.after ?? []).join(',')}`,
          )
          .join('；'),
      )
      const restarted = await deps.restartProxyCore()
      if (restarted) {
        pushLog('info', '已重启代理内核，新 DNS 配置生效', '重启期间网络会短暂中断几秒')
      } else {
        pushLog('warn', '配置文件已改，但没能重启内核', '请在代理客户端里手动重启内核让改动生效')
      }
      emit({ type: 'status' })
      return {
        changed: changedFiles.length + (ruleFix.changed === true ? 1 : 0),
        restarted,
        ...(await readProxyFixStateInternal()),
      }
    })

  /**
   * 双向切换代理模式，并且**切换后必须自证**才报成功。
   *
   * 为什么要自证而不是只看配置：配置只说明"规则怎么写的"，不说明"这次连接怎么走的"。
   * 这里让内核开一条到 claude.ai / api.anthropic.com 的隧道，再读它的 `/connections`，
   * 看 `chains` 里是代理节点还是 DIRECT —— 那是运行时事实。测不出来算失败。
   *
   * 切规则模式失败会回滚到原模式；切全局失败不回滚（它本身就是安全侧），
   * 只如实报告内核没确认。
   */
  const setProxyMode = (target) =>
    serialize(async () => {
      const want = target === 'rule' ? 'rule' : 'global'
      const label = want === 'rule' ? '规则模式' : '全局模式'
      const probe = await deps.probeProxyMode()
      if (!probe.dir) throw new Error('没找到受支持的代理客户端配置，无法自动切换')
      if (probe.mode === 'direct') throw new Error('当前是直连模式，请先在代理客户端里切回全局模式再操作')

      const originalMode = probe.mode === 'unknown' ? 'global' : probe.mode
      const steps = []

      if (probe.mode === want) {
        // 已经是目标模式：不重启内核，只实测一次，如实告诉用户现状。
        const verify = await deps.verifyClaudeRouting({ dir: probe.dir, expectMode: want })
        const summary = (verify.results ?? [])
          .filter((item) => !item.error)
          .map((item) => `${item.host} → ${(item.chains ?? []).join('>')}`)
          .join('；')
        return {
          ok: verify.ok,
          unchanged: true,
          mode: want,
          steps: [`已经是${label}，没有改动`],
          verify,
          restarted: false,
          summary,
          ...(await readProxyFixStateInternal()),
        }
      }

      // 1) 规则模式要先有覆盖：没有就补，补不上就不切（不赌）。
      if (want === 'rule' && !deps.claudeRuleCoverage(deps.readClashRules(probe.dir)).ok) {
        const fixed = deps.applyClaudeRules(probe.dir)
        if (!fixed.changed) throw new Error(`写入 Claude 规则失败：${fixed.reason ?? '未知原因'}`)
        steps.push(`已写入 ${fixed.after?.length ?? 0} 条 Claude 规则${fixed.durable ? '' : '（未写入规则增强文件，订阅更新会丢）'}`)
      }

      // 2) 模式：写到生效配置 + 运行时副本。
      const modeOutcome = deps.writeProxyMode(probe.dir, want)
      if (modeOutcome.changed === 0) {
        throw new Error(`没能把配置改成${label}：${modeOutcome.results.map((item) => item.reason).filter(Boolean).join('；')}`)
      }
      steps.push(`配置已改为${label}`)

      // 3) 重启内核，让新配置真正被读进去。
      const restarted = await deps.restartProxyCore()
      if (!restarted) {
        if (want === 'rule') deps.writeProxyMode(probe.dir, originalMode)
        throw new Error(
          want === 'rule'
            ? '内核没能重启，配置没有生效，已回滚'
            : '配置已改为全局模式，但内核没能重启 —— 实际仍可能是原来的模式，请手动重启代理客户端',
        )
      }

      // 4) 自证：内核报告的是目标模式，且 Claude 的域名确实走了代理。
      const verify = await deps.verifyClaudeRouting({ dir: probe.dir, expectMode: want })
      const summary = (verify.results ?? [])
        .filter((item) => !item.error)
        .map((item) => `${item.host} → ${(item.chains ?? []).join('>')}`)
        .join('；')

      if (!verify.ok) {
        const why = verify.leaks?.length
          ? verify.leaks.map((item) => `${item.host} → ${(item.chains ?? []).join('>') || '直连'}`).join('，')
          : (verify.error ?? '测不出 Claude 的链路')
        if (want === 'rule') {
          deps.writeProxyMode(probe.dir, originalMode)
          await deps.restartProxyCore()
          throw new Error(
            `切到规则模式后没能证明 Claude 走代理（${why}），已回滚到${originalMode === 'global' ? '全局' : originalMode}模式`,
          )
        }
        throw new Error(`已写入全局模式，但内核没确认（${why}），请手动重启代理客户端后重试`)
      }

      pushLog('info', `已切换到${label}，内核自证通过`, summary || steps.join('；'))
      emit({ type: 'status' })
      return {
        ok: true,
        mode: want,
        steps,
        verify,
        restarted,
        summary,
        ...(await readProxyFixStateInternal()),
      }
    })

  /**
   * 代理没开时自愈网卡 DNS。
   *
   * Clash 的 DNS 覆写会把网卡 DNS 设成 198.18.0.2；内核退出后这个地址没人应答，
   * 表现是"国内国外全打不开"。这里在内核不在时把它换回国内公共解析器 ——
   * 内核在跑时一概不动，不和代理客户端抢配置。
   */
  const ensureSystemDns = () =>
    serialize(async () => {
      if (process.platform !== 'win32') return { checked: false, repaired: [] }
      let outcome
      try {
        outcome = deps.repairSystemDns()
      } catch (error) {
        return { checked: false, error: error instanceof Error ? error.message : String(error) }
      }
      if (outcome.repaired?.length > 0) {
        pushLog(
          'warn',
          '代理内核没在跑，网卡 DNS 还指着它 —— 已恢复成国内解析器',
          `网卡索引 ${outcome.repaired.join('、')} → 223.5.5.5、119.29.29.29`,
        )
      }
      return outcome
    })

  const getAccounts = () => serialize(async () => readAccountsState())

  /**
   * 新建空白账号：先占位，切过去由 Claude 弹登录页，登录完再点「更新」。
   *
   * 为什么不直接复制当前登录态：当前账号的 Cookies 是**别人的**。
   * 复制过去就成了重复账号（两个名字同一身份），登录页也不会出现。
   */
  const createEmptyAccountFor = (name) =>
    serialize(async () => {
      const wanted = (name ?? '').trim() || nextAccountName(listAccounts(accountsBase).map((item) => item.name))
      const result = createEmptyAccount(accountsBase, wanted)
      pushLog('info', `已新建空白账号 ${wanted}`, '切换过去后 Claude 会要求登录，登录完成请点「更新」保存')
      emit({ type: 'status' })
      return { ...result, ...readAccountsState() }
    })

  /** 把当前登录态存成账号 <name>；名字留空就自动分配 A、B、C… */
  const saveCurrentAccount = (name) =>
    serialize(async () => {
      const profile = resolveProfile()
      if (!profile) throw new Error('没找到 Claude Desktop 的数据目录（MSIX 包未安装或从未登录）')
      const wanted = (name ?? '').trim()
      const target = wanted || nextAccountName(listAccounts(accountsBase).map((item) => item.name))
      if (wanted) assertAccountName(wanted)
      // 存档前让 Desktop 退出：Cookies 是 SQLite，进程还在写的时候复制的快照可能不一致。
      const running = (await deps.listClaudeProcesses()).filter((item) => item.kind === 'desktop')
      if (running.length > 0) {
        await deps.killClaudeProcessesByKind('desktop')
        await waitForDesktopExit()
      }
      const result = saveAccount({ name: target, profileDir: profile, accountsDir: accountsBase })
      // 必须无条件更新「当前账号」：把现在这份登录保存为 <name>，就意味着"我现在是 <name>"。
      // 只在未记录时才写会产生危险的不一致 —— 用户登出 A、登录 B、保存为 B 之后，
      // current 还写着 A；下次切回 A 时会把 B 的登录态存进 A，直接覆盖 A 的数据。
      writeCurrentAccount(accountsBase, target)
      pushLog('info', `已把当前登录态保存为账号 ${target}`, `共 ${result.entries} 个身份条目`)
      emit({ type: 'status' })
      return { ...result, ...readAccountsState() }
    })

  const waitForDesktopExit = async () => {
    for (let i = 0; i < 40; i += 1) {
      const still = (await deps.listClaudeProcesses()).filter((item) => item.kind === 'desktop')
      if (still.length === 0) return true
      await new Promise((resolve) => setTimeout(resolve, 250))
    }
    return false
  }

  /**
   * 更新某个账号的存档（重新保存登录态）。
   *
   * 使用场景：登录态过期了 —— 用户先在 Claude 里重新登录，然后点这个账号的「更新」，
   * 把新鲜的 Cookies 存回原来的名字，不用删了重建。
   *
   * 关键判断：**只有当这个账号就是当前在用的账号时才允许更新**。
   * 因为"更新 C"的语义是"把现在这台机器上的登录态存成 C" —— 如果当前用的是 B，
   * 那存进去的是 B 的登录态，会把 C 覆盖成 B（数据直接串号）。
   * 想更新离线账号，正确路径是先切过去、重新登录、再更新。
   */
  const updateAccount = (name) =>
    serialize(async () => {
      const profile = resolveProfile()
      if (!profile) throw new Error('没找到 Claude Desktop 的数据目录（MSIX 包未安装或从未登录）')
      const current = readCurrentAccount(accountsBase)
      const target = (name ?? '').trim()
      assertAccountName(target)
      if (current !== target) {
        throw new Error(
          `现在用的是 ${current ?? '（未记录）'}，不能直接把它的登录态存成 ${target}。` +
            `要更新 ${target}，先切换到它、在 Claude 里重新登录，再点更新。`,
        )
      }
      const running = (await deps.listClaudeProcesses()).filter((item) => item.kind === 'desktop')
      if (running.length > 0) {
        await deps.killClaudeProcessesByKind('desktop')
        await waitForDesktopExit()
      }
      const result = saveAccount({ name: target, profileDir: profile, accountsDir: accountsBase })
      pushLog('info', `已更新账号 ${target} 的存档`, `共 ${result.entries} 个身份条目`)
      emit({ type: 'status' })
      return { ...result, updated: true, ...readAccountsState() }
    })

  /** 删除账号存档（不允许删当前正在用的那个）。 */
  const deleteAccount = (name) =>
    serialize(async () => {
      const result = removeAccount(accountsBase, (name ?? '').trim())
      pushLog('info', `已删除账号 ${result.name} 的存档`, '该账号的 Cookies 与会话历史已从本机移除')
      emit({ type: 'status' })
      return { ...result, ...readAccountsState() }
    })

  /**
   * 会话同步：把一个账号的 Desktop 会话索引复制到另一个账号。
   *
   * 三条设计约束（用户明确要求「我自己选择是否同步」）：
   *  1. **必须显式选择**：不传 sessionIds 就报错，绝不提供"同步全部"的默认行为。
   *  2. **必须显式指定目标**：不猜、不默认同步到当前账号。
   *  3. **只搬索引，不动正文**：正文在 ~/.claude 里本来就全账号共享（切号不碰它），
   *     所以复制索引就够；列清单时逐条标出正文是否还在，缺正文的由界面提示。
   */
  const listSyncableSessions = (name) =>
    serialize(async () => {
      const target = (name ?? '').trim()
      assertAccountName(target)
      const dir = accountDir(accountsBase, target)
      if (!existsSync(dir)) throw new Error(`账号 ${target} 不存在`)
      const projectsDir = deps.claudeProjectsDir()
      const sessions = []
      for (const group of listSessionGroups(dir)) {
        for (const session of listSessions(group.dir)) {
          sessions.push({
            ...session,
            orgUuid: group.orgUuid,
            accountUuid: group.accountUuid,
            bodyExists: sessionBodyExists({
              claudeProjectsDir: projectsDir,
              projectFolder: projectFolderFor(session.cwd),
              cliSessionId: session.cliSessionId,
            }),
          })
        }
      }
      return { account: target, sessions }
    })

  const syncSessionsTo = ({ from, to, sessionIds, sourceOrgUuid, targetOrgUuid } = {}) =>
    serialize(async () => {
      const source = (from ?? '').trim()
      const target = (to ?? '').trim()
      assertAccountName(source)
      assertAccountName(target)
      if (source === target) throw new Error('源账号和目标账号不能是同一个')

      const sourceRoot = accountDir(accountsBase, source)
      const targetRoot = accountDir(accountsBase, target)
      if (!existsSync(sourceRoot)) throw new Error(`源账号 ${source} 不存在`)
      if (!existsSync(targetRoot)) throw new Error(`目标账号 ${target} 不存在`)

      const sourceGroups = listSessionGroups(sourceRoot)
      const sourceGroup = sourceOrgUuid
        ? sourceGroups.find((group) => group.orgUuid === sourceOrgUuid)
        : sourceGroups.find((group) => group.count > 0)
      if (!sourceGroup) throw new Error(`源账号 ${source} 没有会话目录`)

      // 目标组织目录必须已经存在——不新建，因为那等于我们猜了一个 org ID，
      // Desktop 未必认，会话会变成"看得见但打不开"。
      const targetGroups = listSessionGroups(targetRoot).filter((group) => group.count > 0)
      const targetGroup = targetOrgUuid
        ? targetGroups.find((group) => group.orgUuid === targetOrgUuid)
        : targetGroups[0]
      if (!targetGroup) {
        throw new Error(
          `目标账号 ${target} 还没有可用的组织目录：先在 ${target} 里创建一个会话，再回来同步`,
        )
      }

      const result = copySessions({
        sourceDir: sourceGroup.dir,
        targetDir: targetGroup.dir,
        sessionIds,
      })
      pushLog(
        'info',
        `已同步 ${result.copied.length} 个会话到账号 ${target}`,
        [
          result.skipped.length ? `跳过 ${result.skipped.length} 个（目标已有）` : undefined,
          result.missing.length ? `缺失 ${result.missing.length} 个` : undefined,
        ]
          .filter(Boolean)
          .join('；') || undefined,
      )
      emit({ type: 'status' })
      return {
        from: source,
        to: target,
        copied: result.copied,
        skipped: result.skipped,
        missing: result.missing,
      }
    })

  const switchAccountTo = (name) =>
    serialize(async () => {
      const profile = resolveProfile()
      if (!profile) throw new Error('没找到 Claude Desktop 的数据目录（MSIX 包未安装或从未登录）')

      // 切号必须先过环境判定。
      //
      // 理由：切号之后用户紧接着就要启动 Desktop，而闸门不会因为"换了个号"就放行。
      // 环境不合规时切过去，结果是新号一启动就被断网、甚至被终止 —— 用户会以为切号坏了，
      // 实际是两个机制各干各的。所以这里和门控启动用同一条判定，不通过就**不动现场**：
      // 不杀进程、不存档，把原因直接返回。
      const check = await checkInternal()
      if (!check.allow) {
        const reasons = (check.blocked ?? []).map((item) => item.title)
        const reason =
          reasons.join('；') || (check.failedClosed ? '出口身份无法确认（failClosed）' : '白名单未命中')
        pushLog('block', `已拒绝切换到账号 ${name}`, reason)
        emit({ type: 'status' })
        return { switched: false, allow: false, reason, check, ...readAccountsState() }
      }

      const current = readCurrentAccount(accountsBase)
      pushLog('info', `正在切换到账号 ${name}`, current ? `当前：${current}` : '当前：未记录')
      const result = await switchAccount({
        name,
        profileDir: profile,
        accountsDir: accountsBase,
        current,
        // 用户明确选择"直接结束进程"：切号必须独占 profile 里的文件。
        killProcesses: async () => {
          const killed = await deps.killClaudeProcessesByKind('desktop')
          const exited = await waitForDesktopExit()
          return { killed, exited }
        },
      })
      writeCurrentAccount(accountsBase, name)
      pushLog(
        'info',
        `已切换到账号 ${name}`,
        [
          result.archivedFrom ? `已把 ${result.archivedFrom} 的登录态存档` : undefined,
          result.captured ? '首次运行：现有登录已收编' : undefined,
          result.killed?.exited === false ? '注意：Desktop 进程未完全退出，切换可能不完整' : undefined,
        ]
          .filter(Boolean)
          .join('；') || undefined,
      )
      emit({ type: 'status' })
      return { ...result, switched: true, ...readAccountsState() }
    })

  /**
   * 门控启动 Claude Desktop：**先检测，判定通过才启动**。
   *
   * 为什么需要这条路径：直接双击 Claude 图标是绕过闸门的 —— 闸门只能事后终止它，
   * 而"启动那一下"的请求已经发出去了。从界面启动则不同：这一次启动有明确的判定作前提。
   *
   * 拒绝时不抛异常，返回结构化原因，界面据此把"为什么不让开"直接显示出来。
   */
  const launchClaudeDesktop = () =>
    serialize(async () => {
      const config = getConfig()
      // 必须用 Internal：本函数已在串行队列里，再走 checkNow 会等自己占用的队列（死锁）。
      const check = await checkInternal()
      if (!check.allow) {
        const reasons = (check.blocked ?? []).map((item) => item.title)
        const reason =
          reasons.join('；') || (check.failedClosed ? '出口身份无法确认（failClosed）' : '白名单未命中')
        pushLog('block', '已拒绝启动 Claude Desktop', reason)
        emit({ type: 'status' })
        return { launched: false, reason, allow: false, check }
      }

      const target = deps.resolveDesktopTarget()
      if (!target) {
        const reason = '找不到 Claude Desktop 的可执行文件'
        pushLog('error', reason, '已发现的可执行文件里没有桌面版入口；请确认已安装 Claude Desktop。')
        emit({ type: 'status' })
        return { launched: false, reason, allow: true, check }
      }

      try {
        const before = await deps.listClaudeProcesses()
        const beforeIds = new Set(before.map((item) => item.pid))
        const pid = deps.launchDesktop(target, proxyEnvFor(config))

        // 拉起进程不能只看"命令没报错"。
        // `cmd /c start` 对 MSIX 别名是立即返回成功的 —— 应用可能根本没起来，
        // 早先就是这么报了个假成功（用户点完按钮，Claude Desktop 实际没运行）。
        // 这里等真实进程出现，再决定报成功还是失败。
        const started = await deps.waitForDesktopProcess(beforeIds)
        if (!started) {
          const reason = '启动命令已执行，但 12 秒内没有检测到 Claude Desktop 进程'
          pushLog('error', 'Claude Desktop 未能启动', `${target.path}；请手动启动一次确认程序本身可用`)
          emit({ type: 'status' })
          return { launched: false, reason, allow: true, check }
        }

        // 窗口可能以最小化状态出现（实测：Claude 会缩到托盘），把它带回前台，
        // 否则用户点完按钮"什么都没发生"。
        const focused = await deps.focusDesktopWindow()
        pushLog('ok', '已启动 Claude Desktop', focused ? target.path : `${target.path}（窗口未能置前，请在任务栏切换）`)
        lastEnforcement = { at: nowIso(), kind: 'launch-desktop', pid }
        emit({ type: 'status' })
        return { launched: true, pid, path: target.path, focused, allow: true, check }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        pushLog('error', '启动 Claude Desktop 失败', message)
        emit({ type: 'status' })
        return { launched: false, reason: message, allow: true, check }
      }
    })

  const enableFirewallProfiles = () =>
    serialize(async () => {
      const result = await deps.enableProfiles()
      invalidateCache()
      if (!result.ok) {
        pushLog('error', '启用防火墙配置文件失败', result.error)
        throw new Error(result.error)
      }
      pushLog('ok', '已启用 Windows 防火墙配置文件', result.profiles.map((item) => item.name).join('、'))
      emit({ type: 'status' })
      return result
    })

  /** 保存配置：写盘 → 重新加载 → 校验 → 若闸门在运行则用新配置重启它。 */
  const saveConfig = (patch) =>
    serialize(async () => {
      const next = applyConfigPatch(getConfig(), patch ?? {})
      const problems = validateConfig(next)
      if (problems.length > 0 && patch?.allowInvalid !== true) {
        const error = new Error(`配置校验未通过：${problems.join('；')}`)
        pushLog('warn', '配置未保存', problems.join('；'))
        throw error
      }
      writeFileSync(configPath, `${JSON.stringify(next, null, 2)}\n`, 'utf8')
      loaded = { path: configPath, exists: true, config: next, raw: next }
      configProblems = problems
      stateDir = resolveStateDir(next, configPath)
      pushLog('ok', '配置已保存', configPath)
      if (guard) {
        // 闸门在跑：先停（撤掉旧阻断）再按新配置重启，保证执法用的是最新白名单。
        // 这里只能用 Internal 版本：当前动作已占用串行队列，不能再入队。
        pushLog('info', '配置变更，正在按新配置重启闸门')
        try {
          await stopGuardInternal()
        } catch {
          // 停不下来也要继续重启。
        }
        await startGuardInternal()
      }
      emit({ type: 'status' })
      return next
    })

  const reloadConfig = () =>
    serialize(async () => {
      loaded = loadConfig(configPath)
      configProblems = validateConfig(loaded.config)
      pushLog('info', '已从磁盘重新读取配置')
      emit({ type: 'status' })
      return getConfig()
    })

  return {
    getStateDir: () => stateDir,
    getConfig,
    getProblems: () => configProblems,
    getStatus,
    getLogs: () => logs.slice(),
    checkNow,
    startGuard,
    stopGuard,
    setFirewall,
    killProcesses,
    getProxyFixState,
    fixClashSettings,
    setProxyMode,
    ensureSystemDns,
    getAccounts,
    saveCurrentAccount,
    createEmptyAccountFor,
    updateAccount,
    deleteAccount,
    listSyncableSessions,
    syncSessionsTo,
    switchAccountTo,
    launchClaudeDesktop,
    enableFirewallProfiles,
    saveConfig,
    reloadConfig,
    subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    /**
     * 监视"阻断状态"的变化并广播，让界面不必等轮询。
     *
     * 为什么需要：阻断可能是**别的实例**建立的（例如安装版托盘的闸门在跑），
     * 那种变化不会触发本会话的任何事件，界面只能靠轮询发现 —— 实测出现过
     * "托盘已经把网络断掉了、界面还写着可以访问网络"的过期显示。
     * 这里只比对两个便宜的信号（常驻宿主数量、生效规则数），变了才推事件。
     */
    startWatching(intervalMs = 6_000) {
      if (watchTimer) return
      const snapshot = async () => {
        try {
          const hosts = await deps.listWfpHosts()
          const rules = await deps.listManagedRules()
          const enabled = rules.filter((rule) => rule.enabled).length
          const blocked = hosts.length > 0 || enabled > 0
          const signature = `${hosts.length}|${enabled}`
          if (watchSignature !== null && watchSignature !== signature) {
            emit({ type: 'status' })
          }
          watchSignature = signature
          void blocked
        } catch {
          // 探测失败不改状态：下一次再比。
        }
      }
      void snapshot()
      watchTimer = setInterval(() => void snapshot(), intervalMs)
      if (typeof watchTimer.unref === 'function') watchTimer.unref()

      // 托盘/CLI 的"启动闸门"请求（`ccgait guard-start`）：执法已经挪进这个常驻服务
      // 进程，别处再也起不了闸门（起了就是第二个、多一套 WFP 过滤器），所以它们只能
      // 请求本进程把自己的闸门对象建起来。单独用 1 秒的轻量定时器盯着，别和上面 6 秒
      // 的状态比对混在一起 —— 托盘点完只等 1.5 秒就会去核对结果。
      watchStartTimer = setInterval(() => {
        if (!stateDir || !existsSync(guardStartRequestPath(stateDir))) return
        clearGuardStartRequest(stateDir)
        if (guard === null) void startGuard()
      }, 1000)
      if (typeof watchStartTimer.unref === 'function') watchStartTimer.unref()
    },
    /** 退出时收尾：停掉闸门并撤掉阻断，避免留下"上不了网"的残留。 */
    async dispose() {
      if (watchTimer) {
        clearInterval(watchTimer)
        watchTimer = null
      }
      if (watchStartTimer) {
        clearInterval(watchStartTimer)
        watchStartTimer = null
      }
      if (guard) {
        try {
          await guard.stop()
        } catch {
          // 忽略：退出流程不阻塞。
        }
        guard = null
      }
      for (const listener of listeners) {
        try {
          listener({ type: 'closed' })
        } catch {
          // 忽略。
        }
      }
      listeners.clear()
    },
  }
}

/** 供 UI 展示：当前配置文件是否存在、示例文件路径。 */
export function describeConfigFile(configPath) {
  return {
    path: configPath,
    exists: existsSync(configPath),
    raw: existsSync(configPath) ? readFileSync(configPath, 'utf8') : '',
  }
}
