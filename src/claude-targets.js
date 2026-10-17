import { existsSync, readdirSync, realpathSync, statSync } from 'node:fs'
import { join } from 'node:path'

/**
 * 找出 Claude Code CLI 与 Claude Desktop 的可执行文件。
 *
 * 不同安装方式的落点完全不同，所以按已知根目录逐个探测：
 *   1. npm 全局：%APPDATA%\npm\node_modules\@anthropic-ai\claude-code\
 *   2. 原生安装器：~/.local/bin、%LOCALAPPDATA%\Programs\claude-code
 *   3. Desktop(Squirrel)：%LOCALAPPDATA%\AnthropicClaude\app-<ver>\
 *   4. Desktop(MSIX)：C:\Program Files\WindowsApps\Claude_<ver>\app\
 *   5. MSIX 别名：%LOCALAPPDATA%\Microsoft\WindowsApps\claude-*.exe（符号链接，需解析到真实路径）
 *
 * 判定"属于 Claude"用的是路径归属：只要可执行文件位于 Claude 的安装根目录内，
 * 就是它的一部分（Desktop 的辅助进程 cowork-svc / ssh-proxy 等也算）。这样既不
 * 会漏掉辅助进程，也不会因为进程名巧合而误伤其它程序。
 */

function safeReaddir(directory) {
  try {
    return readdirSync(directory, { withFileTypes: true })
  } catch {
    return undefined
  }
}

/** 递归收集目录下的 .exe；可传 filter 限定文件名。返回 undefined 表示目录不可读。 */
function collectExecutables(directory, { filter, maxDepth = 4, depth = 0 } = {}) {
  const entries = safeReaddir(directory)
  if (entries === undefined) return undefined
  const found = []
  for (const entry of entries) {
    const full = join(directory, entry.name)
    let isDirectory = entry.isDirectory()
    let isFile = entry.isFile()
    if (entry.isSymbolicLink()) {
      try {
        const stats = statSync(full)
        isDirectory = stats.isDirectory()
        isFile = stats.isFile()
      } catch {
        continue
      }
    }
    if (isFile && /\.exe$/i.test(entry.name)) {
      if (!filter || filter.test(entry.name)) found.push(full)
    } else if (isDirectory && depth < maxDepth) {
      const nested = collectExecutables(full, { filter, maxDepth, depth: depth + 1 })
      if (nested) found.push(...nested)
    }
  }
  return found
}

/** 解析符号链接到真实路径（MSIX 别名用得到）。失败时回退原路径。 */
function resolveRealPath(path) {
  try {
    return realpathSync(path)
  } catch {
    return path
  }
}

export function discoverClaudeTargets(options = {}) {
  const localAppData = options.localAppData ?? process.env.LOCALAPPDATA ?? ''
  const appData = options.appData ?? process.env.APPDATA ?? ''
  const home = options.home ?? process.env.USERPROFILE ?? process.env.HOME ?? ''
  const windowsAppsDir = options.windowsAppsDir ?? 'C:\\Program Files\\WindowsApps'

  const notes = []
  const entries = []

  const addAll = (paths, kind, label) => {
    for (const path of paths ?? []) {
      entries.push({ kind, label, path: resolveRealPath(path) })
    }
  }

  // 1. npm 全局 CLI：整包目录下的 exe 都属于它。
  addAll(
    collectExecutables(join(appData, 'npm', 'node_modules', '@anthropic-ai', 'claude-code')),
    'cli',
    'Claude Code CLI（npm 全局）',
  )

  // 2. 原生安装器落点：只认 claude*.exe，避免把该目录里其它工具算进来。
  addAll(
    collectExecutables(join(home, '.local', 'bin'), { filter: /^claude.*\.exe$/i, maxDepth: 1 }),
    'cli',
    'Claude Code CLI（原生安装器）',
  )
  addAll(
    collectExecutables(join(localAppData, 'Programs', 'claude-code'), {
      filter: /^claude.*\.exe$/i,
      maxDepth: 3,
    }),
    'cli',
    'Claude Code CLI（Programs 安装）',
  )

  // 3. Desktop（Squirrel 安装）
  const squirrel = join(localAppData, 'AnthropicClaude')
  addAll(collectExecutables(squirrel, { maxDepth: 3 }), 'desktop', 'Claude Desktop（Squirrel）')
  if (!existsSync(squirrel)) notes.push(`未发现 Squirrel 安装目录：${squirrel}`)

  // 4. Desktop（MSIX 商店包）：只扫 Claude_* 包目录，避免遍历整个 WindowsApps。
  const windowsAppsEntries = safeReaddir(windowsAppsDir)
  if (windowsAppsEntries === undefined) {
    notes.push(
      `无法读取 ${windowsAppsDir}（需要管理员权限），MSIX 版 Claude Desktop 可能因此未被发现`,
    )
  } else {
    const packages = windowsAppsEntries.filter(
      (entry) => entry.isDirectory() && /^Claude_/i.test(entry.name),
    )
    if (packages.length === 0) notes.push(`${windowsAppsDir} 下没有 Claude_* 包目录`)
    for (const item of packages) {
      addAll(
        collectExecutables(join(windowsAppsDir, item.name), { maxDepth: 4 }),
        'desktop',
        `Claude Desktop（MSIX ${item.name}）`,
      )
    }
  }

  // 5. MSIX 别名：用户通常从这里启动，需解析到真实 exe 才能被防火墙规则覆盖。
  addAll(
    collectExecutables(join(localAppData, 'Microsoft', 'WindowsApps'), {
      filter: /^claude.*\.exe$/i,
      maxDepth: 1,
    }),
    'desktop',
    'Claude Desktop（MSIX 别名）',
  )

  // 去重（Windows 路径大小写不敏感）
  const seen = new Set()
  const unique = []
  for (const entry of entries) {
    const key = entry.path.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    unique.push(entry)
  }
  return { entries: unique, notes }
}

// 命令行兜底只对解释器进程生效：CLI 以 Node 脚本形式安装时，真身是 node.exe 跑
// cli.js，只能靠命令行里的包路径认出来。
const INTERPRETER_NAMES = new Set(['node.exe', 'bun.exe', 'deno.exe'])

// 这些宿主进程一律不判为 Claude 客户端。原因很实际：只要某个终端/编辑器的命令行里
// 出现过 claude-code 路径（打开该目录、跑一次 node 调试都算），仅凭命令行就会把它们
// 认成 CLI，拦截时会把用户自己的终端一起杀掉。
const HOST_PROCESS_NAMES = new Set([
  'bash.exe',
  'sh.exe',
  'dash.exe',
  'zsh.exe',
  'cmd.exe',
  'powershell.exe',
  'pwsh.exe',
  'conhost.exe',
  'windowsterminal.exe',
  'wt.exe',
  'explorer.exe',
  'code.exe',
  'wsl.exe',
  'wslhost.exe',
])

/**
 * 进程命令行/路径是否属于 Claude 客户端。
 *
 * 判定顺序：安装目录 → 包目录 → 可执行文件名 → 解释器命令行兜底。前三条看的是
 * 程序自身的落盘位置，不会误伤；只有最后一条依赖命令行文本，所以额外用宿主进程
 * 名单挡住 shell 与编辑器。
 */
export function classifyProcess({ name, exePath, commandLine }) {
  const exe = String(exePath ?? '')
  const cmd = String(commandLine ?? '')
  const lowerExe = exe.toLowerCase()
  const lowerCmd = cmd.toLowerCase()
  const base = String(name ?? '').toLowerCase() || lowerExe.split(/[\\/]/).pop() || ''

  if (HOST_PROCESS_NAMES.has(base)) return null

  const inDesktopDir =
    lowerExe.includes('anthropicclaude') || (lowerExe.includes('windowsapps') && lowerExe.includes('claude'))
  if (inDesktopDir) return 'desktop'
  if (lowerExe.includes('claude-code')) return 'cli'
  if (/^claude[^\\/]*\.exe$/.test(base)) {
    // 裸 claude.exe：装在 npm / node_modules 下按 CLI 算，其余按桌面版算。
    return lowerExe.includes('npm') || lowerExe.includes('node_modules') ? 'cli' : 'desktop'
  }
  if (INTERPRETER_NAMES.has(base) && lowerCmd.includes('@anthropic-ai') && lowerCmd.includes('claude-code')) {
    return 'cli'
  }
  return null
}
