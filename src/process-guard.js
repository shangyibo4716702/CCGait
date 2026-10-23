import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { classifyProcess, discoverClaudeTargets } from './claude-targets.js'

/**
 * Claude 进程的发现与终止。
 *
 * 只处理被识别为 Claude 客户端的进程：命令里出现 claude-code 包路径、或可执行文件
 * 位于 Claude 的安装目录。绝不按 node.exe / electron.exe 这类通用名字批量终止，
 * 以免波及机器上其它程序。
 */

const execFileAsync = promisify(execFile)

async function runPowerShell(script, timeoutMs = 15_000) {
  const { stdout } = await execFileAsync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', script],
    { windowsHide: true, timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 },
  )
  return stdout.trim()
}

/** 当前正在运行的 Claude 客户端进程。 */
export async function listClaudeProcesses() {
  if (process.platform !== 'win32') return []
  let stdout
  try {
    stdout = await runPowerShell(
      "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '(?i)^claude' -or $_.CommandLine -match '(?i)claude-code' } | Select-Object ProcessId,Name,ExecutablePath,CommandLine | ConvertTo-Json -Compress -Depth 3",
    )
  } catch {
    return []
  }
  if (!stdout || stdout === 'null') return []

  let parsed
  try {
    parsed = JSON.parse(stdout)
  } catch {
    return []
  }
  const rows = Array.isArray(parsed) ? parsed : [parsed]
  const results = []
  for (const row of rows) {
    const kind = classifyProcess({
      name: row.Name,
      exePath: row.ExecutablePath,
      commandLine: row.CommandLine,
    })
    if (!kind) continue
    results.push({
      pid: Number(row.ProcessId),
      name: String(row.Name ?? ''),
      exePath: String(row.ExecutablePath ?? ''),
      commandLine: String(row.CommandLine ?? ''),
      kind,
    })
  }
  return results
}

/** 终止指定进程（含子进程）。 */
export async function killProcess(pid) {
  try {
    await execFileAsync('taskkill.exe', ['/PID', String(pid), '/F', '/T'], {
      windowsHide: true,
      timeout: 15_000,
    })
    return { pid, killed: true }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    // 进程已经退出属于正常情况。
    if (/not found|找不到|没有运行/i.test(message)) return { pid, killed: false, gone: true }
    return { pid, killed: false, error: message }
  }
}

/** 发现 → 终止，返回本次处理明细。 */
export async function killAllClaudeProcesses() {
  return killClaudeProcessesByKind(undefined)
}

/**
 * 只终止某一类进程（'desktop' 或 'cli'）。
 *
 * 切号只需要动桌面版：它换的是 Desktop 的 profile。把正在跑的 CLI 一起杀掉
 * 等于顺带毁掉用户手上的活的 —— CLI 的数据目录根本不参与切换。
 */
export async function killClaudeProcessesByKind(kind) {
  const processes = await listClaudeProcesses()
  const targets = kind ? processes.filter((item) => item.kind === kind) : processes
  const results = []
  for (const processInfo of targets) {
    const outcome = await killProcess(processInfo.pid)
    results.push({ ...processInfo, ...outcome })
  }
  return results
}

/** 供防火墙使用的可执行文件清单。 */
export function claudeExecutablePaths(options) {
  return [...new Set(discoverClaudeTargets(options).entries.map((item) => item.path))]
}

/** 发现结果（含诊断信息），CLI 的 targets/status 用得到。 */
export function claudeDiscovery(options) {
  return discoverClaudeTargets(options)
}
