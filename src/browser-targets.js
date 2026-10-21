import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'

/**
 * 默认浏览器的发现。
 *
 * 为什么需要管浏览器：Claude 客户端登录会打开系统默认浏览器做 OAuth。
 * 只掐 Claude 自己的进程是不够的 —— 浏览器照样能上外网，那条流量同样会出去。
 * 所以登录链路涉及的浏览器必须和 Claude 享受同一套管控：网络按同样规则拦，
 * 但**不杀进程**（用户可能正开着几十个标签页）。
 *
 * 这里只负责"找出默认浏览器是哪个程序"，不写死 Edge：不同机器默认可能是
 * Chrome / Firefox / Brave / Edge。注册表里的 ProgId 是权威来源。
 */

const execFileAsync = promisify(execFile)

/** ProgId → 可执行文件名（用于识别与兜底路径）。 */
const PROGID_HINTS = [
  { test: /^MSEdge/i, name: 'msedge.exe', label: 'Microsoft Edge' },
  { test: /^Chrome/i, name: 'chrome.exe', label: 'Google Chrome' },
  { test: /^Firefox/i, name: 'firefox.exe', label: 'Mozilla Firefox' },
  { test: /^Brave/i, name: 'brave.exe', label: 'Brave' },
  { test: /^Vivaldi/i, name: 'vivaldi.exe', label: 'Vivaldi' },
  { test: /^Opera/i, name: 'opera.exe', label: 'Opera' },
]

/** 各浏览器的常见安装位置（读取失败时按名字兜底）。 */
export function browserFallbackPaths(env = process.env) {
  const pf = env['ProgramFiles'] ?? 'C:\\Program Files'
  const pf86 = env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)'
  const local = env['LOCALAPPDATA'] ?? ''
  return [
    { name: 'msedge.exe', label: 'Microsoft Edge', paths: [join(pf86, 'Microsoft', 'Edge', 'Application', 'msedge.exe'), join(pf, 'Microsoft', 'Edge', 'Application', 'msedge.exe')] },
    { name: 'chrome.exe', label: 'Google Chrome', paths: [join(pf, 'Google', 'Chrome', 'Application', 'chrome.exe'), join(pf86, 'Google', 'Chrome', 'Application', 'chrome.exe'), ...(local ? [join(local, 'Google', 'Chrome', 'Application', 'chrome.exe')] : [])] },
    { name: 'firefox.exe', label: 'Mozilla Firefox', paths: [join(pf, 'Mozilla Firefox', 'firefox.exe'), join(pf86, 'Mozilla Firefox', 'firefox.exe')] },
    { name: 'brave.exe', label: 'Brave', paths: [join(pf, 'BraveSoftware', 'Brave-Browser', 'Application', 'brave.exe')] },
    { name: 'vivaldi.exe', label: 'Vivaldi', paths: [join(local, 'Vivaldi', 'Application', 'vivaldi.exe')] },
    { name: 'opera.exe', label: 'Opera', paths: [join(local, 'Programs', 'Opera', 'opera.exe')] },
  ]
}

/**
 * 读注册表里的默认浏览器 ProgId。
 *
 * 只用 HKCU 的 UserChoice：那里是用户实际点击链接时生效的那一个。
 * 读不到（新账户、被策略锁定）就回退到"按常见浏览器存在性猜一个"。
 */
export async function probeDefaultBrowser({ runPowerShell } = {}) {
  const run = runPowerShell ?? defaultRunPowerShell
  const script =
    "$k='HKCU:\\SOFTWARE\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\https\\UserChoice';" +
    "try { $v=(Get-ItemProperty $k -ErrorAction Stop).ProgId; if ($v) { Write-Output $v } } catch { Write-Output '' }"
  try {
    const progId = String(await run(script)).trim()
    if (progId.length > 0) {
      const hint = PROGID_HINTS.find((item) => item.test.test(progId))
      return { progId, name: hint?.name, label: hint?.label, source: 'registry' }
    }
  } catch {
    // 读注册表失败不是错误：下面还有兜底。
  }
  return { progId: undefined, source: 'unknown' }
}

async function defaultRunPowerShell(script, timeoutMs = 10_000) {
  const { stdout } = await execFileAsync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', script],
    { windowsHide: true, timeout: timeoutMs, maxBuffer: 1024 * 1024 },
  )
  return stdout
}

/**
 * 解析默认浏览器的可执行文件路径。
 *
 * 优先用注册表给出的 ProgId 指明浏览器种类，再到常见安装位置找 exe；
 * 找不到就返回 undefined（调用方据此跳过浏览器管控，并如实写日志，
 * 不能假装管住了）。
 */
export async function discoverDefaultBrowser({ env = process.env, exists = existsSync, runPowerShell } = {}) {
  const probe = await probeDefaultBrowser({ runPowerShell })
  const fallbacks = browserFallbackPaths(env)

  if (probe.name) {
    const entry = fallbacks.find((item) => item.name.toLowerCase() === probe.name.toLowerCase())
    if (entry) {
      const found = entry.paths.find((path) => exists(path))
      if (found) return { ...entry, path: found, progId: probe.progId }
      return { ...entry, path: undefined, progId: probe.progId, missing: true }
    }
  }

  // 未知 ProgId：按"装了哪个就用哪个"的顺序兜底（Edge 排在最前，Windows 必装）。
  for (const entry of fallbacks) {
    const found = entry.paths.find((path) => exists(path))
    if (found) return { ...entry, path: found, progId: probe.progId, inferred: true }
  }
  return { progId: probe.progId, path: undefined, missing: true }
}

/**
 * 需要纳入管控的可执行文件清单。
 *
 * 浏览器只做网络管控、不参与进程终止，所以这个清单和 Claude 的清单分开返回，
 * 调用方据此决定"拦网"还是"拦网+杀进程"。
 */
export function browserBlockTargets(browser) {
  if (!browser || !browser.path) return []
  // 同一浏览器的其它安装副本也要覆盖：用户可能从 Program Files 或 x86 任意一个启动。
  const paths = new Set([browser.path])
  for (const entry of browserFallbackPaths()) {
    if (entry.name.toLowerCase() !== browser.name?.toLowerCase()) continue
    for (const path of entry.paths) if (existsSync(path)) paths.add(path)
  }
  return [...paths]
}
