import { spawn } from 'node:child_process'
import { existsSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Windows 应用窗口：用系统自带的 Edge（或 Chrome）以 APP 模式打开界面。
 *
 * 为什么这样做而不是打包 Electron：
 * - **零依赖**。Electron 要拉 250MB 运行时；APP 模式用机器上已有的 Edge，
 *   得到的是没有地址栏、没有标签页、有独立任务栏图标的原生窗口，观感就是普通桌面应用。
 * - **离线可用**。界面本身完全本地，不请求任何外部资源。
 * - **不污染你的浏览器**。用独立的 user-data-dir，不动你日常的 Edge 配置。
 *
 * 代价：它本质上是 Edge 承载的窗口（进程名是 msedge.exe），不是自包含 .exe。
 * 需要完全独立的分发形态时再上 Electron，这条命令的接口不用变。
 */

const WINDOW_SIZE = '1440,1040'

/** 常见安装位置（按优先级）。 */
export function browserCandidates(env = process.env) {
  const programFiles = env['ProgramFiles'] ?? 'C:\\Program Files'
  const programFilesX86 = env['ProgramFiles(x86)'] ?? 'C:\\Program Files (x86)'
  const localAppData = env.LOCALAPPDATA ?? ''
  return [
    { kind: 'edge', path: join(programFilesX86, 'Microsoft', 'Edge', 'Application', 'msedge.exe') },
    { kind: 'edge', path: join(programFiles, 'Microsoft', 'Edge', 'Application', 'msedge.exe') },
    { kind: 'chrome', path: join(programFiles, 'Google', 'Chrome', 'Application', 'chrome.exe') },
    { kind: 'chrome', path: join(programFilesX86, 'Google', 'Chrome', 'Application', 'chrome.exe') },
    ...(localAppData
      ? [
          { kind: 'chrome', path: join(localAppData, 'Google', 'Chrome', 'Application', 'chrome.exe') },
        ]
      : []),
  ]
}

/** 找到可用的浏览器可执行文件。exists 可注入，便于测试。 */
export function resolveBrowser(env = process.env, exists = existsSync) {
  for (const candidate of browserCandidates(env)) {
    if (exists(candidate.path)) return candidate
  }
  return undefined
}

/** APP 模式参数：独立 profile + 固定窗口 + 无首启向导。 */
export function appWindowArgs(url, profileDir) {
  return [
    `--app=${url}`,
    `--window-size=${WINDOW_SIZE}`,
    `--user-data-dir=${profileDir}`,
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-features=Translate,msEdgeSplitScreen',
    '--disable-sync',
  ]
}

/** 打开应用窗口；返回浏览器信息或原因。 */
export function openAppWindow({ url, profileDir, env = process.env, exists = existsSync }) {
  const browser = resolveBrowser(env, exists)
  if (!browser) {
    return { opened: false, reason: '未找到 Microsoft Edge 或 Google Chrome' }
  }
  const child = spawn(browser.path, appWindowArgs(url, profileDir), {
    detached: true,
    stdio: 'ignore',
  })
  child.unref()
  return { opened: true, browser: browser.kind, executable: browser.path }
}
