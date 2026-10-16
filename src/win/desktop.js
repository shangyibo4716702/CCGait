import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, openSync } from 'node:fs'
import { join } from 'node:path'
import { PROJECT_ROOT } from '../config.js'
import { openAppWindow } from './browser-window.js'
import { writeIconFiles } from './icon.js'

/**
 * Windows 客户端入口：确保本地服务在跑 → 打开独立应用窗口。
 *
 * 服务与窗口分离的好处：关掉窗口不会停掉闸门（后台继续执法），
 * 再次打开窗口会复用同一个服务进程，状态连续。
 */

export const DEFAULT_UI_PORT = 17890

/** 服务是否已经在监听（任何 HTTP 响应都算，401 也算 —— 说明进程活着）。 */
export async function isUiServerUp(port, { fetchImpl = fetch, timeoutMs = 1500 } = {}) {
  try {
    await fetchImpl(`http://127.0.0.1:${port}/`, { signal: AbortSignal.timeout(timeoutMs) })
    return true
  } catch {
    return false
  }
}

/** 轮询等待服务就绪。 */
export async function waitForUiServer(port, { timeoutMs = 12_000, intervalMs = 500, fetchImpl = fetch } = {}) {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    if (await isUiServerUp(port, { fetchImpl })) return true
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }
  return false
}

/** 后台拉起 UI 服务（隐藏窗口，日志写入状态目录）。 */
export function spawnUiServer({ port, stateDir, nodePath = process.execPath }) {
  mkdirSync(stateDir, { recursive: true })
  const cliPath = join(PROJECT_ROOT, 'src', 'cli.js')
  const logPath = join(stateDir, 'ui-server.log')
  const out = openSync(logPath, 'a')
  const child = spawn(nodePath, [cliPath, 'ui', '--port', String(port), '--no-open'], {
    detached: true,
    stdio: ['ignore', out, out],
    windowsHide: true,
    cwd: PROJECT_ROOT,
  })
  child.unref()
  return { pid: child.pid, logPath }
}

/**
 * 启动桌面客户端：服务不在就拉起来，然后开窗口。
 * 返回 { serverStarted, windowOpened, url } 供调用方汇报。
 */
export async function openDesktopClient({
  port = DEFAULT_UI_PORT,
  stateDir,
  env = process.env,
  fetchImpl = fetch,
  spawnServer = spawnUiServer,
  openWindow = openAppWindow,
  exists = existsSync,
  timeoutMs,
} = {}) {
  let serverStarted = false
  if (!(await isUiServerUp(port, { fetchImpl }))) {
    spawnServer({ port, stateDir })
    serverStarted = true
    const ready = await waitForUiServer(port, { fetchImpl, ...(timeoutMs ? { timeoutMs } : {}) })
    if (!ready) {
      return {
        serverStarted,
        windowOpened: false,
        reason: `本地服务未能在端口 ${port} 上就绪，请查看 ${join(stateDir, 'ui-server.log')}`,
      }
    }
  }

  const url = `http://127.0.0.1:${port}/`
  const icons = writeIconFiles(stateDir)
  const result = openWindow({
    url,
    profileDir: join(stateDir, 'app-window-profile'),
    env,
    exists,
  })
  // 统一的返回契约：调用方只看 windowOpened / reason，不依赖底层 openAppWindow 的字段名。
  // （早先这里直接把 opened 透传出去，命令行读 windowOpened 永远是 undefined，
  //   结果窗口明明开了却报"打开失败" —— 由 tests/windows-client.test.js 抓到。）
  return {
    serverStarted,
    windowOpened: result.opened === true,
    url,
    icons,
    ...(result.reason === undefined ? {} : { reason: result.reason }),
    ...(result.browser === undefined ? {} : { browser: result.browser }),
  }
}
