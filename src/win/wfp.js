import { execFile, spawn } from 'node:child_process'
import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { PROJECT_ROOT } from '../config.js'

const execFileAsync = promisify(execFile)

/**
 * WFP 网络阻断的宿主：`CCGaitWfp.exe hold <exe...>` 会挂上内核过滤器并常驻，
 * 过滤器只在这个进程存活期间有效。
 *
 * 为什么用它而不是只靠防火墙规则：Windows 防火墙的规则只有配置文件启用时才生效
 * （已实测：关闭时规则被完全忽略）。WFP 过滤器不受该开关约束，因此"禁止该程序联网"
 * 不再依赖用户是否愿意打开系统防火墙。
 *
 * 生命周期刻意做成"进程即策略"：
 * - 进程活着 → 阻断生效；进程退出 → 过滤器自动消失（失败开放，不会把用户网络锁死）；
 * - 不写注册表、不留持久过滤器，随时可以干净退出。
 */

export const WFP_PID_FILE = 'wfp.pid'
export const WFP_STOP_FILE = 'wfp-stop.request'

export function wfpPidPath(stateDir) {
  return join(stateDir, WFP_PID_FILE)
}

export function wfpStopPath(stateDir) {
  return join(stateDir, WFP_STOP_FILE)
}

/** 找到 WFP 助手：优先安装/构建产物，其次与 CLI 同级的 dist。 */
export function resolveWfpHelper(rootDir = PROJECT_ROOT) {
  const candidates = [
    join(rootDir, 'dist', 'CCGaitWfp.exe'),
    join(rootDir, 'CCGaitWfp.exe'),
    join(rootDir, 'CCGaitWfp.exe'.toLowerCase()),
  ]
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate
  }
  return undefined
}

export function readWfpPid(stateDir) {
  const path = wfpPidPath(stateDir)
  if (!existsSync(path)) return undefined
  try {
    const pid = Number(readFileSync(path, 'utf8').trim())
    return Number.isInteger(pid) && pid > 0 ? pid : undefined
  } catch {
    return undefined
  }
}

function alive(pid) {
  if (!pid) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return error?.code === 'EPERM'
  }
}

export function isWfpBlocking(stateDir) {
  return alive(readWfpPid(stateDir))
}

/**
 * 列出所有**常驻** WFP 宿主进程（`hold` 模式）。
 *
 * 两个必须注意的点：
 *  1. 不能只信 pid 文件：它可能被删掉或被上一轮覆盖，于是出现"宿主还在挂过滤器、
 *     但 pid 文件记的是别的进程"的局面 —— 这时候再建一次阻断就会有**两个宿主并存**，
 *     而 off 只杀得掉一个，剩下的会让用户莫名其妙上不了网。
 *  2. 也不能只按进程名匹配：`purge` / `check` / `list-filters` 这些**一次性**调用
 *     也叫 CCGaitWfp.exe，按名匹配会把它们算成"有宿主在跑"（实测被这个坑到过：
 *     刚清理完就"看到"一个新宿主，其实是 purge 自己还在退出过程中），
 *     进而让状态误报"阻断生效中"，甚至让清扫把一个正在跑的 purge 杀掉。
 *     所以这里按命令行里是否有 `hold` 来判定。
 *
 * 这个助手是我们自己的二进制，机器上不会有第三方在跑，所以按名字+模式筛选是安全的。
 */
export async function listWfpHosts() {
  try {
    const { stdout } = await execFileAsync(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        "Get-CimInstance Win32_Process -Filter \"Name='CCGaitWfp.exe'\" -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -match '\\shold(\\s|$)' } | Select-Object -ExpandProperty ProcessId",
      ],
      { windowsHide: true, timeout: 15_000 },
    )
    return stdout
      .split(/\r?\n/)
      .map((line) => Number(line.trim()))
      .filter((pid) => Number.isInteger(pid) && pid > 0)
  } catch {
    return []
  }
}

/** 所有叫这个名字的进程（含一次性调用），仅用于排查与清理确认。 */
export async function listWfpProcesses() {
  try {
    const { stdout } = await execFileAsync(
      'powershell.exe',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        "Get-CimInstance Win32_Process -Filter \"Name='CCGaitWfp.exe'\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ProcessId",
      ],
      { windowsHide: true, timeout: 15_000 },
    )
    return stdout
      .split(/\r?\n/)
      .map((line) => Number(line.trim()))
      .filter((pid) => Number.isInteger(pid) && pid > 0)
  } catch {
    return []
  }
}

/** 收掉所有宿主，包括 pid 文件没记到的孤儿。返回被收掉的 PID 列表。 */
export async function killAllWfpHosts() {
  const pids = await listWfpHosts()
  for (const pid of pids) {
    try {
      process.kill(pid)
    } catch {
      // 已经退出或权限不足：下一轮扫描还会看到它。
    }
  }
  return pids
}

/**
 * 删掉本工具遗留在内核里的所有过滤器（按自己的 sublayer 认领）。
 *
 * 为什么需要它：早期版本没有用动态会话，进程被硬杀（任务管理器结束进程、按名清扫）
 * 时过滤器会**永久留下** —— 机器上某个程序从此连不上网，却看不到任何宿主进程在跑。
 * 本机实测就这样留下了 30 条（覆盖 15 个可执行文件，包括 System32\curl.exe）。
 * 现在动态会话已经能自动清理，purge 作为兜底：清掉旧版本留下的，也能人工救急。
 */
export async function purgeWfpFilters() {
  const helper = resolveWfpHelper()
  if (!helper) return { ok: false, error: '未找到 CCGaitWfp.exe（请先执行 ccgait build-installer）' }
  try {
    const { stdout } = await execFileAsync(helper, ['purge'], { windowsHide: true, timeout: 60_000 })
    const match = /PURGED (\d+)/.exec(stdout)
    return { ok: true, removed: match ? Number(match[1]) : 0, output: stdout.trim() }
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) }
  }
}

/**
 * 启动阻断并等它就绪（解析 "READY n"）。detached=true 时用于 CLI 的长期阻断。
 * 返回 { ok, pid, blocked, output }。
 */
export async function startWfpBlock({ paths, stateDir, detached = false, timeoutMs = 20_000 }) {
  const helper = resolveWfpHelper()
  if (!helper) {
    return { ok: false, error: '未找到 CCGaitWfp.exe（请先执行 ccgait build-installer 或从安装版运行）' }
  }
  const hosts = await listWfpHosts()
  if (isWfpBlocking(stateDir) && hosts.includes(readWfpPid(stateDir))) {
    // 复用已有宿主时拿不到这一轮的过滤器条数：明确回 null，别让调用方把 undefined 当成 0。
    return { ok: true, alreadyRunning: true, pid: readWfpPid(stateDir), blocked: null, filters: null }
  }
  if (hosts.length > 0) {
    // 有宿主但 pid 文件对不上（孤儿）：先收干净再重建，保证同时只有一个宿主在挂过滤器。
    await killAllWfpHosts()
  }

  const stopFile = wfpStopPath(stateDir)
  // 先清掉上一次可能残留的停止请求，否则新宿主会立刻退出。
  try {
    rmSync(stopFile, { force: true })
  } catch {
    // 忽略
  }

  const child = spawn(helper, ['hold', '--stop-file', stopFile, ...paths], {
    detached,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  let output = ''
  const ready = await new Promise((resolve) => {
    const timer = setTimeout(() => resolve(false), timeoutMs)
    child.stdout.setEncoding('utf8')
    child.stdout.on('data', (chunk) => {
      output += chunk
      if (output.includes('READY')) {
        clearTimeout(timer)
        resolve(true)
      }
    })
    child.on('error', () => {
      clearTimeout(timer)
      resolve(false)
    })
    child.on('exit', () => {
      clearTimeout(timer)
      resolve(false)
    })
  })

  if (!ready) {
    try {
      child.kill()
    } catch {
      // 忽略
    }
    return { ok: false, error: `WFP 助手未能就绪：${output.trim() || '无输出（可能需要管理员权限）'}` }
  }

  const blockedMatch = /READY (\d+)/.exec(output)
  const blocked = blockedMatch ? Number(blockedMatch[1]) : 0

  if (blocked === 0) {
    // 0 条过滤器必须当失败：否则调用方会打印"已断网"而实际上什么都没拦到 ——
    // 这正是防火墙那条路踩过的"假装成功"，实测这里也会出现（同一次构建、同一个程序，
    // 绝大多数时候是 2 条，偶尔返回 0 条）。宁可用报错暴露，也不给一个假的安心。
    try {
      child.kill()
    } catch {
      // 忽略
    }
    return {
      ok: false,
      filters: 0,
      output: output.trim(),
      error: `WFP 助手没有建立任何过滤器：${output.trim() || '无输出（可能需要管理员权限）'}`,
    }
  }

  try {
    writeFileSync(wfpPidPath(stateDir), `${child.pid}\n`, 'utf8')
  } catch {
    // PID 文件只用于状态展示。
  }

  if (detached) {
    // 必须把管道也断开再 unref：只 unref 进程、留着 stdout/stderr 管道，父进程的事件循环
    // 会被这两个句柄一直吊着，`ccgait wfp on` 打完日志也不退出（实测：管道接到 head 时会永久挂住）。
    child.stdout?.destroy()
    child.stderr?.destroy()
    child.unref()
  }

  return { ok: true, pid: child.pid, blocked, filters: blocked, output: output.trim(), child: detached ? undefined : child }
}

/**
 * 停止阻断：先写停止文件让宿主自行收尾（删掉自己的过滤器），再确认它退出。
 * 为什么优先优雅停止而不是直接杀：优雅路径会显式删除过滤器，语义更干净；宿主如果
 * 已经不在了（比如被强杀），动态过滤器也会随会话自动消失，所以两条路都安全。
 */
export async function stopWfpBlock({ stateDir, waitMs = 5000 }) {
  const pid = readWfpPid(stateDir)
  // 不管 pid 文件写了什么，最后都要按进程名扫一遍，确保没有孤儿宿主继续挂着过滤器。
  const sweep = async () => {
    const killed = await killAllWfpHosts()
    try {
      rmSync(wfpPidPath(stateDir), { force: true })
      rmSync(wfpStopPath(stateDir), { force: true })
    } catch {
      // 忽略
    }
    return killed
  }

  if (!pid || !alive(pid)) {
    const killed = await sweep()
    const purged = await purgeWfpFilters()
    const detail = {
      swept: killed,
      purged: purged.ok ? purged.removed : null,
    }
    return killed.length > 0 || detail.purged
      ? { stopped: true, reason: '没有活动宿主，已清理遗留状态', ...detail }
      : { stopped: false, reason: '没有正在运行的 WFP 阻断', ...detail }
  }

  try {
    writeFileSync(wfpStopPath(stateDir), `${new Date().toISOString()}\n`, 'utf8')
  } catch {
    // 写不进停止文件就退回直接结束进程。
  }

  const deadline = Date.now() + waitMs
  while (Date.now() < deadline) {
    if (!alive(pid)) break
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
  if (alive(pid)) {
    try {
      process.kill(pid)
    } catch (error) {
      return { stopped: false, error: error instanceof Error ? error.message : String(error) }
    }
  }
  const swept = await sweep()
  // 兜底再按 sublayer 清一遍：旧版本硬杀留下的过滤器 pid 文件里没有记录，只有这一步能清掉。
  const purged = await purgeWfpFilters()
  return { stopped: true, pid, swept, purged: purged.ok ? purged.removed : null }
}

/** 同步版停止：仅用于无法等待的收尾路径（写停止文件后立即返回）。 */
export function requestWfpStop(stateDir) {
  try {
    writeFileSync(wfpStopPath(stateDir), `${new Date().toISOString()}\n`, 'utf8')
  } catch {
    // 忽略
  }
  const pid = readWfpPid(stateDir)
  if (pid && alive(pid)) {
    try {
      process.kill(pid)
    } catch {
      // 忽略
    }
  }
  return { requested: true, pid }
}

/** 子进程句柄模式下（闸门内部使用）：直接关闭子进程。 */
export function stopWfpChild(child) {
  if (!child) return
  try {
    child.stdin?.end()
  } catch {
    // 忽略
  }
  try {
    child.kill()
  } catch {
    // 忽略
  }
}
