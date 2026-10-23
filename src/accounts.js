import { execFileSync } from 'node:child_process'
import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

/**
 * Claude Desktop 账号切换。
 *
 * 设计依据来自本机实测，不是照抄 claude-switcher 的做法（那个项目的 Windows 版是
 * `Remove-Item -Recurse` 之后 robocopy 回来，中途失败数据就没了）：
 *
 * 1. **不能整目录复制**。Claude Desktop 是 MSIX 打包的 Electron 应用，profile 里
 *    `claude-code/` 占 564MB（CLI 二进制）、`Cache` + `Code Cache` 再占 460MB。
 *    整目录每次切上 GB，既慢又毫无意义 —— 缓存和二进制跟账号无关。
 *
 * 2. **用黑名单排除，而不是白名单挑选**。Claude 版本更新会新增身份文件
 *    （比如 `ant-did`、`buddy-tokens.json`、`ccd-ids.json` 都是某次更新后才出现的）。
 *    白名单一定会漏，漏了就是串号；黑名单最坏只是多复制几个缓存文件。
 *
 * 3. **先存档再动现场**。存档成功才允许删除当前身份文件，任何一步失败都能回滚，
 *    因为原状态已经在 accounts/<current> 里了。
 *
 * 4. **必须切设备标识**。`ant-did` / `ant-device-registry.json` 就是设备指纹。
 *    只换 Cookies 不换它，等于"同一台机器上多个账号轮换"—— 那比不切更显眼。
 */

/** 账号名只允许字母数字下划线短横，避免路径穿越（`..`、斜杠、冒号）。 */
export const ACCOUNT_NAME = /^[A-Za-z0-9_-]{1,32}$/

/** 首次切换时自动收编当前登录态用这个名字。 */
export const DEFAULT_ACCOUNT = 'A'

/**
 * 这些条目属于"缓存 / 二进制 / 设备级共享"，不跟着账号走。
 *
 * 判断标准只有一条：**换了它，账号还能不能正常登录、会不会串号？**
 * - 缓存类（Cache / Code Cache / *ShaderCache / fcache …）：删了会自动重建，不切。
 * - `claude-code/`：Claude Code 的版本化二进制，切了等于每个账号存一份 564MB。
 * - `Local State`：Chromium 的 `os_crypt.encrypted_key`，设备级。必须共享，
 *   否则切过去的 Cookies 解不开。
 * - `lockfile` / `logs` / `Crashpad`：运行时产物。
 */
export const PROFILE_EXCLUDES = new Set([
  'cache',
  'code cache',
  'crashpad',
  'dawncache',
  'dawngraphitecache',
  'dawnwebgpucache',
  'fcache',
  'gpucache',
  'gpupersistentcache',
  'grshadercache',
  'local state',
  'lockfile',
  'logs',
  'shadercache',
  'shared dictionary',
  'videodecodestats',
  'claude-code',
  'declarative_performance_observer.db',
  'declarative_performance_observer.db-journal',
])

/** 身份条目的最小健全性检查：没有 Cookies 就说明这份存档是空的。 */
export const REQUIRED_ENTRY = ['Network', 'Cookies']

/**
 * 找到 Claude Desktop 的 Chromium profile。
 *
 * MSIX 应用的数据不在 `%APPDATA%\Claude`（那是非打包版的路径，被包重定向掉了），
 * 而在 `%LOCALAPPDATA%\Claude-Data\<包名>\`。找不到就返回 undefined，让调用方
 * 明确报"没装 Desktop"，而不是在错的地方建目录。
 */
export function locateDesktopProfile(env = process.env, readDir = readdirSync, exists = existsSync) {
  const localAppData = env.LOCALAPPDATA
  if (!localAppData) return undefined
  const base = join(localAppData, 'Claude-Data')
  if (!exists(base)) return undefined
  let entries
  try {
    entries = readDir(base)
  } catch {
    return undefined
  }
  const packages = entries.filter((name) => name.startsWith('claude_'))
  const candidates = packages.length > 0 ? packages : entries
  for (const name of candidates) {
    const profile = join(base, name)
    // 认 profile 而不是认目录名：必须有 Network/Cookies 才算登录态的宿主。
    if (exists(join(profile, 'Network', 'Cookies'))) return profile
  }
  // 没有 Cookies（从未登录过）时退而求其次，只要目录存在就算。
  for (const name of candidates) {
    const profile = join(base, name)
    try {
      if (statSync(profile).isDirectory()) return profile
    } catch {
      // 继续找
    }
  }
  return undefined
}

export function accountsRoot(env = process.env) {
  const localAppData = env.LOCALAPPDATA || join(env.USERPROFILE || homedir(), 'AppData', 'Local')
  return join(localAppData, 'CCGait', 'accounts')
}

export function accountDir(accountsDir, name) {
  return join(accountsDir, name)
}

/**
 * 当前是哪个账号。
 *
 * 只记名字不记路径：profile 的包名会随 Claude 版本变（`claude_pzs8sxrjxfjjc`），
 * 把路径写死会在升级后指向一个不存在的目录。
 */
export function readCurrentAccount(accountsDir, readFile = (p) => readFileSync(p, 'utf8')) {
  try {
    const meta = JSON.parse(readFile(join(accountsDir, 'current.json')))
    return typeof meta.name === 'string' && ACCOUNT_NAME.test(meta.name) ? meta.name : undefined
  } catch {
    return undefined
  }
}

export function writeCurrentAccount(accountsDir, name) {
  assertAccountName(name)
  mkdirSync(accountsDir, { recursive: true })
  writeFileSync(
    join(accountsDir, 'current.json'),
    `${JSON.stringify({ name, switchedAt: new Date().toISOString() }, null, 2)}\n`,
    'utf8',
  )
  return name
}

/** 校验账号名，非法就抛错（调用方负责提示，不要静默改成安全值）。 */
export function assertAccountName(name) {
  if (typeof name !== 'string' || !ACCOUNT_NAME.test(name)) {
    throw new Error('账号名只能用字母、数字、下划线和短横线，长度 1-32')
  }
  return name
}

/** 这份 profile 里哪些顶层条目属于账号身份（= 全部 - 排除项）。 */
export function identityEntries(profileDir, readDir = readdirSync) {
  let entries
  try {
    entries = readDir(profileDir, { withFileTypes: true })
  } catch {
    return []
  }
  return entries
    .map((item) => item.name)
    // `.ccgait-account.json` 是存档自己的元数据，不能被当成身份条目搬回 profile。
    .filter((name) => !PROFILE_EXCLUDES.has(name.toLowerCase()) && !name.startsWith('.ccgait-'))
    .sort()
}

/** 存档是否看起来完整：Cookies 必须在。 */
export function accountComplete(dir, exists = existsSync, size = (p) => statSync(p).size) {
  const cookies = join(dir, ...REQUIRED_ENTRY)
  try {
    return exists(cookies) && size(cookies) > 0
  } catch {
    return false
  }
}

function rmrf(path) {
  try {
    rmSync(path, { recursive: true, force: true })
  } catch {
    // 删不掉不影响主流程，后续 rename 会暴露真正的问题。
  }
}

/**
 * 复制一组条目。
 *
 * Windows 上用 robocopy（8 线程，实测 607MB 只要 1.5 秒；Node 的 cpSync 单线程会慢
 * 一个数量级）。robocopy 的退出码 0-7 都表示成功，>=8 才是真的失败 —— 不按这个判断
 * 会把"有文件被复制"当成失败。
 */
function copyEntries({ from, to, entries, runRobocopy }) {
  mkdirSync(to, { recursive: true })
  for (const entry of entries) {
    const source = join(from, entry)
    if (!existsSync(source)) continue
    const destination = join(to, entry)
    let isDirectory = false
    try {
      isDirectory = statSync(source).isDirectory()
    } catch {
      continue
    }

    // 单文件必须直接复制：robocopy 的目标参数语义是"目录"，让它复制 ant-did /
    // Preferences 这类单文件会返回退出码 16（实测），整次存档就失败了。
    if (!isDirectory) {
      mkdirSync(dirname(destination), { recursive: true })
      copyFileSync(source, destination)
      continue
    }

    if (!runRobocopy) {
      cpSync(source, destination, { recursive: true, force: true })
      continue
    }
    const args = [source, destination, '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/R:1', '/W:1', '/MT:8']
    let code = 0
    try {
      execFileSync('robocopy.exe', args, { stdio: 'ignore' })
    } catch (error) {
      code = typeof error.status === 'number' ? error.status : 8
    }
    if (code >= 8) {
      throw new Error(`复制 ${entry} 失败（robocopy 退出码 ${code}）`)
    }
  }
}

/**
 * 把当前登录态存成账号 <name>。
 *
 * 先写到 `<name>.tmp` 再 rename：否则写到一半崩溃会留下一个"看起来存在、实际残缺"
 * 的存档，下次切换把它当成有效存档载入，账号就废了。
 */
export function saveAccount({
  name,
  profileDir,
  accountsDir,
  runRobocopy = process.platform === 'win32',
  readDir = readdirSync,
  exists = existsSync,
}) {
  assertAccountName(name)
  if (!exists(profileDir)) throw new Error('找不到 Claude Desktop 的数据目录')
  const entries = identityEntries(profileDir, readDir)
  if (entries.length === 0) throw new Error('Claude Desktop 数据目录是空的，没有可存档的内容')

  const target = accountDir(accountsDir, name)
  const staging = `${target}.tmp`
  rmrf(staging)
  copyEntries({ from: profileDir, to: staging, entries, runRobocopy })

  if (!accountComplete(staging, exists)) {
    rmrf(staging)
    throw new Error('存档不完整（缺少 Network/Cookies），已放弃本次存档')
  }

  rmrf(target)
  renameSync(staging, target)
  writeFileSync(join(target, '.ccgait-account.json'), `${JSON.stringify({ name, savedAt: new Date().toISOString() }, null, 2)}\n`, 'utf8')
  return { name, entries: entries.length, dir: target }
}

/** 读出所有账号（按修改时间倒序，最近用过的在前）。 */
export function listAccounts(accountsDir, readDir = readdirSync) {
  let entries
  try {
    entries = readDir(accountsDir, { withFileTypes: true })
  } catch {
    return []
  }
  const accounts = []
  for (const item of entries) {
    if (!item.isDirectory() || !ACCOUNT_NAME.test(item.name)) continue
    const dir = join(accountsDir, item.name)
    let savedAt
    try {
      const meta = JSON.parse(readFileSync(join(dir, '.ccgait-account.json'), 'utf8'))
      savedAt = meta.savedAt
    } catch {
      // 老存档没有元数据文件，按目录时间算。
    }
    if (!savedAt) {
      try {
        savedAt = statSync(dir).mtime.toISOString()
      } catch {
        savedAt = undefined
      }
    }
    accounts.push({ name: item.name, complete: accountComplete(dir), savedAt, dir })
  }
  return accounts.sort((a, b) => String(b.savedAt ?? '').localeCompare(String(a.savedAt ?? '')))
}

/**
 * 切换账号。
 *
 * 步骤刻意排成"能回滚"的顺序：
 *   1. 结束 Claude（否则 Cookies 这类 SQLite 文件被占用，复制和替换都会失败）
 *   2. 存档当前账号 —— 失败就中止，现场完全没动过
 *   3. 把当前身份条目移进 `profile.prev`（同卷 rename，瞬时）
 *   4. 把目标存档的条目复制进来
 *   5. 校验 Cookies 到位；失败就把 `profile.prev` 移回去
 *   6. 成功才删 `profile.prev`
 *
 * 第 3 步用 rename 而不是删除，是为了让第 5 步的回滚是"移回来"而不是"从别处再拷一遍"。
 */
export async function switchAccount({
  name,
  profileDir,
  accountsDir,
  current,
  killProcesses,
  runRobocopy = process.platform === 'win32',
  readDir = readdirSync,
  exists = existsSync,
}) {
  assertAccountName(name)
  if (!exists(profileDir)) throw new Error('找不到 Claude Desktop 的数据目录')

  const source = accountDir(accountsDir, name)
  const isFirstCapture = !current && name === DEFAULT_ACCOUNT
  if (!isFirstCapture && !exists(source)) {
    throw new Error(`账号 ${name} 还没有存档，请先登录它并保存`)
  }
  if (!isFirstCapture && !accountComplete(source, exists)) {
    throw new Error(`账号 ${name} 的存档不完整（缺少 Network/Cookies）`)
  }

  // 1. 结束 Claude Desktop。用户选择"直接结束"，因为切号必须独占这些文件。
  const killed = await killProcesses?.()

  // 2. 存档当前登录态。首次运行时就是把现有登录收编成 A。
  const archivedFrom = isFirstCapture ? DEFAULT_ACCOUNT : current
  if (archivedFrom) {
    saveAccount({ name: archivedFrom, profileDir, accountsDir, runRobocopy, readDir, exists })
  }

  if (isFirstCapture && name === DEFAULT_ACCOUNT) {
    // 收编完就已经是目标账号了，不用再搬一次。
    return { name, archivedFrom: undefined, copied: 0, killed, captured: true }
  }

  // 3. 当前身份条目移进 prev（rename，瞬时，可回滚）。
  const entries = identityEntries(profileDir, readDir)
  const prev = `${profileDir}.ccgait-prev`
  rmrf(prev)
  mkdirSync(prev, { recursive: true })
  const moved = []
  for (const entry of entries) {
    try {
      renameSync(join(profileDir, entry), join(prev, entry))
      moved.push(entry)
    } catch {
      // 单个条目移不动（被杀软锁住等）就先留着，后面会被覆盖。
    }
  }

  try {
    // 4. 载入目标存档。
    copyEntries({ from: source, to: profileDir, entries: identityEntries(source, readDir), runRobocopy })
    if (!accountComplete(profileDir, exists)) {
      throw new Error('切换后校验失败（Network/Cookies 不在位）')
    }
  } catch (error) {
    // 5. 回滚：把搬走的条目放回去。
    for (const entry of moved) {
      try {
        rmrf(join(profileDir, entry))
        renameSync(join(prev, entry), join(profileDir, entry))
      } catch {
        // 尽力而为：单条回滚失败也要继续回滚其余条目。
      }
    }
    rmrf(prev)
    throw error
  }

  rmrf(prev)
  return { name, archivedFrom, copied: entries.length, killed }
}

/**
 * 读到中断的切换痕迹就说明上次切到一半崩了。
 *
 * `*.ccgait-prev` 还在 = 身份条目已经被搬走但没删掉，直接把它移回来最安全。
 * 这里只做恢复，不猜"那次切换到底想切到哪个账号"—— 猜错会把用户的登录态搞乱。
 */
export function recoverInterruptedSwitch(profileDir, { exists = existsSync, readDir = readdirSync } = {}) {
  const prev = `${profileDir}.ccgait-prev`
  if (!exists(prev)) return { recovered: false }
  let restored = 0
  try {
    for (const entry of readDir(prev)) {
      const target = join(profileDir, entry)
      rmrf(target)
      renameSync(join(prev, entry), target)
      restored += 1
    }
  } catch {
    return { recovered: false, error: '恢复中断的切换失败，请手动检查 ' + prev }
  }
  rmrf(prev)
  return { recovered: true, restored }
}
