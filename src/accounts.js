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

/**
 * 删除账号存档。
 *
 * 两条安全线：
 *  1. **不允许删当前账号** —— 它的登录态正活在 profile 里，删掉存档看似没事，
 *     但一旦以后切换走就再也回不来了。要删当前账号，先切到别的号。
 *  2. 名字带 `.bak` 后缀的备份也会一起删掉：否则用户以为删干净了，
 *     十几 MB 的旧 Cookies 还躺在磁盘上。
 */
export function removeAccount(accountsDir, name, { readDir = readdirSync, exists = existsSync } = {}) {
  assertAccountName(name)
  const current = readCurrentAccount(accountsDir)
  if (current === name) {
    throw new Error(`账号 ${name} 正在使用中，先切换到别的账号再删除`)
  }
  const dir = accountDir(accountsDir, name)
  if (!exists(dir)) throw new Error(`账号 ${name} 不存在`)
  rmrf(dir)
  rmrf(`${dir}.bak`)
  return { name, removed: true }
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

/**
 * 下一个可用的默认账号名：A、B、C…Z，用完再 A1、B1…
 *
 * 有了它，"保存当前登录"就不必先让用户起名字 —— 直接点一下就存好。
 * 名字只是本地标签（跟 Claude 账号邮箱无关），自动分配完全够用，
 * 想改成"工作号"这类记号时再改。
 */
export function nextAccountName(existingNames) {
  const used = new Set(existingNames)
  for (let i = 0; i < 26; i += 1) {
    const name = String.fromCharCode(65 + i)
    if (!used.has(name)) return name
  }
  for (let round = 1; round < 100; round += 1) {
    for (let i = 0; i < 26; i += 1) {
      const name = `${String.fromCharCode(65 + i)}${round}`
      if (!used.has(name)) return name
    }
  }
  throw new Error('账号数量已达上限')
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

/**
 * 邮箱的匹配范围：email_address 之后 300 字节内的窗口里找。
 * 值域放宽到 40 字符用户名，覆盖 privaterelay.appleid.com 这类长前缀。
 */
const EMAIL_PATTERN = /[a-zA-Z0-9][a-zA-Z0-9._%+-]{1,40}@[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,8}/

function walkFiles(dir, depth, out, readDir = readdirSync) {
  if (depth > 5) return
  let entries
  try {
    entries = readDir(dir, { withFileTypes: true })
  } catch {
    return
  }
  for (const entry of entries) {
    const full = join(dir, entry.name)
    if (entry.isDirectory()) {
      walkFiles(full, depth + 1, out, readDir)
    } else {
      out.push(full)
    }
  }
}

/**
 * 从 profile（或存档）目录里提取「这个号是谁、用量还剩多少」。
 *
 * 两个来源都是**本地文件，不发任何网络请求**：
 *
 *  - 邮箱 / 显示名：IndexedDB 的 blob 文件里，leveldb 记录是明文的
 *    `"email_address" "<邮箱>" "full_name" "<名字>"`，拿 `email_address` 当锚点向后找。
 *    注意运行中的 Desktop 会锁住这些文件（实测 EBUSY）—— 所以在存档时（进程必已
 *    退出）提取并写进元数据；在线账号读不到就显示上次存档时的。
 *  - 用量：`plan-usage-history.json` 的 `samples[]`，Desktop 持续追加，取最后一条
 *    带用量的采样。`u.fh` = 5 小时窗已用百分比，`u.sd` = 7 天窗已用百分比
 *    （实测两条：在线号 fh=43/sd=6，存档 A fh=0/sd=73，都是 0-100 的整数）。
 *    这个是普通 JSON，进程运行时也能读（读到写一半的会解析失败，跳过即可）。
 */
export function readAccountInsights(dir, { readDir = readdirSync, readFile = readFileSync } = {}) {
  const insights = {}

  // 登录态是否有效：Claude 自己写的 windowSizeWasSignedIn 是唯一可靠的本地信号。
  //
  // 为什么需要它：存档"看着完整"（Cookies 32KB 在）但 token 已过期，切过去会停在
  // 登录页。实测：现场 profile 的 windowSizeWasSignedIn=false 时，IndexedDB 里也
  // 没有 email_address（登录页不写账户信息），所以"读不到邮箱"往往就是"没登录"的
  // 同一个症状。把它读出来，界面能直接说"需要重新登录"而不是让用户猜。
  try {
    const config = JSON.parse(readFile(join(dir, 'config.json'), 'utf8'))
    if (typeof config?.windowSizeWasSignedIn === 'boolean') {
      insights.signedIn = config.windowSizeWasSignedIn
    }
  } catch {
    // config.json 读不到就不标状态。
  }

  try {
    const history = JSON.parse(readFile(join(dir, 'plan-usage-history.json'), 'utf8'))
    const samples = Array.isArray(history?.samples) ? history.samples : []
    for (let i = samples.length - 1; i >= 0; i -= 1) {
      const usage = samples[i]?.u
      if (usage && (typeof usage.fh === 'number' || typeof usage.sd === 'number')) {
        insights.usage = {
          fiveHourPercent: typeof usage.fh === 'number' ? usage.fh : undefined,
          weeklyPercent: typeof usage.sd === 'number' ? usage.sd : undefined,
          sampledAt: typeof samples[i].t === 'number' ? new Date(samples[i].t).toISOString() : undefined,
        }
        break
      }
    }
  } catch {
    // 文件不存在 / 正被重写读到半截：不显示用量即可。
  }

  try {
    const files = []
    walkFiles(join(dir, 'IndexedDB'), 0, files, readDir)
    const anchor = Buffer.from('email_address', 'latin1')
    const nameAnchor = Buffer.from('full_name', 'latin1')
    outer: for (const file of files) {
      let buffer
      try {
        buffer = readFile(file)
      } catch {
        // 被占用（在线的 Desktop 锁着）就跳过这个文件。
        continue
      }
      let index = buffer.indexOf(anchor)
      while (index >= 0) {
        const window = buffer
          .subarray(index + anchor.length, index + anchor.length + 300)
          .toString('latin1')
        const match = EMAIL_PATTERN.exec(window)
        if (match) {
          insights.email = match[0]
          // 显示名通常紧跟在邮箱后面：锚点 full_name 后第一个 "…" 里的内容。
          const nameIndex = buffer.indexOf(nameAnchor, index)
          if (nameIndex > index) {
            const nameWindow = buffer.subarray(nameIndex, nameIndex + 200).toString('utf8')
            const quoted = /full_name"\s*"([^"]{1,60})"/.exec(nameWindow)
            if (quoted && /^[\x20-\x7e\u4e00-\u9fff\u3040-\u30ff\uac00-\ud7af]+$/.test(quoted[1])) {
              insights.fullName = quoted[1]
            }
          }
          break outer
        }
        index = buffer.indexOf(anchor, index + 1)
      }
    }
  } catch {
    // IndexedDB 不存在或整个目录读不了：只少显示邮箱，不影响其余功能。
  }

  return insights
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

  // 覆盖同名存档前先留一份旧的。
  //
  // 用户重复保存同一个名字很常见（"我重登了一次，再存一遍"），而且旧的那份很可能是
  // 唯一还能用的登录态 —— 静默覆盖等于把它删了，还看不出来发生过什么。
  // 备份固定叫 `<name>.bak`（只保留最近一份），且因为名字里带点，不会被 listAccounts
  // 当成一个账号列出来。
  const backup = `${target}.bak`
  if (exists(target)) {
    rmrf(backup)
    renameSync(target, backup)
  } else {
    rmrf(target)
  }
  renameSync(staging, target)
  // 在存档时刻提取"这个号是谁、用量还剩多少"：此刻 Desktop 必已退出，IndexedDB 不会被锁。
  // 写进元数据后列表接口直接读 JSON，不必每次扫 leveldb。
  const insights = readAccountInsights(target)
  writeFileSync(
    join(target, '.ccgait-account.json'),
    `${JSON.stringify({ name, savedAt: new Date().toISOString(), ...insights }, null, 2)}\n`,
    'utf8',
  )
  return { name, entries: entries.length, dir: target, ...insights }
}

/**
 * 从一个 profile / 存档目录里读出「这个目录属于哪个 Claude 账号」。
 *
 * `lastKnownAccountUuid` 是唯一可靠的账号标识：
 *  - Cookie 值不能比，运行中的 Desktop 会独占锁住它（实测 EBUSY，连共享读都拿不到）；
 *  - 本地名字（A/B/C）是我们自己起的标签，跟真实账号无关；
 *  - `ant-did` 是包级设备标识，所有账号共用一份，不能用来区分。
 *
 * 为什么必须靠它：`current.json` 只是我们记的标签，用户可能直接在 Claude 里换账号、
 * 或者切换中途崩溃，于是标签和现场对不上。靠 uuid 才知道"现在真正登录的是谁"。
 */
export function readAccountUuid(dir, readFile = (p) => readFileSync(p, 'utf8')) {
  try {
    const config = JSON.parse(readFile(join(dir, 'config.json')))
    const uuid = config?.lastKnownAccountUuid
    return typeof uuid === 'string' && uuid.length > 0 ? uuid : undefined
  } catch {
    return undefined
  }
}

/**
 * 哪个存档就是当前 profile 里正在用的那个账号。
 *
 * `matched=false` 表示没有存档与现场对得上（例如用户直接在 Claude 里登录了一个
 * 没保存过的账号）—— 这时候绝不能随便挑一个贴数据，那会把别人的邮箱/用量贴在它身上。
 */
export function matchLiveAccount(accounts, liveUuid, readUuid = readAccountUuid) {
  if (!liveUuid) return { name: undefined, matched: false }
  const hits = accounts.filter((account) => readUuid(account.dir) === liveUuid)
  if (hits.length === 0) return { name: undefined, matched: false }
  // 同一 uuid 可能有多份存档（同一账号存过多次）。取最近保存的那份作代表，
  // 其余作为 duplicates 返回，界面可以提示"这几个是同一个账号"。
  const sorted = [...hits].sort((a, b) => String(b.savedAt ?? '').localeCompare(String(a.savedAt ?? '')))
  return { name: sorted[0].name, matched: true, duplicates: hits.map((item) => item.name) }
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
    let insights = {}
    try {
      const meta = JSON.parse(readFileSync(join(dir, '.ccgait-account.json'), 'utf8'))
      savedAt = meta.savedAt
      insights = {
        email: typeof meta.email === 'string' ? meta.email : undefined,
        fullName: typeof meta.fullName === 'string' ? meta.fullName : undefined,
        usage: meta.usage && typeof meta.usage === 'object' ? meta.usage : undefined,
        signedIn: typeof meta.signedIn === 'boolean' ? meta.signedIn : undefined,
      }
    } catch {
      // 老存档没有元数据文件，按目录时间算。
    }
    // 老存档的元数据里没有识别结果（功能是后来加的）：现场读一次存档目录。
    // 存档不受运行中的 Desktop 锁定，随时读得到；不回写元数据，避免列表接口带副作用。
    if (!insights.email && !insights.usage) {
      const live = readAccountInsights(dir)
      if (live.email || live.usage || typeof live.signedIn === 'boolean') {
        insights = { ...insights, ...live }
      }
    }
    if (!savedAt) {
      try {
        savedAt = statSync(dir).mtime.toISOString()
      } catch {
        savedAt = undefined
      }
    }
    // 带上账号 uuid：界面上"没读到邮箱"时用它做区分标识。
    // 否则几个账号都显示本地字母名字，用户根本分不清哪个是哪个。
    accounts.push({
      name: item.name,
      complete: accountComplete(dir),
      savedAt,
      dir,
      uuid: readAccountUuid(dir),
      ...insights,
    })
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
