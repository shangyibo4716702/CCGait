// 把一个账号的 Desktop 会话索引同步到另一个账号（手动选择、单次触发）。
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

/**
 * Claude Desktop 的会话窗口由两部分组成，**只有索引需要跨账号复制**：
 *
 *  1. 索引：`claude-code-sessions/<账号UUID>/<组织UUID>/local_<uuid>.json`
 *     标题、cwd、时间、模型、权限模式，以及指向正文的 `cliSessionId`。
 *     账号身份只体现在**目录路径**里，文件内容不含任何账号字段（已实测）。
 *  2. 正文：`~/.claude/projects/<项目>/<cliSessionId>.jsonl`
 *     这是所有账号共享的一份（切号不碰 ~/.claude），所以不用复制。
 *
 * 因此同步 = 把源账号索引目录里的选定文件，复制进目标账号**真实存在**的
 * `<账号UUID>/<组织UUID>/` 目录。目标组织必须选对，否则 Desktop 读不到。
 */

const SESSIONS_DIR = 'claude-code-sessions'

/** 读出某个 profile/存档里所有「账号/组织」组合及其会话数。 */
export function listSessionGroups(rootDir, readDir = readdirSync) {
  const base = join(rootDir, SESSIONS_DIR)
  let accounts
  try {
    accounts = readDir(base, { withFileTypes: true })
  } catch {
    return []
  }
  const groups = []
  for (const account of accounts) {
    if (!account.isDirectory()) continue
    const accountDir = join(base, account.name)
    let orgs
    try {
      orgs = readDir(accountDir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const org of orgs) {
      if (!org.isDirectory()) continue
      const orgDir = join(accountDir, org.name)
      let files
      try {
        files = readDir(orgDir).filter((name) => name.endsWith('.json'))
      } catch {
        continue
      }
      groups.push({
        accountUuid: account.name,
        orgUuid: org.name,
        dir: orgDir,
        count: files.length,
      })
    }
  }
  return groups
}

/**
 * 列出一个目录下可同步的会话（只读，供界面勾选）。
 *
 * 只返回元数据，不返回正文 —— 界面需要的只是"标题 + 时间 + 项目"。
 * 正文可能很大（单个 jsonl 几百 KB 到几 MB），不该塞进接口响应。
 */
export function listSessions(dir, { readDir = readdirSync, readFile = (p) => readFileSync(p, 'utf8') } = {}) {
  let files
  try {
    files = readDir(dir).filter((name) => name.endsWith('.json'))
  } catch {
    return []
  }
  const sessions = []
  for (const file of files) {
    let meta
    try {
      meta = JSON.parse(readFile(join(dir, file)))
    } catch {
      // 写了一半或损坏的索引：跳过，不因一个坏文件让整个列表失败。
      continue
    }
    if (!meta?.sessionId) continue
    sessions.push({
      sessionId: meta.sessionId,
      file,
      title: typeof meta.title === 'string' && meta.title !== 'undefined' ? meta.title : '(未命名会话)',
      cwd: typeof meta.cwd === 'string' ? meta.cwd : '',
      cliSessionId: typeof meta.cliSessionId === 'string' ? meta.cliSessionId : undefined,
      createdAt: typeof meta.createdAt === 'number' ? new Date(meta.createdAt).toISOString() : undefined,
      lastActivityAt:
        typeof meta.lastActivityAt === 'number' ? new Date(meta.lastActivityAt).toISOString() : undefined,
      archived: meta.isArchived === true,
      completedTurns: typeof meta.completedTurns === 'number' ? meta.completedTurns : undefined,
    })
  }
  // 最近活跃的在前：用户要找的通常是刚才那段。
  return sessions.sort((a, b) => String(b.lastActivityAt ?? '').localeCompare(String(a.lastActivityAt ?? '')))
}

/**
 * 把选定的会话索引从源目录复制到目标「账号/组织」目录。
 *
 * 安全约束：
 *  - 只在**目标目录已存在**时复制。不新建 `<账号UUID>/<组织UUID>/`：那意味着我们
 *    猜了一个组织 ID，Desktop 未必认，会话会变成"看得见但打不开"。
 *  - 已存在同名 sessionId 的跳过（不覆盖），避免把目标账号自己的会话标题/状态冲掉。
 *  - 返回逐条结果，界面据此告诉用户哪些成功、哪些跳过。
 *
 * @param sourceDir 源「账号/组织」目录
 * @param targetDir 目标「账号/组织」目录（必须已存在）
 * @param sessionIds 要同步的 sessionId 列表
 */
export function copySessions({
  sourceDir,
  targetDir,
  sessionIds,
  exists = existsSync,
  readDir = readdirSync,
  readFile = (p) => readFileSync(p, 'utf8'),
  copyFile = copyFileSync,
}) {
  if (!Array.isArray(sessionIds) || sessionIds.length === 0) {
    throw new Error('没有选择要同步的会话')
  }
  if (!exists(sourceDir)) throw new Error('源账号没有会话目录')
  if (!exists(targetDir)) {
    throw new Error('目标账号还没有对应的组织目录：先在那个账号里创建过一个会话，再回来同步')
  }

  // 目标已有的 sessionId：用来跳过，避免覆盖对方自己的会话。
  const existing = new Set()
  for (const file of readDir(targetDir)) {
    if (!file.endsWith('.json')) continue
    try {
      const meta = JSON.parse(readFile(join(targetDir, file)))
      if (meta?.sessionId) existing.add(meta.sessionId)
    } catch {
      // 坏文件忽略
    }
  }

  // 源目录的文件名 → sessionId 映射，只允许同步确实存在于源目录的会话。
  const byId = new Map()
  for (const file of readDir(sourceDir)) {
    if (!file.endsWith('.json')) continue
    try {
      const meta = JSON.parse(readFile(join(sourceDir, file)))
      if (meta?.sessionId) byId.set(meta.sessionId, { file, meta })
    } catch {
      // 忽略
    }
  }

  const copied = []
  const skipped = []
  const missing = []
  for (const sessionId of sessionIds) {
    const entry = byId.get(sessionId)
    if (!entry) {
      missing.push(sessionId)
      continue
    }
    if (existing.has(sessionId)) {
      skipped.push({ sessionId, title: entry.meta.title, reason: '目标账号已有同一会话' })
      continue
    }
    const destination = join(targetDir, entry.file)
    mkdirSync(dirname(destination), { recursive: true })
    copyFile(join(sourceDir, entry.file), destination)
    copied.push({ sessionId, title: entry.meta.title, file: entry.file })
  }

  return { copied, skipped, missing }
}

/** 会话正文（jsonl）是否还在共享区 —— 索引复制过去但没有正文就是空壳。 */
export function sessionBodyExists({ claudeProjectsDir, projectFolder, cliSessionId, exists = existsSync }) {
  if (!cliSessionId || !projectFolder) return false
  return exists(join(claudeProjectsDir, projectFolder, `${cliSessionId}.jsonl`))
}

/**
 * 由 cwd 推出 ~/.claude/projects 下的目录名。
 *
 * 实测规则：冒号、反斜杠、**空格**都各替换成一个短横。
 *   `D:\Unreal Projects\GASPDemo` → `D--Unreal-Projects-GASPDemo`
 * 注意冒号+反斜杠会变成两个短横（`D:` → `D-`，`\` 再 → `-`），别写成合并成一个。
 */
export function projectFolderFor(cwd) {
  if (typeof cwd !== 'string' || cwd.length === 0) return undefined
  return cwd.replace(/[:\\/\s]/g, '-')
}

/**
 * 会话正文的共享目录：`~/.claude/projects`。
 *
 * 为什么需要单独定位：Desktop 的会话索引按账号切换，但正文在这里是**所有账号共享**
 * 的一份（切号不碰 ~/.claude）。所以同步只要搬索引，正文不用动 —— 但必须确认正文
 * 真的在，否则搬过去的会话是个打不开的空壳。
 */
export function claudeProjectsDir(env = process.env, home = homedir()) {
  const userProfile = env.USERPROFILE || home
  return join(userProfile, '.claude', 'projects')
}
