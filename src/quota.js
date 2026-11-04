import { readFileSync, writeFileSync } from 'node:fs'
import { mkdirSync } from 'node:fs'
import { join } from 'node:path'

/**
 * 5 小时额度窗口的推算。
 *
 * 数据从哪来：Claude Desktop 会往 `plan-usage-history.json` 里追加采样
 * `{t, ms, org, u:{fh, sd}}`（fh = 5 小时窗口百分比，sd = 周百分比）。
 * 它**不给重置时刻**，只给某个时刻的占用率。
 *
 * 所以这里做的是推算而不是查询：
 *  - 采样从 0 跳到 >0 的那一刻，就是这一轮窗口的开始（上限）；
 *  - 重置 = 窗口开始 + 5 小时；
 *  - 那次跳变离"上一个 0 采样"越近，推算越准 —— 采样是事件驱动的、很稀疏
 *    （本机实测：05:50 记到 100%，之后到 19:58 中间一条都没有），
 *    所以必须把误差范围一起报出来，不能只给一个精确到秒的数字装成实测。
 *
 * 明确不做的事：不为了"查准"去调接口。那需要 Claude 的登录态，属于动它自身。
 */

export const FIVE_HOUR_WINDOW_MS = 5 * 60 * 60 * 1000
/** 跳变离上一个 0 采样在这个范围内，才算"高置信"。 */
const HIGH_CONFIDENCE_SPAN_MS = 10 * 60 * 1000
/**
 * 相邻两条采样之间掉这么多百分点，就认为中间重置过一轮。
 * 取 20 是为了躲开正常波动（实测同一次窗口里 100→95 这种抖动很常见），
 * 又足够敏感地抓住"30% → 3%"这种真正的重置。
 */
const RESET_DROP_POINTS = 20
/** 采样超过这么久没更新，就认为数据过期（桌面端没在跑）。 */
const STALE_MS = 90 * 60 * 1000

/** 把文件内容（字符串或已解析对象）规整成按时间升序的采样数组。 */
export function parseUsageSamples(raw) {
  let data = raw
  if (typeof raw === 'string') {
    try {
      data = JSON.parse(raw)
    } catch {
      return []
    }
  }
  const list = Array.isArray(data) ? data : Array.isArray(data?.samples) ? data.samples : []
  return list
    .map((item) => ({
      t: typeof item?.t === 'number' ? item.t : undefined,
      fh: typeof item?.u?.fh === 'number' ? item.u.fh : undefined,
      sd: typeof item?.u?.sd === 'number' ? item.u.sd : undefined,
    }))
    .filter((item) => item.t !== undefined && item.fh !== undefined)
    .sort((a, b) => a.t - b.t)
}

/**
 * 推算当前 5 小时窗口。
 *
 * 返回：
 *  - `active: false`：最新采样是 0，说明没有进行中的窗口；
 *  - `active: true` + `resetAt`：推算的重置时刻，`uncertaintyMs` 是误差上限，
 *    `confidence` 为 `high`（跳变被 10 分钟内的采样夹住）或 `estimate`（更粗）；
 *  - `confidence: 'unknown'`：采样不足，给不出结论。
 */
export function estimateFiveHourWindow(samples, { now = Date.now(), windowMs = FIVE_HOUR_WINDOW_MS, staleMs = STALE_MS } = {}) {
  // 容忍两种输入：parseUsageSamples 的产物 `{t, fh}`，和文件里的原始样本 `{t, u:{fh}}`。
  const rows = (Array.isArray(samples) ? samples : [])
    .map((item) => ({
      t: typeof item?.t === 'number' ? item.t : undefined,
      fh: typeof item?.fh === 'number' ? item.fh : typeof item?.u?.fh === 'number' ? item.u.fh : undefined,
    }))
    .filter((item) => item.t !== undefined && item.fh !== undefined)
    .sort((a, b) => a.t - b.t)
  if (rows.length === 0) {
    return { active: false, confidence: 'unknown', reason: '没有可用采样' }
  }

  const last = rows[rows.length - 1]
  const stale = now - last.t > staleMs

  if (last.fh === 0) {
    return {
      active: false,
      percent: 0,
      confidence: 'high',
      stale,
      sampledAt: new Date(last.t).toISOString(),
      reason: '当前窗口用量为 0（还没开始计时）',
    }
  }

  // 先找"当前这一段"的起点：最后一次归零、或者一次大幅下降之前的最后一条采样。
  //
  // 为什么必须识别"下降"：采样很稀疏，窗口在两次采样之间重置时，根本不会留下 0 的样本。
  // 本机实测就踩到过：11:47 还是 30%，下一条 18:32 已经是 3% —— 中间重置过一次，
  // 但没有任何 0 采样。只认 0 的话会把起点错判成上午 11:17，算出来的重置时间早就过期。
  let boundary = -1
  for (let i = rows.length - 1; i > 0; i -= 1) {
    const drop = rows[i - 1].fh - rows[i].fh
    if (rows[i].fh === 0 || drop >= RESET_DROP_POINTS) {
      boundary = i
      break
    }
  }
  const segment = boundary >= 0 ? rows.slice(boundary) : rows

  // 段内有 0 采样：起点夹在 (那条 0, 之后第一条非零] 之间，这是最靠谱的情况。
  const zeroIndex = segment.findIndex((row) => row.fh === 0)
  if (zeroIndex >= 0) {
    const zero = segment[zeroIndex]
    const first = segment.slice(zeroIndex + 1).find((row) => row.fh > 0)
    if (!first) return { active: false, percent: 0, confidence: 'high', stale, reason: '当前窗口用量为 0' }
    const span = first.t - zero.t
    return {
      active: true,
      percent: last.fh,
      startAt: first.t,
      resetAt: first.t + windowMs,
      remainingMs: Math.max(0, first.t + windowMs - now),
      uncertaintyMs: span,
      confidence: span <= HIGH_CONFIDENCE_SPAN_MS ? 'high' : 'estimate',
      method: 'zero-crossing',
      stale,
      sampledAt: new Date(last.t).toISOString(),
      reason:
        span <= HIGH_CONFIDENCE_SPAN_MS
          ? '窗口起点被相邻采样夹住，误差在 10 分钟内'
          : `窗口起点只夹在 ${Math.round(span / 60000)} 分钟内，误差可能到 ${Math.round(span / 60000)} 分钟`,
    }
  }

  // 段内全是非零（重置发生在采样间隙里）：用最近的上升斜率线性外推到 0。
  const first = segment[0]
  const dt = last.t - first.t
  const df = last.fh - first.fh
  if (segment.length < 2 || dt <= 0 || df <= 0) {
    return {
      active: true,
      percent: last.fh,
      confidence: 'unknown',
      method: 'extrapolation',
      stale,
      sampledAt: new Date(last.t).toISOString(),
      reason: '采样不足以推算窗口起点（看不到归零，也没有明显上升）',
    }
  }

  const slopePerMs = df / dt
  // 外推到 0 的时刻；不能早于上一次大幅下降的位置（那才是上一段）。
  const guess = first.t - first.fh / slopePerMs
  const lowerBound = boundary > 0 ? rows[boundary - 1].t : first.t - windowMs
  const startAt = Math.max(lowerBound, Math.min(first.t, guess))
  const uncertaintyMs = first.t - startAt

  return {
    active: true,
    percent: last.fh,
    startAt,
    resetAt: startAt + windowMs,
    remainingMs: Math.max(0, startAt + windowMs - now),
    uncertaintyMs,
    confidence: 'estimate',
    method: 'extrapolation',
    stale,
    sampledAt: new Date(last.t).toISOString(),
    reason: `重置发生在采样间隙里，按上升斜率反推起点，误差约 ${Math.max(1, Math.round(uncertaintyMs / 60000))} 分钟`,
  }
}

/** 毫秒 → `3:12:44`（超过 24 小时用 `1天 03:12`）。 */
export function formatRemaining(ms) {
  if (!Number.isFinite(ms) || ms < 0) return '—'
  const total = Math.floor(ms / 1000)
  const days = Math.floor(total / 86400)
  const hours = Math.floor((total % 86400) / 3600)
  const minutes = Math.floor((total % 3600) / 60)
  const seconds = total % 60
  const pad = (value) => String(value).padStart(2, '0')
  if (days > 0) return `${days}天 ${pad(hours)}:${pad(minutes)}`
  return `${hours}:${pad(minutes)}:${pad(seconds)}`
}

/* --------------------------------------------------------------- 审计记录 */

/**
 * 额度审计：每一次"重新推算/查询重置时间"都留一条。
 *
 * 记 `environmentSafe` 是因为用户的规则：**只在确认环境安全时才去请求**。
 * 现在这条链路上没有外部请求（纯本地推算），但字段保留并如实写，
 * 以后加了查询也能沿用同一份记录。
 */
const AUDIT_FILE = 'quota-audit.json'
const AUDIT_LIMIT = 100

export function quotaAuditPath(accountsDir) {
  return join(accountsDir, AUDIT_FILE)
}

export function readQuotaAudit(accountsDir, readFile = (p) => readFileSync(p, 'utf8')) {
  try {
    const raw = JSON.parse(readFile(quotaAuditPath(accountsDir)))
    if (!Array.isArray(raw)) return []
    return raw.filter((item) => item && typeof item.at === 'string' && typeof item.account === 'string')
  } catch {
    return []
  }
}

/**
 * 追加一条审计。同一个账号的同一个结论不重复记（界面每秒刷一次，不能刷出一条河）。
 */
export function appendQuotaAudit(
  accountsDir,
  entry,
  {
    readFile = (p) => readFileSync(p, 'utf8'),
    writeFile = (p, text) => writeFileSync(p, text, 'utf8'),
    limit = AUDIT_LIMIT,
  } = {},
) {
  if (!entry || typeof entry.account !== 'string') return []
  const existing = readQuotaAudit(accountsDir, readFile)
  const previous = existing.find((item) => item.account === entry.account)
  const sameConclusion =
    previous &&
    previous.resetAt === entry.resetAt &&
    previous.confidence === entry.confidence &&
    previous.environmentSafe === entry.environmentSafe &&
    previous.source === entry.source
  if (sameConclusion) return existing

  const record = {
    at: typeof entry.at === 'string' ? entry.at : new Date().toISOString(),
    account: entry.account,
    source: entry.source ?? 'plan-usage-history',
    queried: entry.queried === true,
    environmentSafe: typeof entry.environmentSafe === 'boolean' ? entry.environmentSafe : null,
    resetAt: entry.resetAt ?? null,
    confidence: entry.confidence ?? 'unknown',
    percent: typeof entry.percent === 'number' ? entry.percent : null,
    note: entry.note ?? undefined,
  }
  const next = [record, ...existing].slice(0, Math.max(1, limit))
  try {
    mkdirSync(accountsDir, { recursive: true })
    writeFile(quotaAuditPath(accountsDir), `${JSON.stringify(next, null, 2)}\n`)
  } catch {
    // 审计写失败不影响主流程。
  }
  return next
}
