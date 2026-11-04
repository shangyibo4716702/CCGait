import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  FIVE_HOUR_WINDOW_MS,
  appendQuotaAudit,
  estimateFiveHourWindow,
  formatRemaining,
  parseUsageSamples,
  quotaAuditPath,
  readQuotaAudit,
  isExactReset,
  detectResets,
  measurePredictionError,
} from '../src/quota.js'

const tempDirs = []
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'ccgait-quota-'))
  tempDirs.push(dir)
  return dir
}
after(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

const MIN = 60 * 1000
const T0 = Date.UTC(2026, 10, 3, 0, 0, 0)
const sample = (minute, fh, sd = 10) => ({ t: T0 + minute * MIN, u: { fh, sd } })

describe('采样解析', () => {
  it('支持 {samples:[...]} 和裸数组', () => {
    const a = parseUsageSamples({ samples: [sample(0, 0), sample(5, 3)] })
    const b = parseUsageSamples([sample(0, 0), sample(5, 3)])
    assert.deepEqual(a, b)
    assert.equal(a.length, 2)
  })

  it('乱序输入会按时间排好，缺字段的丢掉', () => {
    const rows = parseUsageSamples({ samples: [sample(10, 5), sample(0, 0), { t: T0, u: {} }, null] })
    assert.deepEqual(rows.map((item) => item.fh), [0, 5])
  })

  it('坏 JSON 返回空数组', () => {
    assert.deepEqual(parseUsageSamples('{oops'), [])
  })
})

describe('5 小时窗口推算', () => {
  it('没有采样 → 判不出', () => {
    const out = estimateFiveHourWindow([], { now: T0 })
    assert.equal(out.confidence, 'unknown')
    assert.equal(out.active, false)
  })

  it('最新采样是 0 → 窗口未开始', () => {
    const out = estimateFiveHourWindow([sample(0, 0), sample(10, 0)], { now: T0 + 11 * MIN })
    assert.equal(out.active, false)
    assert.equal(out.confidence, 'high')
  })

  it('跳变被 10 分钟内的采样夹住 → 高置信，重置 = 跳变 + 5h', () => {
    const out = estimateFiveHourWindow([sample(0, 0), sample(6, 2), sample(20, 9)], {
      now: T0 + 30 * MIN,
    })
    assert.equal(out.active, true)
    assert.equal(out.confidence, 'high')
    assert.equal(out.startAt, T0 + 6 * MIN)
    assert.equal(out.resetAt, T0 + 6 * MIN + FIVE_HOUR_WINDOW_MS)
    assert.equal(out.uncertaintyMs, 6 * MIN)
    assert.equal(out.remainingMs, FIVE_HOUR_WINDOW_MS - 24 * MIN)
  })

  it('前后两条采样隔得远 → 粗估，并给出误差范围', () => {
    const out = estimateFiveHourWindow([sample(0, 0), sample(180, 40)], { now: T0 + 200 * MIN })
    assert.equal(out.confidence, 'estimate')
    assert.equal(out.uncertaintyMs, 180 * MIN)
    assert.match(out.reason, /误差可能到 180 分钟/)
  })

  it('段内没有 0 采样 → 按斜率外推起点', () => {
    const out = estimateFiveHourWindow([sample(0, 5), sample(10, 9)], { now: T0 + 20 * MIN })
    assert.equal(out.active, true)
    assert.equal(out.method, 'extrapolation')
    assert.equal(out.confidence, 'estimate')
    // 5% → 9%（10 分钟）反推到 0，起点在第一条采样之前约 12.5 分钟
    assert.ok(out.startAt < T0)
    assert.equal(out.resetAt, out.startAt + FIVE_HOUR_WINDOW_MS)
  })

  it('采样间隙里重置过：识别下降，不把上一段的起点当这一轮', () => {
    // 本机实测形态：11:47=30% → 18:32=3%，中间重置但没有任何 0 采样
    const rows = [sample(0, 0), sample(10, 30), sample(400, 3), sample(415, 14), sample(430, 26), sample(445, 40)]
    const out = estimateFiveHourWindow(rows, { now: T0 + 450 * MIN })
    assert.equal(out.method, 'extrapolation')
    assert.ok(out.startAt > T0 + 380 * MIN, '起点应在 18:xx，而不是上午那次')
    assert.ok(out.startAt < T0 + 400 * MIN)
  })

  it('采样太旧会标 stale', () => {
    const out = estimateFiveHourWindow([sample(0, 0), sample(6, 2)], { now: T0 + 200 * MIN })
    assert.equal(out.stale, true)
  })
})

describe('倒计时格式', () => {
  it('按时分秒补齐，超过一天带天数', () => {
    assert.equal(formatRemaining(3 * 3600 * 1000 + 12 * MIN + 44 * 1000), '3:12:44')
    assert.equal(formatRemaining(26 * 3600 * 1000), '1天 02:00')
    assert.equal(formatRemaining(-1), '—')
  })
})

describe('额度审计', () => {
  it('同一结论不重复记，结论变了才追加', () => {
    const dir = tempDir()
    const base = { account: 'A', resetAt: '2026-11-03T05:00:00.000Z', confidence: 'high', environmentSafe: true, source: 'plan-usage-history' }
    appendQuotaAudit(dir, base)
    appendQuotaAudit(dir, base)
    assert.equal(readQuotaAudit(dir).length, 1)

    appendQuotaAudit(dir, { ...base, resetAt: '2026-11-03T09:00:00.000Z' })
    const audit = readQuotaAudit(dir)
    assert.equal(audit.length, 2)
    assert.equal(audit[0].resetAt, '2026-11-03T09:00:00.000Z')
  })

  it('环境安全与否如实记录，没请求就写 queried=false', () => {
    const dir = tempDir()
    appendQuotaAudit(dir, { account: 'B', confidence: 'unknown', environmentSafe: false })
    const [entry] = readQuotaAudit(dir)
    assert.equal(entry.environmentSafe, false)
    assert.equal(entry.queried, false)
    assert.equal(entry.resetAt, null)
  })

  it('超过上限截断', () => {
    const dir = tempDir()
    for (let i = 0; i < 6; i += 1) appendQuotaAudit(dir, { account: `A${i}` }, { limit: 3 })
    assert.equal(readQuotaAudit(dir).length, 3)
    assert.equal(JSON.parse(readFileSync(quotaAuditPath(dir), 'utf8')).length, 3)
  })

  it('文件坏掉返回空数组', () => {
    const dir = tempDir()
    appendQuotaAudit(dir, { account: 'A' })
    const path = quotaAuditPath(dir)
    assert.ok(path.endsWith('quota-audit.json'))
    assert.deepEqual(readQuotaAudit(dir, () => '{bad'), [])
  })
})

describe('精确性门禁与真实重置', () => {
  it('只有 measured / api 算精确，推算一律不算', () => {
    assert.equal(isExactReset({ method: 'measured' }), true)
    assert.equal(isExactReset({ method: 'api' }), true)
    assert.equal(isExactReset({ method: 'zero-crossing' }), false)
    assert.equal(isExactReset({ method: 'extrapolation' }), false)
    assert.equal(isExactReset({ confidence: 'high' }), false, '高置信也只是推算')
    assert.equal(isExactReset(null), false)
  })

  it('推算出来的窗口不会被当成精确', () => {
    const out = estimateFiveHourWindow([sample(0, 0), sample(6, 2), sample(20, 9)], { now: T0 + 30 * MIN })
    assert.equal(isExactReset(out), false)
  })

  it('从采样里找出真实重置区间', () => {
    const resets = detectResets([sample(0, 0), sample(10, 40), sample(20, 0), sample(30, 5)])
    assert.equal(resets.length, 1)
    assert.equal(resets[0].lowerAt, T0 + 10 * MIN)
    assert.equal(resets[0].upperAt, T0 + 20 * MIN)
    assert.equal(resets[0].spanMs, 10 * MIN)
    assert.equal(resets[0].fromPercent, 40)
  })

  it('预测落在真实区间内 = 命中', () => {
    const resets = detectResets([sample(0, 10), sample(20, 0)])
    const hit = measurePredictionError({ resetAt: T0 + 15 * MIN }, resets)
    assert.equal(hit.hit, true)
    assert.equal(hit.errorMs, 0)
  })

  it('预测偏出区间会算出偏差毫秒数', () => {
    const resets = detectResets([sample(0, 10), sample(20, 0)])
    const miss = measurePredictionError({ resetAt: T0 + 27 * MIN }, resets)
    assert.equal(miss.hit, false)
    assert.equal(miss.errorMs, 7 * MIN)
  })

  it('没有真实重置可对照时返回 null', () => {
    assert.equal(measurePredictionError({ resetAt: T0 }, []), null)
    assert.equal(measurePredictionError(null, detectResets([sample(0, 0)])), null)
  })
})
