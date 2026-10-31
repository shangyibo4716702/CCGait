import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { createUiSession } from '../src/ui/session.js'

const tempDirs = []
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'ccgait-uiswitch-'))
  tempDirs.push(dir)
  return dir
}

after(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

/** 造一个只关心模式切换的会话：代理相关依赖全部注入，不碰真机。 */
function makeSession({ mode = 'global', coverageOk = true, verifyOk = true, restartOk = true } = {}) {
  const calls = []
  // 模拟真实读写：writeProxyMode 改了磁盘，下一次 probe 就该读到新值。
  let currentMode = mode
  const deps = {
    probeProxyMode: async () => {
      calls.push(['probe'])
      return { found: true, dir: 'C:/fake', mode: currentMode, client: 'Clash Verge' }
    },
    readProxySettings: () => ({ nameserver: ['8.8.8.8'], ipv6: false, dnsOverride: true, dnsIpv6: false }),
    judgeProxySettings: () => [],
    judgeDnsUpstreams: () => [],
    needsClashFix: () => false,
    readClashRules: () => (coverageOk ? ['DOMAIN-SUFFIX,anthropic.com,IPEqual', 'MATCH,IPEqual'] : ['MATCH,IPEqual']),
    claudeRuleCoverage: (rules) => {
      const ok = rules.some((rule) => /anthropic/i.test(rule))
      return { ok, issues: ok ? [] : [{ id: 'claude-rules-missing', title: 't', detail: 'd' }], group: ok ? 'IPEqual' : null }
    },
    applyClaudeRules: () => {
      calls.push(['applyRules'])
      return { changed: true, durable: true, after: ['DOMAIN-SUFFIX,anthropic.com,IPEqual'], files: ['C:/fake/rules.yaml'] }
    },
    writeProxyMode: (dir, target) => {
      calls.push(['writeMode', target])
      currentMode = target
      return { changed: 1, results: [{ file: 'C:/fake/clash-verge.yaml', changed: true }] }
    },
    restartProxyCore: async () => {
      calls.push(['restart'])
      return restartOk
    },
    verifyClaudeRouting: async ({ expectMode }) => {
      calls.push(['verify', expectMode])
      return verifyOk
        ? {
            ok: true,
            checked: true,
            mode: expectMode,
            leaks: [],
            results: [{ host: 'claude.ai', chains: ['节点一', 'GLOBAL'] }],
            error: null,
          }
        : {
            ok: false,
            checked: true,
            mode: expectMode,
            leaks: [{ host: 'claude.ai', chains: ['DIRECT'] }],
            results: [],
            error: null,
          }
    },
  }
  const session = createUiSession({ configPath: join(tempDir(), 'config.json'), deps })
  return { session, calls }
}

describe('代理模式双向切换', () => {
  it('全局 → 规则：补规则、改模式、重启、自证通过', async () => {
    const { session, calls } = makeSession({ mode: 'global', coverageOk: false })
    const result = await session.setProxyMode('rule')
    assert.equal(result.ok, true)
    assert.equal(result.mode, 'rule')
    assert.deepEqual(
      calls.map((item) => item[0]),
      ['probe', 'applyRules', 'writeMode', 'restart', 'verify', 'probe'],
    )
    assert.deepEqual(calls[2], ['writeMode', 'rule'])
    assert.match(result.summary, /claude\.ai → 节点一>GLOBAL/)
  })

  it('规则 → 全局：不碰规则，只改模式并自证', async () => {
    const { session, calls } = makeSession({ mode: 'rule' })
    const result = await session.setProxyMode('global')
    assert.equal(result.ok, true)
    assert.equal(result.mode, 'global')
    assert.ok(!calls.some((item) => item[0] === 'applyRules'))
    assert.deepEqual(calls.find((item) => item[0] === 'writeMode'), ['writeMode', 'global'])
    assert.deepEqual(calls.find((item) => item[0] === 'verify'), ['verify', 'global'])
  })

  it('切规则模式自证失败 → 回滚到原模式并报错', async () => {
    const { session, calls } = makeSession({ mode: 'global', verifyOk: false })
    await assert.rejects(
      () => session.setProxyMode('rule'),
      /没能证明 Claude 走代理.*已回滚到全局模式/,
    )
    const writes = calls.filter((item) => item[0] === 'writeMode').map((item) => item[1])
    assert.deepEqual(writes, ['rule', 'global'])
    // 回滚后还要再重启一次
    assert.equal(calls.filter((item) => item[0] === 'restart').length, 2)
  })

  it('切全局自证失败 → 不回滚，如实报没确认', async () => {
    const { session, calls } = makeSession({ mode: 'rule', verifyOk: false })
    await assert.rejects(() => session.setProxyMode('global'), /内核没确认/)
    assert.deepEqual(calls.filter((item) => item[0] === 'writeMode').map((item) => item[1]), ['global'])
  })

  it('内核没重启时，切规则模式会回滚', async () => {
    const { session } = makeSession({ mode: 'global', restartOk: false })
    await assert.rejects(() => session.setProxyMode('rule'), /没能重启.*已回滚/)
  })

  it('已经是目标模式时不做改动，只实测现状', async () => {
    const { session, calls } = makeSession({ mode: 'rule' })
    const result = await session.setProxyMode('rule')
    assert.equal(result.ok, true)
    assert.equal(result.unchanged, true)
    assert.ok(!calls.some((item) => item[0] === 'writeMode' || item[0] === 'restart'))
    assert.deepEqual(result.steps, ['已经是规则模式，没有改动'])
  })
})
