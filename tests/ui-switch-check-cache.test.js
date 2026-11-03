import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { createUiSession } from '../src/ui/session.js'

/**
 * 切号前的合规判定复用。
 *
 * 背景：一次完整检测实测要 10 秒上下（出口探测 6~8 秒 + 解析出口采样 3 秒），
 * 而闸门每 10 秒就已经判过一轮了。切号再等一遍，纯属把同一件事重做。
 */

const tempDirs = []
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'ccgait-cache-'))
  tempDirs.push(dir)
  return dir
}

after(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function makeProfile(root) {
  const profile = join(root, 'profile')
  mkdirSync(join(profile, 'Network'), { recursive: true })
  writeFileSync(join(profile, 'Network', 'Cookies'), 'cookie-data')
  writeFileSync(join(profile, 'Preferences'), '{}')
  return profile
}

function makeSession({ allow = true } = {}) {
  const root = tempDir()
  const profile = makeProfile(root)
  const accounts = join(root, 'accounts')
  mkdirSync(join(accounts, 'A'), { recursive: true })
  // 目标账号 B 的存档
  mkdirSync(join(accounts, 'B', 'Network'), { recursive: true })
  writeFileSync(join(accounts, 'B', 'Network', 'Cookies'), 'b-cookie')
  writeFileSync(join(accounts, 'B', 'Preferences'), '{}')
  writeFileSync(join(accounts, 'current.json'), JSON.stringify({ name: 'A' }))

  let checkRuns = 0
  const deps = {
    locateDesktopProfile: () => profile,
    runChecks: async () => {
      checkRuns += 1
      return {
        verdict: {
          allow,
          failedClosed: false,
          blockedBy: allow ? [] : [{ id: 'egress-country', title: '出口国家不在白名单', detail: 'x' }],
          warnings: [],
          whitelistSummary: 'GB',
        },
        egress: { ip: '1.2.3.4', country: 'GB' },
        dns: {},
        environment: {},
      }
    },
    killClaudeProcessesByKind: async () => 0,
    listClaudeProcesses: async () => [],
    accountsRoot: () => accounts,
    readGuardCheck: () => null,
    listWfpHosts: () => [],
    readWfpPid: () => undefined,
    isWfpBlocking: () => false,
    startupStatus: () => ({ enabled: false }),
  }
  const session = createUiSession({ configPath: join(root, 'config.json'), deps })
  return { session, profile, accounts, checks: () => checkRuns }
}

describe('切号前的合规判定复用', () => {
  it('闸门刚判过 → 切号不再跑完整检测', async () => {
    const { session, checks } = makeSession()
    // 先手动检测一次（模拟闸门/用户检测给出的最近结果）
    await session.checkNow()
    assert.equal(checks(), 1)

    const result = await session.switchAccountTo('B')
    assert.equal(result.switched, true)
    assert.equal(checks(), 1, '30 秒内的判定应被复用，不该重跑')
  })

  it('没有最近的判定 → 老老实实测一次', async () => {
    const { session, checks } = makeSession()
    const result = await session.switchAccountTo('B')
    assert.equal(result.switched, true)
    assert.equal(checks(), 1)
  })

  it('切号成功后写一条历史', async () => {
    const { session, accounts } = makeSession()
    await session.switchAccountTo('B')
    const file = join(accounts, 'switch-history.json')
    assert.ok(existsSync(file), '历史文件应该被创建')
    const history = JSON.parse(readFileSync(file, 'utf8'))
    assert.equal(history[0].to, 'B')
    assert.equal(history[0].from, 'A')
  })

  it('最近判定是拦截 → 仍然拒绝切号，且不动现场', async () => {
    const { session, checks } = makeSession({ allow: false })
    await session.checkNow()
    const result = await session.switchAccountTo('B')
    assert.equal(result.switched, false)
    assert.equal(result.allow, false)
    assert.equal(checks(), 1, '拒绝时也复用判定，不重复探测')
  })
})
