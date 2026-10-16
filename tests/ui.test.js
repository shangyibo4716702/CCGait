import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { createUiSession, applyConfigPatch } from '../src/ui/session.js'
import { createUiServer } from '../src/ui/server.js'
import { normalizeConfig } from '../src/config.js'

/**
 * UI 层测试：会话动作 + HTTP 接口。
 * 依赖全部注入为假实现 —— 测试不会创建防火墙规则、不会结束进程、也不碰真实配置。
 */

const tempDirs = []
after(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function tempConfig(overrides = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'ccgait-ui-'))
  tempDirs.push(dir)
  const path = join(dir, 'config.json')
  const config = {
    whitelist: { ips: [], cidrs: [], countries: ['HK'], asns: [], requireResidential: false },
    checks: { egressIp: { enabled: true, severity: 'block' } },
    enforcement: { killProcesses: true, blockNetwork: true, failClosed: true },
    network: { proxy: { enabled: false, url: '', required: false } },
    runtime: { stateDir: dir, logRetentionDays: 7 },
    ...overrides,
  }
  writeFileSync(path, `${JSON.stringify(config, null, 2)}\n`, 'utf8')
  return { dir, path, config }
}

function fakeDeps(overrides = {}) {
  const calls = []
  const deps = {
    runChecks: async () => {
      calls.push('runChecks')
      return {
        verdict: {
          allow: true,
          failedClosed: false,
          blockedBy: [],
          warnings: [{ id: 'timezone-domestic', title: '系统时区为 Asia/Shanghai', detail: '示例提示' }],
        },
        egress: { ip: '203.0.113.7', country: 'HK', confident: true, hosting: true, asnText: 'Example' },
        dns: { hosts: [{ host: 'claude.ai', addresses: ['160.79.104.10'], country: 'US' }], deniedHits: [], resolved: true, hasResolutionError: false },
        environment: { timezone: { intl: 'Europe/London', domestic: false } },
      }
    },
    createGuard: () => {
      let state = null
      const guard = {
        start: async () => {
          calls.push('guard.start')
          state = { allow: false, reason: 'startup' }
          return state
        },
        stop: async () => {
          calls.push('guard.stop')
        },
        get lastState() {
          return state
        },
      }
      return guard
    },
    applyBlockForPaths: async (paths) => {
      calls.push(['applyBlockForPaths', paths.length])
      return { applied: paths, verified: paths, removed: [], failed: [], error: undefined }
    },
    removeAllBlocks: async () => {
      calls.push('removeAllBlocks')
      return { removed: 2, error: undefined }
    },
    listManagedRules: async () => [],
    firewallProfileState: async () => ({ supported: true, profiles: [{ name: 'Domain', enabled: true }], anyEnabled: true }),
    isElevated: async () => true,
    enableProfiles: async () => ({ ok: true, profiles: [{ name: 'Domain', enabled: true }] }),
    listClaudeProcesses: async () => [],
    killAllClaudeProcesses: async () => [],
    claudeDiscovery: () => ({
      entries: [{ kind: 'cli', label: 'Claude Code CLI', path: 'C:\\x\\claude.exe' }],
      notes: [],
    }),
    startupStatus: async () => ({ supported: true, installed: false }),
    ...overrides,
  }
  return { deps, calls }
}

async function withServer(run) {
  const { path } = tempConfig()
  const { deps, calls } = fakeDeps()
  const session = createUiSession({ configPath: path, deps })
  const ui = createUiServer({ session })
  const address = await ui.listen(0)
  const base = `http://127.0.0.1:${address.port}`
  try {
    await run({ base, token: ui.token, session, calls, configPath: path })
  } finally {
    await session.dispose()
    await ui.close()
  }
}

const post = (base, token, path, body) =>
  fetch(`${base}${path}`, {
    method: 'POST',
    headers: { 'x-ccgait-token': token, 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  })

/** fetch 不允许自定义 Host 头，改用手写请求验证 Host 校验。 */
function rawGet(port, path, hostHeader) {
  return new Promise((resolve, reject) => {
    const request = httpRequest(
      { host: '127.0.0.1', port, path, method: 'GET', headers: { host: hostHeader } },
      (response) => {
        const chunks = []
        response.on('data', (chunk) => chunks.push(chunk))
        response.on('end', () =>
          resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }),
        )
      },
    )
    request.on('error', reject)
    request.end()
  })
}

describe('applyConfigPatch', () => {
  it('merges a patch without breaking untouched fields', () => {
    const base = normalizeConfig({ whitelist: { countries: ['HK'] } })
    const next = applyConfigPatch(base, {
      whitelist: { ips: ['203.0.113.7'] },
      checks: { timezone: { severity: 'block' } },
    })
    assert.deepEqual(next.whitelist.ips, ['203.0.113.7'])
    assert.deepEqual(next.whitelist.countries, ['HK'], '未提到的字段保持原值')
    assert.equal(next.checks.timezone.severity, 'block')
    assert.equal(next.checks.timezone.enabled, true, '只改 severity 不应丢掉 enabled')
    assert.equal(next.checks.fonts.severity, 'warn', '其它检查项不受影响')
  })

  it('normalizes user input (uppercase country codes, trimmed lists)', () => {
    const base = normalizeConfig({})
    const next = applyConfigPatch(base, {
      whitelist: { countries: [' us ', 'jp'], ips: [' 1.2.3.4 '] },
    })
    assert.deepEqual(next.whitelist.countries, ['US', 'JP'])
    assert.deepEqual(next.whitelist.ips, ['1.2.3.4'])
  })
})

describe('ui server', () => {
  it('serves the page with the session token injected', async () => {
    await withServer(async ({ base, token }) => {
      const response = await fetch(`${base}/`)
      assert.equal(response.status, 200)
      const html = await response.text()
      assert.ok(html.includes(token), '页面里应注入令牌，前端才能调用接口')
      assert.ok(html.includes('CCGait'), '应返回真实页面')
      // 页面不得引用任何外部资源（离线可用、不外发请求）
      assert.equal(/https?:\/\//.test(html.replace(/http:\/\/127\.0\.0\.1/g, '')), false)
    })
  })

  it('rejects api calls without the token', async () => {
    await withServer(async ({ base }) => {
      const response = await fetch(`${base}/api/status`)
      assert.equal(response.status, 401)
    })
  })

  it('rejects a non-local Host header (DNS rebinding)', async () => {
    const { path } = tempConfig()
    const session = createUiSession({ configPath: path, deps: fakeDeps().deps })
    const ui = createUiServer({ session })
    const address = await ui.listen(0)
    try {
      const result = await rawGet(address.port, '/api/status', 'evil.example.com')
      assert.equal(result.status, 403)
      const ok = await rawGet(address.port, '/api/status', `127.0.0.1:${address.port}`)
      assert.equal(ok.status, 401, 'Host 合法时进入令牌校验')
    } finally {
      await session.dispose()
      await ui.close()
    }
  })

  it('refuses to escape the public directory via path traversal', async () => {
    await withServer(async ({ base }) => {
      const response = await fetch(`${base}/../package.json`)
      assert.notEqual(response.status, 200)
      const text = await response.text()
      assert.equal(text.includes('"name": "ccgait"'), false)
    })
  })

  it('returns status, runs a check and toggles guard/firewall through the api', async () => {
    await withServer(async ({ base, token, calls }) => {
      const statusResponse = await fetch(`${base}/api/status`, { headers: { 'x-ccgait-token': token } })
      const initial = await statusResponse.json()
      assert.equal(initial.guard.running, false)
      assert.equal(initial.targets.length, 1)
      assert.equal(initial.elevated, true)

      const check = await (await post(base, token, '/api/check')).json()
      assert.equal(check.check.allow, true)
      assert.equal(check.check.warnings.length, 1)

      const guard = await (await post(base, token, '/api/guard/start')).json()
      assert.equal(guard.guard.running, true)

      const afterStart = await (await fetch(`${base}/api/status`, { headers: { 'x-ccgait-token': token } })).json()
      assert.equal(afterStart.guard.running, true)

      const block = await (await post(base, token, '/api/firewall', { enabled: true })).json()
      assert.equal(block.result.verified.length, 1)

      const unblock = await (await post(base, token, '/api/firewall', { enabled: false })).json()
      assert.equal(unblock.result.removed, 2)

      const stopped = await (await post(base, token, '/api/guard/stop')).json()
      assert.equal(stopped.guard.running, false)

      assert.ok(calls.includes('runChecks'))
      assert.ok(calls.includes('guard.start'))
      assert.ok(calls.includes('guard.stop'))
    })
  })

  it('saves a config patch and rejects one that would break the whitelist', async () => {
    await withServer(async ({ base, token, session, configPath }) => {
      const saved = await (
        await post(base, token, '/api/config', {
          patch: { whitelist: { countries: ['us'], ips: ['203.0.113.7'] }, enforcement: { failClosed: false } },
        })
      ).json()
      assert.deepEqual(saved.config.whitelist.countries, ['US'])
      assert.deepEqual(saved.config.whitelist.ips, ['203.0.113.7'])
      assert.equal(saved.config.enforcement.failClosed, false)
      assert.equal(session.getConfig().whitelist.countries[0], 'US', '会话内配置应同步更新')

      // 反过来：把白名单清空（配置校验不通过）应被拒绝且不落盘。
      const rejected = await post(base, token, '/api/config', {
        patch: { whitelist: { countries: [], ips: [], cidrs: [], asns: [] } },
      })
      assert.equal(rejected.status, 400)
      const body = await rejected.json()
      assert.match(body.error, /白名单为空/)
      assert.deepEqual(session.getConfig().whitelist.countries, ['US'], '被拒绝的配置不能生效')

      // 非法 CIDR 同样拒绝
      const badCidr = await post(base, token, '/api/config', {
        patch: { whitelist: { countries: ['US'], cidrs: ['10.0.0.0/99'] } },
      })
      assert.equal(badCidr.status, 400)
      void configPath
    })
  })

  it('restarts the guard with the new whitelist after a config change', async () => {
    await withServer(async ({ base, token, calls }) => {
      await post(base, token, '/api/guard/start')
      calls.length = 0
      await post(base, token, '/api/config', { patch: { whitelist: { countries: ['US'] } } })
      assert.ok(calls.includes('guard.stop'), '改配置应先停掉旧闸门')
      assert.ok(calls.includes('guard.start'), '再按新配置重启')
    })
  })

  it('streams events over sse', async () => {
    await withServer(async ({ base, token }) => {
      const controller = new AbortController()
      const response = await fetch(`${base}/api/events?token=${token}`, { signal: controller.signal })
      assert.equal(response.status, 200)
      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      const first = decoder.decode((await reader.read()).value)
      assert.match(first, /event: hello/)

      // 触发一次检测，应在同一条流里收到 check 事件
      await post(base, token, '/api/check')
      let buffer = first
      for (let index = 0; index < 6 && !buffer.includes('event: check'); index += 1) {
        const chunk = await reader.read()
        if (chunk.done) break
        buffer += decoder.decode(chunk.value)
      }
      assert.match(buffer, /event: check/)
      controller.abort()
    })
  })

  it('reports a failing action with a stable error shape', async () => {
    const { path } = tempConfig()
    const { deps } = fakeDeps({
      applyBlockForPaths: async () => ({ applied: [], verified: [], removed: [], failed: [], error: '需要管理员权限' }),
    })
    const session = createUiSession({ configPath: path, deps })
    const ui = createUiServer({ session })
    const address = await ui.listen(0)
    try {
      const response = await fetch(`http://127.0.0.1:${address.port}/api/firewall`, {
        method: 'POST',
        headers: { 'x-ccgait-token': ui.token, 'content-type': 'application/json' },
        body: JSON.stringify({ enabled: true }),
      })
      assert.equal(response.status, 400)
      assert.match((await response.json()).error, /管理员/)
    } finally {
      await session.dispose()
      await ui.close()
    }
  })
})
