import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
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

  it('serves a favicon so the app window has a taskbar icon', async () => {
    // 应用窗口是 Edge/Chrome 的 APP 模式：任务栏那一格的图标取自页面图标。
    // 没有它，任务栏按钮就是个空的默认图标（用户实测报过这一点）。
    await withServer(async ({ base }) => {
      const response = await fetch(`${base}/favicon.ico`)
      assert.equal(response.status, 200)
      assert.match(response.headers.get('content-type') ?? '', /icon/)
      const bytes = Buffer.from(await response.arrayBuffer())
      assert.deepEqual([...bytes.subarray(0, 4)], [0, 0, 1, 0], 'ICO 头')
      // 任务栏在 100% 缩放下显示 24px。favicon 里给 16 的话，Chromium 会把 16px
      // 交给窗口、Windows 再放大到 24 —— 放大必然发糊。所以这里必须**没有 16**，
      // 并且要从 32/48 缩小，缩小才是清晰的。
      const count = bytes.readUInt16LE(4)
      const sizes = []
      for (let index = 0; index < count; index += 1) {
        let width = bytes[6 + 16 * index]
        if (width === 0) width = 256
        sizes.push(width)
      }
      assert.ok(sizes.length > 0, 'favicon 至少要有一档')
      assert.equal(sizes.includes(16), false, '不能提供 16px（任务栏会把它放大成 24）')
      assert.ok(sizes.some((size) => size >= 32), '必须提供 32px 或更大，让系统缩小使用')
    })
  })

  it('serves an SVG icon for crisp taskbar rendering at any DPI', async () => {
    // 位图挑不到合适尺寸时会被缩放，SVG 由内核按需渲染，任何缩放比例都清晰。
    await withServer(async ({ base }) => {
      const response = await fetch(`${base}/icon.svg`)
      assert.equal(response.status, 200)
      assert.match(response.headers.get('content-type') ?? '', /svg/)
      const text = await response.text()
      assert.match(text, /^<svg /)
      assert.match(text, /M12 3l7 3v6/, '盾牌路径要与位图版一致')
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

  it('launches Claude Desktop only after a passing check', async () => {
    // 这是产品约定的核心：从界面启动必须"先判定、后启动"。
    // 直接双击图标绕过闸门，而这条路径不能有同样的漏洞。
    const { path } = tempConfig()
    const launched = []
    const deps = fakeDeps()
    const session = createUiSession({
      configPath: path,
      deps: {
        ...deps.deps,
        resolveDesktopTarget: () => ({ path: 'C:\\fake\\Claude.exe', label: 'test' }),
        launchDesktop: (target) => {
          launched.push(target.path)
          return 4242
        },
        // 注入"进程真的起来了"的结果：不依赖本机是否装着 Claude。
        waitForDesktopProcess: async () => true,
        focusDesktopWindow: async () => true,
      },
    })
    try {
      const result = await session.launchClaudeDesktop()
      assert.equal(result.launched, true)
      assert.equal(result.pid, 4242)
      assert.deepEqual(launched, ['C:\\fake\\Claude.exe'], '判定通过时应真的拉起进程')
    } finally {
      await session.dispose()
    }
  })

  it('refuses to launch when the check fails, and says why', async () => {
    const { path } = tempConfig()
    const launched = []
    const deps = fakeDeps({
      runChecks: async () => ({
        verdict: {
          allow: false,
          failedClosed: false,
          blockedBy: [{ id: 'egress-country', title: '出口国家不在白名单：CN', detail: '当前 CN' }],
          warnings: [],
        },
        egress: { ip: '36.161.21.75', country: 'CN', confident: true },
        dns: undefined,
        environment: {},
      }),
    })
    const session = createUiSession({
      configPath: path,
      deps: {
        ...deps.deps,
        resolveDesktopTarget: () => ({ path: 'C:\\fake\\Claude.exe' }),
        launchDesktop: (target) => {
          launched.push(target.path)
          return 1
        },
      },
    })
    try {
      const result = await session.launchClaudeDesktop()
      assert.equal(result.launched, false)
      assert.equal(result.allow, false)
      assert.match(result.reason, /出口国家不在白名单：CN/)
      assert.deepEqual(launched, [], '判定不通过时绝不能启动')
    } finally {
      await session.dispose()
    }
  })

  it('does not launch when no Claude Desktop target can be found', async () => {
    const { path } = tempConfig()
    const deps = fakeDeps()
    const session = createUiSession({
      configPath: path,
      deps: {
        ...deps.deps,
        resolveDesktopTarget: () => undefined,
        launchDesktop: () => {
          throw new Error('should not be called')
        },
      },
    })
    try {
      const result = await session.launchClaudeDesktop()
      assert.equal(result.launched, false)
      assert.equal(result.allow, true, '判定本身是通过的，只是找不到入口')
      assert.match(result.reason, /找不到 Claude Desktop/)
    } finally {
      await session.dispose()
    }
  })

  it('reports failure when the launch command runs but no process appears', async () => {
    // 真实踩过的坑：MSIX 别名走外壳激活，`start` 立即返回成功，
    // 但应用可能根本没起来。只信"命令没报错"就会报假成功。
    const { path } = tempConfig()
    const deps = fakeDeps()
    const session = createUiSession({
      configPath: path,
      deps: {
        ...deps.deps,
        resolveDesktopTarget: () => ({ path: 'C:\\fake\\Claude.exe' }),
        launchDesktop: () => 1,
        waitForDesktopProcess: async () => false,
        focusDesktopWindow: async () => false,
      },
    })
    try {
      const result = await session.launchClaudeDesktop()
      assert.equal(result.launched, false, '没有新进程就不能报成功')
      assert.match(result.reason, /没有检测到/)
    } finally {
      await session.dispose()
    }
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

describe('账号切换接口', () => {
  // 切号只针对 Desktop，而且必须在"没装 Desktop"时明确报错，
  // 不能悄悄在别处建目录、也不能把 Claude Code 的数据当目标。
  it('没找到 Desktop 数据目录时返回 found:false，不假装成功', async () => {
    // accountsRoot 也必须注入：否则会读到本机真实的账号目录，测试结果取决于用户存过什么。
    const deps = fakeDeps({
      locateDesktopProfile: () => undefined,
      accountsRoot: () => join(tempConfig().dir, 'accounts'),
    })
    const session = createUiSession({ configPath: deps.path, deps: deps.deps })
    const state = await session.getAccounts()
    assert.equal(state.profile.found, false)
    assert.deepEqual(state.accounts, [])
    await assert.rejects(session.switchAccountTo('A'), /没找到 Claude Desktop/)
    await assert.rejects(session.saveCurrentAccount('A'), /没找到 Claude Desktop/)
  })

  it('切换时只结束 Desktop 进程，不碰 CLI', async () => {
    const root = tempConfig().dir
    const accounts = join(root, 'accounts')
    const profile = join(root, 'profile')
    mkdirSync(join(profile, 'Network'), { recursive: true })
    writeFileSync(join(profile, 'Network', 'Cookies'), 'cookies-1')
    writeFileSync(join(profile, 'ant-did'), 'did-1')

    const kinds = []
    const deps = fakeDeps({
      locateDesktopProfile: () => profile,
      accountsRoot: () => accounts,
      killClaudeProcessesByKind: async (kind) => {
        kinds.push(kind)
        return [{ pid: 1, killed: true, kind }]
      },
      listClaudeProcesses: async () => [],
    })
    const session = createUiSession({ configPath: deps.path, deps: deps.deps })

    const saved = await session.saveCurrentAccount('A')
    assert.equal(saved.entries > 0, true)
    assert.equal(saved.current, 'A', '保存即代表当前账号，必须同步 current')
    // 登出 A、登录 B、再存成 B：current 必须变成 B，否则下次切回 A 会把 B 存进 A。
    const savedB = await session.saveCurrentAccount('B')
    assert.equal(savedB.current, 'B')
    assert.equal(savedB.accounts.length, 2)
    const switched = await session.switchAccountTo('A')
    assert.equal(switched.current, 'A')
    // 没进程在跑时不必杀；关键是凡杀必是 desktop，绝不能顺手把 CLI 一起结束。
    assert.ok(kinds.length >= 1, '切换前必须处理 Desktop 进程')
    assert.ok(kinds.every((kind) => kind === 'desktop'), '只允许结束 desktop 进程')
  })
})

describe('切号的合规门控', () => {
  // 切完号就要启动 Desktop，闸门不会因为"换了个号"就放行。环境不合规时切过去，
  // 新号一启动就被断网，用户会以为切号坏了。所以判定不通过就不能动现场。
  it('判定不通过时拒绝切换，且不杀进程、不改当前账号', async () => {
    const root = tempConfig().dir
    const profile = join(root, 'profile')
    mkdirSync(join(profile, 'Network'), { recursive: true })
    writeFileSync(join(profile, 'Network', 'Cookies'), 'cookies-1')
    writeFileSync(join(profile, 'ant-did'), 'did-1')
    const accounts = join(root, 'accounts')

    let killed = 0
    const deps = fakeDeps({
      locateDesktopProfile: () => profile,
      accountsRoot: () => accounts,
      killClaudeProcessesByKind: async () => {
        killed += 1
        return []
      },
      runChecks: async () => ({
        verdict: {
          allow: false,
          failedClosed: false,
          blockedBy: [{ id: 'egress-country', title: '出口国家不在白名单：CN' }],
          warnings: [],
        },
        egress: { ip: '111.0.116.114', country: 'CN', confident: true, hosting: false },
        dns: { hosts: [], deniedHits: [], resolved: true, hasResolutionError: false },
        environment: { timezone: { intl: 'Asia/Shanghai', domestic: true } },
      }),
    })
    const session = createUiSession({ configPath: deps.path, deps: deps.deps })

    // 存档本身是本地操作，不需要合规 —— 先存一份出来。
    await session.saveCurrentAccount('A')
    const killedBefore = killed

    const result = await session.switchAccountTo('A')
    assert.equal(result.switched, false, '合规未过不能算切换成功')
    assert.match(result.reason, /出口国家不在白名单/)
    assert.equal(killed, killedBefore, '拒绝时不能结束任何进程')
  })
})

describe('保存时留空账号名', () => {
  it('留空自动分配 A，再存一次分配 B', async () => {
    const root = tempConfig().dir
    const profile = join(root, 'profile')
    mkdirSync(join(profile, 'Network'), { recursive: true })
    writeFileSync(join(profile, 'Network', 'Cookies'), 'cookies-1')
    writeFileSync(join(profile, 'ant-did'), 'did-1')
    const accounts = join(root, 'accounts')

    const deps = fakeDeps({
      locateDesktopProfile: () => profile,
      accountsRoot: () => accounts,
      killClaudeProcessesByKind: async () => [],
      listClaudeProcesses: async () => [],
    })
    const session = createUiSession({ configPath: deps.path, deps: deps.deps })

    const first = await session.saveCurrentAccount('')
    assert.equal(first.name, 'A', '留空应自动分配 A')
    assert.deepEqual(first.accounts.map((item) => item.name), ['A'])

    const second = await session.saveCurrentAccount('   ')
    assert.equal(second.name, 'B', '纯空格也算留空，应分配 B')
    assert.deepEqual(second.accounts.map((item) => item.name).sort(), ['A', 'B'])
  })
})

describe('更新与删除账号接口', () => {
  it('更新非当前账号时拒绝，避免把当前号的登录态覆盖进别人', async () => {
    const root = tempConfig().dir
    const profile = join(root, 'profile')
    mkdirSync(join(profile, 'Network'), { recursive: true })
    writeFileSync(join(profile, 'Network', 'Cookies'), 'cookies-a')
    writeFileSync(join(profile, 'ant-did'), 'did')
    const accounts = join(root, 'accounts')

    const deps = fakeDeps({
      locateDesktopProfile: () => profile,
      accountsRoot: () => accounts,
      killClaudeProcessesByKind: async () => [],
      listClaudeProcesses: async () => [],
    })
    const session = createUiSession({ configPath: deps.path, deps: deps.deps })
    await session.saveCurrentAccount('A') // current = A
    await session.saveCurrentAccount('B') // current = B

    await assert.rejects(session.updateAccount('A'), /不能直接把它的登录态存成 A|用的是 B/)
  })

  it('删除当前账号被拒绝，删除其它账号成功', async () => {
    const root = tempConfig().dir
    const profile = join(root, 'profile')
    mkdirSync(join(profile, 'Network'), { recursive: true })
    writeFileSync(join(profile, 'Network', 'Cookies'), 'cookies')
    const accounts = join(root, 'accounts')
    const deps = fakeDeps({
      locateDesktopProfile: () => profile,
      accountsRoot: () => accounts,
      killClaudeProcessesByKind: async () => [],
      listClaudeProcesses: async () => [],
    })
    const session = createUiSession({ configPath: deps.path, deps: deps.deps })
    await session.saveCurrentAccount('A')
    await session.saveCurrentAccount('B')

    await assert.rejects(session.deleteAccount('B'), /正在使用中/)
    const after = await session.deleteAccount('A')
    assert.equal(after.removed, true)
    assert.deepEqual(after.accounts.map((item) => item.name), ['B'])
  })
})
