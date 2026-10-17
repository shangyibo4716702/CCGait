import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  ipInCidr,
  isValidCidr,
  isValidIpv4,
  normalizeConfig,
  validateConfig,
} from '../src/config.js'
import { decide, evaluateEgress } from '../src/verdict.js'
import {
  clearGuardStartRequest,
  clearGuardStopRequest,
  guardStartRequestPath,
  guardStopRequestPath,
  requestGuardStart,
  requestGuardStop,
} from '../src/guard.js'
import { buildClaudeAccess, readGuardCheck } from '../src/ui/session.js'
import { classifyProcess } from '../src/claude-targets.js'
import { normalizeProfileEnabled } from '../src/firewall.js'
import { parseKeyValueText } from '../src/http.js'

const tempDirs = []
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'ccgait-test-'))
  tempDirs.push(dir)
  return dir
}

after(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

describe('config', () => {
  it('normalizes an empty config to the strict defaults', () => {
    const config = normalizeConfig({})
    assert.deepEqual(config.whitelist.countries, [])
    assert.equal(config.enforcement.failClosed, true)
    // 判定前先挂 WFP 过滤器：关掉"第一轮判定还没出结果"这段能连出去的窗口。
    assert.equal(config.enforcement.blockFirst, true)
    assert.equal(config.checks.egressIp.severity, 'block')
    assert.equal(config.checks.timezone.severity, 'warn')
    // DNS 与系统代理属于"出口路径本身"，默认即阻断。
    assert.equal(config.checks.dnsServers.severity, 'block')
    assert.equal(config.checks.proxyEnvLeak.severity, 'block')
    assert.deepEqual(config.checks.claudeDns.deniedCountries, ['CN'])
  })

  it('strips $comment keys and keeps user values', () => {
    const config = normalizeConfig({
      whitelist: { countries: ['us', 'jp'], ips: ['203.0.113.7'] },
      '$comment': 'x',
      checks: { timezone: { enabled: false, severity: 'block', $comment: 'y' } },
    })
    assert.deepEqual(config.whitelist.countries, ['US', 'JP'])
    assert.equal(config.checks.timezone.enabled, false)
    assert.equal(config.checks.timezone.severity, 'block')
    assert.equal(JSON.stringify(config).includes('$comment'), false)
  })

  it('flags an empty whitelist because it blocks everything', () => {
    const problems = validateConfig(normalizeConfig({}))
    assert.equal(problems.length, 1)
    assert.match(problems[0], /白名单为空/)
  })

  it('flags malformed whitelist entries', () => {
    const problems = validateConfig(
      normalizeConfig({
        whitelist: { countries: ['USA'], ips: ['999.1.1.1'], cidrs: ['10.0.0.0/33'], asns: ['15169'] },
      }),
    )
    assert.equal(problems.length, 4)
  })

  it('matches CIDR ranges correctly', () => {
    assert.equal(isValidIpv4('203.0.113.7'), true)
    assert.equal(isValidIpv4('203.0.113.256'), false)
    assert.equal(isValidCidr('203.0.113.0/24'), true)
    assert.equal(isValidCidr('203.0.113.0/33'), false)
    assert.equal(ipInCidr('203.0.113.7', '203.0.113.0/24'), true)
    assert.equal(ipInCidr('203.0.114.7', '203.0.113.0/24'), false)
    assert.equal(ipInCidr('8.8.8.8', '0.0.0.0/0'), true)
  })
})

describe('verdict', () => {
  const baseConfig = normalizeConfig({
    whitelist: { ips: ['203.0.113.7'], countries: ['US'] },
  })

  const goodEgress = {
    ip: '203.0.113.7',
    country: 'US',
    confident: true,
    ipVotes: { '203.0.113.7': 3 },
    countryVotes: { US: 3 },
    hosting: false,
    asnText: 'Example ISP',
    sources: [],
    failedSources: [],
    usableSourceCount: 3,
  }

  it('allows when the export matches the whitelist', () => {
    const reasons = evaluateEgress(baseConfig, goodEgress)
    assert.deepEqual(reasons, [])
    const verdict = decide({ config: baseConfig, egress: goodEgress })
    assert.equal(verdict.allow, true)
  })

  it('blocks a different IP even when the country matches', () => {
    const verdict = decide({
      config: baseConfig,
      egress: { ...goodEgress, ip: '198.51.100.9', ipVotes: { '198.51.100.9': 3 } },
    })
    assert.equal(verdict.allow, false)
    assert.deepEqual(
      verdict.blockedBy.map((item) => item.id),
      ['egress-ip'],
    )
  })

  it('blocks a different country even when the IP matches', () => {
    const verdict = decide({
      config: baseConfig,
      egress: { ...goodEgress, country: 'JP', countryVotes: { JP: 3 } },
    })
    assert.equal(verdict.allow, false)
    assert.deepEqual(
      verdict.blockedBy.map((item) => item.id),
      ['egress-country'],
    )
  })

  it('blocks when sources disagree about the export', () => {
    const verdict = decide({
      config: baseConfig,
      egress: { ...goodEgress, confident: false, ipVotes: { '203.0.113.7': 1, '198.51.100.9': 2 } },
    })
    assert.equal(verdict.allow, false)
    assert.ok(verdict.blockedBy.some((item) => item.id === 'egress-inconsistent'))
  })

  it('fails closed when the export cannot be determined', () => {
    const verdict = decide({
      config: baseConfig,
      egress: { ip: undefined, failedSources: ['cloudflare-trace: timeout'], confident: false },
    })
    assert.equal(verdict.allow, false)
    assert.equal(verdict.failedClosed, true)
  })

  it('can be told not to fail closed', () => {
    const config = normalizeConfig({
      whitelist: { countries: ['US'] },
      enforcement: { failClosed: false },
    })
    const verdict = decide({ config, egress: { ip: undefined, confident: false } })
    assert.equal(verdict.failedClosed, false)
    assert.equal(verdict.allow, false, '出口未知仍然命中 unknown 拦截项')
  })

  it('notes a hosting exit as a warning when residential is not required', () => {
    const config = normalizeConfig({ whitelist: { ips: ['203.0.113.7'], countries: ['US'], requireResidential: false } })
    const verdict = decide({ config, egress: { ...goodEgress, hosting: true } })
    assert.equal(verdict.allow, true)
    assert.ok(verdict.warnings.some((item) => item.id === 'egress-hosting-note'))
  })

  it('respects requireResidential', () => {
    const config = normalizeConfig({ whitelist: { countries: ['US'], requireResidential: true } })
    const verdict = decide({ config, egress: { ...goodEgress, hosting: true } })
    assert.equal(verdict.allow, false)
    assert.ok(verdict.blockedBy.some((item) => item.id === 'egress-hosting'))
  })

  it('honours the ASN whitelist', () => {
    const config = normalizeConfig({ whitelist: { countries: ['US'], asns: ['AS15169'] } })
    assert.equal(decide({ config, egress: { ...goodEgress, asn: 'AS15169 Google LLC' } }).allow, true)
    const other = decide({ config, egress: { ...goodEgress, asn: 'AS9009 M247' } })
    assert.equal(other.allow, false)
    assert.ok(other.blockedBy.some((item) => item.id === 'egress-asn'))
  })

  it('blocks when a Claude domain resolves into a denied region', () => {
    const verdict = decide({
      config: baseConfig,
      egress: goodEgress,
      dns: {
        hosts: [{ host: 'claude.ai', addresses: ['1.2.3.4'] }],
        deniedHits: [{ host: 'claude.ai', ip: '1.2.3.4', country: 'CN', isp: 'China Telecom' }],
        resolved: true,
        hasResolutionError: false,
      },
    })
    assert.equal(verdict.allow, false)
    assert.ok(verdict.blockedBy.some((item) => item.id === 'claude-dns-denied'))
  })

  it('reports device traits as warnings by default', () => {
    const verdict = decide({
      config: baseConfig,
      egress: goodEgress,
      environment: {
        timezone: { intl: 'Asia/Shanghai', domestic: true, matched: 'Asia/Shanghai' },
        language: { uiLanguages: ['zh-CN', 'en-US'], chinese: true, matched: 'zh-CN' },
        fonts: { found: [{ file: 'Deng.ttf', label: '等线 DengXian', strong: true }], strong: true },
      },
    })
    assert.equal(verdict.allow, true, '时区/语言/字体是设备特征，默认只报告、不门控')
    assert.deepEqual(
      verdict.warnings.map((item) => item.id).sort(),
      ['fonts-domestic', 'language-chinese', 'timezone-domestic'],
    )
  })

  it('blocks DNS and system proxy leaks by default', () => {
    const verdict = decide({
      config: baseConfig,
      egress: goodEgress,
      environment: {
        dnsServers: { servers: ['114.114.114.114'], domestic: ['114.114.114.114'] },
        systemProxy: { hasAny: true, system: { enabled: true, server: '127.0.0.1:7890' }, envVars: {} },
      },
    })
    assert.equal(verdict.allow, false, 'DNS/代理属于出口路径本身，默认即门控')
    assert.ok(verdict.blockedBy.some((item) => item.id === 'dns-servers-domestic'))
    assert.ok(verdict.blockedBy.some((item) => item.id === 'proxy-leak'))
  })

  it('escalates an environment check to blocking when configured', () => {
    const config = normalizeConfig({
      whitelist: { countries: ['US'] },
      checks: { timezone: { enabled: true, severity: 'block' } },
    })
    const verdict = decide({
      config,
      egress: goodEgress,
      environment: { timezone: { intl: 'Asia/Shanghai', domestic: true, matched: 'Asia/Shanghai' } },
    })
    assert.equal(verdict.allow, false)
    assert.ok(verdict.blockedBy.some((item) => item.id === 'timezone-domestic'))
  })
})

describe('process classification', () => {
  it('recognizes the npm CLI binary', () => {
    assert.equal(
      classifyProcess({
        name: 'claude.exe',
        exePath: 'C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\@anthropic-ai\\claude-code\\bin\\claude.exe',
        commandLine: '"claude.exe"',
      }),
      'cli',
    )
  })

  it('recognizes Claude Desktop in Squirrel and MSIX layouts', () => {
    assert.equal(
      classifyProcess({
        name: 'claude.exe',
        exePath: 'C:\\Users\\me\\AppData\\Local\\AnthropicClaude\\app-2.31226.1\\claude.exe',
        commandLine: '',
      }),
      'desktop',
    )
    assert.equal(
      classifyProcess({
        name: 'claude.exe',
        exePath: 'C:\\Program Files\\WindowsApps\\Claude_2.31226.1.0_x64__pzs8sxrjxfjjc\\claude.exe',
        commandLine: '',
      }),
      'desktop',
    )
  })

  it('recognizes a node-hosted CLI by command line', () => {
    assert.equal(
      classifyProcess({
        name: 'node.exe',
        exePath: 'C:\\Program Files\\nodejs\\node.exe',
        commandLine: 'node C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\@anthropic-ai\\claude-code\\cli.js',
      }),
      'cli',
    )
  })

  it('never matches unrelated programs', () => {
    assert.equal(classifyProcess({ name: 'node.exe', exePath: 'C:\\node.exe', commandLine: 'node app.js' }), null)
    assert.equal(classifyProcess({ name: 'moa-studio.exe', exePath: 'D:\\MoAStudio\\moa-studio.exe', commandLine: '' }), null)
    assert.equal(classifyProcess({ name: 'cloudflared.exe', exePath: 'C:\\cloudflared.exe', commandLine: '' }), null)
  })

  it('never matches a shell or editor that merely mentions the claude-code path', () => {
    // 实测踩过：终端里 cd 进 claude-code 目录后，仅凭命令行就会被判成 CLI，
    // 拦截时会把用户自己的终端一起杀掉。
    const cliPath = 'C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\@anthropic-ai\\claude-code'
    assert.equal(
      classifyProcess({ name: 'bash.exe', exePath: 'C:\\Program Files\\Git\\bin\\bash.exe', commandLine: `bash -c cd ${cliPath}` }),
      null,
    )
    assert.equal(
      classifyProcess({ name: 'powershell.exe', exePath: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', commandLine: `Get-ChildItem ${cliPath}` }),
      null,
    )
    assert.equal(
      classifyProcess({ name: 'Code.exe', exePath: 'C:\\Program Files\\Microsoft VS Code\\Code.exe', commandLine: `code ${cliPath}\\cli.js` }),
      null,
    )
    assert.equal(
      classifyProcess({ name: 'cmd.exe', exePath: 'C:\\Windows\\System32\\cmd.exe', commandLine: `cmd /c start ${cliPath}` }),
      null,
    )
  })

  it('classifies a bare claude.exe by where it lives', () => {
    assert.equal(
      classifyProcess({ name: 'claude.exe', exePath: 'C:\\Users\\me\\AppData\\Roaming\\npm\\claude.exe', commandLine: '' }),
      'cli',
    )
    assert.equal(
      classifyProcess({ name: 'claude.exe', exePath: 'D:\\Tools\\claude\\claude.exe', commandLine: '' }),
      'desktop',
    )
  })
})

describe('firewall profile state', () => {
  it('treats PowerShell GpoBoolean serialization as enabled', () => {
    // 实测：Get-NetFirewallProfile 的 Enabled 是 GpoBoolean 枚举，
    // ConvertTo-Json 序列化成整数 1/0，不是 true/false。
    // 只认 === true 会导致"防火墙明明开着却报关闭"，且关着时看起来正常，很难发现。
    assert.equal(normalizeProfileEnabled(1), true)
    assert.equal(normalizeProfileEnabled(true), true)
    assert.equal(normalizeProfileEnabled('True'), true)
    assert.equal(normalizeProfileEnabled('1'), true)
    assert.equal(normalizeProfileEnabled('ON'), true)
    assert.equal(normalizeProfileEnabled(0), false)
    assert.equal(normalizeProfileEnabled(false), false)
    assert.equal(normalizeProfileEnabled('False'), false)
    assert.equal(normalizeProfileEnabled(undefined), false)
  })
})

describe('http helpers', () => {  it('parses Cloudflare trace text', () => {
    const parsed = parseKeyValueText('fl=1a2b\nip=203.0.113.7\nloc=US\nwarp=off\n')
    assert.deepEqual(parsed, { fl: '1a2b', ip: '203.0.113.7', loc: 'US', warp: 'off' })
  })
})

describe('endpoint classification used by the risk gate', () => {
  it('keeps a written config file loadable', () => {
    const dir = tempDir()
    const path = join(dir, 'config.json')
    writeFileSync(
      path,
      JSON.stringify({ whitelist: { countries: ['us'] }, checks: { fonts: false } }),
      'utf8',
    )
    const raw = JSON.parse(readFileSync(path, 'utf8'))
    const config = normalizeConfig(raw)
    assert.deepEqual(config.whitelist.countries, ['US'])
    assert.equal(config.checks.fonts.enabled, true, '非对象写法回落到默认')
  })
})

describe('claude access three-state verdict', () => {
  const denyCheck = { allow: false, blocked: [{ id: 'egress-country', title: '出口国家不在白名单：CN' }] }
  const allowCheck = { allow: true, blocked: [] }
  const config = { enforcement: { killProcesses: true } }

  it('denies launch only when enforcement is active and the verdict fails', () => {
    const result = buildClaudeAccess({
      check: denyCheck,
      ownGuard: true,
      externalGuards: [],
      networkBlocked: true,
      networkLayers: ['WFP 内核过滤器'],
      config,
    })
    assert.equal(result.launchState, 'deny')
    assert.equal(result.networkState, 'deny')
  })

  it('marks "unguarded" when the verdict fails but nothing is enforcing', () => {
    // 关键回归：判定不通过、但闸门没在跑时，不能显示绿色"可以"——
    // 那会掩盖"此刻其实没人拦"的事实（实测用户就是因此误以为一切正常）。
    const result = buildClaudeAccess({
      check: denyCheck,
      ownGuard: false,
      externalGuards: [],
      networkBlocked: false,
      networkLayers: [],
      config,
    })
    assert.equal(result.launchState, 'unguarded')
    assert.equal(result.networkState, 'unguarded')
    assert.match(result.networkReason, /确实能联网/)
  })

  it('allows when the verdict passes', () => {
    const result = buildClaudeAccess({
      check: allowCheck,
      ownGuard: true,
      externalGuards: [],
      networkBlocked: false,
      networkLayers: [],
      config,
    })
    assert.equal(result.launchState, 'allow')
    assert.equal(result.networkState, 'allow')
  })

  it('counts a guard in another process as enforcement', () => {
    const result = buildClaudeAccess({
      check: denyCheck,
      ownGuard: false,
      externalGuards: [1234],
      networkBlocked: true,
      networkLayers: ['防火墙规则 11 条'],
      config,
    })
    assert.equal(result.launchState, 'deny')
    assert.match(result.launchReason, /另一个 CCGait 进程/)
  })
})

describe('guard verdict read from another process', () => {
  // 别的进程里的闸门（另一个界面服务进程内闸门、或手工起的 cli.js guard）判定不通过、
  // 正在终止 Claude 时，刚打开的界面必须能读到这份判定，否则会显示"尚未检测"，
  // 而"能否打开"那一格还会是绿色的"可以"。
  it('maps the guard state file onto a check result', () => {
    const dir = tempDir()
    writeFileSync(
      join(dir, 'state.json'),
      JSON.stringify({
        guardPid: 4242,
        updatedAt: '2026-10-17T05:34:10.404Z',
        allow: false,
        blocked: [{ id: 'egress-country', title: '出口国家不在白名单：CN' }],
        warnings: [{ id: 'fonts-domestic', title: '系统装有国内专有字体' }],
        egress: { ip: '36.161.21.75', country: 'CN' },
        failedClosed: false,
        durationMs: 15662,
      }),
      'utf8',
    )

    const check = readGuardCheck(dir)
    assert.equal(check.allow, false)
    assert.equal(check.at, '2026-10-17T05:34:10.404Z', '时间取闸门的 updatedAt')
    assert.equal(check.blocked[0].id, 'egress-country')
    assert.equal(check.warnings.length, 1)
    assert.equal(check.egress.country, 'CN')
    assert.equal(check.from, 'guard')
  })

  it('returns null when there is no usable state file', () => {
    // 没有文件：按"没检测过"处理，不能凭空造一个判定出来。
    assert.equal(readGuardCheck(tempDir()), null)

    const dir = tempDir()
    writeFileSync(join(dir, 'state.json'), '{ 写到一半', 'utf8')
    assert.equal(readGuardCheck(dir), null, '内容读不懂时也不能当成判定')

    const wrongShape = tempDir()
    writeFileSync(join(wrongShape, 'state.json'), JSON.stringify({ updatedAt: '2026-10-17T00:00:00Z' }), 'utf8')
    assert.equal(readGuardCheck(wrongShape), null, '没有 allow 字段的不算判定')
  })
})

describe('guard start/stop request files', () => {
  // 启停都是"文件即请求"：执法跑在常驻界面服务进程里，托盘/CLI 只能靠写请求文件
  // 让它建起 / 停掉自己的闸门。这两个方向的语义必须对称，否则会出现
  // "点了启动没反应""点了停止停不掉"这类说不清的现象。
  it('writes and clears the start request', () => {
    const dir = tempDir()
    assert.equal(existsSync(guardStartRequestPath(dir)), false)
    requestGuardStart(dir)
    assert.equal(existsSync(guardStartRequestPath(dir)), true)
    clearGuardStartRequest(dir)
    assert.equal(existsSync(guardStartRequestPath(dir)), false)
  })

  it('writes and clears the stop request', () => {
    const dir = tempDir()
    assert.equal(existsSync(guardStopRequestPath(dir)), false)
    requestGuardStop(dir)
    assert.equal(existsSync(guardStopRequestPath(dir)), true)
    clearGuardStopRequest(dir)
    assert.equal(existsSync(guardStopRequestPath(dir)), false)
  })
})
