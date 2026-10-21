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
  describeBlockReason,
  describeEgress,
  isDefiniteViolation,
  KILL_CONFIRM_ROUNDS,
  nextKillStreak,
  UNVERIFIABLE_REASON_IDS,
  violationSignature,
  shouldKillProcesses,
  guardStartRequestPath,
  guardStopRequestPath,
  requestGuardStart,
  requestGuardStop,
} from '../src/guard.js'
import { buildClaudeAccess, readGuardCheck } from '../src/ui/session.js'
import { classifyProcess } from '../src/claude-targets.js'
import { normalizeProfileEnabled } from '../src/firewall.js'
import { isPublicDnsAddress } from '../src/environment.js'
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
    // 系统代理属于"出口路径本身"，默认即阻断。
    assert.equal(config.checks.proxyEnvLeak.severity, 'block')
    // 实测解析出口（谁在回答查询）是硬门槛；配置口径的本机 DNS 只提示。
    assert.equal(config.checks.resolverEgress.severity, 'block')
    assert.equal(config.checks.dnsServers.severity, 'warn')
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

  it('blocks a domestic resolver egress but only warns when it cannot be measured', () => {
    const denied = decide({
      config: baseConfig,
      egress: goodEgress,
      environment: {
        resolverEgress: {
          checked: true,
          resolvers: [{ ip: '119.29.29.29', country: 'CN', isp: 'Tencent' }],
          deniedHits: [{ ip: '119.29.29.29', country: 'CN', isp: 'Tencent' }],
        },
      },
    })
    assert.equal(denied.allow, false, '实测解析出口落在被禁地区 = 实际解析路径不对，必须拦')
    assert.ok(denied.blockedBy.some((item) => item.id === 'resolver-egress-denied'))

    // 拿不到应答（对方权威域名可能被墙）只提示：判不出来不等于环境不对。
    const unknown = decide({
      config: baseConfig,
      egress: goodEgress,
      environment: { resolverEgress: { checked: false, resolvers: [], deniedHits: [], error: '无应答' } },
    })
    assert.equal(unknown.allow, true)
    assert.ok(unknown.warnings.some((item) => item.id === 'resolver-egress-unknown'))
  })

  it('warns on configured domestic DNS but blocks system proxy leaks', () => {
    const verdict = decide({
      config: baseConfig,
      egress: goodEgress,
      environment: {
        dnsServers: { servers: ['114.114.114.114'], domestic: ['114.114.114.114'] },
        systemProxy: { hasAny: true, system: { enabled: true, server: '127.0.0.1:7890' }, envVars: {} },
      },
    })
    assert.equal(verdict.allow, false, '代理没覆盖到 CLI 属于出口路径本身，默认即门控')
    assert.ok(verdict.blockedBy.some((item) => item.id === 'proxy-leak'))
    // 本机 DNS 是"配置口径"、与实测口径的参考网站对不齐：只报告，不参与拦截。
    assert.ok(verdict.warnings.some((item) => item.id === 'dns-servers-domestic'))
    assert.equal(verdict.blockedBy.some((item) => item.id === 'dns-servers-domestic'), false)
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

describe('configured DNS server filter', () => {
  it('keeps public resolvers and drops router/local placeholders', () => {
    // 本机实测：WLAN 的 IPv6 解析器是路由器（fe80::…），断开的蓝牙网卡上是
    // Windows 填的 fec0:0:0:ffff::1~3 占位。它们都判不了归属，留着只会让报告变噪音。
    assert.equal(isPublicDnsAddress('119.29.29.29'), true)
    assert.equal(isPublicDnsAddress('182.254.116.116'), true)
    assert.equal(isPublicDnsAddress('2400:3200::1'), true)
    assert.equal(isPublicDnsAddress('2a00:23ee::10'), true)
    assert.equal(isPublicDnsAddress('fe80::5c87:30ff:fe02:d964'), false)
    assert.equal(isPublicDnsAddress('FE80::1'), false)
    assert.equal(isPublicDnsAddress('fec0:0:0:ffff::1'), false)
    assert.equal(isPublicDnsAddress('::1'), false)
    assert.equal(isPublicDnsAddress(''), false)
    assert.equal(isPublicDnsAddress('not-an-address'), false)
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

describe('guard block reasons are recorded', () => {
  // 用户反馈过"Claude Code 被终止很多次，但查不出原因"：当时日志里只有
  // "已处理 N 个进程""已断网"这类执行动作，没有判定原因。这三条测试把
  // "原因必须可读且带上出口"钉死。
  it('states every failed dimension, not just the first', () => {
    const text = describeBlockReason({
      allow: false,
      failedClosed: false,
      blockedBy: [
        { id: 'egress-country', title: '出口国家不在白名单：CN' },
        { id: 'claude-dns-denied', title: '解析出口落在被禁地区' },
      ],
    })
    assert.match(text, /出口国家不在白名单：CN/)
    assert.match(text, /解析出口落在被禁地区/)
  })

  it('marks failClosed when the egress identity could not be verified', () => {
    const onlyFailedClosed = describeBlockReason({ allow: false, failedClosed: true, blockedBy: [] })
    assert.match(onlyFailedClosed, /failClosed/)

    const withCause = describeBlockReason({
      allow: false,
      failedClosed: true,
      blockedBy: [{ id: 'egress-country', title: '出口国家不在白名单：CN' }],
    })
    assert.match(withCause, /出口国家不在白名单：CN/, '有具体原因时不能只写 failClosed')
    assert.match(withCause, /failClosed/)
  })

  it('records the egress actually observed at block time', () => {
    assert.equal(describeEgress({ ip: '36.161.21.75', country: 'CN' }), '出口 36.161.21.75 · CN')
    assert.match(describeEgress({ ip: '1.2.3.4', country: 'HK', hosting: true }), /机房\/代理/)
    assert.match(describeEgress(undefined), /查询失败/)
  })

  it('never kills processes when the check merely failed to complete', () => {
    // 网络抖动导致的一轮"没测出来"不能杀进程：实测曾因此误杀 18 个正在干活的实例。
    const config = { enforcement: { killProcesses: true } }
    assert.equal(
      shouldKillProcesses(config, { allow: false, failedClosed: true, blockedBy: [] }, { confirmed: true }),
      false,
      'failClosed 只表示证据不足，不等于确认违规',
    )
    assert.equal(
      shouldKillProcesses(
        config,
        {
          allow: false,
          failedClosed: false,
          blockedBy: [{ id: 'egress-country', title: '出口国家不在白名单：CN' }],
        },
        { confirmed: true },
      ),
      true,
      '确认违规且连续确认后才终止进程',
    )
    assert.equal(shouldKillProcesses({ enforcement: { killProcesses: false } }, {
      allow: false,
      blockedBy: [{ id: 'egress-country', title: 'x' }],
    }, { confirmed: true }), false, '关掉 killProcesses 时一律不杀')
    assert.equal(shouldKillProcesses(config, { allow: true, blockedBy: [] }, { confirmed: true }), false)
  })

  it('网络抖动只断网、绝不杀进程', () => {
    const config = { enforcement: { killProcesses: true } }
    // 这几条都是"没测出来"：出口查不到、多源对不上、DNS 偶发失败。
    // 用户明确要求：抖动最多阻断网络，不要动进程，宁可漏杀也不能误杀。
    for (const id of UNVERIFIABLE_REASON_IDS) {
      const verdict = { allow: false, failedClosed: true, blockedBy: [{ id, title: id }] }
      assert.equal(isDefiniteViolation(verdict), false, `${id} 不该算确认违规`)
      assert.equal(shouldKillProcesses(config, verdict, { confirmed: true }), false, `${id} 不该杀进程`)
      assert.equal(violationSignature(verdict), '', `${id} 不该产生违规签名`)
    }
  })

  it('只有确认违规才有签名，且同一原因才累计', () => {
    const definite = (id) => ({ allow: false, failedClosed: false, blockedBy: [{ id, title: id }] })
    assert.equal(violationSignature(definite('egress-country')), 'egress-country')
    // 原因换了就是另一个问题，不能接着上一轮的数继续算"连续确认"。
    assert.notEqual(
      violationSignature(definite('egress-country')),
      violationSignature(definite('claude-dns-denied')),
    )
    // 多原因时与顺序无关：否则同一状态会算出两个签名，连续确认永远凑不齐。
    const a = {
      allow: false,
      failedClosed: false,
      blockedBy: [{ id: 'claude-dns-denied', title: 'x' }, { id: 'egress-country', title: 'y' }],
    }
    const b = {
      allow: false,
      failedClosed: false,
      blockedBy: [{ id: 'egress-country', title: 'y' }, { id: 'claude-dns-denied', title: 'x' }],
    }
    assert.equal(violationSignature(a), violationSignature(b))
    assert.equal(violationSignature({ allow: true, blockedBy: [] }), '')
    assert.equal(KILL_CONFIRM_ROUNDS >= 2, true, '至少要求两轮确认')
  })

  it('抖动插在中间会把连续确认清零', () => {
    const config = { enforcement: { killProcesses: true } }
    const violation = {
      allow: false,
      failedClosed: false,
      blockedBy: [{ id: 'egress-country', title: '出口国家不在白名单：CN' }],
    }
    const jitter = {
      allow: false,
      failedClosed: true,
      blockedBy: [{ id: 'egress-inconsistent', title: '多源不一致' }],
    }

    // 连续三轮同一原因 → 到第 3 轮才够格杀。
    let state = { signature: '', streak: 0 }
    const rounds = []
    for (let i = 0; i < KILL_CONFIRM_ROUNDS; i += 1) {
      state = nextKillStreak(state, violation)
      rounds.push(shouldKillProcesses(config, violation, { confirmed: state.streak >= KILL_CONFIRM_ROUNDS }))
    }
    assert.deepEqual(rounds, [...Array(KILL_CONFIRM_ROUNDS - 1).fill(false), true])

    // 违规 → 抖动 → 违规：计数必须回到 1，不能接着算。
    state = nextKillStreak({ signature: '', streak: 0 }, violation)
    assert.equal(state.streak, 1)
    state = nextKillStreak(state, jitter)
    assert.equal(state.streak, 0, '抖动轮必须清零')
    state = nextKillStreak(state, violation)
    assert.equal(state.streak, 1, '抖动之后重新数，不能继承')
    assert.equal(
      shouldKillProcesses(config, violation, { confirmed: state.streak >= KILL_CONFIRM_ROUNDS }),
      false,
    )
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
