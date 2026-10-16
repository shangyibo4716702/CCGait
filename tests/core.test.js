import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
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
import { classifyProcess } from '../src/claude-targets.js'
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
    assert.equal(config.checks.egressIp.severity, 'block')
    assert.equal(config.checks.timezone.severity, 'warn')
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

  it('reports environment traits as warnings by default', () => {
    const verdict = decide({
      config: baseConfig,
      egress: goodEgress,
      environment: {
        timezone: { intl: 'Asia/Shanghai', domestic: true, matched: 'Asia/Shanghai' },
        language: { uiLanguages: ['zh-CN', 'en-US'], chinese: true, matched: 'zh-CN' },
        fonts: { found: [{ file: 'Deng.ttf', label: '等线 DengXian', strong: true }], strong: true },
        dnsServers: { servers: ['114.114.114.114'], domestic: ['114.114.114.114'] },
        systemProxy: { hasAny: false, system: { enabled: false }, envVars: {} },
      },
    })
    assert.equal(verdict.allow, true, '默认只报告，不因环境特征拦截')
    assert.deepEqual(
      verdict.warnings.map((item) => item.id).sort(),
      ['dns-servers-domestic', 'fonts-domestic', 'language-chinese', 'timezone-domestic'],
    )
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
})

describe('http helpers', () => {
  it('parses Cloudflare trace text', () => {
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
