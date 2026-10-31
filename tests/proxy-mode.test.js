import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  judgeProxyMode,
  normalizeController,
  probeProxyMode,
  applyClashFix,
  needsClashFix,
  proxyConfigDirs,
  rewriteNameserver,
  judgeProxySettings,
  readProxySettings,
  classifyDnsUpstream,
  judgeDnsUpstreams,
  readYamlBlock,
  readYamlList,
  readYamlBool,
  readYamlScalar,
  parseRules,
  ruleTarget,
  claudeRuleCoverage,
  claudeRuleBlock,
  claudeRuleGroup,
  insertPrependRules,
  applyClaudeRules,
  parseProfilesIndex,
  ruleEnhancementPath,
  readClashRules,
  writeProxyMode,
  prependRulesToConfig,
  UU_DIRECT_RULES,
  hasUuDirectRules,
  removeRulesFromConfig,
  setUuDirectRules,
} from '../src/proxy-mode.js'

const tempDirs = []
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'ccgait-proxymode-'))
  tempDirs.push(dir)
  return dir
}
after(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

/** 造一个假的 %APPDATA%，里面放指定客户端的配置文件。 */
function makeEnv(yamlText, { clientDir = 'io.github.clash-verge-rev.clash-verge-rev', fileName = 'clash-verge.yaml' } = {}) {
  const appData = tempDir()
  const dir = join(appData, clientDir)
  mkdirSync(dir, { recursive: true })
  if (yamlText !== undefined) writeFileSync(join(dir, fileName), yamlText)
  return { APPDATA: appData, LOCALAPPDATA: join(appData, 'Local'), USERPROFILE: appData }
}

describe('YAML 标量读取', () => {
  it('读普通值、带引号值、去掉行尾注释', () => {
    const text = ['mode: rule', "secret: 'my-secret'", 'external-controller: 127.0.0.1:9097 # 注释'].join('\n')
    assert.equal(readYamlScalar(text, 'mode'), 'rule')
    assert.equal(readYamlScalar(text, 'secret'), 'my-secret')
    assert.equal(readYamlScalar(text, 'external-controller'), '127.0.0.1:9097')
  })

  it('空值返回 undefined（Clash Verge 默认把 external-controller 写成空串）', () => {
    assert.equal(readYamlScalar("external-controller: ''", 'external-controller'), undefined)
    assert.equal(readYamlScalar('mode:', 'mode'), undefined)
  })

  it('键不存在时返回 undefined', () => {
    assert.equal(readYamlScalar('mode: rule', 'secret'), undefined)
  })
})

describe('external-controller 归一', () => {
  it('补齐协议、把 0.0.0.0 与裸冒号换成回环', () => {
    assert.equal(normalizeController('127.0.0.1:9097'), 'http://127.0.0.1:9097')
    assert.equal(normalizeController('0.0.0.0:9090'), 'http://127.0.0.1:9090')
    assert.equal(normalizeController(':9090'), 'http://127.0.0.1:9090')
    assert.equal(normalizeController('http://127.0.0.1:9097/'), 'http://127.0.0.1:9097')
  })

  it('unix socket 这种查不了的地址返回 undefined', () => {
    assert.equal(normalizeController('unix:///tmp/clash.sock'), undefined)
    assert.equal(normalizeController('/tmp/clash.sock'), undefined)
    assert.equal(normalizeController(''), undefined)
  })
})

describe('代理模式探测', () => {
  it('从运行时 YAML 读到 rule（实测本机就是这种）', async () => {
    const env = makeEnv('mode: rule\nmixed-port: 7897\nexternal-controller: ""\n')
    const result = await probeProxyMode({ env })
    assert.equal(result.mode, 'rule')
    assert.equal(result.source, 'config')
  })

  it('读到 global 时判为通过', async () => {
    const env = makeEnv('mode: global\n')
    const result = await probeProxyMode({ env })
    assert.equal(result.mode, 'global')
    assert.deepEqual(judgeProxyMode({ checked: true, mode: result.mode }), { block: false, warn: false })
  })

  it('API 可用时优先信 API 而不是 YAML', async () => {
    const env = makeEnv('mode: rule\nexternal-controller: 127.0.0.1:9097\nsecret: s3cret\n')
    const calls = []
    const result = await probeProxyMode({
      env,
      fetchText: async (url, options) => {
        calls.push({ url, headers: options?.headers })
        return { status: 200, text: JSON.stringify({ mode: 'global' }) }
      },
    })
    assert.equal(result.mode, 'global', 'API 说 global 就信 global')
    assert.equal(result.source, 'api')
    assert.match(calls[0].url, /127\.0\.0\.1:9097\/configs$/)
    assert.equal(calls[0].headers.authorization, 'Bearer s3cret', '有 secret 就要带 Authorization')
  })

  it('API 不通时退回 YAML', async () => {
    const env = makeEnv('mode: rule\nexternal-controller: 127.0.0.1:9097\n')
    const result = await probeProxyMode({
      env,
      fetchText: async () => {
        throw new Error('ECONNREFUSED')
      },
    })
    assert.equal(result.mode, 'rule')
    assert.equal(result.source, 'config')
  })

  it('API 返回异常内容时也退回 YAML', async () => {
    const env = makeEnv('mode: direct\nexternal-controller: 127.0.0.1:9097\n')
    const result = await probeProxyMode({
      env,
      fetchText: async () => ({ status: 200, text: '<html>not json</html>' }),
    })
    assert.equal(result.mode, 'direct')
  })

  it('没有受支持的客户端时返回 unknown，不误判为违规', async () => {
    const env = makeEnv(undefined)
    const result = await probeProxyMode({ env })
    assert.equal(result.mode, 'unknown')
    assert.deepEqual(judgeProxyMode({ checked: true, mode: 'unknown' }), { block: false, warn: false })
  })

  it('yaml 里没有 mode 字段时返回 unknown', async () => {
    const env = makeEnv('mixed-port: 7897\n')
    assert.equal((await probeProxyMode({ env })).mode, 'unknown')
  })

  it('FlClash 的配置目录也能识别', async () => {
    const env = makeEnv('mode: global\n', { clientDir: 'com.follow.clash', fileName: 'config.yaml' })
    const result = await probeProxyMode({ env })
    assert.equal(result.mode, 'global')
  })
})

describe('代理模式判定', () => {
  it('非全局模式一律阻断，并回报当前模式', () => {
    assert.deepEqual(judgeProxyMode({ checked: true, mode: 'rule' }), {
      block: true,
      warn: false,
      mode: 'rule',
      coverage: null,
      reason: 'claude-rules-missing',
    })
    assert.deepEqual(judgeProxyMode({ checked: true, mode: 'direct' }), {
      block: true,
      warn: false,
      mode: 'direct',
    })
  })

  it('关掉 requireGlobal 就一律放行', () => {
    assert.deepEqual(judgeProxyMode({ checked: true, mode: 'rule', requireGlobal: false }), {
      block: false,
      warn: false,
    })
  })

  it('没探测（checked=false）时什么都不做', () => {
    assert.deepEqual(judgeProxyMode({ checked: false, mode: 'rule' }), { block: false, warn: false })
  })
})

describe('客户端配置目录候选', () => {
  it('覆盖 Clash Verge、FlClash 等常见位置', () => {
    const dirs = proxyConfigDirs({ APPDATA: 'C:/R', LOCALAPPDATA: 'C:/L' }, 'C:/U')
    const joined = dirs.join('|').replace(/\\/g, '/')
    assert.match(joined, /io\.github\.clash-verge-rev/)
    assert.match(joined, /com\.follow/)
  })
})

describe('嵌套块读取', () => {
  it('取出 dns 段并读其中的 ipv6', () => {
    const text = [
      'mixed-port: 7897',
      'ipv6: false',
      'dns:',
      '  enable: true',
      '  enhanced-mode: fake-ip',
      '  ipv6: false',
      'tun:',
      '  enable: true',
    ].join('\n')
    const block = readYamlBlock(text, 'dns')
    assert.ok(block, '要能拿到 dns 段')
    assert.equal(readYamlScalar(block, 'enhanced-mode'), 'fake-ip')
    assert.equal(readYamlBool(block, 'ipv6'), false)
    // 不能把后面 tun 段的内容吃进来
    assert.equal(readYamlScalar(block, 'enable'), 'true')
    assert.equal(block.includes('tun:'), false)
  })

  it('段不存在时返回 undefined', () => {
    assert.equal(readYamlBlock('ipv6: false\n', 'dns'), undefined)
  })

  it('布尔解析只在 true/false 上成立', () => {
    assert.equal(readYamlBool('ipv6: true', 'ipv6'), true)
    assert.equal(readYamlBool('ipv6: false', 'ipv6'), false)
    assert.equal(readYamlBool('ipv6: maybe', 'ipv6'), undefined)
    assert.equal(readYamlBool('other: 1', 'ipv6'), undefined)
  })
})

describe('代理开关读取', () => {
  function makeClient({ verge, clash }) {
    const appData = tempDir()
    const dir = join(appData, 'io.github.clash-verge-rev.clash-verge-rev')
    mkdirSync(dir, { recursive: true })
    if (verge) writeFileSync(join(dir, 'verge.yaml'), verge)
    if (clash) writeFileSync(join(dir, 'clash-verge.yaml'), clash)
    return dir
  }

  it('三项都合规时读出全 false/true 组合', () => {
    const dir = makeClient({
      verge: 'enable_tun_mode: true\nenable_system_proxy: true\nenable_dns_settings: true\n',
      clash: 'mode: global\nipv6: false\ndns:\n  enable: true\n  ipv6: false\n',
    })
    const settings = readProxySettings(dir)
    assert.deepEqual(settings, {
      tunMode: true,
      systemProxy: true,
      dnsOverride: true,
      ipv6: false,
      dnsEnabled: true,
      dnsIpv6: false,
    })
    assert.deepEqual(judgeProxySettings(settings), [], '全合规时没有问题项')
  })

  it('IPv6 开着要报一条', () => {
    const dir = makeClient({ clash: 'ipv6: true\ndns:\n  ipv6: false\n' })
    const issues = judgeProxySettings(readProxySettings(dir))
    assert.equal(issues.length, 1)
    assert.equal(issues[0].id, 'proxy-ipv6-enabled')
  })

  it('DNS 覆写关着要报一条', () => {
    const dir = makeClient({ verge: 'enable_dns_settings: false\n' })
    const issues = judgeProxySettings(readProxySettings(dir))
    assert.ok(issues.some((item) => item.id === 'proxy-dns-override-off'))
  })

  it('DNS 覆写里的 IPv6 开着要单独报一条（实测踩过的组合）', () => {
    const dir = makeClient({
      verge: 'enable_dns_settings: true\n',
      clash: 'ipv6: false\ndns:\n  enable: true\n  ipv6: true\n',
    })
    const issues = judgeProxySettings(readProxySettings(dir))
    assert.equal(issues.length, 1)
    assert.equal(issues[0].id, 'proxy-dns-ipv6-enabled')
    assert.match(issues[0].detail, /来回摆|时拦时放/)
  })

  it('三项都错时三条一起报', () => {
    const dir = makeClient({
      verge: 'enable_dns_settings: false\n',
      clash: 'ipv6: true\ndns:\n  ipv6: true\n',
    })
    const ids = judgeProxySettings(readProxySettings(dir)).map((item) => item.id).sort()
    assert.deepEqual(ids, ['proxy-dns-ipv6-enabled', 'proxy-dns-override-off', 'proxy-ipv6-enabled'])
  })

  it('关掉这个检查项就一条都不报', () => {
    const dir = makeClient({ verge: 'enable_dns_settings: false\n', clash: 'ipv6: true\ndns:\n  ipv6: true\n' })
    assert.deepEqual(judgeProxySettings(readProxySettings(dir), { enabled: false }), [])
  })

  it('读不到的字段不瞎猜（不把 undefined 当成 false）', () => {
    const dir = makeClient({ clash: 'mode: global\n' })
    const settings = readProxySettings(dir)
    assert.equal(settings.ipv6, undefined)
    assert.equal(settings.dnsIpv6, undefined)
    assert.deepEqual(judgeProxySettings(settings), [], '没读到就不能报问题')
  })

  it('dns_config.yaml 里的 IPv6 也能兜底读到', () => {
    const appData = tempDir()
    const dir = join(appData, 'io.github.clash-verge-rev.clash-verge-rev')
    mkdirSync(dir, { recursive: true })
    writeFileSync(join(dir, 'clash-verge.yaml'), 'mode: global\n')
    writeFileSync(join(dir, 'dns_config.yaml'), 'dns:\n  enable: true\n  ipv6: true\n')
    assert.equal(readProxySettings(dir).dnsIpv6, true)
  })
})

describe('YAML 列表解析', () => {
  it('只读同一缩进的列表项，不吃进后面的子结构', () => {
    const text = [
      'dns:',
      '  nameserver:',
      '  - 8.8.8.8',
      '  - https://doh.pub/dns-query',
      '  fallback-filter:',
      '    domain:',
      '    - +.google.com',
      '    - +.facebook.com',
    ].join('\n')
    const dns = readYamlBlock(text, 'dns')
    assert.deepEqual(readYamlList(dns, 'nameserver'), ['8.8.8.8', 'https://doh.pub/dns-query'])
  })

  it('空列表返回空数组', () => {
    assert.deepEqual(readYamlList('  nameserver:\n  fallback: []', 'nameserver'), [])
  })

  it('键不存在返回空数组', () => {
    assert.deepEqual(readYamlList('  fallback: []', 'nameserver'), [])
  })

  it('去掉引号与行尾注释', () => {
    const text = ['nameserver:', "  - '1.1.1.1'", '  - 8.8.8.8 # 谷歌'].join('\n')
    assert.deepEqual(readYamlList(text, 'nameserver'), ['1.1.1.1', '8.8.8.8'])
  })
})

describe('DNS 上游分类', () => {
  it('识别国内与境外解析器', () => {
    assert.equal(classifyDnsUpstream('https://doh.pub/dns-query'), 'domestic')
    assert.equal(classifyDnsUpstream('https://dns.alidns.com/dns-query'), 'domestic')
    assert.equal(classifyDnsUpstream('119.29.29.29'), 'domestic')
    assert.equal(classifyDnsUpstream('223.5.5.5'), 'domestic')
    assert.equal(classifyDnsUpstream('8.8.8.8'), 'overseas')
    assert.equal(classifyDnsUpstream('https://dns.google/dns-query'), 'overseas')
    assert.equal(classifyDnsUpstream('1.1.1.1'), 'overseas')
    assert.equal(classifyDnsUpstream('https://custom.example/dns'), 'unknown')
  })

  it('以 .cn 结尾的按国内算', () => {
    assert.equal(classifyDnsUpstream('https://dns.example.cn/dns-query'), 'domestic')
  })
})

describe('DNS 上游判定', () => {
  it('国内+国外混着 → 报"混入国内"（实测就是这种会飘）', () => {
    const issues = judgeDnsUpstreams({ nameserver: ['8.8.8.8', 'https://doh.pub/dns-query'] })
    assert.equal(issues.length, 1)
    assert.equal(issues[0].id, 'proxy-dns-upstream-domestic')
    assert.match(issues[0].title, /混入/)
    assert.match(issues[0].detail, /谁先答用谁|并发/)
  })

  it('全是国内 → 报"全是国内"', () => {
    const issues = judgeDnsUpstreams({ nameserver: ['119.29.29.29', '223.5.5.5'] })
    assert.equal(issues.length, 1)
    assert.match(issues[0].title, /全是国内/)
  })

  it('只有境外 → 不报', () => {
    assert.deepEqual(judgeDnsUpstreams({ nameserver: ['8.8.8.8', 'https://dns.google/dns-query'] }), [])
  })

  it('空列表或没读到 → 不报（不瞎猜）', () => {
    assert.deepEqual(judgeDnsUpstreams({ nameserver: [] }), [])
    assert.deepEqual(judgeDnsUpstreams({}), [])
    assert.deepEqual(judgeDnsUpstreams(undefined), [])
  })

  it('关掉检查项就不报', () => {
    assert.deepEqual(
      judgeDnsUpstreams({ nameserver: ['8.8.8.8', 'doh.pub'] }, { enabled: false }),
      [],
    )
  })
})

describe('readProxySettings 带上 nameserver', () => {
  it('读出 dns 段里的 nameserver，同时不影响 proxy-server-nameserver', () => {
    const appData = tempDir()
    const dir = join(appData, 'io.github.clash-verge-rev.clash-verge-rev')
    mkdirSync(dir, { recursive: true })
    writeFileSync(
      join(dir, 'clash-verge.yaml'),
      [
        'mode: global',
        'ipv6: false',
        'dns:',
        '  enable: true',
        '  ipv6: false',
        '  nameserver:',
        '  - 8.8.8.8',
        '  - https://dns.google/dns-query',
        '  proxy-server-nameserver:',
        '  - https://doh.pub/dns-query',
      ].join('\n'),
    )
    const settings = readProxySettings(dir)
    assert.deepEqual(settings.nameserver, ['8.8.8.8', 'https://dns.google/dns-query'])
    // 机场节点用的国内解析器不算问题
    assert.deepEqual(judgeDnsUpstreams({ nameserver: settings.nameserver }), [])
  })
})

describe('一键修正：改写 nameserver', () => {
  const build = (list) =>
    ['dns:', '  enable: true', '  nameserver:'].concat(list.map((x) => `  - ${x}`)).concat(['  fallback: []']).join('\n')

  it('删掉国内上游，保留境外', () => {
    const outcome = rewriteNameserver(build(['8.8.8.8', 'https://doh.pub/dns-query', '223.5.5.5']))
    assert.equal(outcome.changed, true)
    assert.deepEqual(outcome.before, ['8.8.8.8', 'https://doh.pub/dns-query', '223.5.5.5'])
    assert.deepEqual(outcome.after, ['8.8.8.8'])
    assert.ok(!outcome.text.includes('doh.pub'))
    assert.ok(outcome.text.includes('fallback: []'), '不能破坏后面的段')
  })

  it('全是国内时替换成安全默认值', () => {
    const outcome = rewriteNameserver(build(['119.29.29.29', '223.5.5.5']))
    assert.equal(outcome.changed, true)
    assert.deepEqual(outcome.after, ['8.8.8.8', 'https://dns.google/dns-query'])
  })

  it('已经只有境外时不改动', () => {
    const text = build(['8.8.8.8', 'https://dns.google/dns-query'])
    const outcome = rewriteNameserver(text)
    assert.equal(outcome.changed, false)
    assert.equal(outcome.reason, '已经只有境外上游')
    assert.equal(outcome.text, undefined, '不该产生新内容')
  })

  it('不碰 proxy-server-nameserver（机场节点解析用）', () => {
    const text = [
      'dns:',
      '  nameserver:',
      '  - 8.8.8.8',
      '  - https://doh.pub/dns-query',
      '  proxy-server-nameserver:',
      '  - https://doh.pub/dns-query',
    ].join('\n')
    const outcome = rewriteNameserver(text)
    assert.equal(outcome.changed, true)
    // 第二处 doh.pub（proxy-server-nameserver 下）必须还在
    assert.ok(outcome.text.includes('proxy-server-nameserver:\n  - https://doh.pub/dns-query'))
  })

  it('没有 dns 段或没有 nameserver 时明确说明原因', () => {
    assert.equal(rewriteNameserver('mode: global').reason, '没有 dns 段')
    assert.equal(rewriteNameserver('dns:\n  enable: true').reason, 'dns 段里没有 nameserver')
  })
})

describe('修正计划与按钮状态', () => {
  it('needsClashFix 覆盖四类问题', () => {
    assert.equal(needsClashFix({ nameserver: ['8.8.8.8', 'doh.pub'] }), true)
    assert.equal(needsClashFix({ nameserver: ['8.8.8.8'], ipv6: true }), true)
    assert.equal(needsClashFix({ nameserver: ['8.8.8.8'], dnsOverride: false }), true)
    assert.equal(needsClashFix({ nameserver: ['8.8.8.8'], dnsIpv6: true }), true)
    assert.equal(needsClashFix({ nameserver: ['8.8.8.8'], ipv6: false, dnsOverride: true, dnsIpv6: false }), false)
    assert.equal(needsClashFix(undefined), false)
  })

  it('applyClashFix 改多个文件并汇总结果', () => {
    const root = tempDir()
    const clientDir = join(root, 'client')
    mkdirSync(clientDir, { recursive: true })
    const bad = ['dns:', '  nameserver:', '  - 8.8.8.8', '  - https://doh.pub/dns-query'].join('\n')
    writeFileSync(join(clientDir, 'dns_config.yaml'), bad)
    writeFileSync(join(clientDir, 'clash-verge.yaml'), bad)

    // findRuntimeConfigs 找 ProgramData，用不存在的 programData 让它返回空
    const outcome = applyClashFix(clientDir, { programData: join(root, 'nope') })
    assert.equal(outcome.changed, 2)
    assert.equal(outcome.needsRestart, true)
    for (const name of ['dns_config.yaml', 'clash-verge.yaml']) {
      const text = readFileSync(join(clientDir, name), 'utf8')
      assert.ok(!text.includes('doh.pub'), `${name} 里不该再有国内上游`)
      assert.ok(text.includes('8.8.8.8'))
    }
  })

  it('已经正确时不写文件、不要求重启', () => {
    const root = tempDir()
    const clientDir = join(root, 'client')
    mkdirSync(clientDir, { recursive: true })
    writeFileSync(
      join(clientDir, 'dns_config.yaml'),
      ['dns:', '  nameserver:', '  - 8.8.8.8'].join('\n'),
    )
    const outcome = applyClashFix(clientDir, { programData: join(root, 'nope') })
    assert.equal(outcome.changed, 0)
    assert.equal(outcome.needsRestart, false)
  })
})

describe('规则模式：Claude 规则覆盖', () => {
  const baseRules = [
    'GEOSITE,category-ads-all,REJECT',
    'GEOSITE,CN,DIRECT',
    'GEOIP,CN,DIRECT',
    'MATCH,IPEqual',
  ]

  it('解析 rules 段：按第一条的缩进走，遇到下一个顶层键就停', () => {
    const text = [
      'mode: rule',
      'rules:',
      '- DOMAIN-SUFFIX,a.com,PROXY',
      '- MATCH,DIRECT',
      'proxy-groups:',
      '  - name: PROXY',
    ].join('\n')
    assert.deepEqual(parseRules(text), ['DOMAIN-SUFFIX,a.com,PROXY', 'MATCH,DIRECT'])
  })

  it('订阅里缩进两格的 rules 也能读', () => {
    const text = ['rules:', '  - DOMAIN-SUFFIX,a.com,PROXY', '  - MATCH,PROXY'].join('\n')
    assert.deepEqual(parseRules(text), ['DOMAIN-SUFFIX,a.com,PROXY', 'MATCH,PROXY'])
  })

  it('规则目标跳过 no-resolve', () => {
    assert.equal(ruleTarget('GEOIP,PRIVATE,DIRECT,no-resolve'), 'DIRECT')
  })

  it('没有 Claude 规则 → 不覆盖', () => {
    const coverage = claudeRuleCoverage(baseRules)
    assert.equal(coverage.ok, false)
    assert.equal(coverage.issues[0].id, 'claude-rules-missing')
  })

  it('Claude 规则排在 CN 分流之后 → 不覆盖', () => {
    const coverage = claudeRuleCoverage([
      'GEOSITE,CN,DIRECT',
      'DOMAIN-SUFFIX,anthropic.com,IPEqual',
      'MATCH,IPEqual',
    ])
    assert.equal(coverage.ok, false)
    assert.equal(coverage.issues[0].id, 'claude-rules-after-cn')
  })

  it('Claude 规则指向 DIRECT → 不覆盖', () => {
    const coverage = claudeRuleCoverage([
      'DOMAIN-SUFFIX,anthropic.com,DIRECT',
      'GEOSITE,CN,DIRECT',
      'MATCH,PROXY',
    ])
    assert.equal(coverage.ok, false)
    assert.equal(coverage.issues[0].id, 'claude-rules-direct')
  })

  it('Claude 规则在前面且指向代理组 → 覆盖', () => {
    const coverage = claudeRuleCoverage([
      'DOMAIN-SUFFIX,anthropic.com,IPEqual',
      'GEOSITE,CN,DIRECT',
      'MATCH,IPEqual',
    ])
    assert.equal(coverage.ok, true)
    assert.equal(coverage.group, 'IPEqual')
  })

  it('生成的规则覆盖所有 Anthropic 域名，并带一条进程规则', () => {
    const block = claudeRuleBlock('IPEqual')
    for (const domain of ['anthropic.com', 'claude.ai', 'claudeusercontent.com']) {
      assert.ok(block.some((rule) => rule === `DOMAIN-SUFFIX,${domain},IPEqual`), domain)
    }
    assert.ok(block.some((rule) => rule.startsWith('PROCESS-PATH-REGEX,')))
    // 生成的这组规则本身必须被判定为"已覆盖"
    assert.equal(claudeRuleCoverage([...block, 'GEOSITE,CN,DIRECT', 'MATCH,IPEqual']).ok, true)
  })

  it('目标组取 MATCH 的去处', () => {
    assert.equal(claudeRuleGroup(['GEOSITE,CN,DIRECT', 'MATCH,IPEqual']), 'IPEqual')
    assert.equal(claudeRuleGroup(['GEOSITE,CN,DIRECT', 'MATCH,DIRECT']), 'PROXY')
  })

  it('judgeProxyMode：规则模式已覆盖就放过，没覆盖照旧拦', () => {
    assert.equal(judgeProxyMode({ checked: true, mode: 'rule' }).block, true)
    assert.equal(
      judgeProxyMode({
        checked: true,
        mode: 'rule',
        coverage: claudeRuleCoverage(['DOMAIN-SUFFIX,anthropic.com,IPEqual', 'MATCH,IPEqual']),
      }).block,
      false,
    )
    assert.equal(judgeProxyMode({ checked: true, mode: 'global' }).block, false)
    assert.equal(judgeProxyMode({ checked: true, mode: 'direct' }).block, true)
  })
})

describe('规则增强文件写入', () => {
  it('prepend: [] 换成带条目的列表', () => {
    const text = ['# 模板', '', 'prepend: []', '', 'append: []'].join('\n')
    const next = insertPrependRules(text, ['DOMAIN-SUFFIX,a.com,PROXY'])
    assert.ok(next.includes('prepend:\n  - DOMAIN-SUFFIX,a.com,PROXY'))
    assert.ok(next.includes('append: []'))
  })

  it('已有 prepend 条目时追加在后面', () => {
    const text = ['prepend:', '  - OLD,1', 'append: []'].join('\n')
    const next = insertPrependRules(text, ['NEW,2'])
    assert.ok(next.indexOf('OLD,1') < next.indexOf('NEW,2'))
  })

  it('没有 prepend 段就补一个', () => {
    const next = insertPrependRules('# 空文件', ['NEW,1'])
    assert.ok(next.trim().endsWith('prepend:\n  - NEW,1'))
  })

  it('从 profiles.yaml 找到当前订阅挂的规则增强文件', () => {
    const root = tempDir()
    const profilesDir = join(root, 'profiles')
    mkdirSync(profilesDir, { recursive: true })
    writeFileSync(
      join(root, 'profiles.yaml'),
      [
        'current: SUB',
        'items:',
        '- uid: RULES',
        '  type: rules',
        '  file: RULES.yaml',
        '- uid: SUB',
        '  type: remote',
        '  file: SUB.yaml',
        '  option:',
        '    rules: RULES',
      ].join('\n'),
    )
    writeFileSync(join(profilesDir, 'RULES.yaml'), 'prepend: []\n')
    const index = parseProfilesIndex(readFileSync(join(root, 'profiles.yaml'), 'utf8'))
    assert.equal(index.current, 'SUB')
    assert.equal(index.items.get('SUB').rulesUid, 'RULES')
    assert.equal(ruleEnhancementPath(root), join(profilesDir, 'RULES.yaml'))
  })

  it('写入 Claude 规则，且二次调用不再重复写', () => {
    const root = tempDir()
    const profilesDir = join(root, 'profiles')
    mkdirSync(profilesDir, { recursive: true })
    writeFileSync(
      join(root, 'profiles.yaml'),
      [
        'current: SUB',
        'items:',
        '- uid: RULES',
        '  type: rules',
        '  file: RULES.yaml',
        '- uid: SUB',
        '  type: remote',
        '  file: SUB.yaml',
        '  option:',
        '    rules: RULES',
      ].join('\n'),
    )
    writeFileSync(join(profilesDir, 'RULES.yaml'), 'prepend: []\n')
    // 生效配置（订阅本体）里没有 Claude 规则
    writeFileSync(
      join(root, 'clash-verge.yaml'),
      ['mode: rule', 'rules:', '- GEOSITE,CN,DIRECT', '- MATCH,IPEqual'].join('\n'),
    )

    const first = applyClaudeRules(root)
    assert.equal(first.changed, true)
    const written = readFileSync(join(profilesDir, 'RULES.yaml'), 'utf8')
    assert.ok(written.includes('DOMAIN-SUFFIX,anthropic.com,IPEqual'))
    assert.ok(written.includes('DOMAIN-SUFFIX,claude.ai,IPEqual'))

    // 真实场景：增强文件会并进生效配置，这里手动模拟合并后再判
    const merged = [
      'mode: rule',
      'rules:',
      ...claudeRuleBlock('IPEqual').map((rule) => `- ${rule}`),
      '- GEOSITE,CN,DIRECT',
      '- MATCH,IPEqual',
    ]
    writeFileSync(join(root, 'clash-verge.yaml'), merged.join('\n'))
    assert.equal(claudeRuleCoverage(readClashRules(root)).ok, true)
  })

  it('找不到规则增强文件时仍然写生效配置，但标记为不持久', () => {
    const root = tempDir()
    writeFileSync(join(root, 'clash-verge.yaml'), 'rules:\n- MATCH,DIRECT\n')
    const outcome = applyClaudeRules(root, { programData: join(root, 'nope') })
    // 先让当前这套跑起来；durable=false 提醒"订阅更新会冲掉"。
    assert.equal(outcome.changed, true)
    assert.equal(outcome.durable, false)
    assert.ok(readFileSync(join(root, 'clash-verge.yaml'), 'utf8').includes('anthropic.com'))
  })
})

describe('切模式与规则前置', () => {
  it('writeProxyMode 同时改生效配置和运行时副本', () => {
    const root = tempDir()
    const clientDir = join(root, 'client')
    const runtime = join(root, 'runtime')
    mkdirSync(clientDir, { recursive: true })
    mkdirSync(runtime, { recursive: true })
    const body = ['mode: global', 'mixed-port: 7897', 'rules:', '- MATCH,PROXY'].join('\n')
    writeFileSync(join(clientDir, 'clash-verge.yaml'), body)
    // 运行时副本走 ProgramData 约定路径
    const programData = join(root, 'pd')
    const runtimeDir = join(programData, 'clash-verge-service', 'users', 'h1', 'runtime')
    mkdirSync(runtimeDir, { recursive: true })
    writeFileSync(join(runtimeDir, 'config.yaml'), body)

    const outcome = writeProxyMode(clientDir, 'rule', { programData })
    assert.equal(outcome.changed, 2)
    assert.ok(readFileSync(join(clientDir, 'clash-verge.yaml'), 'utf8').startsWith('mode: rule'))
    assert.ok(readFileSync(join(runtimeDir, 'config.yaml'), 'utf8').startsWith('mode: rule'))
  })

  it('已经是目标模式时不写', () => {
    const root = tempDir()
    const clientDir = join(root, 'client')
    mkdirSync(clientDir, { recursive: true })
    writeFileSync(join(clientDir, 'clash-verge.yaml'), 'mode: rule\nrules:\n- MATCH,PROXY\n')
    const outcome = writeProxyMode(clientDir, 'rule', { programData: join(root, 'nope') })
    assert.equal(outcome.changed, 0)
  })

  it('prependRulesToConfig 插在 rules 段最前面，保持缩进', () => {
    const text = ['rules:', '  - GEOSITE,CN,DIRECT', '  - MATCH,PROXY'].join('\n')
    const outcome = prependRulesToConfig(text, ['DOMAIN-SUFFIX,claude.ai,PROXY'])
    assert.equal(outcome.changed, true)
    const lines = outcome.text.split('\n')
    assert.equal(lines[1], '  - DOMAIN-SUFFIX,claude.ai,PROXY')
  })

  it('applyClaudeRules 同时写增强文件和生效配置', () => {
    const root = tempDir()
    const profilesDir = join(root, 'profiles')
    mkdirSync(profilesDir, { recursive: true })
    writeFileSync(
      join(root, 'profiles.yaml'),
      ['current: SUB', 'items:', '- uid: RULES', '  type: rules', '  file: RULES.yaml', '- uid: SUB', '  type: remote', '  file: SUB.yaml', '  option:', '    rules: RULES'].join('\n'),
    )
    writeFileSync(join(profilesDir, 'RULES.yaml'), 'prepend: []\n')
    writeFileSync(join(root, 'clash-verge.yaml'), ['mode: rule', 'rules:', '- GEOSITE,CN,DIRECT', '- MATCH,IPEqual'].join('\n'))

    const outcome = applyClaudeRules(root, { programData: join(root, 'nope') })
    assert.equal(outcome.changed, true)
    assert.ok(readFileSync(join(profilesDir, 'RULES.yaml'), 'utf8').includes('anthropic.com'))
    assert.ok(readFileSync(join(root, 'clash-verge.yaml'), 'utf8').includes('DOMAIN-SUFFIX,anthropic.com,IPEqual'))
  })
})

describe('UU 远程直连规则', () => {
  it('规则覆盖进程、域名、内网网段', () => {
    const block = UU_DIRECT_RULES
    assert.ok(block.some((rule) => rule.startsWith('PROCESS-NAME-REGEX')))
    assert.ok(block.some((rule) => rule.startsWith('PROCESS-PATH-REGEX')))
    assert.ok(block.some((rule) => rule === 'DOMAIN-SUFFIX,uu.163.com,DIRECT'))
    for (const cidr of ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12']) {
      assert.ok(block.includes(`IP-CIDR,${cidr},DIRECT,no-resolve`), cidr)
    }
  })

  it('命中判定按整条规则比对，不做模糊匹配', () => {
    assert.equal(hasUuDirectRules(UU_DIRECT_RULES), true)
    assert.equal(hasUuDirectRules(['DOMAIN-SUFFIX,uu.163.com,PROXY']), false)
    assert.equal(hasUuDirectRules([]), false)
  })

  it('删除时只删这组规则，别的原样保留', () => {
    const text = [
      'rules:',
      `- ${UU_DIRECT_RULES[0]}`,
      '- GEOSITE,CN,DIRECT',
      `- ${UU_DIRECT_RULES[6]}`,
      '- MATCH,IPEqual',
    ].join('\n')
    const outcome = removeRulesFromConfig(text, UU_DIRECT_RULES)
    assert.equal(outcome.changed, true)
    assert.equal(outcome.removed, 2)
    assert.ok(!outcome.text.includes(UU_DIRECT_RULES[0]))
    assert.ok(outcome.text.includes('GEOSITE,CN,DIRECT'))
    assert.ok(outcome.text.includes('MATCH,IPEqual'))
  })

  it('写一次再撤一次，配置回到原样', () => {
    const root = tempDir()
    const profilesDir = join(root, 'profiles')
    mkdirSync(profilesDir, { recursive: true })
    writeFileSync(
      join(root, 'profiles.yaml'),
      ['current: SUB', 'items:', '- uid: RULES', '  type: rules', '  file: RULES.yaml', '- uid: SUB', '  type: remote', '  file: SUB.yaml', '  option:', '    rules: RULES'].join('\n'),
    )
    writeFileSync(join(profilesDir, 'RULES.yaml'), 'prepend: []\n')
    const original = ['mode: rule', 'rules:', '- GEOSITE,CN,DIRECT', '- MATCH,IPEqual'].join('\n')
    writeFileSync(join(root, 'clash-verge.yaml'), original)

    const on = setUuDirectRules(root, true, { programData: join(root, 'nope') })
    assert.equal(on.changed, true)
    assert.equal(on.enabled, true)
    assert.equal(hasUuDirectRules(readClashRules(root)), true)
    assert.ok(readFileSync(join(profilesDir, 'RULES.yaml'), 'utf8').includes('uu.163.com'))

    const again = setUuDirectRules(root, true, { programData: join(root, 'nope') })
    assert.equal(again.changed, false)

    const off = setUuDirectRules(root, false, { programData: join(root, 'nope') })
    assert.equal(off.changed, true)
    assert.equal(hasUuDirectRules(readClashRules(root)), false)
    assert.equal(readFileSync(join(root, 'clash-verge.yaml'), 'utf8'), original)
  })
})
