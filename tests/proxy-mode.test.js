import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  judgeProxyMode,
  normalizeController,
  probeProxyMode,
  proxyConfigDirs,
  judgeProxySettings,
  readProxySettings,
  readYamlBlock,
  readYamlBool,
  readYamlScalar,
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
    assert.deepEqual(judgeProxyMode({ checked: true, mode: 'rule' }), { block: true, warn: false, mode: 'rule' })
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
