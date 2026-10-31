import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  controllerPipeFromConfig,
  controllerSecret,
  findControlPipe,
  isClaudeHost,
  isClaudeProcess,
  judgeClaudeConnections,
  probeClaudeRouting,
  verifyClaudeRouting,
} from '../src/proxy-connections.js'

const tempDirs = []
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'ccgait-conn-'))
  tempDirs.push(dir)
  return dir
}

after(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

describe('Claude 域名与进程识别', () => {
  it('认得出 Claude 的域名，包括子域和带端口', () => {
    assert.equal(isClaudeHost('claude.ai'), true)
    assert.equal(isClaudeHost('api.anthropic.com'), true)
    assert.equal(isClaudeHost('claude.ai:443'), true)
    assert.equal(isClaudeHost('cdn.claudeusercontent.com'), true)
  })

  it('不把相似域名当成 Claude', () => {
    assert.equal(isClaudeHost('notclaude.ai'), false)
    assert.equal(isClaudeHost('claude.ai.evil.com'), false)
    assert.equal(isClaudeHost(''), false)
  })

  it('认得出 claude.exe（Desktop 与内置 claude-code）', () => {
    assert.equal(isClaudeProcess('C:\\Program Files\\WindowsApps\\Claude_1\\app\\Claude.exe'), true)
    assert.equal(isClaudeProcess('C:\\Users\\x\\AppData\\Local\\Claude-Data\\claude-code\\2\\x\\claude.exe'), true)
    assert.equal(isClaudeProcess('C:\\Program Files\\nodejs\\node.exe'), false)
  })
})

describe('连接表判定', () => {
  const conn = (host, chains) => ({ metadata: { host }, chains })

  it('链里是代理节点 → 不算泄露', () => {
    const judged = judgeClaudeConnections([
      conn('api.anthropic.com', ['节点一', 'GLOBAL']),
      conn('claude.ai', ['节点一', 'GLOBAL']),
    ])
    assert.equal(judged.claude, 2)
    assert.deepEqual(judged.leaks, [])
  })

  it('第一跳是 DIRECT 或链条为空 → 算泄露', () => {
    const judged = judgeClaudeConnections([
      conn('claude.ai', ['DIRECT']),
      conn('api.anthropic.com', []),
    ])
    assert.equal(judged.leaks.length, 2)
    assert.equal(judged.leaks[0].host, 'claude.ai')
  })

  it('按进程路径也能挑出 Claude 的连接', () => {
    const judged = judgeClaudeConnections([
      { metadata: { host: 'unknown-host.example', processPath: 'C:\\x\\Claude.exe' }, chains: ['DIRECT'] },
    ])
    assert.equal(judged.claude, 1)
    assert.equal(judged.leaks.length, 1)
  })

  it('别的程序的连接不参与判定', () => {
    const judged = judgeClaudeConnections([conn('example.com', ['DIRECT'])])
    assert.equal(judged.claude, 0)
    assert.deepEqual(judged.leaks, [])
  })
})

describe('内核控制接口', () => {
  it('从进程命令行里抠管道名', () => {
    const pipe = findControlPipe({
      run: () =>
        '"C:\\ProgramData\\clash-verge-service\\cores\\verge-mihomo.exe" -d C:\\x -f C:\\x\\config.yaml -ext-ctl-pipe \\\\.\\pipe\\verge-mihomo-production-abc\r\n',
    })
    assert.equal(pipe, '\\\\.\\pipe\\verge-mihomo-production-abc')
  })

  it('命令行拿不到时返回 null，不瞎猜', () => {
    assert.equal(findControlPipe({ run: () => '' }), null)
    assert.equal(findControlPipe({ run: () => { throw new Error('boom') } }), null)
  })

  it('配置里的管道名与 secret 能读出来', () => {
    const root = tempDir()
    writeFileSync(
      join(root, 'clash-verge.yaml'),
      ['external-controller: \'\'', "secret: 'abc123'", 'external-controller-pipe: \\\\.\\pipe\\verge-mihomo-sidecar-x'].join('\n'),
    )
    assert.equal(controllerPipeFromConfig(root), '\\\\.\\pipe\\verge-mihomo-sidecar-x')
    assert.equal(controllerSecret(root), 'abc123')
  })
})

describe('路由自证', () => {
  it('Claude 的域名走了代理 → ok', async () => {
    const result = await probeClaudeRouting({
      pipe: 'p',
      secret: 's',
      port: 7897,
      hosts: ['claude.ai'],
      open: async ({ host }) => ({ host, close() {} }),
      read: async () => ({
        connections: [{ metadata: { host: 'claude.ai' }, chains: ['节点一', 'GLOBAL'], rule: 'DomainSuffix', rulePayload: 'claude.ai' }],
      }),
    })
    assert.equal(result.checked, true)
    assert.equal(result.ok, true)
    assert.equal(result.leaks.length, 0)
  })

  it('同一条走 DIRECT → 判失败', async () => {
    const result = await probeClaudeRouting({
      pipe: 'p',
      hosts: ['claude.ai'],
      open: async ({ host }) => ({ host, close() {} }),
      read: async () => ({ connections: [{ metadata: { host: 'claude.ai' }, chains: ['DIRECT'] }] }),
    })
    assert.equal(result.ok, false)
    assert.equal(result.leaks[0].chains[0], 'DIRECT')
  })

  it('开隧道失败也算没测到，不当成通过', async () => {
    const result = await probeClaudeRouting({
      hosts: ['claude.ai'],
      open: async () => {
        throw new Error('connect refused')
      },
    })
    assert.equal(result.checked, false)
    assert.equal(result.ok, false)
    assert.match(result.results[0].error, /refused/)
  })

  it('verifyClaudeRouting：管道不存在时报告未验证', async () => {
    const result = await verifyClaudeRouting({
      dir: tempDir(),
      findPipe: () => null,
      attempts: 1,
      delayMs: 0,
      sleep: async () => {},
    })
    assert.equal(result.ok, false)
    assert.equal(result.checked, false)
    assert.match(result.error, /管道/)
  })
})
