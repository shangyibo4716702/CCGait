import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  browserBlockTargets,
  browserFallbackPaths,
  discoverDefaultBrowser,
  probeDefaultBrowser,
} from '../src/browser-targets.js'

// 这些测试钉住一条产品约定：Claude 登录会拉起系统默认浏览器，
// 浏览器必须和 Claude 走同一套网络管控，但**永远不终止它的进程**。

describe('default browser discovery', () => {
  it('maps the registry ProgId to a concrete browser', async () => {
    const probe = await probeDefaultBrowser({ runPowerShell: async () => 'MSEdgeHTM\r\n' })
    assert.equal(probe.progId, 'MSEdgeHTM')
    assert.equal(probe.name, 'msedge.exe')
    assert.equal(probe.source, 'registry')
  })

  it('recognises non-Edge defaults instead of assuming Edge', async () => {
    const chrome = await probeDefaultBrowser({ runPowerShell: async () => 'ChromeHTML' })
    assert.equal(chrome.name, 'chrome.exe')
    const firefox = await probeDefaultBrowser({ runPowerShell: async () => 'FirefoxURL-308046B0AF4A39CB' })
    assert.equal(firefox.name, 'firefox.exe')
  })

  it('does not invent a browser when the registry read fails', async () => {
    const probe = await probeDefaultBrowser({
      runPowerShell: async () => {
        throw new Error('powershell unavailable')
      },
    })
    assert.equal(probe.progId, undefined)
    assert.equal(probe.name, undefined)
  })

  it('resolves the executable path for the declared default', async () => {
    const edge = browserFallbackPaths({})[0].paths[0]
    const result = await discoverDefaultBrowser({
      runPowerShell: async () => 'MSEdgeHTM',
      exists: (path) => path === edge,
    })
    assert.equal(result.path, edge)
    assert.equal(result.name, 'msedge.exe')
  })

  it('falls back to an installed browser when the ProgId is unknown', async () => {
    const edge = browserFallbackPaths({})[0].paths[0]
    const result = await discoverDefaultBrowser({
      runPowerShell: async () => 'SomeUnknownHandler',
      exists: (path) => path === edge,
    })
    assert.equal(result.path, edge)
    assert.equal(result.inferred, true)
  })

  it('reports a missing browser rather than pretending it is managed', async () => {
    const result = await discoverDefaultBrowser({
      runPowerShell: async () => 'MSEdgeHTM',
      exists: () => false,
    })
    assert.equal(result.path, undefined)
    assert.equal(result.missing, true)
    assert.deepEqual(browserBlockTargets(result), [], '找不到可执行文件时不应产生阻断目标')
  })

  it('includes every installed copy of the same browser', () => {
    const fallbacks = browserFallbackPaths({})
    const edgePaths = fallbacks[0].paths
    const targets = browserBlockTargets({
      name: 'msedge.exe',
      label: 'Microsoft Edge',
      path: edgePaths[1],
    })
    // 用户可能从 Program Files 或 x86 任一位置启动，两个副本都要覆盖；
    // 只覆盖注册表路径会在"从另一个副本启动"时漏放。
    assert.ok(targets.includes(edgePaths[1]))
  })
})
