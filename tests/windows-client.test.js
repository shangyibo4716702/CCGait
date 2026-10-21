import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  LAST_CHECK_FILE,
  readStatusSnapshot,
  traySummary,
  trayTooltip,
  verdictChanged,
  writeLastCheck,
} from '../src/win/status.js'
import { appWindowArgs, browserCandidates, resolveBrowser } from '../src/win/browser-window.js'
import { buildIco, buildIconPng, buildIconSvg, ICON_SIZES, renderIconRgba, writeIconFiles } from '../src/win/icon.js'
import { isUiServerUp, openDesktopClient, resolveNativeClient, waitForUiServer } from '../src/win/desktop.js'

const tempDirs = []
after(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'ccgait-win-'))
  tempDirs.push(dir)
  return dir
}

const checkResult = (allow) => ({
  verdict: {
    allow,
    failedClosed: false,
    blockedBy: allow ? [] : [{ id: 'egress-country', title: '出口国家不在白名单：SG' }],
    warnings: allow ? [] : [{ id: 'timezone-domestic', title: '系统时区为 Asia/Shanghai' }],
    whitelistSummary: { countries: ['GB'], ips: [] },
  },
  egress: { ip: '51.140.1.1', country: 'GB', org: 'Example ISP', asn: 'AS1 Example', hosting: false, confident: true },
})

describe('windows status files', () => {
  it('persists a check result and reads it back for the tray', () => {
    const dir = tempDir()
    const written = writeLastCheck(dir, checkResult(true))
    assert.equal(written.allow, true)

    const snapshot = readStatusSnapshot(dir)
    assert.equal(snapshot.lastCheck.allow, true)
    assert.equal(snapshot.lastCheck.egress.country, 'GB')
    assert.deepEqual(snapshot.lastCheck.whitelist.countries, ['GB'])
    assert.equal(snapshot.guardRunning, false, '没有 guard 状态文件时视为未运行')
  })

  it('reports the guard as running only while its state file says so', () => {
    const dir = tempDir()
    writeFileSync(join(dir, 'state.json'), JSON.stringify({ allow: false, reason: 'recheck' }), 'utf8')
    assert.equal(readStatusSnapshot(dir).guardRunning, true)

    writeFileSync(
      join(dir, 'state.json'),
      JSON.stringify({ running: false, stoppedAt: new Date().toISOString() }),
      'utf8',
    )
    assert.equal(readStatusSnapshot(dir).guardRunning, false)
  })

  it('survives a corrupt state file instead of throwing', () => {
    const dir = tempDir()
    writeFileSync(join(dir, LAST_CHECK_FILE), '{ broken', 'utf8')
    assert.doesNotThrow(() => readStatusSnapshot(dir))
    assert.equal(readStatusSnapshot(dir).lastCheck, undefined)
  })

  it('keeps the tray tooltip inside the WinForms 63-character limit', () => {
    const dir = tempDir()
    writeLastCheck(dir, checkResult(false))
    const snapshot = readStatusSnapshot(dir)
    const tooltip = trayTooltip({ ...snapshot, guardRunning: true })
    assert.ok(tooltip.length <= 63, `tooltip 过长：${tooltip.length}`)
    assert.match(tooltip, /CCGait/)
    assert.match(tooltip, /拦截/)
    assert.match(tooltip, /闸门运行中/)
  })

  it('summarizes allow and block outcomes for balloon notifications', () => {
    const allowDir = tempDir()
    writeLastCheck(allowDir, checkResult(true))
    const allowSummary = traySummary(readStatusSnapshot(allowDir))
    assert.match(allowSummary.title, /放行/)

    const blockDir = tempDir()
    writeLastCheck(blockDir, checkResult(false))
    const blockSummary = traySummary(readStatusSnapshot(blockDir))
    assert.match(blockSummary.title, /拦截/)
    assert.match(blockSummary.text, /不在白名单/)
  })

  it('only flags a real allow → block flip', () => {
    assert.equal(verdictChanged({ allow: true }, { allow: false }), true)
    assert.equal(verdictChanged({ allow: true }, { allow: true }), false)
    assert.equal(verdictChanged({ allow: false }, { allow: false }), false)
    assert.equal(verdictChanged(undefined, { allow: false }), false)
  })
})

describe('browser window', () => {
  it('prefers Edge over Chrome and reports its kind', () => {
    const edge = browserCandidates({})[0].path
    assert.equal(resolveBrowser({}, (path) => path === edge).kind, 'edge')

    const chrome = browserCandidates({})[2].path
    assert.equal(resolveBrowser({}, (path) => path === chrome).kind, 'chrome')
  })

  it('returns undefined when no supported browser exists', () => {
    assert.equal(resolveBrowser({}, () => false), undefined)
  })

  it('builds app-mode arguments with an isolated profile', () => {
    const args = appWindowArgs('http://127.0.0.1:17890/', 'D:\\CCGait\\.ccgait\\app-window-profile')
    assert.ok(args.includes('--app=http://127.0.0.1:17890/'))
    assert.ok(args.some((item) => item.startsWith('--user-data-dir=')), '必须使用独立 profile，避免污染日常浏览器')
    assert.ok(args.some((item) => item.startsWith('--window-size=')))
    assert.ok(args.includes('--no-first-run'))
  })
})

describe('icon encoder', () => {
  it('produces a valid PNG', () => {
    const png = buildIconPng(64)
    assert.deepEqual([...png.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
    assert.equal(png.subarray(12, 16).toString('ascii'), 'IHDR')
    assert.equal(png.readUInt32BE(16), 64)
    assert.equal(png.readUInt32BE(20), 64)
  })

  it('produces an ICO covering every size Windows actually asks for', () => {
    const ico = buildIco()
    assert.equal(ico.readUInt16LE(0), 0)
    assert.equal(ico.readUInt16LE(2), 1, 'ICO 类型应为图标')
    // 缺了中间尺寸，外壳就会拿相邻尺寸缩放，任务栏那格就会发虚。
    // 100% 缩放下任务栏要 24px —— 早先只做 16/32，正好踩中这个坑。
    assert.deepEqual(ICON_SIZES, [16, 20, 24, 32, 40, 48, 64, 96, 128, 256])
    assert.equal(ico.readUInt16LE(4), ICON_SIZES.length, '应包含全部尺寸')
    // 第一张图偏移应指向 PNG 签名
    const firstOffset = ico.readUInt32LE(6 + 12)
    assert.deepEqual([...ico.subarray(firstOffset + 1, firstOffset + 4)], [0x50, 0x4e, 0x47])
  })

  it('records the real pixel size of every ICO entry', () => {
    // 目录里写错尺寸会让外壳按错误的尺寸挑图，任务栏/通知区就会拿到被放大的糊图。
    const ico = buildIco()
    ICON_SIZES.forEach((size, index) => {
      const offset = 6 + 16 * index
      const encoded = size >= 256 ? 0 : size
      assert.equal(ico[offset], encoded, `${size}px 项的宽度字节`)
      assert.equal(ico[offset + 1], encoded, `${size}px 项的高度字节`)
    })
  })

  it('ships an SVG variant so the app window icon stays crisp at any DPI', () => {
    // 任务栏图标取自页面 favicon。位图挑不到合适尺寸时会缩放，SVG 则由内核按需渲染。
    const svg = buildIconSvg(256)
    assert.match(svg, /^<svg xmlns="http:\/\/www\.w3\.org\/2000\/svg"/)
    assert.match(svg, /viewBox="0 0 256 256"/)
    assert.match(svg, /stroke="rgb\(255,255,255\)"/, '线稿必须是白色（深色底上才看得清）')
    assert.match(svg, /M12 3l7 3v6/, '盾牌路径应与位图版一致')
  })

  it('draws an opaque rounded square with transparent corners', () => {
    const size = 32
    const rgba = renderIconRgba(size)
    const alphaAt = (x, y) => rgba[(y * size + x) * 4 + 3]
    assert.equal(alphaAt(0, 0), 0, '圆角外的像素应透明')
    assert.equal(alphaAt(size / 2, size / 2), 255, '中心应不透明')
    assert.ok(alphaAt(size / 2, 2) > 200, '上边缘内侧应基本不透明')
  })

  it('writes both icon files', () => {
    const dir = tempDir()
    const files = writeIconFiles(dir)
    assert.ok(files.ico.endsWith('ccgait.ico'))
    assert.ok(files.png.endsWith('ccgait.png'))
  })
})

describe('desktop client launcher', () => {
  const okFetch = async () => ({ status: 200 })
  const deadFetch = async () => {
    throw new Error('ECONNREFUSED')
  }

  it('detects a live server and a dead port', async () => {
    assert.equal(await isUiServerUp(17890, { fetchImpl: okFetch }), true)
    assert.equal(await isUiServerUp(17890, { fetchImpl: deadFetch }), false)
  })

  it('waits until the server answers', async () => {
    let attempts = 0
    const flakyFetch = async () => {
      attempts += 1
      if (attempts < 3) throw new Error('ECONNREFUSED')
      return { status: 200 }
    }
    assert.equal(await waitForUiServer(17890, { fetchImpl: flakyFetch, intervalMs: 1 }), true)
    assert.equal(attempts, 3)
  })

  it('reuses a running server and opens the window', async () => {
    const calls = []
    const result = await openDesktopClient({
      port: 17890,
      stateDir: tempDir(),
      fetchImpl: okFetch,
      spawnServer: () => calls.push('spawn'),
      openWindow: () => ({ opened: true, browser: 'edge' }),
    })
    assert.equal(result.serverStarted, false)
    assert.equal(result.windowOpened, true)
    assert.deepEqual(calls, [], '服务已在运行时不应重复拉起')
  })

  it('starts the server first when the port is dead', async () => {
    const calls = []
    const result = await openDesktopClient({
      port: 17890,
      stateDir: tempDir(),
      // 先失败一次（拉起前探测）再成功（就绪探测）
      fetchImpl: (() => {
        let call = 0
        return async () => {
          call += 1
          if (call === 1) throw new Error('ECONNREFUSED')
          return { status: 200 }
        }
      })(),
      spawnServer: () => calls.push('spawn'),
      openWindow: () => ({ opened: true, browser: 'edge' }),
    })
    assert.equal(result.serverStarted, true)
    assert.deepEqual(calls, ['spawn'])
    assert.equal(result.windowOpened, true)
  })

  it('reports a clear reason when the server never becomes ready', async () => {
    const result = await openDesktopClient({
      port: 17890,
      stateDir: tempDir(),
      fetchImpl: deadFetch,
      spawnServer: () => undefined,
      openWindow: () => ({ opened: true }),
      timeoutMs: 30,
    })
    assert.equal(result.windowOpened, false)
    assert.match(result.reason, /ui-server\.log/)
  })

  it('reports when no browser is available', async () => {
    const result = await openDesktopClient({
      port: 17890,
      stateDir: tempDir(),
      fetchImpl: okFetch,
      spawnServer: () => undefined,
      openWindow: () => ({ opened: false, reason: '未找到 Microsoft Edge 或 Google Chrome' }),
    })
    assert.equal(result.windowOpened, false)
    assert.match(result.reason, /Edge/)
  })

  it('delegates to the native client when it is installed', async () => {
    // 已安装形态必须整体交给原生客户端：它带跨进程单实例判重。
    // 如果这里退回 Node 的 openAppWindow，连点就会重新叠窗口。
    const calls = []
    const result = await openDesktopClient({
      port: 17890,
      stateDir: tempDir(),
      fetchImpl: deadFetch,
      spawnServer: () => calls.push('spawn-server'),
      openWindow: () => calls.push('open-window'),
      spawnNative: (path) => calls.push(`native:${path}`),
      nativeClientPath: 'C:\\CCGait\\CCGaitClient.exe',
    })
    assert.equal(result.native, true)
    assert.equal(result.windowOpened, true)
    assert.deepEqual(calls, ['native:C:\\CCGait\\CCGaitClient.exe'], '不应再自己拉起服务或窗口')
  })

  it('only resolves the native client when the exe is present on Windows', () => {
    const path = 'C:\\CCGait\\CCGaitClient.exe'
    assert.equal(resolveNativeClient({ rootDir: 'C:\\CCGait', exists: (p) => p === path, platform: 'win32' }), path)
    assert.equal(resolveNativeClient({ rootDir: 'C:\\CCGait', exists: () => false, platform: 'win32' }), undefined)
    assert.equal(resolveNativeClient({ rootDir: '/opt/ccgait', exists: () => true, platform: 'linux' }), undefined)
  })
})
