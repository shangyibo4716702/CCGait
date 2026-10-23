import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  accountComplete,
  assertAccountName,
  identityEntries,
  listAccounts,
  locateDesktopProfile,
  PROFILE_EXCLUDES,
  recoverInterruptedSwitch,
  saveAccount,
  switchAccount,
} from '../src/accounts.js'

const tempDirs = []
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'ccgait-accounts-'))
  tempDirs.push(dir)
  return dir
}
after(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

/**
 * 造一个和真实 Claude Desktop profile 同构的目录。
 * 里面有真身份（Cookies / Local Storage / ant-did）和不该跟着账号走的
 * 大件与缓存（claude-code / Cache / Local State）。
 */
function makeProfile(root, label) {
  const profile = join(root, 'Claude-Data', 'claude_testpkg')
  mkdirSync(join(profile, 'Network'), { recursive: true })
  mkdirSync(join(profile, 'Local Storage', 'leveldb'), { recursive: true })
  mkdirSync(join(profile, 'IndexedDB'), { recursive: true })
  mkdirSync(join(profile, 'Cache'), { recursive: true })
  mkdirSync(join(profile, 'claude-code', '2.1.308'), { recursive: true })
  writeFileSync(join(profile, 'Network', 'Cookies'), `cookies-${label}`)
  writeFileSync(join(profile, 'Local Storage', 'leveldb', 'x.ldb'), `ls-${label}`)
  writeFileSync(join(profile, 'IndexedDB', 'x.db'), `idb-${label}`)
  writeFileSync(join(profile, 'Preferences'), `prefs-${label}`)
  writeFileSync(join(profile, 'ant-did'), `did-${label}`)
  writeFileSync(join(profile, 'Local State'), 'device-key')
  writeFileSync(join(profile, 'Cache', 'blob'), 'x'.repeat(64))
  writeFileSync(join(profile, 'claude-code', '2.1.308', 'claude.exe'), 'binary')
  return profile
}

const opts = { runRobocopy: false }

describe('Claude Desktop profile 定位', () => {
  it('从 Claude-Data 下认出带 Cookies 的包目录', () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    const found = locateDesktopProfile({ LOCALAPPDATA: root })
    assert.equal(found, profile)
  })

  it('没装 Desktop 时返回 undefined，而不是造一个假目录', () => {
    const root = tempDir()
    assert.equal(locateDesktopProfile({ LOCALAPPDATA: join(root, 'nothing') }), undefined)
  })
})

describe('身份条目筛选', () => {
  it('带上身份文件，排除缓存、二进制和设备级 Local State', () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    const entries = identityEntries(profile)
    assert.ok(entries.includes('Network'))
    assert.ok(entries.includes('Local Storage'))
    assert.ok(entries.includes('IndexedDB'))
    assert.ok(entries.includes('ant-did'), 'ant-did 是设备标识，必须跟着账号走')
    assert.ok(!entries.includes('Cache'))
    assert.ok(!entries.includes('claude-code'), 'CLI 二进制不能每个账号存一份')
    assert.ok(!entries.includes('Local State'), 'Chromium 加密密钥必须共享')
    assert.ok(PROFILE_EXCLUDES.has('claude-code'))
  })
})

describe('存档', () => {
  it('存出一份可用的快照，并带上元数据', () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    const accounts = join(root, 'accounts')
    const result = saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })
    assert.equal(result.name, 'A')
    assert.ok(accountComplete(join(accounts, 'A')))
    assert.equal(readFileSync(join(accounts, 'A', 'Network', 'Cookies'), 'utf8'), 'cookies-A')
    assert.ok(!existsSync(join(accounts, 'A', 'claude-code')), '不该把 CLI 二进制存进快照')
    assert.ok(existsSync(join(accounts, 'A', '.ccgait-account.json')))
  })

  it('缺 Cookies 的存档判为不完整', () => {
    const root = tempDir()
    const dir = join(root, 'broken')
    mkdirSync(join(dir, 'Network'), { recursive: true })
    assert.equal(accountComplete(dir), false)
  })

  it('拒绝非法账号名，避免路径穿越', () => {
    for (const name of ['..', '../evil', 'a/b', 'a\\b', '', 'x'.repeat(33), '名字']) {
      assert.throws(() => assertAccountName(name), /账号名/)
    }
    assert.equal(assertAccountName('acc_1-B'), 'acc_1-B')
  })
})

describe('切换', () => {
  it('首次运行把现有登录收编为 A', async () => {
    const root = tempDir()
    const profile = makeProfile(root, 'now')
    const accounts = join(root, 'accounts')
    const result = await switchAccount({
      name: 'A',
      profileDir: profile,
      accountsDir: accounts,
      current: undefined,
      ...opts,
    })
    assert.equal(result.captured, true)
    assert.ok(accountComplete(join(accounts, 'A')))
    // 现场没被搬动过
    assert.equal(readFileSync(join(profile, 'Network', 'Cookies'), 'utf8'), 'cookies-now')
  })

  it('A → B 时身份条目互换，缓存和二进制原样不动', async () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    const accounts = join(root, 'accounts')
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })

    // 模拟登录成 B：换掉身份文件内容
    writeFileSync(join(profile, 'Network', 'Cookies'), 'cookies-B')
    writeFileSync(join(profile, 'IndexedDB', 'x.db'), 'idb-B')
    writeFileSync(join(profile, 'ant-did'), 'did-B')
    saveAccount({ name: 'B', profileDir: profile, accountsDir: accounts, ...opts })

    // 回到 A
    const back = await switchAccount({
      name: 'A',
      profileDir: profile,
      accountsDir: accounts,
      current: 'B',
      ...opts,
    })
    assert.equal(back.archivedFrom, 'B')
    assert.equal(readFileSync(join(profile, 'Network', 'Cookies'), 'utf8'), 'cookies-A')
    assert.equal(readFileSync(join(profile, 'IndexedDB', 'x.db'), 'utf8'), 'idb-A')
    assert.equal(readFileSync(join(profile, 'ant-did'), 'utf8'), 'did-A', '设备标识必须跟着账号换')
    // 共享的东西没被动
    assert.equal(readFileSync(join(profile, 'Local State'), 'utf8'), 'device-key')
    assert.ok(existsSync(join(profile, 'claude-code', '2.1.308', 'claude.exe')))
    // B 的登录态被存下来了，没丢
    assert.equal(readFileSync(join(accounts, 'B', 'Network', 'Cookies'), 'utf8'), 'cookies-B')
  })

  it('目标账号没有存档时拒绝切换，且现场一点没动', async () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    const accounts = join(root, 'accounts')
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })
    await assert.rejects(
      switchAccount({ name: 'ZZ', profileDir: profile, accountsDir: accounts, current: 'A', ...opts }),
      /还没有存档/,
    )
    assert.equal(readFileSync(join(profile, 'Network', 'Cookies'), 'utf8'), 'cookies-A')
  })

  it('切换会先结束 Claude 进程', async () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    const accounts = join(root, 'accounts')
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })
    let called = 0
    await switchAccount({
      name: 'A',
      profileDir: profile,
      accountsDir: accounts,
      current: 'A',
      killProcesses: async () => {
        called += 1
        return { killed: 3 }
      },
      ...opts,
    })
    assert.equal(called, 1)
  })
})

describe('中断恢复', () => {
  it('发现上一轮留下的 .ccgait-prev 就把身份条目移回来', () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    const prev = `${profile}.ccgait-prev`
    mkdirSync(prev, { recursive: true })
    // 模拟"身份条目已被搬走、还没搬回来"的中间态
    rmSync(join(profile, 'Network'), { recursive: true, force: true })
    mkdirSync(join(prev, 'Network'), { recursive: true })
    writeFileSync(join(prev, 'Network', 'Cookies'), 'cookies-rescued')

    const result = recoverInterruptedSwitch(profile)
    assert.equal(result.recovered, true)
    assert.ok(result.restored >= 1)
    assert.equal(readFileSync(join(profile, 'Network', 'Cookies'), 'utf8'), 'cookies-rescued')
    assert.ok(!existsSync(prev))
  })

  it('没有残留时什么都不做', () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    assert.equal(recoverInterruptedSwitch(profile).recovered, false)
  })
})

describe('账号列表', () => {
  it('列出可用账号，最近保存的在前', () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    const accounts = join(root, 'accounts')
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })
    saveAccount({ name: 'B', profileDir: profile, accountsDir: accounts, ...opts })
    const listed = listAccounts(accounts)
    assert.equal(listed.length, 2)
    assert.ok(listed.every((item) => item.complete))
    assert.deepEqual(listed.map((item) => item.name).sort(), ['A', 'B'])
  })
})
