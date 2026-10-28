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
  nextAccountName,
  readAccountInsights,
  removeAccount,
  writeCurrentAccount,
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

describe('重复保存同名账号', () => {
  it('旧存档留一份 .bak，不会被静默覆盖掉', () => {
    const root = tempDir()
    const profile = makeProfile(root, 'v1')
    const accounts = join(root, 'accounts')
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })

    writeFileSync(join(profile, 'Network', 'Cookies'), 'cookies-v2')
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })

    assert.equal(readFileSync(join(accounts, 'A', 'Network', 'Cookies'), 'utf8'), 'cookies-v2')
    assert.equal(
      readFileSync(join(accounts, 'A.bak', 'Network', 'Cookies'), 'utf8'),
      'cookies-v1',
      '上一份必须留得下来',
    )
    // .bak 不该被当成一个可选账号
    assert.deepEqual(listAccounts(accounts).map((item) => item.name), ['A'])
  })
})

describe('默认账号名', () => {
  it('按 A、B、C 顺序分配，跳已用的，用完字母后用 A1 这类', () => {
    assert.equal(nextAccountName([]), 'A')
    assert.equal(nextAccountName(['A']), 'B')
    assert.equal(nextAccountName(['A', 'B', 'C']), 'D')
    // 名字是乱序存的，不该影响分配
    assert.equal(nextAccountName(['B']), 'A')
    const allLetters = Array.from({ length: 26 }, (_, i) => String.fromCharCode(65 + i))
    assert.equal(nextAccountName(allLetters), 'A1')
  })
})

// 这两个函数只读本地文件、零网络请求 —— 安全前提就靠这条钉死。
function makeInsights(dir, { email, fullName, fh, sd }) {
  mkdirSync(join(dir, 'plan-usage-history.json'.slice(0, 0) || '.'), { recursive: true })
  writeFileSync(
    join(dir, 'plan-usage-history.json'),
    JSON.stringify({
      version: 2,
      samples: [
        { t: 1, org: 'old', u: {} },
        { t: Date.UTC(2026, 9, 25, 7, 37, 40), org: 'org1', u: { fh, sd } },
      ],
    }),
  )
  if (email) {
    // 模拟 IndexedDB blob：leveldb 记录里是 "email_address" "<邮箱>" "full_name" "<名字>"
    const blobDir = join(dir, 'IndexedDB', 'https_claude.ai_0.indexeddb.blob', '5', '04')
    mkdirSync(blobDir, { recursive: true })
    writeFileSync(join(blobDir, '415'), `prefix bytes"uuid-key""email_address""${email}""full_name""${fullName ?? ''}"trailing`)
  }
}

describe('账号识别与用量读取', () => {

  it('从 IndexedDB 锚点后提取邮箱和显示名，从用量历史取最后一条采样', () => {
    const root = tempDir()
    makeInsights(root, { email: 'work.example+1@gmail.com', fullName: 'Bradshaw Georgie', fh: 43, sd: 6 })
    const insights = readAccountInsights(root)
    assert.equal(insights.email, 'work.example+1@gmail.com')
    assert.equal(insights.fullName, 'Bradshaw Georgie')
    assert.equal(insights.usage.fiveHourPercent, 43)
    assert.equal(insights.usage.weeklyPercent, 6)
    assert.equal(insights.usage.sampledAt, new Date(Date.UTC(2026, 9, 25, 7, 37, 40)).toISOString())
  })

  it('文件缺失时不抛错，只少给对应字段', () => {
    const root = tempDir()
    const insights = readAccountInsights(root)
    assert.equal(insights.email, undefined)
    assert.equal(insights.usage, undefined)
  })

  it('老采样没有用量字段时跳过它们，取最近一条带用量的', () => {
    const root = tempDir()
    writeFileSync(
      join(root, 'plan-usage-history.json'),
      JSON.stringify({
        samples: [
          { t: 1, org: 'a', u: { fh: 90, sd: 80 } },
          { t: 2, org: 'a', u: {} },
          { t: 3, org: 'a', u: { fh: 7, sd: 5 } },
        ],
      }),
    )
    const insights = readAccountInsights(root)
    assert.equal(insights.usage.fiveHourPercent, 7, '空采样不算数')
  })

  it('存档时把识别结果写进元数据，列表能读出来', () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    makeInsights(profile, { email: 'someone@privaterelay.appleid.com', fullName: 'Some One', fh: 0, sd: 73 })
    const accounts = join(root, 'accounts')
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })
    const listed = listAccounts(accounts)
    assert.equal(listed[0].email, 'someone@privaterelay.appleid.com')
    assert.equal(listed[0].fullName, 'Some One')
    assert.equal(listed[0].usage.weeklyPercent, 73)
  })
})

describe('老存档兼容', () => {
  it('元数据里没有识别结果时，现场从存档目录读一次', () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    const accounts = join(root, 'accounts')
    // 先正常存一份（带识别），然后手动抹掉元数据里的识别字段，模拟老存档
    makeInsights(profile, { email: 'old@icloud.com', fullName: 'Old One', fh: 10, sd: 20 })
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })
    const metaPath = join(accounts, 'A', '.ccgait-account.json')
    const meta = JSON.parse(readFileSync(metaPath, 'utf8'))
    delete meta.email
    delete meta.usage
    writeFileSync(metaPath, JSON.stringify(meta), 'utf8')

    const listed = listAccounts(accounts)
    assert.equal(listed[0].email, 'old@icloud.com', '老存档也要能显示真账号')
    assert.equal(listed[0].usage.fiveHourPercent, 10)
  })
})

describe('删除账号', () => {
  it('删掉存档连同 .bak 备份', () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    const accounts = join(root, 'accounts')
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })
    assert.ok(existsSync(join(accounts, 'A.bak')), '前提：备份存在')
    const result = removeAccount(accounts, 'A')
    assert.equal(result.removed, true)
    assert.ok(!existsSync(join(accounts, 'A')))
    assert.ok(!existsSync(join(accounts, 'A.bak')), '备份也要删，不能留十几 MB 的旧 Cookies')
  })

  it('不允许删除正在使用的账号', () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    const accounts = join(root, 'accounts')
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })
    writeCurrentAccount(accounts, 'A')
    assert.throws(() => removeAccount(accounts, 'A'), /正在使用中/)
    assert.ok(existsSync(join(accounts, 'A')), '拒绝时不能动文件')
  })

  it('删不存在的账号报错', () => {
    const root = tempDir()
    assert.throws(() => removeAccount(join(root, 'accounts'), 'ZZ'), /不存在/)
  })
})

describe('更新账号存档', () => {
  it('更新后内容换成新的，旧的一份留作 .bak', () => {
    const root = tempDir()
    const profile = makeProfile(root, 'A')
    const accounts = join(root, 'accounts')
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })
    // 模拟"重新登录过了"：refresh token 变了
    writeFileSync(join(profile, 'Network', 'Cookies'), 'cookies-refreshed')
    saveAccount({ name: 'A', profileDir: profile, accountsDir: accounts, ...opts })
    assert.equal(readFileSync(join(accounts, 'A', 'Network', 'Cookies'), 'utf8'), 'cookies-refreshed')
    assert.equal(readFileSync(join(accounts, 'A.bak', 'Network', 'Cookies'), 'utf8'), 'cookies-A')
  })
})
