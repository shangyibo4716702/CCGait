import { after, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  copySessions,
  listSessionGroups,
  listSessions,
  projectFolderFor,
  sessionBodyExists,
} from '../src/sessions-sync.js'

const tempDirs = []
function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), 'ccgait-sync-'))
  tempDirs.push(dir)
  return dir
}
after(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

function writeSession(dir, { sessionId, title, cliSessionId, cwd = 'D:\\proj', lastActivityAt = 1000 }) {
  mkdirSync(dir, { recursive: true })
  writeFileSync(
    join(dir, `${sessionId}.json`),
    JSON.stringify({ sessionId, cliSessionId, title, cwd, lastActivityAt, createdAt: 1, completedTurns: 3 }),
  )
}

function makeProfile(root, accountUuid, orgUuid, sessions) {
  const dir = join(root, 'claude-code-sessions', accountUuid, orgUuid)
  // 空数组也要把目录建出来：目标账号存在但没有会话是合法状态。
  mkdirSync(dir, { recursive: true })
  for (const session of sessions) writeSession(dir, session)
  return dir
}

describe('项目目录名推导', () => {
  it('冒号、反斜杠、空格都各变成一个短横', () => {
    // 实测：D:\Unreal Projects\GASPDemo → D--Unreal-Projects-GASPDemo
    assert.equal(
      projectFolderFor('D:\\Unreal Projects\\GASPDemo\\Plugins\\ExternalAnimationFramework'),
      'D--Unreal-Projects-GASPDemo-Plugins-ExternalAnimationFramework',
    )
    assert.equal(projectFolderFor('D:\\CCGait'), 'D--CCGait')
    assert.equal(projectFolderFor(''), undefined)
  })
})

describe('会话清单', () => {
  it('列出账号/组织组合与各自会话数', () => {
    const root = tempDir()
    makeProfile(root, 'acc1', 'org1', [{ sessionId: 's1', title: 'a' }])
    makeProfile(root, 'acc1', 'org2', [{ sessionId: 's2', title: 'b' }])
    const groups = listSessionGroups(root)
    assert.equal(groups.length, 2)
    assert.deepEqual(
      groups.map((g) => `${g.accountUuid}/${g.orgUuid}:${g.count}`).sort(),
      ['acc1/org1:1', 'acc1/org2:1'],
    )
  })

  it('会话按最近活跃倒序，跳过损坏的索引', () => {
    const dir = join(tempDir(), 'sessions')
    writeSession(dir, { sessionId: 'old', title: '旧会话', lastActivityAt: 100 })
    writeSession(dir, { sessionId: 'new', title: '新会话', lastActivityAt: 900 })
    writeFileSync(join(dir, 'broken.json'), '{ not json')

    const sessions = listSessions(dir)
    assert.equal(sessions.length, 2, '坏文件被跳过')
    assert.equal(sessions[0].title, '新会话')
    assert.equal(sessions[1].title, '旧会话')
  })

  it('标题为 undefined 字符串时给可读占位', () => {
    const dir = join(tempDir(), 'sessions')
    writeSession(dir, { sessionId: 's1', title: 'undefined' })
    assert.equal(listSessions(dir)[0].title, '(未命名会话)')
  })
})

describe('复制会话索引', () => {
  it('只复制选中的那几个，正文留在原处不动', () => {
    const root = tempDir()
    const source = makeProfile(root, 'src', 'org', [
      { sessionId: 's1', title: '要的' },
      { sessionId: 's2', title: '不要的' },
    ])
    const target = makeProfile(root, 'dst', 'org', [{ sessionId: 'x', title: '对方自己的' }])

    const result = copySessions({ sourceDir: source, targetDir: target, sessionIds: ['s1'] })
    assert.equal(result.copied.length, 1)
    assert.equal(result.copied[0].sessionId, 's1')
    assert.ok(existsSync(join(target, 's1.json')))
    assert.ok(!existsSync(join(target, 's2.json')), '没选中的不能带过去')
    assert.ok(existsSync(join(target, 'x.json')), '目标自己的会话不能被删')
  })

  it('目标已有同一会话时跳过，不覆盖', () => {
    const root = tempDir()
    const source = makeProfile(root, 'src', 'org', [{ sessionId: 's1', title: '源标题' }])
    const target = makeProfile(root, 'dst', 'org', [{ sessionId: 's1', title: '目标标题' }])
    const result = copySessions({ sourceDir: source, targetDir: target, sessionIds: ['s1'] })
    assert.equal(result.copied.length, 0)
    assert.equal(result.skipped.length, 1)
    const kept = JSON.parse(readFileSync(join(target, 's1.json'), 'utf8'))
    assert.equal(kept.title, '目标标题', '不能覆盖目标账号自己的会话')
  })

  it('没选任何会话就报错（不允许默认全同步）', () => {
    const root = tempDir()
    const source = makeProfile(root, 'src', 'org', [{ sessionId: 's1', title: 'a' }])
    const target = makeProfile(root, 'dst', 'org', [])
    assert.throws(() => copySessions({ sourceDir: source, targetDir: target, sessionIds: [] }), /没有选择/)
    assert.throws(() => copySessions({ sourceDir: source, targetDir: target }), /没有选择/)
  })

  it('目标组织目录不存在时报错，不擅自新建', () => {
    const root = tempDir()
    const source = makeProfile(root, 'src', 'org', [{ sessionId: 's1', title: 'a' }])
    const missing = join(root, 'claude-code-sessions', 'dst', 'guess-org')
    assert.throws(
      () => copySessions({ sourceDir: source, targetDir: missing, sessionIds: ['s1'] }),
      /目标账号还没有对应的组织目录/,
    )
    assert.ok(!existsSync(missing), '不能凭空建一个猜出来的组织目录')
  })

  it('源里没有的 sessionId 记为缺失', () => {
    const root = tempDir()
    const source = makeProfile(root, 'src', 'org', [{ sessionId: 's1', title: 'a' }])
    const target = makeProfile(root, 'dst', 'org', [])
    const result = copySessions({ sourceDir: source, targetDir: target, sessionIds: ['s1', 'nope'] })
    assert.equal(result.copied.length, 1)
    assert.deepEqual(result.missing, ['nope'])
  })
})

describe('正文存在性', () => {
  it('按 cwd 推出的目录名找 jsonl', () => {
    const root = tempDir()
    const folder = projectFolderFor('D:\\CCGait')
    mkdirSync(join(root, folder), { recursive: true })
    writeFileSync(join(root, folder, 'abc.jsonl'), '{}')

    assert.equal(
      sessionBodyExists({ claudeProjectsDir: root, projectFolder: folder, cliSessionId: 'abc' }),
      true,
    )
    assert.equal(
      sessionBodyExists({ claudeProjectsDir: root, projectFolder: folder, cliSessionId: 'missing' }),
      false,
    )
    assert.equal(sessionBodyExists({ claudeProjectsDir: root, projectFolder: folder }), false)
  })
})
