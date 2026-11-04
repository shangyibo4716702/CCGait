import { spawn } from 'node:child_process'
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { killProcesses } from '../src/process-guard.js'

const isWindows = process.platform === 'win32'

const alive = (pid) => {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    return error?.code === 'EPERM'
  }
}

describe('批量结束进程', { skip: !isWindows }, () => {
  it('空列表不 spawn，直接返回', async () => {
    assert.deepEqual(await killProcesses([]), [])
    assert.deepEqual(await killProcesses(undefined), [])
  })

  it('一条命令结束多个进程，pid 去重', async () => {
    const spawnDummy = () =>
      spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'], { stdio: 'ignore' })
    const a = spawnDummy()
    const b = spawnDummy()
    try {
      await new Promise((resolve) => setTimeout(resolve, 300))
      assert.equal(alive(a.pid), true)
      const result = await killProcesses([a.pid, b.pid, a.pid])
      assert.equal(result.length, 2, '重复 pid 应被去掉')
      // 进程退出是异步的，给它一点时间
      for (let i = 0; i < 40 && (alive(a.pid) || alive(b.pid)); i += 1) {
        await new Promise((resolve) => setTimeout(resolve, 50))
      }
      assert.equal(alive(a.pid), false)
      assert.equal(alive(b.pid), false)
    } finally {
      for (const child of [a, b]) {
        if (child.exitCode === null) child.kill('SIGKILL')
      }
    }
  })

  it('不存在的 pid 不抛错', async () => {
    const result = await killProcesses([999999])
    assert.equal(result.length, 1)
    assert.equal(result[0].pid, 999999)
  })
})
