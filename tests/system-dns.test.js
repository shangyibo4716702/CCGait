import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  SAFE_SYSTEM_DNS,
  isFakeIpDns,
  isProxyCoreRunning,
  planDnsRecovery,
  readAdapterDns,
  repairSystemDns,
  restoreAdapterDns,
} from '../src/win/system-dns.js'

describe('fake-ip 地址识别', () => {
  it('198.18/198.19 段算 fake-ip', () => {
    assert.equal(isFakeIpDns('198.18.0.2'), true)
    assert.equal(isFakeIpDns('198.19.4.4'), true)
  })

  it('普通地址不算', () => {
    assert.equal(isFakeIpDns('223.5.5.5'), false)
    assert.equal(isFakeIpDns('198.20.0.1'), false)
    assert.equal(isFakeIpDns(''), false)
    assert.equal(isFakeIpDns('fd00::1'), false)
  })
})

describe('恢复计划', () => {
  const adapters = [
    { index: 5, alias: 'WLAN', servers: ['198.18.0.2'] },
    { index: 12, alias: 'Meta', servers: ['198.18.0.2'] },
    { index: 7, alias: '以太网', servers: ['223.5.5.5'] },
  ]

  it('内核在跑 → 一律不动', () => {
    assert.deepEqual(planDnsRecovery(adapters, { coreRunning: true }), [])
  })

  it('内核不在 → 只挑指向 fake-ip 的网卡', () => {
    assert.deepEqual(planDnsRecovery(adapters, { coreRunning: false }), ['WLAN', 'Meta'])
  })

  it('没有 fake-ip 时不动', () => {
    assert.deepEqual(planDnsRecovery([adapters[2]], { coreRunning: false }), [])
  })
})

describe('系统 DNS 读写', () => {
  it('解析 PowerShell 输出', () => {
    const adapters = readAdapterDns({
      run: () => '5|WLAN|198.18.0.2\r\n12|Meta|198.18.0.2,223.5.5.5\r\n',
    })
    assert.deepEqual(adapters, [
      { index: 5, alias: 'WLAN', servers: ['198.18.0.2'] },
      { index: 12, alias: 'Meta', servers: ['198.18.0.2', '223.5.5.5'] },
    ])
  })

  it('内核探测：有进程为 true，查不出来也当 true（宁可不动网卡）', () => {
    assert.equal(isProxyCoreRunning({ run: () => '2\r\n' }), true)
    assert.equal(isProxyCoreRunning({ run: () => '0\r\n' }), false)
    assert.equal(
      isProxyCoreRunning({
        run: () => {
          throw new Error('boom')
        },
      }),
      true,
    )
  })

  it('逐网卡恢复，单块失败不影响其它', () => {
    const calls = []
    const done = restoreAdapterDns([5, 12], {
      run: (script) => {
        calls.push(script)
        if (script.includes('12')) throw new Error('denied')
      },
    })
    assert.deepEqual(done, [5])
    assert.equal(calls.length, 2)
    assert.match(calls[0], /223\.5\.5\.5/)
  })

  it('repairSystemDns：内核不在时修，在时不修', () => {
    const adapters = [{ index: 5, alias: 'WLAN', servers: ['198.18.0.2'] }]
    const fixed = repairSystemDns({
      readDns: () => adapters,
      coreRunning: () => false,
      restore: (indexes) => indexes,
    })
    assert.deepEqual(fixed.repaired, [5])

    const untouched = repairSystemDns({
      readDns: () => adapters,
      coreRunning: () => true,
      restore: () => {
        throw new Error('不该被调用')
      },
    })
    assert.deepEqual(untouched.repaired, [])
    assert.equal(untouched.coreRunning, true)
  })

  it('默认兜底解析器是国内公共 DNS', () => {
    assert.deepEqual(SAFE_SYSTEM_DNS, ['223.5.5.5', '119.29.29.29'])
  })
})
