import { execFileSync } from 'node:child_process'

/**
 * 代理关掉之后还能不能上网。
 *
 * 问题出在哪：Clash 的「DNS 覆写」会把网卡 DNS 改成 fake-ip 段里的地址
 * （本机是 198.18.0.2）。开着 TUN 时那个地址由 Clash 应答；Clash 一退出，
 * 网卡还指着它，系统问谁都问不到 —— 表现为**国内国外全都打不开**，
 * 而不只是"代理没开"。
 *
 * 这里只做一件事：内核不在、网卡却还指着 fake-ip 地址时，把 DNS 恢复成
 * 国内公共解析器。内核在的时候一概不动，避免和代理客户端抢配置。
 */

/** 内核不在时给网卡用的解析器（国内可用、稳定、不需要代理）。 */
export const SAFE_SYSTEM_DNS = ['223.5.5.5', '119.29.29.29']

const CORE_NAMES = ['verge-mihomo', 'mihomo', 'clash-meta', 'FlClashCore', 'clash-win64']

/** 198.18.0.0/15 是 fake-ip 默认段（mihomo 用 198.18.0.1/16）。 */
export function isFakeIpDns(address) {
  const ip = String(address ?? '').trim()
  const match = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/)
  if (!match) return false
  const [a, b] = [Number(match[1]), Number(match[2])]
  return a === 198 && (b === 18 || b === 19)
}

/**
 * 哪些网卡需要恢复。纯函数，便于测试。
 *
 * `coreRunning` 为 true 时一律返回空 —— 内核还在跑，DNS 指向它是对的。
 */
export function planDnsRecovery(adapters = [], { coreRunning = false } = {}) {
  if (coreRunning) return []
  return adapters
    .filter((adapter) => (adapter.servers ?? []).some((server) => isFakeIpDns(server)))
    .map((adapter) => adapter.alias)
}

/** 网卡 → DNS 列表。走 PowerShell，返回结构化数组。 */
export function readAdapterDns({
  run = (script) => execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
    windowsHide: true,
    encoding: 'utf8',
    timeout: 15_000,
  }),
} = {}) {
  const script = [
    'Get-DnsClientServerAddress -AddressFamily IPv4',
    '| Where-Object { $_.ServerAddresses.Count -gt 0 }',
    "| ForEach-Object { \"$($_.InterfaceIndex)|$($_.InterfaceAlias)|$($_.ServerAddresses -join ',')\" }",
    '; exit 0',
  ].join(' ')
  const raw = run(script)
  const adapters = []
  for (const line of String(raw ?? '').split(/\r?\n/)) {
    const parts = line.trim().split('|')
    if (parts.length < 3) continue
    const index = Number(parts[0])
    if (!Number.isInteger(index)) continue
    adapters.push({
      index,
      alias: parts[1],
      servers: parts[2].split(',').map((item) => item.trim()).filter(Boolean),
    })
  }
  return adapters
}

/** 代理内核在不在跑。 */
export function isProxyCoreRunning({
  run = (script) => execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
    windowsHide: true,
    encoding: 'utf8',
    timeout: 10_000,
  }),
} = {}) {
  const script = `@(Get-Process -Name ${CORE_NAMES.join(',')} -ErrorAction SilentlyContinue).Count; exit 0`
  try {
    return Number(String(run(script)).trim()) > 0
  } catch {
    // 查不出来就当"在跑"：宁可不动网卡，也不要和代理客户端抢。
    return true
  }
}

/** 把指定网卡的 DNS 换成国内公共解析器。 */
export function restoreAdapterDns(
  indexes,
  {
    servers = SAFE_SYSTEM_DNS,
    run = (script) => execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      windowsHide: true,
      encoding: 'utf8',
      timeout: 15_000,
    }),
  } = {},
) {
  const done = []
  for (const index of indexes) {
    try {
      run(
        `Set-DnsClientServerAddress -InterfaceIndex ${Number(index)} -ServerAddresses ${servers.join(',')}; exit 0`,
      )
      done.push(index)
    } catch {
      // 单个网卡失败（多半是没权限）不影响其它网卡
    }
  }
  return done
}

/**
 * 自愈入口：内核不在 + 网卡指向 fake-ip → 恢复成国内 DNS。
 *
 * 返回 `{ checked, coreRunning, repaired, adapters }`，调用方据此写日志。
 */
export function repairSystemDns({ readDns = readAdapterDns, coreRunning = isProxyCoreRunning, restore = restoreAdapterDns } = {}) {
  const adapters = readDns()
  const running = coreRunning()
  const targets = adapters.filter((adapter) => planDnsRecovery([adapter], { coreRunning: running }).length > 0)
  if (targets.length === 0) return { checked: true, coreRunning: running, repaired: [], adapters }
  const repaired = restore(targets.map((adapter) => adapter.index))
  return { checked: true, coreRunning: running, repaired, adapters }
}
