import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'
import { connect } from 'node:net'
import { join } from 'node:path'

/**
 * 直接问内核：这条连接到底走了哪条链路。
 *
 * 为什么非要读内核而不是读配置：配置只说明"规则怎么写的"，不说明"这次连接怎么走的"。
 * 规则模式的泄露恰恰发生在两者不一致的时候（域名没匹配上、规则被它前面的条目先吃掉），
 * 只看配置永远查不出来。mihomo 的 `/connections` 每条都带 `chains` 与 `rule`，
 * 这是运行时事实。
 *
 * 注意管道名：配置里的 `external-controller-pipe` 可能和实际运行的不一样 ——
 * 本机实测配置写的是 `verge-mihomo-sidecar-release-…`，服务模式实际跑的是
 * `verge-mihomo-production-…`，按配置连会 ENOENT。所以优先从内核命令行取
 * `-ext-ctl-pipe`，取不到才退回配置。
 */

const CORE_NAMES = ['verge-mihomo', 'mihomo', 'clash-meta', 'FlClashCore', 'clash-win64']

/** 从内核进程命令行里抠出 `-ext-ctl-pipe <name>`。 */
export function findControlPipe({
  run = (script) =>
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], {
      windowsHide: true,
      encoding: 'utf8',
      timeout: 15_000,
    }),
} = {}) {
  const filter = CORE_NAMES.map((name) => `Name='${name}.exe'`).join(' or ')
  const script = `Get-CimInstance Win32_Process -Filter "${filter}" | Select-Object -ExpandProperty CommandLine; exit 0`
  let raw
  try {
    raw = run(script)
  } catch {
    return null
  }
  for (const line of String(raw ?? '').split(/\r?\n/)) {
    const match = line.trim().match(/-ext-ctl-pipe\s+(\S+)/i)
    if (match) return match[1]
  }
  return null
}

/** 配置里声明的管道名（内核命令行拿不到时的兜底）。 */
export function controllerPipeFromConfig(dir, { exists, readFile = (p) => readFileSync(p, 'utf8') } = {}) {
  const path = join(dir, 'clash-verge.yaml')
  if (exists && !exists(path)) return null
  try {
    const match = readFile(path).match(/^external-controller-pipe:\s*(.+)$/m)
    if (!match) return null
    return match[1].trim().replace(/^['"]|['"]$/g, '') || null
  } catch {
    return null
  }
}

/** 配置里的 secret（本地管道也校验它）。 */
export function controllerSecret(dir, { exists, readFile = (p) => readFileSync(p, 'utf8') } = {}) {
  const path = join(dir, 'clash-verge.yaml')
  if (exists && !exists(path)) return undefined
  try {
    const match = readFile(path).match(/^secret:\s*(.+)$/m)
    return match ? match[1].trim().replace(/^['"]|['"]$/g, '') : undefined
  } catch {
    return undefined
  }
}

/** 走命名管道发一个 GET，返回解析后的 JSON。管道不通就抛错，不吞。 */
export function getOverPipe(pipe, path, { secret, timeout = 4000 } = {}) {
  return new Promise((resolve, reject) => {
    if (!pipe) {
      reject(new Error('没有可用的内核控制管道'))
      return
    }
    const req = httpRequest(
      {
        socketPath: pipe,
        path,
        method: 'GET',
        timeout,
        headers: secret ? { Authorization: `Bearer ${secret}` } : {},
      },
      (res) => {
        let body = ''
        res.setEncoding('utf8')
        res.on('data', (chunk) => (body += chunk))
        res.on('end', () => {
          if (res.statusCode !== 200) {
            reject(new Error(`内核接口返回 ${res.statusCode}`))
            return
          }
          try {
            resolve(JSON.parse(body))
          } catch (error) {
            reject(new Error(`内核接口返回的不是 JSON：${error.message}`))
          }
        })
      },
    )
    req.on('timeout', () => {
      req.destroy(new Error('内核接口超时'))
    })
    req.on('error', reject)
    req.end()
  })
}

/** 这些是 Claude 客户端会连的域名（后缀匹配）。 */
export const CLAUDE_HOST_SUFFIXES = [
  'anthropic.com',
  'claude.ai',
  'claude.com',
  'claudeusercontent.com',
  'statsig.com',
  'featuregates.org',
]

export function isClaudeHost(host) {
  const value = String(host ?? '')
    .toLowerCase()
    .replace(/:\d+$/, '')
  if (!value) return false
  return CLAUDE_HOST_SUFFIXES.some(
    (suffix) => value === suffix || value.endsWith(`.${suffix}`),
  )
}

/** Claude 的进程（Desktop 与它内置的 claude-code 都叫 claude.exe）。 */
export function isClaudeProcess(processPath) {
  return /\\claude\.exe$/i.test(String(processPath ?? ''))
}

/**
 * 从内核的连接表里挑出"Claude 的连接却走了直连"的那些。
 *
 * 直连的判据：`chains` 为空、或第一跳就是 DIRECT —— 这两种情况出口都是物理网卡。
 * 命中代理的连接 `chains` 末尾一定是代理组/节点名。
 */
export function judgeClaudeConnections(connections = []) {
  const list = Array.isArray(connections) ? connections : []
  const leaks = []
  let claude = 0
  for (const conn of list) {
    const host = conn?.metadata?.host ?? conn?.metadata?.destinationIP ?? ''
    const processPath = conn?.metadata?.processPath ?? ''
    if (!isClaudeHost(host) && !isClaudeProcess(processPath)) continue
    claude += 1
    const chains = Array.isArray(conn.chains) ? conn.chains : []
    const first = String(chains[0] ?? '').toUpperCase()
    if (chains.length === 0 || first === 'DIRECT' || first === 'REJECT') {
      leaks.push({
        host: host || processPath,
        chains,
        rule: conn.rule ?? '',
        rulePayload: conn.rulePayload ?? '',
      })
    }
  }
  return { checked: list.length, claude, leaks }
}

/**
 * 通过混合端口开一条 CONNECT 隧道，用来"制造"一条可观测的连接。
 *
 * 只是建链、不发请求就关掉，用来在 Claude 空闲时也能问内核"这个域名走哪条规则"。
 */
export function openConnectTunnel({ port, host, timeout = 5000 }) {
  return new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port })
    let buffer = ''
    let settled = false
    const fail = (error) => {
      if (settled) return
      settled = true
      socket.destroy()
      reject(error)
    }
    const timer = setTimeout(() => fail(new Error(`CONNECT ${host} 超时`)), timeout)
    socket.setEncoding('utf8')
    socket.on('connect', () => {
      socket.write(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n\r\n`)
    })
    socket.on('data', (chunk) => {
      buffer += chunk
      if (!buffer.includes('\r\n\r\n')) return
      if (!/^HTTP\/1\.[01] 200/.test(buffer)) {
        clearTimeout(timer)
        fail(new Error(`CONNECT ${host} 被拒绝：${buffer.split('\r\n')[0]}`))
        return
      }
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolve({
        host,
        close: () => socket.destroy(),
      })
    })
    socket.on('error', fail)
  })
}

/**
 * 实测一次：让内核自己说 Claude 的域名命中了哪条规则。
 *
 * 每条域名先开隧道、再读连接表、再关掉。返回每条域名的 `{ host, chains, rule }`。
 * 读不到连接表就返回 `checked: false` —— 不拿"没测到"当"没问题"。
 */
export async function probeClaudeRouting({
  pipe,
  secret,
  port,
  hosts = ['claude.ai', 'api.anthropic.com'],
  open = openConnectTunnel,
  read = (target, path) => getOverPipe(target, path, { secret }),
} = {}) {
  const results = []
  for (const host of hosts) {
    let tunnel
    try {
      tunnel = await open({ port, host })
    } catch (error) {
      results.push({ host, error: error.message })
      continue
    }
    try {
      const payload = await read(pipe, '/connections')
      const list = payload?.connections ?? []
      const normalize = (value) => String(value ?? '').toLowerCase()
      const found =
        list.find((conn) => normalize(conn?.metadata?.host) === host) ??
        list.find((conn) => isClaudeHost(conn?.metadata?.host))
      if (!found) {
        results.push({ host, error: '连接表里没看到这条连接' })
        continue
      }
      results.push({
        host,
        chains: found.chains ?? [],
        rule: found.rule ?? '',
        rulePayload: found.rulePayload ?? '',
      })
    } catch (error) {
      results.push({ host, error: error.message })
    } finally {
      tunnel.close()
    }
  }

  const judged = judgeClaudeConnections(
    results
      .filter((item) => !item.error)
      .map((item) => ({ metadata: { host: item.host }, chains: item.chains, rule: item.rule })),
  )
  return {
    checked: results.some((item) => !item.error),
    results,
    leaks: judged.leaks,
    ok: results.some((item) => !item.error) && judged.leaks.length === 0,
  }
}

/**
 * 切到规则模式之后的自证：模式真的是 rule，且 Claude 的域名真的走了代理。
 *
 * 内核重启后管道要过一会儿才起来，所以带重试；重试用尽仍测不出来就返回
 * `checked: false` —— 调用方应当据此回滚，而不是把"没测到"当成"没问题"。
 */
export async function verifyClaudeRouting({
  dir,
  hosts = ['claude.ai', 'api.anthropic.com', 'claudeusercontent.com'],
  readFile = (p) => readFileSync(p, 'utf8'),
  attempts = 8,
  delayMs = 1200,
  findPipe = findControlPipe,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
  let lastError = null
  for (let i = 0; i < attempts; i += 1) {
    const pipe = findPipe() ?? controllerPipeFromConfig(dir, { readFile })
    if (pipe) {
      const secret = controllerSecret(dir, { readFile })
      try {
        const configs = await getOverPipe(pipe, '/configs', { secret })
        if (String(configs?.mode).toLowerCase() === 'rule') {
          const probe = await probeClaudeRouting({
            pipe,
            secret,
            port: Number(configs['mixed-port'] ?? 0),
            hosts,
          })
          if (probe.checked) return { ...probe, mode: configs.mode, pipe }
          lastError = '内核里看不到 Claude 的连接（可能是没起来或没在监听）'
        } else {
          lastError = `内核报告的仍是 ${configs?.mode ?? '未知'} 模式`
        }
      } catch (error) {
        lastError = error.message
      }
    } else {
      lastError = '没有找到内核控制管道'
    }
    if (i < attempts - 1) await sleep(delayMs)
  }
  return { ok: false, checked: false, mode: null, leaks: [], results: [], error: lastError }
}
