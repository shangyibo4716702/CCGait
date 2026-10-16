import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect as tlsConnect } from 'node:tls'

/**
 * 极简 HTTP 客户端：支持「直连」与「经 HTTP(S) 代理（CONNECT 隧道）」两种取数路径。
 *
 * 为什么要支持代理：判定必须测**客户端真正会走的出口**。Claude Code CLI 与 Desktop
 * 若被配置成经代理出去，那么直连测到的 IP 毫无意义 —— 检测要走同一条路。
 */

const DEFAULT_TIMEOUT_MS = 8000
const USER_AGENT = 'ccgait/0.1 (environment gate)'

/** 经代理建立到目标的 CONNECT 隧道，返回裸 socket。 */
export async function openTunnel(proxyUrl, targetHost, targetPort, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const proxy = new URL(proxyUrl)
  if (proxy.protocol !== 'http:' && proxy.protocol !== 'https:') {
    throw new Error(`不支持的代理协议：${proxy.protocol}`)
  }
  const secureProxy = proxy.protocol === 'https:'
  const requestFn = secureProxy ? httpsRequest : httpRequest
  const headers = {}
  if (proxy.username || proxy.password) {
    const credentials = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`
    headers['proxy-authorization'] = `Basic ${Buffer.from(credentials).toString('base64')}`
  }

  return await new Promise((resolve, reject) => {
    const req = requestFn({
      host: proxy.hostname,
      port: proxy.port === '' ? (secureProxy ? 443 : 80) : Number(proxy.port),
      method: 'CONNECT',
      path: `${targetHost}:${targetPort}`,
      headers,
      timeout: timeoutMs,
    })
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy()
        reject(new Error(`代理 CONNECT 失败：HTTP ${res.statusCode}`))
        return
      }
      resolve(socket)
    })
    req.on('timeout', () => req.destroy(new Error('代理 CONNECT 超时')))
    req.on('error', reject)
    req.end()
  })
}

function collectBody(res) {
  return new Promise((resolve, reject) => {
    const chunks = []
    res.on('data', (chunk) => chunks.push(chunk))
    res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    res.on('error', reject)
  })
}

/** 经已建立的隧道发一次请求，返回 { status, text }。 */
export async function requestThroughTunnel(url, tunnelSocket, options = {}) {
  const target = new URL(url)
  const isTls = target.protocol === 'https:'
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const socket = isTls
    ? tlsConnect({ socket: tunnelSocket, servername: target.hostname })
    : tunnelSocket
  const requestFn = isTls ? httpsRequest : httpRequest
  if (isTls) {
    await new Promise((resolve, reject) => {
      socket.once('secureConnect', resolve)
      socket.once('error', reject)
    })
  }

  return await new Promise((resolve, reject) => {
    const req = requestFn(
      {
        host: target.hostname,
        port: target.port === '' ? (isTls ? 443 : 80) : Number(target.port),
        path: `${target.pathname}${target.search}`,
        method: options.method ?? 'GET',
        headers: {
          host: target.hostname,
          'user-agent': USER_AGENT,
          'accept-encoding': 'identity',
          ...(options.headers ?? {}),
        },
        createConnection: () => socket,
        timeout: timeoutMs,
      },
      async (res) => {
        try {
          resolve({ status: res.statusCode ?? 0, text: await collectBody(res) })
        } catch (error) {
          reject(error)
        }
      },
    )
    req.on('timeout', () => req.destroy(new Error('请求超时')))
    req.on('error', reject)
    if (options.body !== undefined) req.write(options.body)
    req.end()
  })
}

/** 取文本。proxyUrl 为空表示直连。options.body 存在时按 POST 发送（默认 JSON）。 */
export async function fetchText(url, options = {}) {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const method = options.method ?? (options.body === undefined ? 'GET' : 'POST')
  const body = options.body
  const extraHeaders = body === undefined ? {} : { 'content-type': 'application/json' }

  if (!options.proxyUrl) {
    const res = await fetch(url, {
      method,
      ...(body === undefined ? {} : { body }),
      signal: AbortSignal.timeout(timeoutMs),
      headers: {
        'user-agent': USER_AGENT,
        'accept-encoding': 'identity',
        ...extraHeaders,
        ...(options.headers ?? {}),
      },
    })
    return { status: res.status, text: await res.text() }
  }
  const target = new URL(url)
  const port = target.port === '' ? (target.protocol === 'https:' ? 443 : 80) : Number(target.port)
  const tunnel = await openTunnel(options.proxyUrl, target.hostname, port, timeoutMs)
  try {
    return await requestThroughTunnel(url, tunnel, {
      ...options,
      method,
      ...(body === undefined
        ? {}
        : { headers: { ...extraHeaders, 'content-length': String(Buffer.byteLength(body)) }, body }),
    })
  } finally {
    tunnel.destroy()
  }
}

/** 取 JSON；解析失败抛出带片段的可读错误。 */
export async function fetchJson(url, options = {}) {
  const { status, text } = await fetchText(url, options)
  if (status < 200 || status >= 300) {
    throw new Error(`HTTP ${status}`)
  }
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(`响应不是 JSON：${text.slice(0, 120).replace(/\s+/g, ' ')}`)
  }
}

/** 解析 key=value 形式的纯文本（Cloudflare /cdn-cgi/trace）。 */
export function parseKeyValueText(text) {
  const out = {}
  for (const line of text.split('\n')) {
    const separator = line.indexOf('=')
    if (separator <= 0) continue
    out[line.slice(0, separator).trim()] = line.slice(separator + 1).trim()
  }
  return out
}
