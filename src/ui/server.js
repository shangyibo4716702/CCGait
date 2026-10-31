import { createServer } from 'node:http'
import { createHash, randomBytes } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { extname, join, normalize, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { buildFaviconIco, buildIconSvg } from '../win/icon.js'

/**
 * 本地 Web 客户端服务。
 *
 * 安全边界（这个服务能改防火墙规则、能结束进程，必须收紧）：
 * 1. **只监听 127.0.0.1**，不对外网暴露；
 * 2. **校验 Host 头**：只接受 localhost / 127.0.0.1 / [::1]，防 DNS 重绑定（恶意域名解析
 *    到本机后从浏览器里访问本服务）；
 * 3. **会话令牌**：所有 /api/* 请求都要带启动时随机生成的令牌；令牌只写进本机页面，
 *    跨站页面拿不到，因此站点无法伪造请求；
 * 4. **不设 CORS 头**：其它来源读不到响应；
 * 5. **只读静态文件且限定目录**：路径规范化后必须仍在 public/ 内。
 */

const PUBLIC_DIR = resolve(fileURLToPath(new URL('./public', import.meta.url)))

/**
 * 服务端代码版本（本文件内容的哈希）。
 *
 * 为什么需要：升级后如果旧的服务进程还开着，它会继续用**旧代码**响应请求，
 * 而浏览器拿到的是磁盘上的**新前端**。两边字段对不上时页面会显示错误结论
 * （实测：旧后端没有 launchState 字段，前端把 undefined 渲染成"未被拦截"，
 * 而真实判定是"通过"）。把版本写进状态，前端一比对就知道该提示重载。
 */
const SERVER_BUILD = (() => {
  try {
    return createHash('sha256').update(readFileSync(fileURLToPath(import.meta.url))).digest('hex').slice(0, 12)
  } catch {
    return 'unknown'
  }
})()

/**
 * 图标内容版本：用 ICO 字节的哈希。
 *
 * 为什么需要：浏览器的 favicon 缓存按 URL 存，图标换了但 URL 不变，它就继续用旧图 ——
 * 实测出现过"换了图标、任务栏还是老样子"。把哈希写进 URL 查询串，内容一变 URL 就变，
 * 缓存自然失效；内容没变时 URL 稳定，也不会白白多一次请求。
 */
const ICON_VERSION = (() => {
  try {
    return createHash('sha256').update(buildFaviconIco()).digest('hex').slice(0, 10)
  } catch {
    return '0'
  }
})()

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.json': 'application/json; charset=utf-8',
}

const ALLOWED_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '::1'])

function hostAllowed(hostHeader) {
  if (!hostHeader) return false
  const hostname = hostHeader.startsWith('[')
    ? hostHeader.slice(0, hostHeader.indexOf(']') + 1)
    : hostHeader.split(':')[0]
  return ALLOWED_HOSTS.has(hostname.toLowerCase())
}

function sendJson(response, status, payload) {
  const body = JSON.stringify(payload)
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  })
  response.end(body)
}

async function readJsonBody(request, limitBytes = 512 * 1024) {
  const chunks = []
  let total = 0
  for await (const chunk of request) {
    total += chunk.length
    if (total > limitBytes) throw new Error('请求体过大')
    chunks.push(chunk)
  }
  if (chunks.length === 0) return {}
  try {
    const parsed = JSON.parse(Buffer.concat(chunks).toString('utf8'))
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('请求体必须是 JSON 对象')
    }
    return parsed
  } catch (error) {
    throw new Error(`请求体解析失败：${error instanceof Error ? error.message : String(error)}`)
  }
}

/** 图标只生成一次（每次请求重新编码 6 张 PNG 没必要）。 */
let cachedIco = null
let cachedSvg = null

function sendFavicon(response) {
  if (!cachedIco) cachedIco = buildFaviconIco()
  response.writeHead(200, {
    'content-type': 'image/x-icon',
    'content-length': cachedIco.length,
    'cache-control': 'no-store',
  })
  response.end(cachedIco)
}

/**
 * SVG 版图标：应用窗口的任务栏图标优先用它。
 *
 * 位图 favicon 只有固定尺寸，Edge 在 100% 缩放下要 24px、而位图里挑不到时会缩放，
 * 结果是任务栏那格发虚。SVG 由内核按目标分辨率现渲染，任何 DPI 都清晰。
 */
function sendIconSvg(response) {
  if (!cachedSvg) cachedSvg = Buffer.from(buildIconSvg(256), 'utf8')
  response.writeHead(200, {
    'content-type': 'image/svg+xml; charset=utf-8',
    'content-length': cachedSvg.length,
    'cache-control': 'no-store',
  })
  response.end(cachedSvg)
}

function serveStatic(response, urlPath, token) {
  const relative = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '')
  const target = resolve(join(PUBLIC_DIR, normalize(relative)))
  if (!target.startsWith(PUBLIC_DIR) || !existsSync(target)) {
    response.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' })
    response.end('Not found')
    return
  }
  let body = readFileSync(target)
  const type = MIME[extname(target).toLowerCase()] ?? 'application/octet-stream'
  // 令牌只注入页面本身；跨站页面读不到 HTML 内容（无 CORS），因此拿不到令牌。
  if (type.startsWith('text/html')) {
    body = Buffer.from(
      body
        .toString('utf8')
        .replaceAll('__CCGAIT_TOKEN__', token)
        .replaceAll('__CCGAIT_FRONTEND_BUILD__', SERVER_BUILD)
        .replaceAll('__CCGAIT_ICON_VERSION__', ICON_VERSION),
      'utf8',
    )
  }
  response.writeHead(200, {
    'content-type': type,
    'content-length': body.length,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'content-security-policy':
      "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'none'",
  })
  response.end(body)
}

/** 创建一个 UI 服务实例（不自动监听，便于测试里用随机端口）。 */
export function createUiServer({ session, logger, token = randomBytes(24).toString('hex') }) {
  const sseClients = new Set()

  const broadcast = (event) => {
    const payload = `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`
    for (const client of sseClients) {
      try {
        client.write(payload)
      } catch {
        sseClients.delete(client)
      }
    }
  }
  session.subscribe(broadcast)

  const server = createServer((request, response) => {
    void (async () => {
      const url = new URL(request.url ?? '/', 'http://127.0.0.1')
      const path = url.pathname

      if (!hostAllowed(request.headers.host)) {
        sendJson(response, 403, { error: 'Host 不被允许（只接受本机访问）' })
        return
      }

      if (!path.startsWith('/api/')) {
        if (request.method !== 'GET') {
          sendJson(response, 405, { error: '只支持 GET' })
          return
        }
        // 应用窗口是 Edge/Chrome 的 APP 模式承载的：任务栏那一格的图标取自**页面图标**。
        // 不提供 favicon 的话，任务栏按钮就落回一个空的默认图标（实测就是"没有图标"）。
        // 支持带查询串（/favicon.ico?v=…）：图标换了之后必须让浏览器当成新资源，
        // 否则它会一直用 profile 里缓存的旧图（实测：换了图标、任务栏还是老样子）。
        if (path === '/favicon.ico') {
          sendFavicon(response)
          return
        }
        if (path === '/icon.svg') {
          sendIconSvg(response)
          return
        }
        serveStatic(response, path, token)
        return
      }

      // 所有 API 都要令牌：GET 走查询参数（EventSource 不能自定义头），其余走请求头。
      const provided = request.headers['x-ccgait-token'] ?? url.searchParams.get('token')
      if (provided !== token) {
        sendJson(response, 401, { error: '会话令牌无效：请通过 ccgait ui 打开的页面访问' })
        return
      }

      if (path === '/api/events' && request.method === 'GET') {
        response.writeHead(200, {
          'content-type': 'text/event-stream; charset=utf-8',
          'cache-control': 'no-store',
          connection: 'keep-alive',
        })
        response.write(`event: hello\ndata: ${JSON.stringify({ type: 'hello', at: new Date().toISOString() })}\n\n`)
        sseClients.add(response)
        const heartbeat = setInterval(() => {
          try {
            response.write(': ping\n\n')
          } catch {
            clearInterval(heartbeat)
          }
        }, 20_000)
        request.on('close', () => {
          clearInterval(heartbeat)
          sseClients.delete(response)
        })
        return
      }

      if (path === '/api/status' && request.method === 'GET') {
        const status = await session.getStatus()
        sendJson(response, 200, { ...status, serverBuild: SERVER_BUILD })
        return
      }

      if (path === '/api/logs' && request.method === 'GET') {
        sendJson(response, 200, { logs: session.getLogs() })
        return
      }

      if (path === '/api/proxy' && request.method === 'GET') {
        sendJson(response, 200, await session.getProxyFixState())
        return
      }

      if (path === '/api/accounts' && request.method === 'GET') {
        sendJson(response, 200, await session.getAccounts())
        return
      }

      if (request.method !== 'POST') {
        sendJson(response, 405, { error: '只支持 GET / POST' })
        return
      }

      try {
        switch (path) {
          case '/api/check':
            sendJson(response, 200, { check: await session.checkNow() })
            return
          case '/api/guard/start':
            sendJson(response, 200, { guard: await session.startGuard() })
            return
          case '/api/guard/stop': {
            const body = await readJsonBody(request).catch(() => ({}))
            sendJson(response, 200, { guard: await session.stopGuard({ keepBlocks: body.keepBlocks === true }) })
            return
          }
          case '/api/firewall': {
            const body = await readJsonBody(request)
            sendJson(response, 200, { result: await session.setFirewall(body.enabled !== false) })
            return
          }
          case '/api/firewall/enable-profiles':
            sendJson(response, 200, { result: await session.enableFirewallProfiles() })
            return
          case '/api/kill':
            sendJson(response, 200, { result: await session.killProcesses() })
            return
          case '/api/accounts/save': {
            const body = await readJsonBody(request)
            sendJson(response, 200, await session.saveCurrentAccount(body.name))
            return
          }
          case '/api/proxy/fix':
            sendJson(response, 200, await session.fixClashSettings())
            return
          case '/api/proxy/safe-rule':
            sendJson(response, 200, await session.switchToRuleMode())
            return
          case '/api/accounts/create-empty': {
            const body = await readJsonBody(request)
            sendJson(response, 200, await session.createEmptyAccountFor(body.name))
            return
          }
          case '/api/accounts/update': {
            const body = await readJsonBody(request)
            sendJson(response, 200, await session.updateAccount(body.name))
            return
          }
          case '/api/accounts/delete': {
            const body = await readJsonBody(request)
            sendJson(response, 200, await session.deleteAccount(body.name))
            return
          }
          case '/api/accounts/sync/list': {
            const body = await readJsonBody(request)
            sendJson(response, 200, await session.listSyncableSessions(body.name))
            return
          }
          case '/api/accounts/sync': {
            const body = await readJsonBody(request)
            sendJson(
              response,
              200,
              await session.syncSessionsTo({
                from: body.from,
                to: body.to,
                sessionIds: body.sessionIds,
                sourceOrgUuid: body.sourceOrgUuid,
                targetOrgUuid: body.targetOrgUuid,
              }),
            )
            return
          }
          case '/api/accounts/switch': {
            const body = await readJsonBody(request)
            sendJson(response, 200, await session.switchAccountTo(body.name))
            return
          }
          case '/api/launch': {
            // 门控启动：内部会先跑一轮检测，判定通过才真的拉起 Claude Desktop。
            sendJson(response, 200, await session.launchClaudeDesktop())
            return
          }
          case '/api/config': {
            const body = await readJsonBody(request)
            sendJson(response, 200, { config: await session.saveConfig(body.patch ?? body) })
            return
          }
          case '/api/config/reload':
            sendJson(response, 200, { config: await session.reloadConfig() })
            return
          default:
            sendJson(response, 404, { error: `未知接口：${path}` })
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error)
        logger?.warn?.('UI 操作失败', `${path}：${message}`)
        sendJson(response, 400, { error: message })
      }
    })().catch((error) => {
      sendJson(response, 500, { error: error instanceof Error ? error.message : String(error) })
    })
  })

  return {
    server,
    token,
    listen(port, host = '127.0.0.1') {
      return new Promise((resolvePromise, reject) => {
        server.once('error', reject)
        server.listen(port, host, () => {
          server.removeListener('error', reject)
          resolvePromise(server.address())
        })
      })
    },
    async close() {
      for (const client of sseClients) {
        try {
          client.end()
        } catch {
          // 忽略。
        }
      }
      sseClients.clear()
      await new Promise((resolvePromise) => server.close(() => resolvePromise()))
    },
  }
}
