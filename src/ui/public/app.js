/**
 * CCGait 前端。纯原生 ES 模块，无框架、无外部资源（离线可用，也不会向外发请求）。
 *
 * 数据来源两条：
 * - REST：拉取状态快照、触发动作；
 * - SSE（/api/events）：闸门状态变化、检测结果、日志实时推送。
 */

const TOKEN = document.querySelector('meta[name="ccgait-token"]').content
// 本页面（前端）的构建标识，由服务端投递 HTML 时注入；与服务端返回的 serverBuild 比对。
const FRONTEND_BUILD = document.querySelector('meta[name="ccgait-frontend-build"]')?.content
let buildMismatchReported = false

/**
 * 前后端版本是否错配。
 *
 * 为什么必须检查：升级后如果**旧的服务进程**还开着，它会用旧代码响应 API，
 * 而浏览器加载的是磁盘上的新前端。两边字段对不上时页面会给出错误结论
 * （实测：旧后端没有 launchState 字段，前端把 undefined 渲染成"未被拦截"，
 * 而真实判定是"通过"）。这比"没更新"更危险 —— 它显示的是反的结论。
 */
function checkBuildMatch() {
  if (buildMismatchReported) return
  const server = status?.serverBuild
  if (!server || !FRONTEND_BUILD || server === 'unknown' || FRONTEND_BUILD === 'unknown') return
  if (server === FRONTEND_BUILD) return
  buildMismatchReported = true
  const host = document.querySelector('#side-status')
  if (host) {
    host.textContent = '界面与后台版本不一致：请完全关闭页面后重新打开（旧的服务进程还在跑）'
    host.style.color = 'var(--danger-text)'
  }
  toast('error', '界面与后台版本不一致', '旧的服务进程还在运行，显示的状态可能不正确。请关闭本页并重新打开。')
}

const CHECK_LABELS = {
  egressIp: { name: '出口 IP / 国家 / ASN', scope: '白名单主体' },
  claudeDns: { name: 'Claude 域名解析落地', scope: '解析被污染时命中' },
  timezone: { name: '系统时区', scope: '如 Asia/Shanghai' },
  language: { name: '界面语言', scope: '列表含 zh-CN' },
  fonts: { name: '中文字体指纹', scope: '等线 / 鸿蒙 / 阿里普惠体' },
  emojiFlags: { name: 'Emoji 国旗渲染', scope: '系统 emoji 字体被裁剪' },
  resolverEgress: { name: '解析出口（实测）', scope: '谁在实际回答 DNS 查询' },
  dnsServers: { name: 'DNS 服务器位置', scope: '已连接网卡配置的公共解析器' },
  proxyEnvLeak: { name: '系统代理 / 分流覆盖', scope: 'CLI 是否直连' },
}

/** 出口相关的判定 id：出口卡片的结论标签与分区徽章都从这一组里取。 */
const EGRESS_IDS = [
  'egress-unknown',
  'egress-inconsistent',
  'egress-country',
  'egress-ip',
  'egress-cidr',
  'egress-asn',
  'egress-hosting',
  'egress-hosting-note',
  'egress-proxy-fallback',
]

const list = (value) => (Array.isArray(value) ? value : [])

/** ------------------------------------------------------------------ 网络 */

async function api(path, options = {}) {
  const response = await fetch(path, {
    method: options.method ?? 'GET',
    headers: {
      'x-ccgait-token': TOKEN,
      ...(options.body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(options.body === undefined ? {} : { body: JSON.stringify(options.body) }),
  })
  const text = await response.text()
  let payload
  try {
    payload = text ? JSON.parse(text) : {}
  } catch {
    throw new Error(`响应不是 JSON：${text.slice(0, 120)}`)
  }
  if (!response.ok) throw new Error(payload.error ?? `HTTP ${response.status}`)
  return payload
}

/** ------------------------------------------------------------------ 状态 */

let status = undefined
let busy = new Set()
const pending = new Set()

/**
 * 界面会话是否已失效。服务端每次启动都会生成新的会话令牌，而已经打开的页面还揣着旧令牌：
 * 重启界面之后，这个页面的每个请求都会 401，`refresh()` 抛错、DOM 停在最后一次渲染上 ——
 * 界面上那些结论就变成了过期数据，却看不出任何异样（实测：闸门正在拦截，页面还写着
 * "未被拦截"）。所以这里要显式认账，而不是让旧结论一直挂在屏幕上。
 */
let sessionLost = false

function setBusy(action, active) {
  if (active) pending.add(action)
  else pending.delete(action)
  renderActions()
}

async function run(action, fn, successMessage) {
  if (pending.has(action)) return
  setBusy(action, true)
  try {
    const result = await fn()
    if (successMessage) toast('ok', successMessage)
    return result
  } catch (error) {
    toast('error', '操作失败', error instanceof Error ? error.message : String(error))
    return undefined
  } finally {
    setBusy(action, false)
    void refresh()
  }
}

async function refresh() {
  try {
    // 账号面板也一起刷：它在侧栏常驻，用户改完登录态/切完号回来看到的是屏幕上的旧值，
    // 必须关掉页面重开才更新（实测被投诉）。这里并行拉，互不阻塞。
    const [next] = await Promise.all([api('/api/status'), refreshAccounts()])
    status = next
    checkBuildMatch()
    render()
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    // 令牌失效不是"偶发读取失败"：刷新多少次都不会好，必须让用户去重开页面。
    if (message.includes('令牌')) {
      markSessionLost(message)
      return
    }
    toast('error', '读取状态失败', message)
  }
}

/** 会话失效后，把屏幕上已有的结论降级 —— 停在旧结论上比写着"不知道"更危险。 */
function markSessionLost(message) {
  if (!sessionLost) {
    sessionLost = true
    const banner = el('div', 'notice danger session-lost')
    banner.append(
      el('span', 'icon', '!'),
      el(
        'span',
        undefined,
        `${message}。服务端每次启动都会换新的会话令牌，所以这个页面读取状态、执行操作的请求都会失败 —— ` +
          '下面显示的都不是最新状态，请重新打开界面地址（或刷新页面）再操作。',
      ),
    )
    // 贴在内容区最上方（先于页面标题），不遮挡任何东西。
    const content = document.querySelector('.content') ?? document.body
    content.prepend(banner)
  }

  const host = document.querySelector('#access-state')
  const sub = document.querySelector('#access-sub')
  if (!host) return
  sub.textContent = '会话已失效 · 显示的不是最新状态'
  host.replaceChildren(
    accessCard('能否打开 Claude', undefined, undefined, '▶'),
    accessCard('能否访问网络', undefined, undefined, '🌐'),
  )
}

/** ------------------------------------------------------------------ UI 组件 */

function toast(kind, title, detail) {
  const host = document.querySelector('#toasts')
  const node = document.createElement('div')
  node.className = `toast ${kind}`
  const strong = document.createElement('strong')
  strong.textContent = title
  node.append(strong)
  if (detail) {
    const body = document.createElement('div')
    body.textContent = detail
    node.append(body)
  }
  host.append(node)
  setTimeout(() => node.remove(), 6000)
}

function el(tag, className, text) {
  const node = document.createElement(tag)
  if (className) node.className = className
  if (text !== undefined) node.textContent = text
  return node
}

function badge(kind, text, pulse = false) {
  const node = el('span', `badge ${kind}`)
  node.append(el('span', `dot${pulse ? ' pulse' : ''}`), document.createTextNode(text))
  return node
}

/** 国家代码 → 旗帜 emoji；Windows 上通常渲染成两位字母，不影响可读。 */
function flagEmoji(code) {
  const cc = String(code ?? '').toUpperCase()
  if (!/^[A-Z]{2}$/.test(cc)) return ''
  return String.fromCodePoint(...[...cc].map((char) => 0x1f1e6 + char.charCodeAt(0) - 65))
}

/**
 * 归属地一行：旗帜 + 国家名 + 城市/地区，例如 `🇬🇧 United Kingdom, Hatfield`。
 * 数据来自反查（ip-api），缺哪项就少哪项，不编造。
 */
function geoLine(info, prefix) {
  const place = [info.countryName ?? info.country, info.city ?? info.regionName].filter(Boolean).join(', ')
  if (!place) return undefined
  const span = el('span', 'geo')
  if (prefix) span.append(document.createTextNode(prefix))
  const flag = flagEmoji(info.country)
  if (flag) span.append(el('span', 'geo-flag', flag))
  span.append(document.createTextNode(place))
  return span
}

function tagNode(kind, text) {
  return el('span', `tag ${kind}`, text)
}

/**
 * 明细卡片：一条数据一张卡 —— 主值（IP 之类用等宽）+ 副行（归属地 / 机构所在）
 * + 右侧结论徽章。对齐参考站的分区卡片：把每项摊开成可核对的读数，
 * 而不是把所有东西压成一行"某某有提示"的笼统结论。
 */
function detailCard({ label, value, sub, tag, tone = 'neutral', mono = false }) {
  const card = el('div', `detail-card ${tone}`)
  const body = el('div', 'card-body')
  if (label) body.append(el('div', 'card-label', label))
  const valueHost = el('div', `card-value${mono ? ' mono' : ''}`)
  if (value instanceof Node) valueHost.append(value)
  else valueHost.textContent = String(value ?? '—')
  body.append(valueHost)
  if (sub instanceof Node) {
    const subHost = el('div', 'card-sub')
    subHost.append(sub)
    body.append(subHost)
  } else if (sub) {
    body.append(el('div', 'card-sub', String(sub)))
  }
  card.append(body)
  if (tag) card.append(tag)
  return card
}

/** 分区：标题 + 右侧结论徽章 + 卡片列表。 */
function envSection(title, badgeNode, cards, { wide = false } = {}) {
  const section = el('div', 'env-section')
  const head = el('div', 'env-section-head')
  head.append(el('div', 'env-section-title', title))
  if (badgeNode) head.append(badgeNode)
  section.append(head)
  const grid = el('div', `env-cards${wide ? ' wide' : ''}`)
  for (const card of cards) grid.append(card)
  section.append(grid)
  return section
}

/** 分区右上角的结论徽章，与卡片上的 tag 共用同一套配色。 */
function sectionBadge(kind, text) {
  return el('span', `section-badge ${kind}`, text)
}

/** 把判定原文（"为什么这一格是这个结论"）附到副行上。 */
function appendReason(sub, tagResult) {
  const host = sub instanceof Node ? sub : el('span')
  if (tagResult?.reason) host.append(el('span', 'tag-detail', tagResult.reason.title))
  return host
}

/**
 * 每格的结论标签。
 *
 * 结论直接取自判定结果里的 reason id（check.blocked / check.warnings），
 * 不在界面里另写一套判断 —— 否则"界面显示通过、闸门却在拦"这种事迟早会发生。
 * kind 同时用作卡片左描边颜色，所以在这里一并算出来。
 */
function statusTag(ids, { disabled = false } = {}) {
  const check = status.lastCheck ?? {}
  const blockedHit = list(check.blocked).find((item) => ids.includes(item.id))
  const warnHit = list(check.warnings).find((item) => ids.includes(item.id))
  if (blockedHit) return { node: el('span', 'tag danger', '未通过'), reason: blockedHit, kind: 'danger' }
  if (warnHit) return { node: el('span', 'tag warn', '提示'), reason: warnHit, kind: 'warn' }
  if (disabled) return { node: el('span', 'tag', '未启用'), reason: undefined, kind: 'neutral' }
  return { node: el('span', 'tag ok', '通过'), reason: undefined, kind: 'ok' }
}

/** 该检查项在配置里是否启用；关了就不该显示"通过"，那会让人以为它在把关。 */
function checksEnabled(key) {
  const checks = status.config?.checks
  if (!checks || !checks[key]) return true
  return checks[key].enabled !== false
}

/** IPv4 是否落在 CIDR 内。界面要显示白名单逐项命中情况，就得自己算，不能猜。 */
function ipv4InCidr(ip, cidr) {
  const [range, bitsText] = String(cidr).split('/')
  const bits = Number(bitsText)
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip) || !/^\d+\.\d+\.\d+\.\d+$/.test(range) || !Number.isInteger(bits)) return false
  const toInt = (text) => text.split('.').reduce((acc, part) => (acc << 8) + Number(part), 0) >>> 0
  if (bits === 0) return true
  const mask = (0xffffffff << (32 - bits)) >>> 0
  return (toInt(ip) & mask) === (toInt(range) & mask)
}

/** ASN 命中判定，与服务端 evaluateEgress 的宽松匹配保持一致。 */
function asnMatches(egressAsn, allowed) {
  const asn = String(egressAsn ?? '').toUpperCase()
  if (!asn) return false
  return allowed.some((item) => {
    const bare = String(item).replace(/^AS/, '')
    return asn === String(item) || asn.endsWith(`AS${bare}`) || asn.includes(bare)
  })
}

/** ------------------------------------------------------------------ 渲染 */

function render() {
  if (!status) return
  renderHeader()
  renderClaudeAccess()
  renderEnvironment()
  renderActions()
  renderInventory()
  renderForm()
  renderChecks()
  document.querySelector('#config-path').textContent = status.configPath
  document.querySelector('#state-dir').textContent = status.stateDir ?? '—'
  const side = document.querySelector('#side-status')
  if (side) {
    const check = status.lastCheck
    side.textContent = check
      ? `最近检测 ${new Date(check.at).toLocaleTimeString()} · ${check.allow ? '放行' : '拦截'}`
      : '尚未检测环境'
  }
}

function renderHeader() {
  const host = document.querySelector('#verdict')
  host.replaceChildren()

  const check = status.lastCheck
  if (!check) {
    host.append(badge('neutral', '尚未检测'))
  } else if (check.allow) {
    host.append(badge('ok', `放行 · ${check.egress?.ip ?? '出口已确认'}`))
  } else {
    host.append(badge('danger', `拦截 · ${check.blocked.length} 项不通过`))
  }

  host.append(
    status.guard.running ? badge('ok', '闸门运行中', true) : badge('neutral', '闸门未运行'),
  )
  host.append(status.elevated ? badge('ok', '管理员') : badge('warn', '非管理员'))
  host.append(
    status.firewallProfile?.anyEnabled
      ? badge('neutral', '系统防火墙已开')
      : badge('warn', '系统防火墙已关'),
  )
}

/**
 * 一格结论卡。三态由服务端给出：allow=可以、deny=不可以、unguarded=未被拦截
 * （判定不通过、但此刻确实没有任何拦截在生效）。
 *
 * state 缺失时**不能**按"未被拦截"显示：那等于拿一个读不到的数据去下结论，而"未被拦截"
 * 偏偏是在断言"此刻它确实能开、能联网"。实测就栽在这里 —— 页面读到的状态是过期/不完整的，
 * 屏幕上却写着"未被拦截"，看着像一切正常。读不到就如实说读不到。
 */
function accessCard(title, state, reason, icon) {
  const tone = state === 'allow' ? 'ok' : state === 'deny' ? 'deny' : state === 'unguarded' ? 'unknown' : ''
  const label = state === 'allow' ? '可以' : state === 'deny' ? '不可以' : state === 'unguarded' ? '未被拦截' : '状态未知'
  const tagClass = state === 'allow' ? 'tag ok' : state === 'deny' ? 'tag danger' : state === 'unguarded' ? 'tag warn' : 'tag'
  const box = el('div', `access-card ${tone}`.trim())
  const head = el('div', 'access-head')
  head.append(el('span', 'access-icon', icon))
  head.append(el('strong', undefined, title))
  head.append(el('span', tagClass, label))
  box.append(head)
  box.append(
    el(
      'p',
      'access-reason',
      reason ?? (state ? '' : '这一格没有拿到结论：界面读到的状态不完整或已过期，刷新页面后重新确认。'),
    ),
  )
  return box
}

/**
 * Claude 客户端现状：能不能打开、能不能联网，外加拦截记录。
 *
 * 两个结论都由服务端算好（`status.claudeAccess`）—— 界面不自己推断，
 * 否则"界面显示可以打开、闸门却在杀进程"这种事迟早会发生。
 */
function renderClaudeAccess() {
  const host = document.querySelector('#access-state')
  const sub = document.querySelector('#access-sub')
  const listHost = document.querySelector('#interception-list')
  const listSub = document.querySelector('#interception-sub')
  if (!host) return

  const access = status.claudeAccess ?? {}
  const records = list(status.interceptions)

  sub.textContent = status.guard.running ? '闸门运行中 · 实时更新' : '闸门未运行 · 仅显示阻断状态'
  host.replaceChildren()

  // 启动按钮要如实反映"现在点下去会怎样"：判定不通过时置灰并写明原因，
  // 而不是让用户点了才被拒。
  const launchButton = document.querySelector('#launch-desktop')
  if (launchButton) {
    const blocked = access.launchState === 'deny'
    launchButton.disabled = blocked
    launchButton.title = blocked
      ? `当前判定不通过，启动会被拒绝：${access.launchReason ?? ''}`
      : '先检测，判定通过才启动'
    launchButton.classList.toggle('primary', !blocked)
    launchButton.classList.toggle('danger', blocked)
  }

  host.append(
    accessCard('能否打开 Claude', access.launchState, access.launchReason, '▶'),
    accessCard('能否访问网络', access.networkState, access.networkReason, '🌐'),
  )

  listHost.replaceChildren()
  listSub.textContent = records.length === 0 ? '暂无' : `最近 ${records.length} 条`
  if (records.length === 0) {
    listHost.append(el('div', 'empty', '还没有拦截记录：没有出现过不通过的判定，也没有执行过阻断。'))
    return
  }
  for (const item of records.slice(0, 40)) {
    const row = el('div', 'record ' + (item.level === 'block' ? 'block' : 'warn'))
    row.append(el('span', `tag ${item.level === 'block' ? 'danger' : 'warn'}`, item.level === 'block' ? '拦截' : '提示'))
    row.append(el('span', 'record-time', item.at ? new Date(item.at).toLocaleString() : ''))
    const body = el('div', 'record-body')
    body.append(el('div', 'record-message', item.message ?? ''))
    if (item.detail) body.append(el('div', 'record-detail', item.detail))
    row.append(body)
    listHost.append(row)
  }
  if (records.length > 40) {
    listHost.append(el('div', 'record-more', `只显示最近 40 条，共 ${records.length} 条`))
  }
}

function renderEnvironment() {
  const body = document.querySelector('#env-body')
  const sub = document.querySelector('#env-sub')
  const check = status.lastCheck
  body.replaceChildren()

  if (!check) {
    sub.textContent = '尚未检测'
    body.append(el('div', 'empty', '点击「立即检测」读取出口与环境特征'))
    return
  }
  sub.textContent = new Date(check.at).toLocaleTimeString()

  const egress = check.egress ?? {}
  const dns = check.dns
  const env = check.environment ?? {}
  const wl = check.whitelist ?? {}
  const sections = []

  // 总体结论放在最上面：一眼看到"通过 / 未通过"，再往下看是哪一项。
  const verdictBanner = el('div', 'verdict ' + (check.allow ? 'ok' : 'danger'))
  verdictBanner.append(el('strong', undefined, check.allow ? '判定通过：放行' : '判定未通过：拦截'))
  const blockCount = list(check.blocked).length
  const warnCount = list(check.warnings).length
  verdictBanner.append(
    el(
      'span',
      undefined,
      check.allow
        ? warnCount > 0
          ? `　白名单命中；另有 ${warnCount} 项提示（不影响放行）`
          : '　白名单命中，各项特征均在阈值内'
        : `　${blockCount} 项不通过${warnCount > 0 ? `，另有 ${warnCount} 项提示` : ''}`,
    ),
  )
  body.append(verdictBanner)

  // —— 分区一：网络出口。逐条摊开成可核对的读数（IP、归属地、机构、一致性），
  // 而不是只给一个 GB 让人猜。
  const egressTag = statusTag(EGRESS_IDS)
  const egressSub = el('span')
  const egressGeo = geoLine(egress)
  if (egressGeo) egressSub.append(egressGeo)
  // 机构名与 ASN 单独占一张卡（下面那张），这里只留归属地与网络特征标记，
  // 免得一张卡里塞两种信息、副行绕成四行。
  if (egress.hosting) egressSub.append(el('span', 'tag warn', '机房/代理'))
  if (egress.mobile) egressSub.append(el('span', 'tag', '移动网络'))

  const consistent = egress.confident
    ? '一致（可信）'
    : `不一致 → IP ${JSON.stringify(egress.ipVotes ?? {})} / 国家 ${JSON.stringify(egress.countryVotes ?? {})}`
  const consistentTag = statusTag(['egress-inconsistent', 'egress-unknown'])
  const consistentNotes = []
  if (!egress.confident) consistentNotes.push('多源读数互相矛盾，按拦截处理')
  if (check.failedClosed && !list(check.blocked).some((item) => item.id.startsWith('egress'))) {
    consistentNotes.push('failClosed 生效：出口身份确认不了就拦')
  }

  const egressCards = [
    detailCard({
      label: '出口 IP',
      value: egress.ip ?? '未知',
      mono: true,
      sub: egressSub.childNodes.length > 0 ? egressSub : undefined,
      tag: egressTag.node,
      tone: egressTag.kind,
    }),
    detailCard({
      label: '多源一致性',
      value: consistent,
      sub: consistentNotes.length > 0 ? el('span', 'dim', consistentNotes.join('；')) : undefined,
      tag: consistentTag.node,
      tone: consistentTag.kind,
    }),
  ]

  // ASN / 机构：出口身份的另一半，单独一张卡，免得一格里塞太多。
  if (egress.asnText) {
    const asnTag = statusTag(['egress-asn', 'egress-hosting'])
    egressCards.push(
      detailCard({
        label: 'ASN / 机构',
        value: egress.asnText,
        sub: appendReason(el('span', 'dim', egress.isp ?? '出口运营商'), asnTag),
        tag: asnTag.node,
        tone: asnTag.kind,
      }),
    )
  }

  // 代理连不上时回退直连：必须说清楚"这次判的是直连出口"，
  // 否则用户会以为代理在生效、看到的却是物理线路的出口。
  if (egress.proxyFallback) {
    const note = el('div', 'notice warn')
    note.append(el('strong', undefined, `代理 ${egress.proxyUrl ?? ''} 连不上，本次按直连出口判定`))
    note.append(
      el(
        'span',
        undefined,
        `　出口读数为 ${egress.ip ?? '未知'}。要按代理出口判定，请先启动代理；若希望代理不可用就直接拦截，把 network.proxy.required 设为 true。`,
      ),
    )
    body.append(note)
  }

  // 出口查不到时，最常见的原因是"配了代理但代理没在跑"。这种情况必须点名，
  // 否则用户只看到"未通过"，会以为是策略判错了（对比网站明明显示正常）。
  if (egress.ip === undefined) {
    const failed = list(egress.failedSources).join('；')
    const proxyDown = /ECONNREFUSED|ETIMEDOUT|ECONNRESET|socket hang up/i.test(failed)
    const proxyUrl = status.config?.network?.proxy?.url
    const proxyOn = status.config?.network?.proxy?.enabled === true
    const hint = el('div', 'notice danger')
    hint.append(
      el(
        'strong',
        undefined,
        proxyOn && proxyDown && proxyUrl
          ? `出口检测失败：配置的代理 ${proxyUrl} 连不上`
          : '出口检测失败：所有数据源都查询不到',
      ),
    )
    hint.append(
      el(
        'span',
        undefined,
        proxyOn && proxyDown
          ? '　代理进程没在运行（或端口不对），而检测被配置成走这个代理，所以拿不到出口 IP；按 failClosed 规则直接判拦截。请启动代理，或把「系统代理」相关配置改为直连后再检测。'
          : `　${failed || '原因未知'}。按 failClosed 规则直接判拦截。`,
      ),
    )
    body.append(hint)
  }

  // 白名单逐项比对：命中打 ✓、未命中打 ✗、没配的写"未限制"。
  const wlItems = []
  if (list(wl.countries).length > 0) {
    const hit = egress.country ? wl.countries.includes(egress.country) : false
    wlItems.push({ label: `国家 ${list(wl.countries).join('/')}`, hit, value: egress.country ?? '未知' })
  }
  if (list(wl.ips).length > 0) {
    wlItems.push({ label: `固定 IP ${list(wl.ips).length} 个`, hit: list(wl.ips).includes(egress.ip), value: egress.ip ?? '未知' })
  }
  if (list(wl.cidrs).length > 0) {
    wlItems.push({
      label: `网段 ${list(wl.cidrs).join('/')}`,
      hit: list(wl.cidrs).some((cidr) => ipv4InCidr(egress.ip ?? '', cidr)),
      value: egress.ip ?? '未知',
    })
  }
  if (list(wl.asns).length > 0) {
    wlItems.push({
      label: `ASN ${list(wl.asns).join('/')}`,
      hit: asnMatches(egress.asn, list(wl.asns)),
      value: egress.asn ?? '未知',
    })
  }
  if (wl.requireResidential === true) {
    wlItems.push({
      label: '要求住宅出口',
      hit: !egress.hosting,
      value: egress.hosting ? '机房/代理' : egress.mobile ? '移动网络' : '非机房',
    })
  }
  if (wlItems.length > 0) {
    const wlNode = el('span')
    wlItems.forEach((item, index) => {
      if (index > 0) wlNode.append(document.createTextNode('　'))
      const span = el('span', 'wl-item ' + (item.hit ? 'hit' : 'miss'), `${item.hit ? '✓' : '✗'} ${item.label}`)
      span.append(el('span', 'wl-value', `（当前 ${item.value}）`))
      wlNode.append(span)
    })
    const anyMiss = wlItems.some((item) => !item.hit)
    egressCards.push(
      detailCard({
        label: '白名单比对',
        value: wlNode,
        sub: el('span', 'dim', anyMiss ? '有不命中项，整体判定为拦截' : '逐项都命中'),
        tag: tagNode(anyMiss ? 'danger' : 'ok', anyMiss ? '有不命中项' : '全部命中'),
        tone: anyMiss ? 'danger' : 'ok',
      }),
    )
  }

  // 系统代理：它不是设备特征，而是出口路径本身，所以跟出口放同一区。
  if (env.systemProxy) {
    const enabled = env.systemProxy.system?.enabled
    const envKeys = Object.keys(env.systemProxy.envVars ?? {})
    const proxyTag = statusTag(['proxy-leak'], { disabled: !checksEnabled('proxyEnvLeak') })
    egressCards.push(
      detailCard({
        label: '系统代理 / 分流覆盖',
        value: enabled
          ? `开启（${env.systemProxy.system.server ?? '—'}）`
          : envKeys.length > 0
            ? `未开启，但有 ${envKeys.join('、')}`
            : '未检测到',
        sub: appendReason(el('span', 'dim', 'CLI 是否直连，最终由出口白名单说了算'), proxyTag),
        tag: proxyTag.node,
        tone: proxyTag.kind,
      }),
    )
  }

  sections.push(
    envSection(
      'Claude 连通性及网络出口（实时数据）',
      sectionBadge(egressTag.kind, egressTag.node.textContent),
      egressCards,
    ),
  )

  // —— 分区二：Claude 域名解析落地。每个域名一张卡：解析到哪个 IP、归属哪里。
  if (dns) {
    const dnsTag = statusTag(['claude-dns-denied', 'claude-dns-unresolved', 'claude-dns-partial'], {
      disabled: !checksEnabled('claudeDns'),
    })
    const dnsCards = list(dns.hosts).map((item) => {
      const address = item.addresses?.[0]
      const denied = list(dns.deniedHits).some((hit) => hit.host === item.host)
      const sub = address
        ? geoLine(item, '解析落地：') ?? el('span', 'dim', item.isp ?? '归属地未知')
        : el('span', 'dim', item.error ?? '没有解析结果')
      return detailCard({
        label: item.host,
        value: address ?? '无结果',
        mono: true,
        sub,
        tag: tagNode(
          denied ? 'danger' : address ? 'ok' : 'warn',
          denied ? '解析到被禁地区' : address ? '落地正常' : '未解析',
        ),
        tone: denied ? 'danger' : address ? 'ok' : 'warn',
      })
    })
    if (dnsCards.length > 0) {
      sections.push(
        envSection('Claude 域名解析落地', sectionBadge(dnsTag.kind, dnsTag.node.textContent), dnsCards, {
          wide: true,
        }),
      )
    }
  }

  // —— 分区三：DNS 区域泄露隐患（对齐参考站的 "DNS LEAK" 分组）。
  // 每个实测解析出口一张卡：IP + 解析服务器归属地 + 结论徽章。
  const leakCards = []
  const resolverEgress = env.resolverEgress
  if (resolverEgress) {
    const resolvers = list(resolverEgress.resolvers)
    const deniedHits = list(resolverEgress.deniedHits)
    for (const item of resolvers) {
      const denied = deniedHits.some((hit) => hit.ip === item.ip)
      leakCards.push(
        detailCard({
          value: item.ip,
          mono: true,
          sub: geoLine(item, '解析服务器归属地：') ?? el('span', 'dim', item.isp ?? '归属地未知（反查没有结果）'),
          tag: tagNode(
            denied ? 'danger' : item.country ? 'ok' : 'warn',
            denied ? '被禁地区' : item.country ? '国外安全DNS' : '归属地未知',
          ),
          tone: denied ? 'danger' : item.country ? 'ok' : 'warn',
        }),
      )
    }
    if (resolvers.length === 0) {
      leakCards.push(
        detailCard({
          value: '未取得应答',
          sub: el('span', 'dim', `无法确认谁在回答 DNS 查询：${resolverEgress.error ?? '查询没拿到结果'}`),
          tag: tagNode('warn', '无法确认'),
          tone: 'warn',
        }),
      )
    }
  }

  if (env.dnsServers) {
    const servers = list(env.dnsServers.servers)
    const domestic = list(env.dnsServers.domestic)
    const dnsServerTag = statusTag(['dns-servers-domestic'], { disabled: !checksEnabled('dnsServers') })
    // 列表为空有两种情况，说清楚是哪一种：只配了路由器地址，还是根本没读到。
    const value =
      servers.join('、') || (Number(env.dnsServers.filtered) > 0 ? '只有路由器/链路本地地址' : '未读取')
    leakCards.push(
      detailCard({
        label: '本机 DNS 服务器（配置）',
        value,
        mono: true,
        sub: appendReason(
          el(
            'span',
            'dim',
            domestic.length > 0
              ? `已连接网卡上配置了国内解析器：${domestic.join('、')}（读的是配置，不是实测解析路径）`
              : '已连接网卡上配置的公共解析器',
          ),
          dnsServerTag,
        ),
        tag: dnsServerTag.node,
        tone: dnsServerTag.kind,
      }),
    )
  }

  if (leakCards.length > 0) {
    const deniedCount = list(resolverEgress?.deniedHits).length
    const leakBadge = !resolverEgress || !checksEnabled('resolverEgress')
      ? sectionBadge('neutral', '未启用')
      : resolverEgress.checked === false
        ? sectionBadge('warn', '⚠ 无法确认解析出口')
        : deniedCount > 0
          ? sectionBadge('danger', `⚠ 解析出口落在被禁地区（${deniedCount} 个）`)
          : sectionBadge('ok', '⚠ DNS 伪装正常')
    sections.push(envSection('DNS 区域泄露隐患（DNS LEAK）', leakBadge, leakCards, { wide: true }))
  }

  // —— 分区四：设备特征（中文用户环境）。
  const deviceCards = []
  const deviceKinds = []

  if (env.timezone) {
    const tzTag = statusTag(['timezone-domestic'], { disabled: !checksEnabled('timezone') })
    deviceKinds.push(tzTag.kind)
    deviceCards.push(
      detailCard({
        label: '系统时区',
        value: `${env.timezone.intl}${env.timezone.windows ? ` / ${env.timezone.windows}` : ''}`,
        mono: true,
        sub: appendReason(el('span', 'dim', env.timezone.domestic ? '国内时区' : '非国内时区'), tzTag),
        tag: tzTag.node,
        tone: tzTag.kind,
      }),
    )
  }

  if (env.language) {
    const langTag = statusTag(['language-chinese'], { disabled: !checksEnabled('language') })
    deviceKinds.push(langTag.kind)
    deviceCards.push(
      detailCard({
        label: '界面语言',
        value: list(env.language.uiLanguages).join('、') || '未知',
        sub: appendReason(el('span', 'dim', env.language.chinese ? '含中文' : '不含中文'), langTag),
        tag: langTag.node,
        tone: langTag.kind,
      }),
    )
  }

  if (env.fonts) {
    // 同一字体的多个字重会反复命中同一标签，去重后再展示（文件数用副行体现）。
    const strong = list(env.fonts.found).filter((item) => item.strong)
    const labels = [...new Set(strong.map((item) => item.label))]
    const fontTag = statusTag(['fonts-domestic', 'fonts-weak'], { disabled: !checksEnabled('fonts') })
    deviceKinds.push(fontTag.kind)
    deviceCards.push(
      detailCard({
        label: '中文字体指纹',
        value: labels.length > 0 ? labels.join('、') : '未命中专有字体',
        sub: appendReason(
          el('span', 'dim', labels.length > 0 ? `命中 ${strong.length} 个字体文件` : '只装了常见中文字体'),
          fontTag,
        ),
        tag: fontTag.node,
        tone: fontTag.kind,
      }),
    )
  }

  if (env.emojiFont?.checked) {
    const emojiTag = statusTag(['emoji-flags-suspect'], { disabled: !checksEnabled('emojiFlags') })
    deviceKinds.push(emojiTag.kind)
    deviceCards.push(
      detailCard({
        label: 'Emoji 国旗渲染',
        value: env.emojiFont.present
          ? `Segoe UI Emoji ${Math.round((env.emojiFont.sizeBytes ?? 0) / 1024 / 1024)} MB`
          : '未检测到 Segoe UI Emoji',
        sub: appendReason(el('span', 'dim', env.emojiFont.suspect ? '可能被裁剪' : '字体完整'), emojiTag),
        tag: emojiTag.node,
        tone: emojiTag.kind,
      }),
    )
  }

  if (deviceCards.length > 0) {
    const deviceWarn = deviceKinds.filter((kind) => kind === 'warn' || kind === 'danger').length
    const deviceBadge = deviceKinds.includes('danger')
      ? sectionBadge('danger', `${deviceWarn} 项未通过`)
      : deviceWarn > 0
        ? sectionBadge('warn', `${deviceWarn} 项提示`)
        : deviceKinds.every((kind) => kind === 'neutral')
          ? sectionBadge('neutral', '未启用')
          : sectionBadge('ok', '均在阈值内')
    sections.push(envSection('设备特征（中文用户环境）', deviceBadge, deviceCards))
  }

  body.append(...sections)

  const findings = [
    ...list(check.blocked).map((item) => ({ kind: 'block', ...item })),
    ...list(check.warnings).map((item) => ({ kind: 'warn', ...item })),
  ]
  if (check.failedClosed) {
    findings.unshift({
      kind: 'block',
      title: '判定不通过（failClosed）',
      detail: '出口身份无法确认，按拦截处理；可在白名单面板关闭 failClosed。',
    })
  }
  if (findings.length === 0) {
    const ok = el('div', 'notice', '未发现问题：出口命中白名单，各项特征均在阈值内。')
    ok.classList.add('warn')
    ok.style.background = 'var(--ok-soft)'
    ok.style.borderColor = 'rgba(54, 211, 153, 0.3)'
    ok.style.color = '#a7f3d0'
    body.append(ok)
  } else {
    const ul = el('ul', 'findings')
    for (const item of findings) {
      const li = el('li', `finding ${item.kind}`)
      li.append(el('span', 'kind', item.kind === 'block' ? '拦截' : '提示'))
      const content = el('div')
      content.append(el('strong', undefined, item.title))
      if (item.detail) content.append(el('span', undefined, item.detail))
      li.append(content)
      ul.append(li)
    }
    body.append(ul)
  }
}

/**
 * 操作按钮：**只创建一次**，之后仅更新文案/禁用/加载态。
 *
 * 为什么不用"每次刷新重建"：状态每 15 秒（以及每次闸门事件）都会刷新，重建会
 * 把按钮节点换掉 —— 用户（或自动化）正好点在这一瞬间，点击就丢了。保持节点稳定
 * 也顺带解决了焦点丢失与加载态闪烁。
 */
const ACTION_SPECS = [
  { id: 'check', label: '立即检测', className: 'primary' },
  { id: 'guard', label: '启动闸门', className: 'ok' },
  { id: 'block', label: '阻断网络', className: 'danger' },
  { id: 'unblock', label: '解除阻断' },
  { id: 'kill', label: '终止进程', className: 'danger' },
  { id: 'profiles', label: '启用系统防火墙', needsFirewallOff: true },
]

const actionHandlers = {
  check: () => run('check', () => api('/api/check', { method: 'POST' })),
  guard: () =>
    status?.guard.running
      ? run('guard', () => api('/api/guard/stop', { method: 'POST' }), '闸门已停止')
      : run('guard', () => api('/api/guard/start', { method: 'POST' }), '闸门已启动'),
  block: () =>
    run('block', () => api('/api/firewall', { method: 'POST', body: { enabled: true } }), '已建立阻断'),
  unblock: () =>
    run('unblock', () => api('/api/firewall', { method: 'POST', body: { enabled: false } }), '已解除阻断'),
  kill: () => run('kill', () => api('/api/kill', { method: 'POST' })),
  profiles: () =>
    run('profiles', () => api('/api/firewall/enable-profiles', { method: 'POST' }), '已启用系统防火墙'),
}

/**
 * 门控启动 Claude Desktop。
 *
 * 与"双击图标"的区别：这里先跑一轮检测，判定通过才真的拉起。拒绝时不能只弹一句
 * "失败"——要把是哪一项不通过直接说出来，否则用户只看到按钮没反应。
 */
async function launchClaudeDesktop() {
  const button = document.querySelector('#launch-desktop')
  if (!button || button.disabled) return
  const original = button.textContent
  button.disabled = true
  button.textContent = '检测中…'
  try {
    const result = await api('/api/launch', { method: 'POST' })
    if (result?.launched) {
      toast('ok', '已启动 Claude Desktop', result.path ?? '')
    } else if (result?.allow === false) {
      // 判定不通过：明确写出原因，并说明这次没有启动。
      toast('error', '环境不满足，已拒绝启动', result.reason ?? '白名单未命中')
    } else {
      toast('error', '启动失败', result?.reason ?? '未知原因')
    }
  } catch (error) {
    toast('error', '启动失败', error instanceof Error ? error.message : String(error))
  } finally {
    button.disabled = false
    button.textContent = original
    void refresh()
  }
}

/** -------------------------------------------------------------- 账号切换 */

/**
 * 账号列表。
 *
 * 只做 Desktop：换的是 Desktop profile 里的登录态与设备标识，不动 Claude Code 的
 * `~/.claude` 与 `~/.claude.json`。切换会结束 Desktop 进程 —— 这些是 SQLite 文件，
 * 进程还在写的时候复制出来的快照会不一致。
 */
/** 最近一次读到的账号状态：同步弹层要用它列出"同步到哪个账号"。 */
let accountsState = undefined

function renderAccounts(data) {
  accountsState = data
  const host = document.querySelector('#account-list')
  const sub = document.querySelector('#accounts-sub')
  if (!host || !sub) return

  if (!data?.profile?.found) {
    sub.textContent = '未找到'
    host.replaceChildren(el('div', 'side-hint', '没找到 Desktop 数据目录（MSIX 包未安装或从未登录）。'))
    return
  }

  const accounts = list(data.accounts)
  sub.textContent = data.current ? `当前 ${data.current}` : '未记录'
  host.replaceChildren()

  if (accounts.length === 0) {
    host.append(el('div', 'side-hint', '还没有账号。点下面的「添加账号」把当前登录存下来。'))
    return
  }

  for (const account of accounts) {
    const row = el('div', 'account-row')
    const isCurrent = account.name === data.current
    if (isCurrent) row.classList.add('is-current')
    if (!account.complete) row.classList.add('is-disabled')
    row.tabIndex = 0
    row.setAttribute('role', 'button')

    // 标题优先显示真实账号（IndexedDB 里的邮箱）。
    //
    // 读不到邮箱时退到「uuid 前 8 位」而不是本地字母名字：Claude 把账户信息存在
    // 服务端，本地只在特定时机缓存，所以有些存档就是没有邮箱（实测扫描 25 个存储
    // 文件、两种编码，0 命中）。uuid 至少能唯一区分账号，字母名字只能看出"我们给它
    // 起了什么名"，用户没法据此认出是谁。
    const shortUuid = account.uuid ? account.uuid.slice(0, 8) : undefined
    const label = account.email ?? (shortUuid ? `账号 ${shortUuid}` : account.name)
    if (account.fullName) row.title = account.fullName

    const head = el('div', 'account-head')
    const name = el('span', 'account-name', label)
    const status = el(
      'span',
      `account-status ${isCurrent ? 'is-online' : 'is-offline'}`,
      account.complete ? (isCurrent ? '在线' : '离线') : '存档不完整',
    )
    head.append(name, status)

    // 同一个 Claude 账号存了多份：标出来，否则会被当成几个不同账号。
    if (list(account.sameAccountAs).length > 0) {
      const same = el('span', 'account-badge', `同 ${account.sameAccountAs.join('/')}`)
      same.title = `这些存档是同一个 Claude 账号：${account.sameAccountAs.join('、')}`
      head.append(same)
    }

    // 用量是"最后一次记录"：在线号读的是 profile 里持续追加的采样，
    // 离线号是它存档那一刻的 —— 都不发任何网络请求。
    const usage = account.usage
    const meta = el('span', 'account-meta')
    meta.textContent = [
      // 本地名字始终显示（用户自己起的标签，切换时要用它）
      account.name,
      // 登录态：windowSizeWasSignedIn=false 只说明"窗口尺寸不是在登录状态下保存的"，
      // 不等于当前没登录 —— 之前我按"登录失效"显示是错的，这里只提示、不下结论。
      account.signedIn === false ? '本窗口可能在登录前打开' : undefined,
      account.savedAt ? new Date(account.savedAt).toLocaleDateString() : undefined,
    ]
      .filter(Boolean)
      .join(' · ')

    row.append(head, meta)
    if (usage) {
      row.append(usageBar('5h', usage.fiveHourPercent), usageBar('周', usage.weeklyPercent))
    }

    // 每个账号一行的操作：更新 / 删除。放在 meta 之后，整行可点的前提下
    // 必须 stopPropagation，否则点按钮会连带触发切换。
    const actions = el('div', 'account-actions')
    if (isCurrent) {
      // 只有当前在用的号才能"更新"：更新 = 把现在机器上的登录态存成这个名字，
      // 对离线号做这件事只会把别人的登录态覆盖进来。
      const update = el('button', 'account-mini', '更新')
      update.type = 'button'
      update.title = '把当前登录态存回这个账号（登录过期后重新登录再点这里）'
      update.addEventListener('click', (event) => {
        event.stopPropagation()
        void updateAccount(account.name, label)
      })
      actions.append(update)
    }
    // 会话同步：从哪个号搬出去由用户自己点，不自动、不批量。
    // 只有一个以上账号时才有意义。
    if (list(accountsState?.accounts).length > 1) {
      const sync = el('button', 'account-mini', '同步会话')
      sync.type = 'button'
      sync.title = '手动选择这个账号的会话，同步到另一个账号'
      sync.addEventListener('click', (event) => {
        event.stopPropagation()
        void openSyncModal(account.name)
      })
      actions.append(sync)
    }
    const remove = el('button', 'account-mini is-danger', '删除')
    remove.type = 'button'
    remove.disabled = isCurrent
    remove.title = isCurrent ? '正在使用的账号不能删除' : '删除这个账号的存档'
    remove.addEventListener('click', (event) => {
      event.stopPropagation()
      void deleteAccount(account.name, label)
    })
    actions.append(remove)
    row.append(actions)

    const activate = () => {
      if (!account.complete) return
      if (isCurrent) {
        toast('info', `当前就是 ${label}`, '已经在用它了，不需要切换')
        return
      }
      // 切换必须结束 Desktop 才能搬运登录文件。这一步用户必须事先知道，
      // 否则就是"点了一下，Claude 莫名其妙被关掉"。
      const confirmed = window.confirm(
        `切换到 ${label}？\n\n` +
          `· 会先关闭当前的 Claude Desktop，未发送的对话会丢失\n` +
          `· 然后载入这个账号的登录态\n` +
          `· 切换完成后请手动打开 Claude\n\n` +
          `继续吗？`,
      )
      if (!confirmed) return
      void switchToAccount(account.name, label)
    }
    row.addEventListener('click', activate)
    row.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault()
        activate()
      }
    })

    host.append(row)
  }
}

/** 细进度条：标签 + 3px 轨道 + 百分比。≥80% 变红提示快到顶。 */
function usageBar(label, percent) {
  const bar = el('div', 'usage-bar')
  const caption = el('span', 'usage-label', label)
  const track = el('div', 'usage-track')
  const value = typeof percent === 'number' ? Math.max(0, Math.min(100, Math.round(percent))) : null
  const fill = el('div', 'usage-fill')
  if (value !== null) {
    fill.style.width = `${value}%`
    if (value >= 80) fill.classList.add('is-high')
  } else {
    fill.style.width = '0%'
    fill.classList.add('is-unknown')
  }
  track.append(fill)
  const text = el('span', 'usage-value', value === null ? '?' : `${value}%`)
  bar.append(caption, track, text)
  return bar
}

/** ---------------------------------------------------------- 会话同步弹层 */

// 当前弹层里可选的会话与已选集合。放模块级是为了让全选/计数/确认共用同一份状态。
let syncState = { from: undefined, sessions: [], selected: new Set(), targetsLoading: false }

async function openSyncModal(fromAccount) {
  const modal = document.querySelector('#sync-modal')
  if (!modal) return
  syncState = { from: fromAccount, sessions: [], selected: new Set(), targetsLoading: true }
  modal.hidden = false
  document.querySelector('#sync-note').textContent = `正在读取账号 ${fromAccount} 的会话…`
  document.querySelector('#sync-list').replaceChildren()
  document.querySelector('#sync-confirm').disabled = true
  document.querySelector('#sync-count').textContent = '已选 0 个'
  const all = document.querySelector('#sync-all')
  if (all) all.checked = false

  try {
    // 这个接口在读磁盘（几十个索引文件），用 POST 和其它写操作走同一条分支；
    // 它不是写操作，但服务端只对 POST 开放业务路由。
    const data = await api('/api/accounts/sync/list', {
      method: 'POST',
      body: { name: fromAccount },
    })
    syncState.sessions = list(data?.sessions)
    renderSyncTargets(fromAccount)
    renderSyncList()
    const bodyless = syncState.sessions.filter((item) => !item.bodyExists).length
    document.querySelector('#sync-note').textContent =
      `账号 ${fromAccount} 共 ${syncState.sessions.length} 个会话。勾选要同步的那些，再选目标账号。` +
      (bodyless > 0 ? ` 其中 ${bodyless} 个的正文已不在本机（标黄的），同步过去可能打不开。` : '')
  } catch (error) {
    document.querySelector('#sync-note').textContent = '读取会话失败：' + (error?.message ?? '')
  } finally {
    syncState.targetsLoading = false
  }
}

function closeSyncModal() {
  const modal = document.querySelector('#sync-modal')
  if (modal) modal.hidden = true
}

/** 目标账号下拉：排除源账号自己。 */
function renderSyncTargets(fromAccount) {
  const select = document.querySelector('#sync-to')
  if (!select) return
  const others = list(accountsState?.accounts).filter((item) => item.name !== fromAccount)
  select.replaceChildren()
  if (others.length === 0) {
    const option = el('option', undefined, '（没有其它账号可同步）')
    option.value = ''
    select.append(option)
    select.disabled = true
    return
  }
  select.disabled = false
  for (const account of others) {
    const option = el('option', undefined, account.email ?? account.name)
    option.value = account.name
    select.append(option)
  }
}

function renderSyncList() {
  const host = document.querySelector('#sync-list')
  if (!host) return
  host.replaceChildren()
  const sessions = syncState.sessions
  if (sessions.length === 0) {
    host.append(el('div', 'side-hint', '这个账号没有可同步的会话。'))
    updateSyncCount()
    return
  }
  for (const session of sessions) {
    const row = el('label', 'sync-item')
    if (!session.bodyExists) row.classList.add('is-bodyless')

    const box = document.createElement('input')
    box.type = 'checkbox'
    box.checked = syncState.selected.has(session.sessionId)
    box.addEventListener('change', () => {
      if (box.checked) syncState.selected.add(session.sessionId)
      else syncState.selected.delete(session.sessionId)
      syncListItemState()
    })

    const title = el('span', 'sync-item-title', session.title)
    title.title = [session.title, session.cwd, session.bodyExists ? '' : '正文缺失']
      .filter(Boolean)
      .join('\n')

    const meta = el(
      'span',
      'sync-item-meta',
      [
        session.lastActivityAt ? new Date(session.lastActivityAt).toLocaleDateString() : undefined,
        session.completedTurns !== undefined ? `${session.completedTurns} 轮` : undefined,
        session.bodyExists ? undefined : '正文缺失',
      ]
        .filter(Boolean)
        .join(' · '),
    )

    row.append(box, title, meta)
    host.append(row)
  }
  updateSyncCount()
}

/** 勾选变化后同步"全选"框与按钮状态。 */
function syncListItemState() {
  updateSyncCount()
}

function updateSyncCount() {
  const count = syncState.selected.size
  document.querySelector('#sync-count').textContent = `已选 ${count} 个`
  const confirm = document.querySelector('#sync-confirm')
  const target = document.querySelector('#sync-to')
  if (confirm) confirm.disabled = count === 0 || !target?.value
  const all = document.querySelector('#sync-all')
  if (all) all.checked = count > 0 && count === syncState.sessions.length
}

async function confirmSync() {
  const target = document.querySelector('#sync-to')
  const button = document.querySelector('#sync-confirm')
  if (!target?.value || syncState.selected.size === 0) return
  const sessions = syncState.sessions.filter((item) => syncState.selected.has(item.sessionId))
  // 正文缺失的会话要单独警告：同步过去看得见标题，但点开是空的。
  const bodyless = sessions.filter((item) => !item.bodyExists)
  const detail =
    `· 源账号：${syncState.from}\n` +
    `· 目标账号：${target.value}\n` +
    `· 会话数量：${sessions.length}\n` +
    (bodyless.length > 0 ? `· 其中 ${bodyless.length} 个正文缺失，同步过去可能打不开\n` : '') +
    `\n同步后，目标账号就能看到这些会话的内容。`
  if (!window.confirm(`确认同步这些会话？\n\n${detail}`)) return

  const original = button.textContent
  button.disabled = true
  button.textContent = '同步中…'
  try {
    const result = await api('/api/accounts/sync', {
      method: 'POST',
      body: {
        from: syncState.from,
        to: target.value,
        sessionIds: [...syncState.selected],
        sourceOrgUuid: sessions[0]?.orgUuid,
        targetOrgUuid: undefined,
      },
    })
    const copied = result?.copied?.length ?? 0
    const skipped = result?.skipped?.length ?? 0
    toast(
      'ok',
      `已同步 ${copied} 个会话到 ${target.value}`,
      skipped > 0 ? `${skipped} 个因目标已存在而跳过` : '请重新打开 Claude 查看',
    )
    closeSyncModal()
    await refreshAccounts()
  } catch (error) {
    toast('error', '同步失败', error instanceof Error ? error.message : String(error))
  } finally {
    button.disabled = false
    button.textContent = original
  }
}

async function refreshAccounts() {
  try {
    renderAccounts(await api('/api/accounts'))
  } catch {
    // 读不到就保持上一屏，不要把界面清空。
  }
}

let switchingAccount = false

async function switchToAccount(name, label) {
  // 切换要几秒（结束进程 + 搬运 13MB），期间重复点击会排队执行好几次切换。
  if (switchingAccount) return
  switchingAccount = true
  document.querySelectorAll('.account-row').forEach((row) => row.classList.add('is-busy'))
  try {
    const result = await api('/api/accounts/switch', { method: 'POST', body: { name } })
    if (result?.switched === false) {
      // 合规检查没过：切换根本没发生，现场也没动过。
      toast('error', '环境不满足，已拒绝切号', result.reason ?? '白名单未命中')
      renderAccounts(result)
      return
    }
    toast('ok', `已切换到 ${label ?? name}`, 'Claude Desktop 需要你手动打开')
    renderAccounts(result)
  } catch (error) {
    toast('error', '切换失败', error instanceof Error ? error.message : String(error))
  } finally {
    switchingAccount = false
    document.querySelectorAll('.account-row').forEach((row) => row.classList.remove('is-busy'))
  }
}

/**
 * 更新账号存档：登录过期后，先在 Claude 里重新登录，再点这个把新登录态存回去。
 * 后端只允许更新"当前正在用的"那个号 —— 详见 session.js 里的说明。
 */
async function updateAccount(name, label) {
  const running = true
  if (running) {
    const confirmed = window.confirm(
      `用当前登录态更新 ${label} 的存档？\n\n` +
        `· 会先关闭 Claude Desktop\n` +
        `· 把现在的登录态存成 ${name}（覆盖旧存档，旧的一份留作 .bak）\n` +
        `· 完成后请手动重新打开 Claude\n\n` +
        `确认你已经在 Claude 里重新登录过了吗？`,
    )
    if (!confirmed) return
  }
  try {
    const result = await api('/api/accounts/update', { method: 'POST', body: { name } })
    toast('ok', `已更新 ${label}`, `${result?.entries ?? 0} 个身份条目`)
    renderAccounts(result)
  } catch (error) {
    toast('error', '更新失败', error instanceof Error ? error.message : String(error))
  }
}

async function deleteAccount(name, label) {
  const confirmed = window.confirm(
    `删除账号 ${label} 的存档？\n\n` +
      `· 会删掉这个账号在本机的 Cookies、会话历史和用量记录\n` +
      `· 不影响 Anthropic 服务端的账号本身\n` +
      `· 删掉后要再来得重新登录一次\n\n` +
      `确定删除吗？`,
  )
  if (!confirmed) return
  try {
    const result = await api('/api/accounts/delete', { method: 'POST', body: { name } })
    toast('ok', `已删除 ${label}`, '本机存档已移除')
    renderAccounts(result)
  } catch (error) {
    toast('error', '删除失败', error instanceof Error ? error.message : String(error))
  }
}

async function saveCurrentAccount() {
  const input = document.querySelector('#account-name')
  const button = document.querySelector('#account-save')
  // 名字可以留空：留空就自动分配 A、B、C…，这样"存一份"就是点一下的事。
  const name = (input?.value ?? '').trim()
  const original = button?.textContent
  // 保存同样要结束 Desktop（Cookies 是 SQLite，进程还在写的时候复制出来的快照可能不一致），
  // 所以也得先讲清楚，别让用户莫名其妙发现应用被关了。
  const confirmed = window.confirm(
    `把当前登录保存为账号 ${name || '（自动命名）'}？\n\n` +
      `· 如果 Claude Desktop 正在运行，会先关闭它\n` +
      `· 保存完成后请手动重新打开\n\n` +
      `继续吗？`,
  )
  if (!confirmed) return
  if (button) {
    button.disabled = true
    button.textContent = '保存中…'
  }
  try {
    const result = await api('/api/accounts/save', { method: 'POST', body: { name } })
    toast('ok', `已保存账号 ${result?.name ?? ''}`, `${result?.entries ?? 0} 个身份条目`)
    if (input) input.value = ''
    const form = document.querySelector('#account-form')
    if (form) form.hidden = true
    renderAccounts(result)
  } catch (error) {
    toast('error', '保存失败', error instanceof Error ? error.message : String(error))
  } finally {
    if (button) {
      button.disabled = false
      button.textContent = original
    }
  }
}

/** 首次构建按钮；重复调用不会重复创建。 */
function ensureActionButtons() {
  const host = document.querySelector('#action-buttons')
  if (host.dataset.ready === '1') return
  host.dataset.ready = '1'
  host.replaceChildren()
  for (const spec of ACTION_SPECS) {
    const button = el('button', `action ${spec.className ?? ''}`.trim())
    button.id = `action-${spec.id}`
    button.dataset.action = spec.id
    button.addEventListener('click', () => actionHandlers[spec.id]?.())
    const spinner = el('span', 'spinner')
    spinner.dataset.role = 'spinner'
    const label = el('span', 'action-label', spec.label)
    label.dataset.role = 'label'
    button.append(spinner, label)
    host.append(button)
  }
}

function updateActionButtons() {
  if (!status) return
  const host = document.querySelector('#action-buttons')
  const firewallOff = !status.firewallProfile?.anyEnabled
  const net = status.networkBlock ?? {}
  const running = Boolean(status.guard.running)
  for (const spec of ACTION_SPECS) {
    const button = host.querySelector(`button[data-action="${spec.id}"]`)
    if (!button) continue
    const busy = pending.has(spec.id)
    const labelNode = button.querySelector('[data-role="label"]')

    // 按钮要能回答"现在是什么状态"，而不只是"点了会发生什么"：
    // 已经在生效的动作改成"已…"并置为激活态，同时禁用（再点没有意义）。
    let label = spec.label
    let active = false
    let disabled = busy
    let hint = ''

    if (spec.id === 'guard') {
      const external = Boolean(status.claudeAccess?.externalGuard)
      label = running ? '停止闸门' : external ? '闸门已在运行（别处）' : '启动闸门'
      active = running
      // 别的实例已经在执法时，再点一下只会在它之外多起一个闸门 —— 两个闸门各自守一套
      // WFP 过滤器，停掉其中一个也解除不掉另一个的阻断。所以这里置灰并说清原因。
      disabled = busy || (!running && external)
      hint = disabled && !busy ? `闸门由${status.claudeAccess?.enforcedBy ?? '别的 CCGait 实例'}启动并维持着` : ''
      button.classList.toggle('ok', !running)
      button.classList.toggle('danger', running)
    } else if (spec.id === 'block') {
      if (net.blocked) {
        label = `已阻断网络（${net.programs ?? 0} 个程序）`
        active = true
        disabled = true
      }
    } else if (spec.id === 'unblock') {
      // 没有阻断时这个按钮点了也不会有任何变化，直接禁用并说明。
      disabled = busy || !net.blocked
      active = false
    } else if (spec.id === 'profiles') {
      label = '启用系统防火墙'
      active = false
    }

    labelNode.textContent = busy ? '处理中…' : label
    button.querySelector('[data-role="spinner"]').style.display = busy ? '' : 'none'
    button.classList.toggle('active', active)
    button.disabled = disabled
    button.title = hint || (spec.id === 'unblock' && !net.blocked ? '当前没有生效中的阻断' : '')
    // 「启用系统防火墙」只在防火墙关闭时出现。
    if (spec.needsFirewallOff) button.style.display = firewallOff ? '' : 'none'
  }
}

/**
 * 操作面板顶部的状态条：把"闸门在不在跑、网络断没断、防火墙开没开"写成一眼能读的三格。
 * 之前这些只体现在按钮文案上（启动闸门 / 停止闸门），很容易看不出当前状态。
 */
function renderStateStrip() {
  const host = document.querySelector('#action-state')
  if (!host) return
  host.replaceChildren()
  if (!status) return
  const net = status.networkBlock ?? {}
  const firewallOn = Boolean(status.firewallProfile?.anyEnabled)

  const cell = (name, value, tone) => {
    const box = el('div', 'state-cell')
    box.append(el('span', 'state-name', name))
    box.append(el('span', `state-value ${tone}`, value))
    return box
  }

  const layers = []
  if (net.wfp) layers.push('WFP 内核过滤器')
  if (net.firewallRules > 0) layers.push(`防火墙规则 ${net.firewallRules} 条`)

  // 「闸门」这一格不能只看本界面有没有自己的闸门：托盘（或另一个界面）起的闸门照样在执法，
  // 只看自己的会把"闸门正在终止 Claude"写成"未运行"，还和右边那格"网络阻断 生效中"打架。
  const external = Boolean(status.claudeAccess?.externalGuard)
  const guardValue = status.guard.running ? '运行中' : external ? '运行中（别的实例）' : '未运行'
  const guardOn = status.guard.running || external

  host.append(
    cell('闸门', guardValue, guardOn ? 'on' : 'off'),
    cell('网络阻断', net.blocked ? `生效中（${layers.join(' + ')}）` : '未生效', net.blocked ? 'on' : 'off'),
    cell('系统防火墙', firewallOn ? '已开' : '已关', firewallOn ? 'on' : 'warn'),
  )

  // 闸门对象在、pid 文件却指向别的进程：说明这个"运行中"不可信，必须明说。
  if (status.guard.running && status.guard.pidMatches === false) {
    const warn = el('div', 'notice warn')
    warn.append(
      el('span', 'icon', '!'),
      el(
        'span',
        undefined,
        `闸门状态可疑：pid 文件记录的是 ${status.guard.pid ?? '未知'}，不是当前界面进程。请点「停止闸门」再重新「启动闸门」以恢复一致。`,
      ),
    )
    host.append(warn)
  }
}

function renderActions() {
  ensureActionButtons()
  const sub = document.querySelector('#actions-sub')
  const notices = document.querySelector('#action-notices')
  notices.replaceChildren()
  renderStateStrip()

  const running = status.guard.running
  const externalGuard = Boolean(status.claudeAccess?.externalGuard)
  sub.textContent =
    running && status.guard.startedAt
      ? `运行中 · 启动于 ${new Date(status.guard.startedAt).toLocaleTimeString()}`
      : externalGuard
        ? `闸门由${status.claudeAccess?.enforcedBy ?? '别的 CCGait 实例'}启动并维持着`
        : ''

  // 执法不是本界面启动的：要说清"谁在拦"以及本界面能做什么，
  // 否则用户会以为这里写着"未运行"就是没人在拦（实测：托盘闸门正在终止 Claude，
  // 页面却显示"闸门 未运行"）。
  if (!running && externalGuard) {
    const notice = el('div', 'notice warn')
    notice.append(
      el('span', 'icon', '!'),
      el(
        'span',
        undefined,
        `闸门正在运行，但跑着的那个不是本界面启动的（${status.claudeAccess?.enforcedBy ?? '别的 CCGait 实例'}启动）：判定不通过时它同样会终止 Claude、阻断网络。` +
          '本界面的「停止闸门」停不到它，所以这里也不提供重复启动 —— 要停掉它，用托盘菜单，或命令行 `ccgait guard-stop`。',
      ),
    )
    notices.append(notice)
  }

  if (!status.elevated) {
    const notice = el('div', 'notice warn')
    notice.append(
      el('span', 'icon', '!'),
      el(
        'span',
        undefined,
        '当前进程不是管理员：无法创建/删除防火墙规则，网络阻断不会生效。请以管理员身份重启（ccgait ui）。',
      ),
    )
    notices.append(notice)
  }
  if (!status.firewallProfile?.anyEnabled) {
    const notice = el('div', 'notice warn')
    notice.append(
      el('span', 'icon', '!'),
      el('span', undefined, 'Windows 防火墙三个配置文件都是关闭状态，阻断规则不会生效。点「启用系统防火墙」开启。'),
    )
    notices.append(notice)
  }

  updateActionButtons()
}

function renderInventory() {
  const body = document.querySelector('#inventory-body')
  const sub = document.querySelector('#inventory-sub')
  body.replaceChildren()
  sub.textContent = `客户端 ${status.targets.length} · 规则 ${status.rules.length} · 进程 ${status.processes.length}`

  const sections = [
    { title: '发现的客户端', items: status.targets.map((item) => `[${item.kind}] ${item.path}`) },
    {
      title: '防火墙阻断规则',
      items: status.rules.map((rule) => `${rule.enabled ? '启用' : '停用'} · ${rule.program}`),
      empty: '当前没有 CCGait 阻断规则',
    },
    {
      title: '运行中的 Claude 进程',
      items: status.processes.map((item) => `${item.name} #${item.pid} [${item.kind}] ${item.exePath}`),
      empty: '没有正在运行的 Claude 客户端',
    },
  ]

  for (const section of sections) {
    const title = el('div', 'list-title')
    title.append(
      document.createTextNode(section.title),
      el('span', 'count', String(section.items.length)),
    )
    body.append(title)
    if (section.items.length === 0) {
      body.append(el('div', 'empty', section.empty ?? '无'))
    } else {
      const ul = el('ul', 'list')
      for (const item of section.items) ul.append(el('li', undefined, item))
      body.append(ul)
    }
  }
  for (const note of status.targetNotes ?? []) {
    body.append(el('div', 'hint dim', `注意：${note}`))
  }
}

let formDirty = false

function renderForm() {
  const config = status.config
  const set = (id, value) => {
    const input = document.querySelector(id)
    if (document.activeElement === input && formDirty) return
    if (input.type === 'checkbox') input.checked = Boolean(value)
    else input.value = value
  }
  set('#ips', list(config.whitelist.ips).join(', '))
  set('#cidrs', list(config.whitelist.cidrs).join(', '))
  set('#countries', list(config.whitelist.countries).join(', '))
  set('#asns', list(config.whitelist.asns).join(', '))
  set('#requireResidential', config.whitelist.requireResidential)
  set('#failClosed', config.enforcement.failClosed)
  set('#killProcesses', config.enforcement.killProcesses)
  set('#blockNetwork', config.enforcement.blockNetwork)
}

function renderChecks() {
  const host = document.querySelector('#checks-editor')
  host.replaceChildren()
  const checks = status.config.checks

  for (const [id, label] of Object.entries(CHECK_LABELS)) {
    const current = checks[id] ?? { enabled: true, severity: 'warn' }
    const row = el('div', 'check-row')

    const nameBox = el('div')
    nameBox.append(el('div', 'name', label.name), el('div', 'scope', label.scope))
    row.append(nameBox)

    const severity = el('select')
    for (const [value, text] of [
      ['block', '阻断'],
      ['warn', '仅提示'],
    ]) {
      const option = el('option', undefined, text)
      option.value = value
      if (current.severity === value) option.selected = true
      severity.append(option)
    }
    severity.dataset.check = id
    severity.dataset.field = 'severity'
    row.append(severity)

    const enabledWrap = el('label')
    enabledWrap.style.display = 'flex'
    enabledWrap.style.alignItems = 'center'
    enabledWrap.style.gap = '8px'
    enabledWrap.style.fontSize = '12px'
    enabledWrap.style.color = 'var(--text-dim)'
    const enabled = el('input')
    enabled.type = 'checkbox'
    enabled.checked = current.enabled
    enabled.dataset.check = id
    enabled.dataset.field = 'enabled'
    enabledWrap.append(enabled, document.createTextNode('启用'))
    row.append(enabledWrap)

    host.append(row)
  }
}

const splitList = (value) =>
  value
    .split(/[\s,，;；]+/)
    .map((item) => item.trim())
    .filter(Boolean)

function configPatchFromForm() {
  const checks = {}
  for (const input of document.querySelectorAll('#checks-editor [data-check]')) {
    const id = input.dataset.check
    checks[id] = checks[id] ?? {}
    checks[id][input.dataset.field] = input.dataset.field === 'enabled' ? input.checked : input.value
  }
  return {
    whitelist: {
      ips: splitList(document.querySelector('#ips').value),
      cidrs: splitList(document.querySelector('#cidrs').value),
      countries: splitList(document.querySelector('#countries').value).map((item) => item.toUpperCase()),
      asns: splitList(document.querySelector('#asns').value).map((item) => item.toUpperCase()),
      requireResidential: document.querySelector('#requireResidential').checked,
    },
    enforcement: {
      failClosed: document.querySelector('#failClosed').checked,
      killProcesses: document.querySelector('#killProcesses').checked,
      blockNetwork: document.querySelector('#blockNetwork').checked,
    },
    checks,
  }
}

async function saveConfig(successMessage) {
  await run('save-config', async () => {
    const result = await api('/api/config', { method: 'POST', body: { patch: configPatchFromForm() } })
    formDirty = false
    return result
  }, successMessage)
}

/** ------------------------------------------------------------------ 日志 */

const LOG_COLORS = { ok: 'OK', warn: 'WARN', block: 'BLOCK', error: 'ERR', info: 'INFO' }

function appendLog(entry) {
  const host = document.querySelector('#logs')
  if (host.querySelector('.empty')) host.replaceChildren()
  const line = el('div', `log-line ${entry.level}`)
  line.append(
    el('span', 'time', new Date(entry.at).toLocaleTimeString()),
    el('span', 'lvl', LOG_COLORS[entry.level] ?? entry.level),
  )
  const message = el('span')
  message.append(document.createTextNode(entry.message))
  if (entry.detail) message.append(el('span', 'detail', ` · ${entry.detail}`))
  line.append(message)
  host.append(line)
  host.scrollTop = host.scrollHeight
}

/** ------------------------------------------------------------------ 启动 */

document.querySelector('#save-config').addEventListener('click', () => void saveConfig('配置已保存'))
document.querySelector('#reload-config').addEventListener('click', () =>
  run('reload', () => api('/api/config/reload', { method: 'POST' }), '已重新读取配置'),
)
document.querySelector('#save-checks').addEventListener('click', () => void saveConfig('检查项已保存'))
document.querySelector('#ips').addEventListener('input', () => {
  formDirty = true
})
for (const id of ['#cidrs', '#countries', '#asns']) {
  document.querySelector(id).addEventListener('input', () => {
    formDirty = true
  })
}

/**
 * 国家点选器：常用国家做成可点的 chip，点一下加入/移出白名单。
 * 数据来自 CLDR 的常用地区中文名 —— 纯静态映射，不联网。
 */
const COUNTRY_CHOICES = [
  ['GB', '英国'],
  ['US', '美国'],
  ['JP', '日本'],
  ['SG', '新加坡'],
  ['HK', '香港'],
  ['DE', '德国'],
  ['FR', '法国'],
  ['NL', '荷兰'],
  ['KR', '韩国'],
  ['TW', '台湾'],
  ['CA', '加拿大'],
  ['AU', '澳大利亚'],
  ['IT', '意大利'],
  ['SE', '瑞典'],
  ['CH', '瑞士'],
  ['MY', '马来西亚'],
  ['TH', '泰国'],
  ['AE', '阿联酋'],
]

// 国家点选器默认收起：只在用户点「选择国家」时展开，避免整块 chip 墙占屏。
let countryPickerOpen = false

function renderCountryPicker() {
  const host = document.querySelector('#country-picker')
  if (!host) return
  const input = document.querySelector('#countries')
  const selected = () => new Set(splitList(input.value).map((item) => item.toUpperCase()))

  // 展开条：显示当前已选的 chip（紧凑），点击切换展开/收起。
  const toggle = el('button', 'country-toggle')
  toggle.type = 'button'
  const activeCodes = COUNTRY_CHOICES.filter(([code]) => selected().has(code))
  toggle.textContent = countryPickerOpen
    ? '收起国家列表 ▲'
    : `选择国家 ▼${activeCodes.length ? `（已选 ${activeCodes.length} 个）` : ''}`
  toggle.addEventListener('click', () => {
    countryPickerOpen = !countryPickerOpen
    renderCountryPicker()
  })

  host.replaceChildren(toggle)
  if (!countryPickerOpen) return

  const grid = el('div', 'country-grid')
  for (const [code, label] of COUNTRY_CHOICES) {
    const chip = el('button', 'country-chip', `${label} ${code}`)
    chip.type = 'button'
    chip.dataset.code = code
    chip.addEventListener('click', () => {
      const set = selected()
      if (set.has(code)) {
        set.delete(code)
      } else {
        set.add(code)
      }
      // 保留手写进去的非列表项：只按 COUNTRY_CHOICES 的顺序重排，不丢其它代码
      const chosen = COUNTRY_CHOICES.filter(([c]) => set.has(c)).map(([c]) => c)
      const extras = [...set].filter((code2) => !COUNTRY_CHOICES.some(([c]) => c === code2))
      input.value = [...chosen, ...extras].join(', ')
      formDirty = true
      renderCountryPicker()
    })
    if (selected().has(code)) chip.classList.add('is-active')
    grid.append(chip)
  }
  host.append(grid)
}
renderCountryPicker()
// 配置回填后（renderForm 会重写 #countries）再渲染一次，选中态才对得上磁盘上的值。
// 包一层而不是替换函数：调用方拿到的引用不变。
const originalRenderForm = renderForm
renderForm = function (...args) {
  originalRenderForm(...args)
  renderCountryPicker()
}

const events = new EventSource(`/api/events?token=${encodeURIComponent(TOKEN)}`)
events.addEventListener('log', (event) => {
  const payload = JSON.parse(event.data)
  appendLog(payload.entry)
})
for (const type of ['status', 'check', 'guard', 'interception']) {
  events.addEventListener(type, () => void refresh())
}
events.addEventListener('error', () => {
  // 浏览器会自动重连；只在日志区提示一次即可。
  document.querySelector('#logs-sub').textContent = '连接中断，重连中…'
})

void refresh()

// 门控启动按钮：每次点击都重新检测，不缓存上一次的结论 ——
// 用户点它的目的就是"按当前环境决定能不能开"。
document.querySelector('#launch-desktop')?.addEventListener('click', () => {
  void launchClaudeDesktop()
})

document.querySelector('#account-save')?.addEventListener('click', () => {
  void saveCurrentAccount()
})

// 「添加账号」默认收起：只有要加新号时才展开，展开后直接给出该做什么。
document.querySelector('#account-add')?.addEventListener('click', () => {
  const form = document.querySelector('#account-form')
  if (!form) return
  form.hidden = !form.hidden
  if (!form.hidden) document.querySelector('#account-name')?.focus()
})

// 会话同步弹层：关闭 / 取消 / 全选 / 目标变化 / 确认。
document.querySelector('#sync-close')?.addEventListener('click', () => closeSyncModal())
document.querySelector('#sync-cancel')?.addEventListener('click', () => closeSyncModal())
document.querySelector('#sync-modal')?.addEventListener('click', (event) => {
  // 只有点到背景才关，点弹层内部不关（否则拖动选择就会误关）。
  if (event.target?.id === 'sync-modal') closeSyncModal()
})
document.querySelector('#sync-all')?.addEventListener('change', (event) => {
  const checked = event.target.checked
  syncState.selected = checked
    ? new Set(syncState.sessions.map((item) => item.sessionId))
    : new Set()
  renderSyncList()
})
document.querySelector('#sync-to')?.addEventListener('change', () => updateSyncCount())
document.querySelector('#sync-confirm')?.addEventListener('click', () => void confirmSync())

// 回车就保存，省得每次都要去找按钮。
document.querySelector('#account-name')?.addEventListener('keydown', (event) => {
  if (event.key === 'Enter') void saveCurrentAccount()
})

setInterval(() => {
  // 兜底轮询：SSE 只推送"本界面自己"的动作 —— 托盘那边的闸门建立的阻断不会推事件，
  // 必须靠轮询兜住。这里**不再判断标签页是否在前台**：切到后台就不刷新，会让用户
  // 回来时看到过期状态（实测：托盘已经把网络断掉了，界面还写着"可以访问网络"）。
  // 本机回环请求很便宜，8 秒一次可以接受。
  void refresh()
}, 8_000)

/**
 * 侧栏导航：滚动时高亮当前所在面板（对齐 MoA Studio 的导航态）。
 */
function initScrollSpy() {
  const items = [...document.querySelectorAll('.nav-item')]
  if (items.length === 0) return
  const activate = (id) => {
    for (const item of items) item.classList.toggle('active', item.dataset.target === id)
  }
  activate(items[0].dataset.target)

  const observer = new IntersectionObserver(
    (entries) => {
      const visible = entries
        .filter((entry) => entry.isIntersecting)
        .sort((left, right) => left.boundingClientRect.top - right.boundingClientRect.top)[0]
      if (visible) activate(visible.target.id)
    },
    { rootMargin: '-10% 0px -70% 0px', threshold: 0 },
  )
  for (const item of items) {
    const section = document.getElementById(item.dataset.target)
    if (section) observer.observe(section)
  }
}

initScrollSpy()
