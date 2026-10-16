/**
 * CCGait 前端。纯原生 ES 模块，无框架、无外部资源（离线可用，也不会向外发请求）。
 *
 * 数据来源两条：
 * - REST：拉取状态快照、触发动作；
 * - SSE（/api/events）：闸门状态变化、检测结果、日志实时推送。
 */

const TOKEN = document.querySelector('meta[name="ccgait-token"]').content

const CHECK_LABELS = {
  egressIp: { name: '出口 IP / 国家 / ASN', scope: '白名单主体' },
  claudeDns: { name: 'Claude 域名解析落地', scope: '解析被污染时命中' },
  timezone: { name: '系统时区', scope: '如 Asia/Shanghai' },
  language: { name: '界面语言', scope: '列表含 zh-CN' },
  fonts: { name: '中文字体指纹', scope: '等线 / 鸿蒙 / MiSans' },
  dnsServers: { name: 'DNS 服务器位置', scope: '国内公共 DNS' },
  proxyEnvLeak: { name: '系统代理 / 分流覆盖', scope: 'CLI 是否直连' },
}

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
    status = await api('/api/status')
    render()
  } catch (error) {
    toast('error', '读取状态失败', error instanceof Error ? error.message : String(error))
  }
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

function kvRow(term, value, extra) {
  const dt = el('dt', undefined, term)
  const dd = el('dd')
  if (typeof value === 'string') {
    dd.append(document.createTextNode(value))
  } else if (value instanceof Node) {
    dd.append(value)
  }
  if (extra) dd.append(extra)
  return { dt, dd }
}

/** ------------------------------------------------------------------ 渲染 */

function render() {
  if (!status) return
  renderHeader()
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
  const dl = el('dl', 'kv')

  const ipText = egress.ip ?? '未知'
  const parts = [ipText, egress.country ? `${egress.country}${egress.countryName ? `（${egress.countryName}）` : ''}` : undefined]
    .filter(Boolean)
    .join(' · ')
  const ipNode = el('span', 'mono', parts)
  if (egress.hosting) ipNode.append(el('span', 'tag warn', '机房/代理'))
  if (egress.mobile) ipNode.append(el('span', 'tag', '移动网络'))
  const { dt, dd } = kvRow('出口', ipNode)
  dl.append(dt, dd)

  const consistent = egress.confident
    ? '一致（可信）'
    : `不一致 → IP ${JSON.stringify(egress.ipVotes ?? {})} / 国家 ${JSON.stringify(egress.countryVotes ?? {})}`
  const row = kvRow('多源一致性', consistent)
  if (!egress.confident) row.dd.append(el('span', 'tag danger', '按拦截处理'))
  dl.append(row.dt, row.dd)

  if (egress.asnText) {
    const row2 = kvRow('ASN / 机构', egress.asnText)
    dl.append(row2.dt, row2.dd)
  }

  if (dns) {
    const groups = list(dns.hosts).map((item) => {
      const address = item.addresses?.[0]
      const suffix = item.country ? `(${item.country})` : ''
      return `${item.host} → ${address ?? item.error ?? '无结果'}${suffix}`
    })
    const row3 = kvRow('Claude 域名', groups.join('  ·  ') || '—')
    if (list(dns.deniedHits).length > 0) row3.dd.append(el('span', 'tag danger', '解析到被禁地区'))
    dl.append(row3.dt, row3.dd)
  }

  if (env.timezone) {
    const row4 = kvRow('系统时区', `${env.timezone.intl}${env.timezone.windows ? ` / ${env.timezone.windows}` : ''}`)
    if (env.timezone.domestic) row4.dd.append(el('span', 'tag warn', '国内时区'))
    dl.append(row4.dt, row4.dd)
  }

  if (env.language) {
    const row5 = kvRow('界面语言', list(env.language.uiLanguages).join('、') || '未知')
    if (env.language.chinese) row5.dd.append(el('span', 'tag warn', '含中文'))
    dl.append(row5.dt, row5.dd)
  }

  if (env.fonts) {
    // 同一字体的多个字重会反复命中同一标签，去重后再展示（文件数用 tag 体现）。
    const strong = list(env.fonts.found).filter((item) => item.strong)
    const labels = [...new Set(strong.map((item) => item.label))]
    const row6 = kvRow('国内字体', labels.length > 0 ? labels.join('、') : '未命中专有字体')
    if (labels.length > 0) {
      row6.dd.append(el('span', 'tag warn', `命中 ${strong.length} 个字体文件`))
    }
    dl.append(row6.dt, row6.dd)
  }

  if (env.dnsServers) {
    const row7 = kvRow('DNS 服务器', list(env.dnsServers.servers).join('、') || '未读取')
    if (list(env.dnsServers.domestic).length > 0) {
      row7.dd.append(el('span', 'tag warn', `国内 ${list(env.dnsServers.domestic).join('、')}`))
    }
    dl.append(row7.dt, row7.dd)
  }

  if (env.systemProxy) {
    const enabled = env.systemProxy.system?.enabled
    const envKeys = Object.keys(env.systemProxy.envVars ?? {})
    const row8 = kvRow(
      '系统代理',
      enabled ? `开启（${env.systemProxy.system.server ?? '—'}）` : envKeys.length > 0 ? `未开启，但有 ${envKeys.join('、')}` : '未检测到',
    )
    dl.append(row8.dt, row8.dd)
  }

  body.append(dl)

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
  for (const spec of ACTION_SPECS) {
    const button = host.querySelector(`button[data-action="${spec.id}"]`)
    if (!button) continue
    const busy = pending.has(spec.id)
    const running = Boolean(status.guard.running)
    const label = spec.id === 'guard' ? (running ? '停止闸门' : '启动闸门') : spec.label
    button.querySelector('[data-role="label"]').textContent = busy ? '处理中…' : label
    button.querySelector('[data-role="spinner"]').style.display = busy ? '' : 'none'
    button.classList.toggle('ok', spec.id === 'guard' && !running)
    button.classList.toggle('danger', spec.id === 'guard' && running)
    button.disabled = busy
    // 「启用系统防火墙」只在防火墙关闭时出现。
    if (spec.needsFirewallOff) button.style.display = firewallOff ? '' : 'none'
  }
}

function renderActions() {
  ensureActionButtons()
  const sub = document.querySelector('#actions-sub')
  const notices = document.querySelector('#action-notices')
  notices.replaceChildren()

  const running = status.guard.running
  sub.textContent =
    running && status.guard.startedAt
      ? `运行中 · 启动于 ${new Date(status.guard.startedAt).toLocaleTimeString()}`
      : ''

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

const events = new EventSource(`/api/events?token=${encodeURIComponent(TOKEN)}`)
events.addEventListener('log', (event) => {
  const payload = JSON.parse(event.data)
  appendLog(payload.entry)
})
for (const type of ['status', 'check', 'guard']) {
  events.addEventListener(type, () => void refresh())
}
events.addEventListener('error', () => {
  // 浏览器会自动重连；只在日志区提示一次即可。
  document.querySelector('#logs-sub').textContent = '连接中断，重连中…'
})

void refresh()
setInterval(() => {
  // 兜底轮询：SSE 断线时界面仍能自更新（管理员/防火墙状态等本地信息变化不会推事件）。
  if (document.visibilityState === 'visible') void refresh()
}, 15_000)

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
