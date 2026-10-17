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
  fonts: { name: '中文字体指纹', scope: '等线 / 鸿蒙 / 阿里普惠体' },
  emojiFlags: { name: 'Emoji 国旗渲染', scope: '系统 emoji 字体被裁剪' },
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

/**
 * 每行的状态标签。
 *
 * 结论直接取自判定结果里的 reason id（check.blocked / check.warnings），
 * 不在界面里另写一套判断 —— 否则"界面显示通过、闸门却在拦"这种事迟早会发生。
 */
function statusTag(ids, { disabled = false } = {}) {
  const check = status.lastCheck ?? {}
  const blockedHit = list(check.blocked).find((item) => ids.includes(item.id))
  const warnHit = list(check.warnings).find((item) => ids.includes(item.id))
  if (blockedHit) return { node: el('span', 'tag danger', '未通过'), reason: blockedHit }
  if (warnHit) return { node: el('span', 'tag warn', '提示'), reason: warnHit }
  if (disabled) return { node: el('span', 'tag', '未启用'), reason: undefined }
  return { node: el('span', 'tag ok', '通过'), reason: undefined }
}

/** 带状态标签的一行：标签统一贴在值后面，鼠标悬停可看判定原文。 */
function statusRow(term, value, ids, options) {
  const row = kvRow(term, value)
  const { node, reason } = statusTag(ids, options)
  if (reason) {
    row.dd.append(el('span', 'tag-detail', reason.title))
  }
  row.dd.append(node)
  return row
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
  const wl = check.whitelist ?? {}
  const dl = el('dl', 'kv')

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

  // 出口：把"为什么通过/不通过"逐项摊开，而不是只给一个 GB 让人猜。
  const ipText = egress.ip ?? '未知'
  const parts = [ipText, egress.country ? `${egress.country}${egress.countryName ? `（${egress.countryName}）` : ''}` : undefined]
    .filter(Boolean)
    .join(' · ')
  const ipNode = el('span', 'mono', parts)
  if (egress.hosting) ipNode.append(el('span', 'tag warn', '机房/代理'))
  if (egress.mobile) ipNode.append(el('span', 'tag', '移动网络'))
  const egressRow = statusRow('出口', ipNode, [
    'egress-unknown',
    'egress-inconsistent',
    'egress-country',
    'egress-ip',
    'egress-cidr',
    'egress-asn',
    'egress-hosting',
    'egress-hosting-note',
    'egress-proxy-fallback',
  ])
  dl.append(egressRow.dt, egressRow.dd)

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
    const wlRow = kvRow('白名单比对', wlNode)
    const anyMiss = wlItems.some((item) => !item.hit)
    wlRow.dd.append(el('span', `tag ${anyMiss ? 'danger' : 'ok'}`, anyMiss ? '有不命中项' : '全部命中'))
    dl.append(wlRow.dt, wlRow.dd)
  }

  const consistent = egress.confident
    ? '一致（可信）'
    : `不一致 → IP ${JSON.stringify(egress.ipVotes ?? {})} / 国家 ${JSON.stringify(egress.countryVotes ?? {})}`
  const consistentRow = statusRow('多源一致性', consistent, ['egress-inconsistent', 'egress-unknown'])
  if (!egress.confident) consistentRow.dd.append(el('span', 'tag danger', '按拦截处理'))
  if (check.failedClosed && !list(check.blocked).some((item) => item.id.startsWith('egress'))) {
    consistentRow.dd.append(el('span', 'tag danger', 'failClosed 拦截'))
  }
  dl.append(consistentRow.dt, consistentRow.dd)

  if (egress.asnText) {
    const asnRow = statusRow('ASN / 机构', egress.asnText, ['egress-asn'])
    dl.append(asnRow.dt, asnRow.dd)
  }

  if (dns) {
    const groups = list(dns.hosts).map((item) => {
      const address = item.addresses?.[0]
      const suffix = item.country ? `(${item.country})` : ''
      return `${item.host} → ${address ?? item.error ?? '无结果'}${suffix}`
    })
    const dnsRow = statusRow('Claude 域名', groups.join('  ·  ') || '—', [
      'claude-dns-denied',
      'claude-dns-unresolved',
      'claude-dns-partial',
    ], { disabled: !checksEnabled('claudeDns') })
    if (list(dns.deniedHits).length > 0) dnsRow.dd.append(el('span', 'tag danger', '解析到被禁地区'))
    dl.append(dnsRow.dt, dnsRow.dd)
  }

  if (env.timezone) {
    const tzRow = statusRow(
      '系统时区',
      `${env.timezone.intl}${env.timezone.windows ? ` / ${env.timezone.windows}` : ''}`,
      ['timezone-domestic'],
      { disabled: !checksEnabled('timezone') },
    )
    if (env.timezone.domestic) tzRow.dd.append(el('span', 'tag warn', '国内时区'))
    dl.append(tzRow.dt, tzRow.dd)
  }

  if (env.language) {
    const langRow = statusRow('界面语言', list(env.language.uiLanguages).join('、') || '未知', ['language-chinese'], {
      disabled: !checksEnabled('language'),
    })
    if (env.language.chinese) langRow.dd.append(el('span', 'tag warn', '含中文'))
    dl.append(langRow.dt, langRow.dd)
  }

  if (env.fonts) {
    // 同一字体的多个字重会反复命中同一标签，去重后再展示（文件数用 tag 体现）。
    const strong = list(env.fonts.found).filter((item) => item.strong)
    const labels = [...new Set(strong.map((item) => item.label))]
    const fontRow = statusRow(
      '国内字体',
      labels.length > 0 ? labels.join('、') : '未命中专有字体',
      ['fonts-domestic', 'fonts-weak'],
      { disabled: !checksEnabled('fonts') },
    )
    if (labels.length > 0) fontRow.dd.append(el('span', 'tag warn', `命中 ${strong.length} 个字体文件`))
    dl.append(fontRow.dt, fontRow.dd)
  }

  if (env.emojiFont?.checked) {
    const emojiRow = statusRow(
      'Emoji 国旗渲染',
      env.emojiFont.present
        ? `Segoe UI Emoji ${Math.round((env.emojiFont.sizeBytes ?? 0) / 1024 / 1024)} MB`
        : '未检测到 Segoe UI Emoji',
      ['emoji-flags-suspect'],
      { disabled: !checksEnabled('emojiFlags') },
    )
    if (env.emojiFont.suspect) emojiRow.dd.append(el('span', 'tag warn', '可能被裁剪'))
    dl.append(emojiRow.dt, emojiRow.dd)
  }

  if (env.dnsServers) {
    const dnsServerRow = statusRow(
      '本机 DNS 服务器',
      list(env.dnsServers.servers).join('、') || '未读取',
      ['dns-servers-domestic'],
      { disabled: !checksEnabled('dnsServers') },
    )
    if (list(env.dnsServers.domestic).length > 0) {
      dnsServerRow.dd.append(el('span', 'tag warn', `国内 ${list(env.dnsServers.domestic).join('、')}`))
    }
    dl.append(dnsServerRow.dt, dnsServerRow.dd)
  }

  if (env.systemProxy) {
    const enabled = env.systemProxy.system?.enabled
    const envKeys = Object.keys(env.systemProxy.envVars ?? {})
    const proxyRow = statusRow(
      '系统代理',
      enabled ? `开启（${env.systemProxy.system.server ?? '—'}）` : envKeys.length > 0 ? `未开启，但有 ${envKeys.join('、')}` : '未检测到',
      ['proxy-leak'],
      { disabled: !checksEnabled('proxyEnvLeak') },
    )
    dl.append(proxyRow.dt, proxyRow.dd)
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

    if (spec.id === 'guard') {
      label = running ? '停止闸门' : '启动闸门'
      active = running
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
    button.title = spec.id === 'unblock' && !net.blocked ? '当前没有生效中的阻断' : ''
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

  host.append(
    cell('闸门', status.guard.running ? '运行中' : '未运行', status.guard.running ? 'on' : 'off'),
    cell('网络阻断', net.blocked ? `生效中（${layers.join(' + ')}）` : '未生效', net.blocked ? 'on' : 'off'),
    cell('系统防火墙', firewallOn ? '已开' : '已关', firewallOn ? 'on' : 'warn'),
  )
}

function renderActions() {
  ensureActionButtons()
  const sub = document.querySelector('#actions-sub')
  const notices = document.querySelector('#action-notices')
  notices.replaceChildren()
  renderStateStrip()

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
