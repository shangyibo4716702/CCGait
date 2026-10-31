import { ipInCidr } from './config.js'

/**
 * 白名单判定：把各维度检测结果折算成"放行 / 拦截"以及可读的原因列表。
 *
 * 判定原则：
 * - 白名单（IP / CIDR / 国家 / ASN）是主体：任一不命中即拦截。
 * - 判定不出结果（查询失败、多源互相矛盾）时，failClosed=true 一律按拦截处理。
 * - 其余维度（时区/语言/字体/DNS/系统代理）默认只报告，可按 config 提升为拦截。
 */

/** 严重度排序：block 立即拦截，warn 只提示。 */
const SEVERITY_RANK = { block: 2, warn: 1 }

function reason(id, severity, title, detail) {
  return { id, severity, title, detail }
}

/** 出口身份与白名单比对。 */
export function evaluateEgress(config, egress) {
  const reasons = []
  const { whitelist } = config
  if (!egress || egress.ip === undefined) {
    reasons.push(
      reason(
        'egress-unknown',
        'block',
        '无法确定出口 IP',
        `所有数据源都查询失败（${(egress?.failedSources ?? []).join('；') || '未知原因'}）。判定不出结果时按拦截处理。`,
      ),
    )
    return reasons
  }

  if (egress.proxyFallback) {
    reasons.push(
      reason(
        'egress-proxy-fallback',
        'warn',
        '配置的代理连不上，已按直连出口判定',
        `代理 ${egress.proxyUrl ?? '（未记录地址）'} 不可用（${(egress.proxyErrors ?? []).join('；') || '连接失败'}）。因为 network.proxy.required = false，本次按真实直连出口判定：${egress.ip}。如果你本来期望客户端走代理，请先启动代理再检测；若希望拿不到代理就一律拦截，把 network.proxy.required 设为 true。`,
      ),
    )
  }

  if (!egress.confident) {
    reasons.push(
      reason(
        'egress-inconsistent',
        'block',
        '出口信息多源不一致',
        `各数据源返回的 IP/国家互相矛盾（IP：${JSON.stringify(egress.ipVotes)}，国家：${JSON.stringify(egress.countryVotes)}）。这通常意味着流量被中间设备改造或分流只覆盖了部分程序，按拦截处理。`,
      ),
    )
  }

  if (whitelist.countries.length > 0 && !whitelist.countries.includes(egress.country)) {
    reasons.push(
      reason(
        'egress-country',
        'block',
        `出口国家不在白名单：${egress.country ?? '未知'}`,
        `当前出口 ${egress.ip} 落在 ${egress.countryName ?? egress.country ?? '未知'}（${egress.country ?? '??'}），白名单只允许 ${whitelist.countries.join('、')}。`,
      ),
    )
  }

  if (whitelist.ips.length > 0 && !whitelist.ips.includes(egress.ip)) {
    reasons.push(
      reason(
        'egress-ip',
        'block',
        `出口 IP 不是固定 IP：${egress.ip}`,
        `白名单固定 IP 为 ${whitelist.ips.join('、')}，当前是 ${egress.ip}。`,
      ),
    )
  }

  if (whitelist.cidrs.length > 0 && !whitelist.cidrs.some((cidr) => ipInCidr(egress.ip, cidr))) {
    reasons.push(
      reason(
        'egress-cidr',
        'block',
        `出口 IP 不在允许的网段：${egress.ip}`,
        `允许的网段为 ${whitelist.cidrs.join('、')}。`,
      ),
    )
  }

  if (whitelist.asns.length > 0) {
    const asn = String(egress.asn ?? '').toUpperCase()
    const matched = whitelist.asns.some((allowed) => {
      const bare = allowed.replace(/^AS/, '')
      return asn === allowed || asn.endsWith(`AS${bare}`) || asn.includes(bare)
    })
    if (!matched) {
      reasons.push(
        reason(
          'egress-asn',
          'block',
          `出口 ASN 不在白名单：${egress.asn ?? '未知'}`,
          `白名单允许 ${whitelist.asns.join('、')}；当前 ${egress.asnText || egress.asn || '未知'}。`,
        ),
      )
    }
  }

  if (!whitelist.requireResidential && egress.hosting) {
    reasons.push(
      reason(
        'egress-hosting-note',
        'warn',
        '出口是机房/代理 IP',
        `ASN/机构为 ${egress.asnText || '未知'}${egress.warp ? '（Cloudflare WARP）' : ''}。这是"非住宅出口"特征：公开经验里住宅出口比机房出口干净。若想一并拒绝机房出口，把 whitelist.requireResidential 设为 true。`,
      ),
    )
  }

  if (whitelist.requireResidential && egress.hosting) {
    reasons.push(
      reason(
        'egress-hosting',
        'block',
        '出口被判定为机房/代理，而非住宅网络',
        `ASN/机构为 ${egress.asnText || '未知'}${egress.warp ? '（检测到 Cloudflare WARP）' : ''}。白名单要求住宅出口；若你的固定 IP 本身就是机房或代理，请在 config 里把 whitelist.requireResidential 设为 false。`,
      ),
    )
  }

  return reasons
}

/** Claude 域名解析落地。 */
export function evaluateClaudeDns(config, dns, deniedCountries) {
  const reasons = []
  if (!dns) return reasons
  if (dns.deniedHits.length > 0) {
    reasons.push(
      reason(
        'claude-dns-denied',
        'block',
        'Claude 域名解析到被禁地区',
        dns.deniedHits
          .map((hit) => `${hit.host} → ${hit.ip}（${hit.country}${hit.isp ? `，${hit.isp}` : ''}）`)
          .join('；') + `。解析被污染或被就近劫持到 ${deniedCountries.join('、')} 节点。`,
      ),
    )
  } else if (!dns.resolved) {
    reasons.push(
      reason(
        'claude-dns-unresolved',
        'warn',
        'Claude 域名无法解析',
        '三个 Claude 域名都解析不到地址，网络可能未就绪或解析被拦截。',
      ),
    )
  } else if (dns.hasResolutionError) {
    reasons.push(
      reason(
        'claude-dns-partial',
        'warn',
        '部分 Claude 域名解析失败',
        dns.hosts
          .filter((item) => item.error)
          .map((item) => `${item.host}: ${item.error}`)
          .join('；'),
      ),
    )
  }
  return reasons
}

/** 系统环境特征（时区/语言/字体/DNS/系统代理）。 */
export function evaluateEnvironment(config, env) {
  const reasons = []

  if (env.timezone?.domestic) {
    reasons.push(
      reason(
        'timezone-domestic',
        'warn',
        `系统时区为 ${env.timezone.matched}`,
        `公开分析指出客户端会读取系统时区，Asia/Shanghai、Asia/Urumqi 等时区是与账号地区不一致的明显特征。CCGait 不会替你改系统设置；如需一致，请自行在系统设置里改成与出口国家相同的时区。`,
      ),
    )
  }

  if (env.language?.chinese) {
    reasons.push(
      reason(
        'language-chinese',
        'warn',
        '界面语言包含中文',
        `界面语言列表为 ${env.language.uiLanguages.join('、') || '未知'}（匹配 ${env.language.matched ?? env.language.culture}）。浏览器/客户端语言列表里的 zh-CN 同样是地区特征。`,
      ),
    )
  }

  if (env.fonts?.strong) {
    reasons.push(
      reason(
        'fonts-domestic',
        'warn',
        '系统装有国内专有字体',
        env.fonts.found
          .filter((item) => item.strong)
          .map((item) => `${item.label}（${item.file}）`)
          .join('、'),
      ),
    )
  } else if (env.fonts?.found?.length > 0) {
    reasons.push(
      reason(
        'fonts-weak',
        'warn',
        '系统装有中文 Windows 常见字体',
        env.fonts.found.slice(0, 6).map((item) => item.label).join('、'),
      ),
    )
  }

  // 实测解析出口：谁在真正回答我们的查询、它从哪个国家出去（对齐 ippure 的 DNS LEAK）。
  if (env.resolverEgress?.checked && env.resolverEgress.deniedHits?.length > 0) {
    reasons.push(
      reason(
        'resolver-egress-denied',
        'block',
        '解析出口落在被禁地区',
        `实测回答我们 DNS 查询的递归解析器是：${env.resolverEgress.deniedHits
          .map((item) => `${item.ip}（${item.country}${item.isp ? ` ${item.isp}` : ''}）`)
          .join('、')}。这是"实际解析路径"，与出口白名单是同一档：解析在国内落地会被就近调度到国内节点，也更容易解析到被墙地址。想让解析从境外出去，就把系统 DNS 换掉或让代理接管 DNS。`,
      ),
    )
  } else if (env.resolverEgress && env.resolverEgress.checked === false) {
    // 拿不到应答（对方权威域名被墙/网络没有解析器）：只提示，不拦 ——
    // 否则在国内网络会被自己拦住，而这个项目本身要拦的是"环境不对"，不是"测不出来"。
    reasons.push(
      reason(
        'resolver-egress-unknown',
        'warn',
        '无法确认解析出口',
        `查询谁在回答我们的 DNS 时没有拿到应答（${env.resolverEgress.error ?? '无应答'}）。这一项只提示、不拦截 —— 判不出结果不等于环境有问题。`,
      ),
    )
  }

  // 代理模式：规则模式下没命中规则的流量走直连，等于出口可能绕过代理。
  //
  // 为什么算硬门槛：和"系统代理开着但 CLI 不走它"是同一类问题 —— 出口路径本身
  // 不可控。实测踩过：Clash Verge 在 rule 模式时，DNS 查询在隧道和 WLAN 的国内
  // 解析器之间来回摆，闸门时拦时放，属于间歇性泄露。
  //
  // unknown 不拦：读不到配置通常说明本机没装受支持的代理客户端，当成违规就是误杀；
  // 真正的把关交给出口 IP / 解析出口这些实测项。
  if (env.proxyMode?.mode && env.proxyMode.mode !== 'unknown') {
    const mode = env.proxyMode.mode
    const coverage = env.proxyMode.coverage
    // 规则模式：Claude 的域名有专属规则、且排在 CN 分流之前 —— 这时等价于全局，
    // 只把非 Claude 的流量放直连，省流量。证明不了就照旧拦。
    const covered = mode === 'rule' && coverage?.ok === true
    if (mode !== 'global' && !covered) {
      const modeName = { rule: '规则模式', direct: '直连模式' }[mode] ?? mode
      const detail =
        mode === 'rule'
          ? `检测到代理客户端（${env.proxyMode.client ?? '未知客户端'}）当前是规则模式，但规则里没有可用的 Claude / Anthropic 条目。规则模式下没命中规则的流量走直连 —— Claude 的域名一旦不被规则覆盖，就会从物理网卡直接出去，和隧道出口不是同一个，属于间歇性泄露。请把 Claude 的域名加进规则并排在 CN 分流之前（面板上的「修正 Clash 设置」可以直接写进去），或者切回全局模式。`
          : `检测到代理客户端（${env.proxyMode.client ?? '未知客户端'}）当前是 ${modeName}。这种模式下没有命中规则的流量会走直连 —— 同一个程序有时走代理、有时从物理网卡直接出去，属于间歇性泄露，比稳定泄露更难发现。请在代理客户端里切到「全局模式」，或确认 Claude 相关域名与 DNS 查询都被规则覆盖。`
      reasons.push(
        reason('proxy-mode-not-global', 'block', `代理不是全局模式：${modeName}`, detail),
      )
    }
  } else if (env.proxyMode && env.proxyMode.mode === 'unknown') {
    reasons.push(
      reason(
        'proxy-mode-unknown',
        'warn',
        '无法确认代理模式',
        '没找到受支持的代理客户端配置（Clash Verge / FlClash 等），或配置里没有可读的模式字段。这一项只提示、不拦截。',
      ),
    )
  }

  // 代理的三个关键开关：IPv6 / DNS 覆写 / 覆写内的 IPv6。
  //
  // 它们共同决定"DNS 是不是被代理接管"。实测踩过的组合：IPv6 关了但 DNS 覆写里的
  // IPv6 还开着，解析出口在境外隧道和国内递归解析器之间来回摆，闸门时拦时放。
  // 只在检测到代理客户端时才判 —— 没装代理的环境不该被这项拦住。
  if (env.proxySettings?.checked && env.proxySettings.issues?.length > 0) {
    for (const issue of env.proxySettings.issues) {
      reasons.push(reason(issue.id, 'block', issue.title, issue.detail))
    }
  }

  if (env.dnsServers?.domestic?.length > 0) {
    reasons.push(
      reason(
        'dns-servers-domestic',
        'warn',
        '配置的解析服务器在国内',
        `已连接网卡上配置了：${env.dnsServers.domestic.join('、')}。注意这一项读的是"系统里配置了哪台解析服务器"，不是"实际解析走了哪条路径" —— 网卡同时配了 IPv6 解析器时，真正回答查询的可能是路由器转发的 ISP 解析器（那台是运营商自带、判不了归属，本项测不到）。配在国内意味着哪天这条路径被用上，CDN 会就近调度到国内节点、也更容易解析到被墙地址。`,
      ),
    )
  }

  // Emoji 国旗渲染：对齐 ippure 的同类检测（那边用 Canvas 逐像素，这里看系统字体资产）。
  if (env.emojiFont?.checked && env.emojiFont.suspect) {
    reasons.push(
      reason(
        'emoji-flags-suspect',
        'warn',
        'Emoji 国旗渲染可能被裁剪',
        `${env.emojiFont.reason ?? '系统 emoji 字体不是完整的彩色版本'}。公开分析把它列为"中国区系统特征"之一。注意本项是基于系统字体资产的近似判定（浏览器端 Canvas 逐像素探测更准），因此默认只提示。`,
      ),
    )
  }

  if (env.systemProxy?.hasAny) {
    const parts = []
    if (env.systemProxy.system?.enabled) {
      parts.push(`系统代理已开启（${env.systemProxy.system.server ?? '未记录地址'}）`)
    }
    const envKeys = Object.keys(env.systemProxy.envVars ?? {})
    if (envKeys.length > 0) parts.push(`进程环境变量里有 ${envKeys.join('、')}`)
    reasons.push(
      reason(
        'proxy-leak',
        'warn',
        '检测到系统代理/代理环境变量',
        `${parts.join('；')}。注意：系统代理只对走 WinINET 的程序生效，CLI 直连时看到的是物理网卡出口 —— 如果出口检测拿到的不是白名单 IP，说明分流没有覆盖到 CLI，需要用 TUN 模式或给 CLI 单独指定代理。`,
      ),
    )
  }

  return reasons
}

/**
 * 汇总判定。
 * input: { config, egress, dns, environment, deniedCountries }
 * 返回 { allow, blockedBy, reasons, whitelistSummary }
 */
export function decide({ config, egress, dns, environment, deniedCountries = ['CN'] }) {
  const reasons = []
  const checks = config.checks

  if (checks.egressIp.enabled) {
    reasons.push(...evaluateEgress(config, egress))
  } else {
    reasons.push(
      reason('egress-disabled', 'warn', 'IP/国家白名单检查已关闭', 'checks.egressIp.enabled=false，闸门不会因为出口地址拦截任何客户端。'),
    )
  }

  if (checks.claudeDns.enabled) reasons.push(...evaluateClaudeDns(config, dns, deniedCountries))
  reasons.push(...evaluateEnvironment(config, environment ?? {}))

  // 按配置的严重度折算：warn 类检查若被提升为 block，就在此处生效。
  // 注意：egress-* 里有几条例外 —— 关闭检查的提示、机房出口提示、代理回退提示，
  // 它们本身是 warn，不能因为前缀是 egress 就被当成拦截项。
  const WARN_ONLY_IDS = new Set([
    'egress-disabled',
    'egress-hosting-note',
    'egress-proxy-fallback',
    // 判不出结果 ≠ 环境不对：这一条不该被提升成拦截。
    'resolver-egress-unknown',
    // 同上：读不到代理配置，不等于它开着规则模式。
    'proxy-mode-unknown',
  ])
  const severityOf = (id) => {
    if (WARN_ONLY_IDS.has(id)) return 'warn'
    if (id.startsWith('egress')) return 'block'
    if (id.startsWith('claude-dns')) return checks.claudeDns.severity
    if (id === 'timezone-domestic') return checks.timezone.severity
    if (id.startsWith('language')) return checks.language.severity
    if (id.startsWith('fonts')) return checks.fonts.severity
    if (id.startsWith('emoji-flags')) return checks.emojiFlags.severity
    if (id.startsWith('resolver-egress')) return checks.resolverEgress.severity
    if (id.startsWith('dns-servers')) return checks.dnsServers.severity
    if (id === 'proxy-leak') return checks.proxyEnvLeak.severity
    if (id.startsWith('proxy-mode')) return checks.proxyMode.severity
    if (id.startsWith('proxy-ipv6') || id.startsWith('proxy-dns')) return checks.proxySettings.severity
    return 'warn'
  }

  const enabledOf = (id) => {
    if (id.startsWith('egress')) return checks.egressIp.enabled
    if (id.startsWith('claude-dns')) return checks.claudeDns.enabled
    if (id === 'timezone-domestic') return checks.timezone.enabled
    if (id.startsWith('language')) return checks.language.enabled
    if (id.startsWith('fonts')) return checks.fonts.enabled
    if (id.startsWith('emoji-flags')) return checks.emojiFlags.enabled
    if (id.startsWith('resolver-egress')) return checks.resolverEgress.enabled
    if (id.startsWith('dns-servers')) return checks.dnsServers.enabled
    if (id === 'proxy-leak') return checks.proxyEnvLeak.enabled
    if (id.startsWith('proxy-mode')) return checks.proxyMode.enabled
    if (id.startsWith('proxy-ipv6') || id.startsWith('proxy-dns')) return checks.proxySettings.enabled
    return true
  }

  const effective = []
  for (const item of reasons) {
    if (!enabledOf(item.id)) continue
    effective.push({ ...item, severity: severityOf(item.id) })
  }

  // failClosed：出口判定不可信时，即使检查项自身只报 warn，也必须拦。
  const egressUnverified =
    checks.egressIp.enabled &&
    (!egress || egress.ip === undefined || egress.confident !== true)
  const failedClosed = config.enforcement.failClosed && egressUnverified

  const blocked = effective.filter((item) => item.severity === 'block')
  const warnings = effective.filter((item) => item.severity === 'warn')

  return {
    allow: blocked.length === 0 && !failedClosed,
    failedClosed,
    blockedBy: blocked,
    warnings,
    reasons: effective,
    whitelistSummary: {
      ips: config.whitelist.ips,
      cidrs: config.whitelist.cidrs,
      countries: config.whitelist.countries,
      asns: config.whitelist.asns,
      requireResidential: config.whitelist.requireResidential,
    },
  }
}

export function severityRank(severity) {
  return SEVERITY_RANK[severity] ?? 0
}
