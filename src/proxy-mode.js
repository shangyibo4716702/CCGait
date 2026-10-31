import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/**
 * 代理模式检查：代理客户端是不是"全局模式"。
 *
 * 为什么这一项算硬门槛：规则模式下，没命中任何规则的流量**走直连**。Claude 的域名
 * 一旦没被规则覆盖、或者 DNS 查询本身不属于任何规则，就会从物理网卡直接出去 ——
 * 这和"出口不在白名单"是同一件事，只是更隐蔽（同一台机器上有时走代理、有时直连）。
 *
 * 实测佐证：本机开着 Clash Verge、`mode: rule` 时，DNS 查询会在隧道和
 * WLAN 的腾讯解析器（119.29.29.29）之间来回摆，闸门有时报国内解析出口、有时通过。
 * 这是间歇性泄露，比稳定泄露更难发现。
 *
 * 判定顺序（先准后全）：
 *  1. Clash 的 external-controller API（`GET /configs` 返回当前 mode）—— 最准，
 *     因为它反映运行时真实状态，不受配置文件里"写的是什么"影响；
 *  2. 退回读运行时 YAML 里的 `mode:`；
 *  3. 都拿不到 → mode = 'unknown'（**判不出来不算违规**，只提示 —— 和
 *     其它"没测出来"的项保持同一口径）。
 */

/** 常见代理客户端的配置目录（按优先级）。同一台机器可能装了多个，全部尝试。 */
export function proxyConfigDirs(env = process.env, home = homedir()) {
  const roaming = env.APPDATA || join(home, 'AppData', 'Roaming')
  const local = env.LOCALAPPDATA || join(home, 'AppData', 'Local')
  return [
    // Clash Verge / Verge Rev
    join(roaming, 'io.github.clash-verge-rev.clash-verge-rev'),
    join(local, 'io.github.clash-verge-rev.clash-verge-rev'),
    // FlClash
    join(roaming, 'com.follow.clash'),
    join(local, 'com.follow', 'clash'),
    // Clash for Windows / 旧版
    join(roaming, 'Clash for Windows'),
    join(home, '.config', 'clash'),
  ]
}

/** 运行时配置文件（Clash Verge 用 clash-verge.yaml，其它客户端用 config.yaml）。 */
const CONFIG_FILES = ['clash-verge.yaml', 'config.yaml', 'verge.yaml', 'clash.yaml']

/**
 * 从 YAML 里取一个标量。只处理本节需要的形态（`key: value`、引号、行内注释），
 * 不引入 YAML 依赖 —— 这个项目零依赖。
 */
export function readYamlScalar(text, key) {
  const pattern = new RegExp(`^[ \\t]*${key}[ \\t]*:[ \\t]*(.*)$`, 'm')
  const match = pattern.exec(text)
  if (!match) return undefined
  let value = match[1].trim()
  // 去掉行尾注释（但别把引号里的 # 当注释）
  if (!value.startsWith("'") && !value.startsWith('"')) {
    const hash = value.indexOf(' #')
    if (hash >= 0) value = value.slice(0, hash).trim()
  }
  value = value.replace(/^['"]|['"]$/g, '').trim()
  return value.length > 0 ? value : undefined
}

/** external-controller 可能是 `127.0.0.1:9097`、`0.0.0.0:9090`、`:9090` 或带协议。 */
export function normalizeController(value) {
  if (!value) return undefined
  let address = value.trim()
  // unix socket 没法用 HTTP 查，直接放弃
  if (address.startsWith('unix://') || address.startsWith('/')) return undefined
  address = address.replace(/^0\.0\.0\.0:/, '127.0.0.1:').replace(/^:/, '127.0.0.1:')
  if (!/^https?:\/\//.test(address)) address = `http://${address}`
  return address.replace(/\/+$/, '')
}

const VALID_MODES = new Set(['global', 'rule', 'direct'])

/**
 * 读出代理当前模式。
 *
 * @returns {{ mode: 'global'|'rule'|'direct'|'unknown', source?: string, endpoint?: string, client?: string }}
 */
export async function probeProxyMode({
  env = process.env,
  home = homedir(),
  exists = existsSync,
  readFile = (p) => readFileSync(p, 'utf8'),
  readDir = readdirSync,
  fetchText,
  timeoutMs = 3000,
} = {}) {
  const dirs = proxyConfigDirs(env, home).filter((dir) => exists(dir))

  for (const dir of dirs) {
    for (const name of CONFIG_FILES) {
      const file = join(dir, name)
      if (!exists(file)) continue
      let text
      try {
        text = readFile(file)
      } catch {
        continue
      }

      // 1) API 优先：它反映运行时真实状态。
      const controller = normalizeController(readYamlScalar(text, 'external-controller'))
      if (controller && fetchText) {
        const secret = readYamlScalar(text, 'secret')
        const headers = secret ? { authorization: `Bearer ${secret}` } : {}
        try {
          const result = await withTimeout(
            fetchText(`${controller}/configs`, { headers }),
            timeoutMs,
          )
          if (result?.status === 200 && result.text) {
            const mode = String(JSON.parse(result.text)?.mode ?? '').toLowerCase()
            if (VALID_MODES.has(mode)) {
              return { mode, source: 'api', endpoint: controller, client: name, dir }
            }
          }
        } catch {
          // 端口没开 / 认证失败 / 超时：退回读 YAML。
        }
      }

      // 2) 退回 YAML 里的 mode。
      const rawMode = readYamlScalar(text, 'mode')
      const mode = rawMode ? rawMode.toLowerCase() : ''
      if (VALID_MODES.has(mode)) {
        return { mode, source: 'config', client: name, dir }
      }
    }
  }

  return { mode: 'unknown' }
}

/** 简单超时包装：fetch 本身带 signal，这里兜住不支持 signal 的实现。 */
function withTimeout(promise, ms) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms)),
  ])
}

/**
 * 取一个顶层块（如 `dns:`）下的全部内容，供读嵌套字段用。
 *
 * 只处理"顶层键 + 缩进子块"这种形态，不引入 YAML 依赖。返回的是子块原文，
 * 再交给 readYamlScalar 取具体键 —— 例如 `dns.ipv6` 就是先取 dns 块再读 ipv6。
 */
export function readYamlBlock(text, section) {
  const lines = text.split(/\r?\n/)
  const start = lines.findIndex((line) => new RegExp(`^${section}[ \\t]*:`).test(line))
  if (start < 0) return undefined
  const collected = []
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i]
    if (line.trim().length === 0) {
      collected.push(line)
      continue
    }
    // 缩进没了就说明这个块结束了
    if (!/^[ \t]/.test(line)) break
    collected.push(line)
  }
  return collected.length > 0 ? collected.join('\n') : undefined
}

/**
 * 读一个 YAML 列表（`key:` 后面跟若干 `- item` 行）。
 *
 * 只处理这种最常见的列表形态 —— 代理配置里的 `nameserver` 就是它。
 * 引号会被去掉，行尾注释会被切掉。
 */
export function readYamlList(text, key) {
  const lines = text.split(/\r?\n/)
  const pattern = new RegExp('^' + '[ \\t]*' + key + '[ \\t]*:' + '[ \\t]*$')
  const start = lines.findIndex((line) => pattern.test(line))
  if (start < 0) return []

  // 以**第一个列表项的缩进**为基准。同一缩进的 `- x` 才算这个列表的成员；
  // 缩进退回去（出现新的键）或变成更深缩进（进了子结构）就结束。
  // 早先只判断"是不是列表项"，结果把后面 fallback-filter 的 `- +.google.com`
  // 也吃进来了 —— 那会让判定看到一堆根本不存在的上游。
  let baseIndent = undefined
  const items = []
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i]
    if (line.trim().length === 0) continue
    const match = /^([ \t]*)-[ \t]*(.+?)\s*$/.exec(line)
    if (!match) break
    const indent = match[1].length
    if (baseIndent === undefined) baseIndent = indent
    if (indent !== baseIndent) break

    let value = match[2].trim()
    if (!value.startsWith('"') && !value.startsWith("'")) {
      const hash = value.indexOf(' #')
      if (hash >= 0) value = value.slice(0, hash).trim()
    }
    value = value.replace(/^['"]|['"]$/g, '').trim()
    if (value.length > 0) items.push(value)
  }
  return items
}

/** 国内解析器的特征（用于识别"混进去会飘"的上游）。 */
const DOMESTIC_DNS_MARKERS = [
  'doh.pub',
  'alidns',
  'dnspod',
  '223.5.5.5',
  '223.6.6.6',
  '119.29.29.29',
  '182.254.116.116',
  '114.114.114.114',
  '114.114.115.115',
  '180.76.76.76',
  '1.2.4.8',
  '117.50.10.10',
  '101.226.4.6',
  'dns.qq.com',
  'dns.baidu.com',
]

/** 境外解析器的特征。 */
const OVERSEAS_DNS_MARKERS = [
  '8.8.8.8',
  '8.8.4.4',
  '1.1.1.1',
  '1.0.0.1',
  '9.9.9.9',
  '149.112.112.112',
  '208.67.222.222',
  '208.67.220.220',
  'dns.google',
  'cloudflare-dns.com',
  'dns.quad9.net',
  'opendns.com',
]

/** 把一个上游条目分类成 domestic / overseas / unknown。 */
export function classifyDnsUpstream(entry) {
  const lower = String(entry ?? '').toLowerCase()
  if (!lower) return 'unknown'
  if (DOMESTIC_DNS_MARKERS.some((marker) => lower.includes(marker))) return 'domestic'
  if (OVERSEAS_DNS_MARKERS.some((marker) => lower.includes(marker))) return 'overseas'
  // 以 .cn 结尾的域名一律按国内算
  if (/\.cn(\/|$|:)/.test(lower) || lower.endsWith('.cn')) return 'domestic'
  return 'unknown'
}

/**
 * 判 DNS 上游列表：混入国内解析器就会让解析出口"飘"。
 *
 * 实测机制（本机）：`nameserver` 同时写了 8.8.8.8（经代理出国）和
 * doh.pub / dns.alidns.com（国内 DoH）。Clash 对这些上游**并发查询、谁先答用谁**，
 * 国内 DoH 通常更快，于是多数时候解析出口是国内的 112.28.209.x（中国移动），
 * 偶尔 8.8.8.8 抢先就变成海外 IP。因为不是每查询都随机，表现为"一段时间稳定在国内、
 * 过一会儿稳定在海外" —— 看起来像飘，实际是上游选路在切换。
 *
 * 后果：解析出口这个信号变得不可信，既不能当硬门槛也会误报。
 */
export function judgeDnsUpstreams({ nameserver } = {}, { enabled = true } = {}) {
  if (!enabled) return []
  const list = Array.isArray(nameserver) ? nameserver : []
  if (list.length === 0) return []

  const domestic = list.filter((entry) => classifyDnsUpstream(entry) === 'domestic')
  const overseas = list.filter((entry) => classifyDnsUpstream(entry) === 'overseas')
  if (domestic.length === 0) return []

  const mixed = overseas.length > 0
  return [
    {
      id: 'proxy-dns-upstream-domestic',
      title: mixed ? 'DNS 上游混入了国内解析器' : 'DNS 上游全是国内解析器',
      detail: mixed
        ? `代理的 DNS 上游同时包含国内（${domestic.join('、')}）与国外（${overseas.join('、')}）解析器。Clash 对这些上游并发查询、谁先答用谁，国内通常更快，于是解析出口会在"国内递归解析器"和"境外出口"之间来回切换 —— 表现就是解析出口时好时坏。请把国内那几条从 nameserver 里删掉，只留国外；解析机场节点域名用的 proxy-server-nameserver 可以保留国内。`
        : `代理的 DNS 上游只有国内解析器（${domestic.join('、')}），解析出口必然落在国内，与出口白名单不一致。请改成国外解析器（如 8.8.8.8 / https://dns.google/dns-query）。`,
    },
  ]
}

/** 从块里读布尔；读不到返回 undefined（不要默认成 false 或 true）。 */
export function readYamlBool(text, key) {
  const value = readYamlScalar(text, key)
  if (value === undefined) return undefined
  const lower = value.toLowerCase()
  if (lower === 'true') return true
  if (lower === 'false') return false
  return undefined
}

/**
 * 读出代理客户端的关键开关。
 *
 * 为什么这三项要查：它们共同决定"DNS 是不是被代理接管"。
 *  - `ipv6`（clash 顶层）：一旦开启，IPv6 流量可能绕开 TUN 直连；
 *  - `enable_dns_settings`（Verge 的 DNS 覆写）：关掉后系统 DNS 回到网卡配置，
 *    解析就从运营商/公共国内解析器出去，与隧道出口不一致；
 *  - `dns.ipv6`（覆写内的 IPv6）：即使覆写开着，DNS 查询仍可能走 IPv6 出去。
 *
 * 实测踩过的坑就是这三个的组合：Verge 里 IPv6 关掉但 DNS 覆写的 IPv6 没关，
 * 解析出口会间歇性落到国内递归解析器（112.28.209.x 中国移动），
 * 闸门时拦时放 —— 属于间歇性泄露，比稳定泄露更难发现。
 */
export function readProxySettings(dir, { exists = existsSync, readFile = (p) => readFileSync(p, 'utf8') } = {}) {
  const settings = {}

  // Verge 自己的开关（verge.yaml）
  try {
    const vergePath = join(dir, 'verge.yaml')
    if (exists(vergePath)) {
      const verge = readFile(vergePath)
      const tun = readYamlBool(verge, 'enable_tun_mode')
      const systemProxy = readYamlBool(verge, 'enable_system_proxy')
      const dnsOverride = readYamlBool(verge, 'enable_dns_settings')
      if (tun !== undefined) settings.tunMode = tun
      if (systemProxy !== undefined) settings.systemProxy = systemProxy
      if (dnsOverride !== undefined) settings.dnsOverride = dnsOverride
    }
  } catch {
    // 读不到就少几个字段，不影响其它判定
  }

  // 运行时的 clash 配置（clash-verge.yaml / config.yaml）
  for (const name of ['clash-verge.yaml', 'config.yaml']) {
    const path = join(dir, name)
    if (!exists(path)) continue
    let text
    try {
      text = readFile(path)
    } catch {
      continue
    }
    const ipv6 = readYamlBool(text, 'ipv6')
    if (ipv6 !== undefined) settings.ipv6 = ipv6

    const dnsBlock = readYamlBlock(text, 'dns')
    if (dnsBlock) {
      const upstreams = readYamlList(dnsBlock, 'nameserver')
      if (upstreams.length > 0) settings.nameserver = upstreams
    }
    if (dnsBlock) {
      const dnsEnabled = readYamlBool(dnsBlock, 'enable')
      const dnsIpv6 = readYamlBool(dnsBlock, 'ipv6')
      if (dnsEnabled !== undefined) settings.dnsEnabled = dnsEnabled
      if (dnsIpv6 !== undefined) settings.dnsIpv6 = dnsIpv6
    }
    if (settings.ipv6 !== undefined || settings.dnsIpv6 !== undefined) break
  }

  // 覆写配置单独一份时（Verge 的 dns_config.yaml）也读一下，作为 dnsIpv6 的补充。
  if (settings.dnsIpv6 === undefined) {
    try {
      const dnsPath = join(dir, 'dns_config.yaml')
      if (exists(dnsPath)) {
        const block = readYamlBlock(readFile(dnsPath), 'dns')
        if (block) {
          const value = readYamlBool(block, 'ipv6')
          if (value !== undefined) settings.dnsIpv6 = value
        }
      }
    } catch {
      // 忽略
    }
  }

  return settings
}

/**
 * 代理设置的三项判定。
 *
 * 只在"确实检测到代理客户端"时生效：没装代理、走别的方式分流的环境不该被这项拦住。
 * 每个问题单独成条，用户能一眼看出是哪个开关没关。
 */
export function judgeProxySettings(settings, { enabled = true } = {}) {
  if (!enabled || !settings) return []
  const issues = []

  if (settings.ipv6 === true) {
    issues.push({
      id: 'proxy-ipv6-enabled',
      title: '代理的 IPv6 是开启状态',
      detail:
        'Clash 顶层的 IPv6 开着。IPv6 流量不一定走 TUN 虚拟网卡（很多规则只覆盖 IPv4），会从物理网卡直连出去 —— 这条路的出口和代理出口不同，属于绕过代理的泄露通道。请在代理客户端里关掉 IPv6。',
    })
  }

  if (settings.dnsOverride === false) {
    issues.push({
      id: 'proxy-dns-override-off',
      title: 'DNS 覆写没有开启',
      detail:
        '代理客户端的「DNS 覆写」是关着的。这样系统 DNS 会回到网卡上配置的解析器（通常是运营商或国内公共 DNS），解析出口与隧道出口不一致，解析结果也可能被就近调度到国内节点。请开启 DNS 覆写。',
    })
  }

  if (settings.dnsIpv6 === true) {
    issues.push({
      id: 'proxy-dns-ipv6-enabled',
      title: 'DNS 覆写里的 IPv6 是开启状态',
      detail:
        '即使 DNS 覆写整体开着，其中的 IPv6 子开关开着时，DNS 查询仍可能从 IPv6 路径发出、落到运营商的递归解析器。实测这种情况会让解析出口在"境外隧道"和"国内解析器"之间来回摆，表现为时拦时放。请把 DNS 覆写里的 IPv6 也关掉。',
    })
  }

  return issues
}

/**
 * 这一项该不该拦。
 *
 * `unknown` 不拦：拿不到配置说明本机可能根本没装代理客户端（用户走的是别的分流方式），
 * 把它当成违规就是误杀。真正的把关交给出口 IP / 解析出口这些"实测"项。
 */
export function judgeProxyMode({ checked, mode, requireGlobal = true, coverage = null }) {
  if (!checked || mode === 'unknown') return { block: false, warn: false }
  if (!requireGlobal) return { block: false, warn: false }
  if (mode === 'global') return { block: false, warn: false }
  // 规则模式可以放过，但必须先证明 Claude 的域名有专属规则、且排在 CN 分流之前。
  // 证明不了就照旧拦 —— "配置里看着像对的"不算证明。
  if (mode === 'rule') {
    if (coverage?.ok) return { block: false, warn: false, mode, coverage }
    return { block: true, warn: false, mode, coverage, reason: 'claude-rules-missing' }
  }
  return { block: true, warn: false, mode }
}

/* ------------------------------------------------------------------ 一键修正 */

/** 兜底用：一条都识别不出来时写这个（境外且稳定）。 */
const SAFE_NAMESERVERS = ['8.8.8.8', 'https://dns.google/dns-query']

/** 常见内核可执行名 → 用来判断该重启哪个进程。 */
const CORE_PROCESS_NAMES = ['verge-mihomo', 'mihomo', 'clash-meta', 'FlClashCore', 'clash-win64']

/**
 * 找出内核实际使用的运行时配置。
 *
 * Clash Verge 把内核配置放在 ProgramData 下（服务模式下），和 AppData 里那份
 * 不是同一个文件 —— 只改 AppData 的话内核读到的还是旧的，等于没改。
 * 路径形如 `ProgramData/clash-verge-service/users/<hash>/runtime/config.yaml`。
 */
export function findRuntimeConfigs({
  programData = process.env.ProgramData ?? 'C:\ProgramData',
  exists = existsSync,
  readDir = readdirSync,
} = {}) {
  const found = []
  const usersDir = join(programData, 'clash-verge-service', 'users')
  if (!exists(usersDir)) return found
  let users
  try {
    users = readDir(usersDir)
  } catch {
    return found
  }
  for (const user of users) {
    const path = join(usersDir, String(user), 'runtime', 'config.yaml')
    if (exists(path)) found.push(path)
  }
  return found
}

/** 要在哪些文件上动手：Verge 的 DNS 覆写源 + 运行时副本 + 内核实际读取的那份。 */
export function clashConfigTargets(dir, options = {}) {
  const { exists = existsSync, programData } = options
  const targets = []
  for (const name of ['dns_config.yaml', 'clash-verge.yaml', 'config.yaml']) {
    const path = join(dir, name)
    if (exists(path)) targets.push(path)
  }
  // 只把需要的字段传下去：findRuntimeConfigs 还接受 exists/readDir，转手时别丢了。
  for (const path of findRuntimeConfigs(programData ? { programData, exists } : options)) targets.push(path)
  // 去重（config.yaml 可能同时出现在 dir 和 runtime 里）
  return [...new Set(targets)]
}

/**
 * 把一份配置里的 `dns.nameserver` 里的国内上游删掉。
 *
 * 只动这一个列表：`proxy-server-nameserver`（解析机场节点域名用）必须保留国内，
 * 删了代理会连不上。返回改前/改后的列表，便于界面显示改了什么。
 */
export function rewriteNameserver(text) {
  const lines = text.split('\n')
  const dnsStart = lines.findIndex((line) => /^dns:\s*$/.test(line))
  if (dnsStart < 0) return { changed: false, reason: '没有 dns 段' }

  let target = -1
  for (let i = dnsStart + 1; i < lines.length; i += 1) {
    if (/^\S/.test(lines[i])) break
    if (/^ {2}nameserver:\s*$/.test(lines[i])) {
      target = i
      break
    }
  }
  if (target < 0) return { changed: false, reason: 'dns 段里没有 nameserver' }

  let end = target + 1
  while (end < lines.length && /^ {2}- /.test(lines[end])) end += 1

  const before = lines.slice(target + 1, end).map((line) => line.replace(/^ {2}- /, '').trim())
  const kept = before.filter((entry) => classifyDnsUpstream(entry) !== 'domestic')
  const next = kept.length > 0 ? kept : SAFE_NAMESERVERS

  if (before.length === next.length && before.every((entry, index) => entry === next[index])) {
    return { changed: false, reason: '已经只有境外上游', before }
  }

  lines.splice(target + 1, end - target - 1, ...next.map((entry) => `  - ${entry}`))
  return { changed: true, before, after: next, text: lines.join('\n') }
}

/**
 * 执行修正：改所有目标文件，返回逐文件结果。
 *
 * 不在这里重启内核 —— 重启会短暂断网，交给调用方决定（界面会提示）。
 */
export function applyClashFix(
  dir,
  {
    exists = existsSync,
    readFile = (p) => readFileSync(p, 'utf8'),
    writeFile = (p, t) => writeFileSync(p, t),
    // 允许测试隔离：不指定时用真实 ProgramData，测试里传一个空目录就不会碰到本机配置。
    programData = process.env.ProgramData ?? 'C:\\ProgramData',
  } = {},
) {
  const results = []
  for (const file of clashConfigTargets(dir, { exists, programData })) {
    let text
    try {
      text = readFile(file)
    } catch (error) {
      results.push({ file, changed: false, reason: `读取失败：${error.code ?? error.message}` })
      continue
    }
    const outcome = rewriteNameserver(text)
    if (!outcome.changed) {
      results.push({ file, changed: false, reason: outcome.reason, before: outcome.before })
      continue
    }
    try {
      writeFile(file, outcome.text)
      results.push({ file, changed: true, before: outcome.before, after: outcome.after })
    } catch (error) {
      results.push({ file, changed: false, reason: `写入失败：${error.code ?? error.message}` })
    }
  }
  return {
    results,
    changed: results.filter((item) => item.changed).length,
    needsRestart: results.some((item) => item.changed),
  }
}

/**
 * 把内核配置里的 `mode` 改成指定值。
 *
 * 和 DNS 一样要写到运行时那份：服务模式下内核读的是 ProgramData 下的副本，
 * 只改 AppData 里的 clash-verge.yaml 等于没改。
 */
export function writeProxyMode(
  dir,
  mode,
  {
    exists = existsSync,
    readFile = (p) => readFileSync(p, 'utf8'),
    writeFile = (p, t) => writeFileSync(p, t),
    programData = process.env.ProgramData ?? 'C:\\ProgramData',
  } = {},
) {
  const results = []
  for (const file of clashConfigTargets(dir, { exists, programData })) {
    let text
    try {
      text = readFile(file)
    } catch (error) {
      results.push({ file, changed: false, reason: `读取失败：${error.code ?? error.message}` })
      continue
    }
    const current = (text.match(/^mode:\s*(\S+)/m) ?? [])[1]
    if (!current) {
      results.push({ file, changed: false, reason: '没有 mode 字段' })
      continue
    }
    if (current === mode) {
      results.push({ file, changed: false, reason: `已经是 ${mode}` })
      continue
    }
    try {
      writeFile(file, text.replace(/^mode:\s*\S+\s*$/m, `mode: ${mode}`))
      results.push({ file, changed: true, before: current, after: mode })
    } catch (error) {
      results.push({ file, changed: false, reason: `写入失败：${error.code ?? error.message}` })
    }
  }
  return { results, changed: results.filter((item) => item.changed).length }
}

/** 当前环境需不需要修正（给按钮上色用）。 */
export function needsClashFix(settings) {
  if (!settings) return false
  const hasDomestic = (settings.nameserver ?? []).some(
    (entry) => classifyDnsUpstream(entry) === 'domestic',
  )
  return hasDomestic || settings.ipv6 === true || settings.dnsOverride === false || settings.dnsIpv6 === true
}

/* ------------------------------------------------- 规则模式下的 Claude 覆盖 */

/**
 * 规则模式能用的前提：Claude 的域名有专属规则，且排在 CN 分流之前。
 *
 * 为什么不能只信 `MATCH,代理组` 兜底：订阅更新、机场换模板、手滑加一条
 * `FINAL,DIRECT`，兜底就没了，而规则模式的泄露是**静默**的 —— 不像全局模式，
 * 漏了不会有任何信号。所以要么显式覆盖，要么别用规则模式。
 *
 * 域名按实际客户端抓的来：Desktop 与 CLI 都打 api.anthropic.com / claude.ai，
 * 登录走 Google OAuth（GEOSITE,GOOGLE 已覆盖），功能开关走 statsig。
 */
export const CLAUDE_DOMAIN_SUFFIXES = [
  'anthropic.com',
  'claude.ai',
  'claude.com',
  'claudeusercontent.com',
  'statsig.com',
  'featuregates.org',
]

/** 这些目标等于"没走代理"，规则写在这儿不算覆盖。 */
const NOT_PROXY_TARGETS = new Set(['DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE'])

/**
 * 从一份内核配置里取出顶层 `rules:` 的规则数组。
 *
 * 缩进按第一条 `- ` 定，遇到下一个顶层键就停 —— 和 readYamlList 踩过的坑一样：
 * 不定缩进会把别的结构的列表一起吞进来。
 */
export function parseRules(text) {
  const lines = String(text ?? '').split(/\r?\n/)
  const start = lines.findIndex((line) => /^rules:\s*$/.test(line))
  if (start < 0) return []

  const rules = []
  let indent = null
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i]
    if (!line.trim()) continue
    const match = line.match(/^(\s*)- (.+)$/)
    if (!match) {
      if (/^\S/.test(line)) break
      continue
    }
    if (indent === null) indent = match[1].length
    if (match[1].length !== indent) break
    rules.push(match[2].trim())
  }
  return rules
}

/** 规则的目标（最后一段）；`GEOIP,...,no-resolve` 这种带参数的要往前挪一格。 */
export function ruleTarget(rule) {
  const parts = String(rule ?? '').split(',')
  while (parts.length > 1 && /^(no-resolve|src)$/i.test(parts[parts.length - 1].trim())) parts.pop()
  return (parts[parts.length - 1] ?? '').trim()
}

/**
 * Claude 的规则覆盖够不够。
 *
 * 返回 `{ ok, issues, group }`。`group` 是那条 Claude 规则指向的代理组，
 * 修的时候沿用它，不另造新组名。
 */
export function claudeRuleCoverage(rules = []) {
  const list = rules.map((rule) => String(rule ?? '').trim()).filter(Boolean)
  const isClaudeRule = (rule) => /anthropic|claude/i.test(rule)
  const claudeIndex = list.findIndex(isClaudeRule)
  const cnIndex = list.findIndex((rule) => /^(GEOSITE,CN|GEOIP,CN)\b/i.test(rule))
  const issues = []

  if (claudeIndex < 0) {
    issues.push({
      id: 'claude-rules-missing',
      title: '规则里没有 Claude / Anthropic 的专属规则',
      detail:
        '当前是规则模式，但分流规则里找不到任何 Claude / Anthropic 的条目。规则模式下没命中规则的流量会走直连 —— Claude 的域名一旦不在规则里，就会从物理网卡直接出去，出口和隧道出口不是同一个。请把 Claude 的域名加进规则（排在 CN 分流之前）。',
    })
    return { ok: false, issues, group: null }
  }

  const target = ruleTarget(list[claudeIndex])
  if (NOT_PROXY_TARGETS.has(target.toUpperCase())) {
    issues.push({
      id: 'claude-rules-direct',
      title: `Claude 的规则指向 ${target}`,
      detail: `规则里有一条 Claude 的条目，但目标是 ${target}，等于明着直连。请改成指向代理组。`,
    })
    return { ok: false, issues, group: null }
  }

  if (cnIndex >= 0 && claudeIndex > cnIndex) {
    issues.push({
      id: 'claude-rules-after-cn',
      title: 'Claude 的规则排在 CN 分流之后',
      detail:
        'Claude 的规则排在 GEOSITE,CN / GEOIP,CN 后面。这两条会先把一部分流量判成直连，Claude 的域名一旦被它们先命中（GeoIP 依赖解析结果，上游被换回国内就会命中），后面那条规则就永远不会执行。请把 Claude 的规则移到 CN 分流之前。',
    })
    return { ok: false, issues, group: null }
  }

  return { ok: true, issues, group: target }
}

/** 按配置里的实际代理组生成一组 Claude 规则（给一键修正用）。 */
export function claudeRuleBlock(group = 'PROXY') {
  const rules = CLAUDE_DOMAIN_SUFFIXES.map((suffix) => `DOMAIN-SUFFIX,${suffix},${group}`)
  // Desktop 与它内置的 claude-code 都是 claude.exe；npm 装的 CLI 跑在 node.exe 里，
  // 抓不到进程，只能靠上面的域名规则。
  rules.push(`PROCESS-PATH-REGEX,(?i).*\\\\claude\\\\.exe,${group}`)
  return rules
}

/** 规则该指向哪个组：直接用 MATCH 的目标，它就是这个配置里"其余流量"的去处。 */
export function claudeRuleGroup(rules = []) {
  const list = rules.map((rule) => String(rule ?? '').trim()).filter(Boolean)
  for (let i = list.length - 1; i >= 0; i -= 1) {
    if (!/^MATCH,/i.test(list[i])) continue
    const target = ruleTarget(list[i])
    if (target && !NOT_PROXY_TARGETS.has(target.toUpperCase())) return target
    break
  }
  for (const rule of list) {
    const target = ruleTarget(rule)
    if (target && !NOT_PROXY_TARGETS.has(target.toUpperCase()) && !/^(DIRECT|REJECT)/i.test(rule)) return target
  }
  return 'PROXY'
}

/* --------------------------------------------- 规则增强文件（订阅更新不覆盖） */

/**
 * 解析 profiles.yaml：当前订阅是谁、它挂的规则增强文件是哪个。
 *
 * Clash Verge 每次更新订阅都会重写 clash-verge.yaml，直接往里写规则等于白写；
 * 真正不会被覆盖的是 profiles/<option.rules>.yaml 这份增强文件。
 */
export function parseProfilesIndex(text) {
  const current = (String(text ?? '').match(/^current:\s*(\S+)/m) ?? [])[1] ?? null
  const items = new Map()
  for (const block of String(text ?? '').split(/\n(?=- uid: )/)) {
    const uid = (block.match(/^- uid:\s*(\S+)/) ?? [])[1]
    if (!uid) continue
    items.set(uid, {
      uid,
      file: (block.match(/^\s+file:\s*(\S+)/m) ?? [])[1] ?? null,
      type: (block.match(/^\s+type:\s*(\S+)/m) ?? [])[1] ?? null,
      rulesUid: (block.match(/^\s+rules:\s*(\S+)/m) ?? [])[1] ?? null,
    })
  }
  return { current, items }
}

/** 当前订阅的规则增强文件路径；找不到返回 null（不瞎猜路径）。 */
export function ruleEnhancementPath(dir, options = {}) {
  const { exists = existsSync, readFile = (p) => readFileSync(p, 'utf8') } = options
  const indexPath = join(dir, 'profiles.yaml')
  if (!exists(indexPath)) return null
  let index
  try {
    index = parseProfilesIndex(readFile(indexPath))
  } catch {
    return null
  }
  const profile = index.items.get(index.current)
  const file = profile?.rulesUid ? index.items.get(profile.rulesUid)?.file : null
  if (!file) return null
  const path = join(dir, 'profiles', file)
  return exists(path) ? path : null
}

/** 把规则插进增强文件的 `prepend:` 段（Clash Verge 会把这些规则排在订阅规则最前面）。 */
export function insertPrependRules(text, rules) {
  const lines = String(text ?? '').split(/\r?\n/)
  const additions = rules.map((rule) => `  - ${rule}`)
  const empty = lines.findIndex((line) => /^prepend:\s*\[\s*\]\s*$/.test(line))
  if (empty >= 0) {
    lines.splice(empty, 1, 'prepend:', ...additions)
    return lines.join('\n')
  }
  const head = lines.findIndex((line) => /^prepend:\s*$/.test(line))
  if (head >= 0) {
    let end = head + 1
    while (end < lines.length && /^\s+- /.test(lines[end])) end += 1
    lines.splice(end, 0, ...additions)
    return lines.join('\n')
  }
  const trimmed = String(text ?? '').replace(/\s*$/, '')
  return `${trimmed ? `${trimmed}\n` : ''}prepend:\n${additions.join('\n')}\n`
}

/* ------------------------------------------------------- UU 远程直连 */

/**
 * UU 远程 / 内网一律直连。
 *
 * 为什么需要专门的规则：全局模式下规则不生效，连 192.168.x.x 都会被塞进代理；
 * 而 UU 这类远程工具靠 UDP 打洞，绕一圈代理后 NAT 类型变了，打洞基本失败。
 * 这条规则把"本机进程 + 局域网 + UU 域名"整段摘出来直连。
 *
 * 进程用正则而不是精确名：不同版本的 UU 客户端 exe 叫 uu.exe / UUClient.exe /
 * uu_remote.exe 不等，`^uu` 一把罩住。已用 `mihomo -t` 验证过内核认这两个规则类型。
 */
export const UU_DIRECT_RULES = [
  'PROCESS-NAME-REGEX,(?i)^uu,DIRECT',
  'PROCESS-PATH-REGEX,(?i).*\\\\uu[^\\\\]*\\\\.exe,DIRECT',
  'DOMAIN-SUFFIX,uu.163.com,DIRECT',
  'DOMAIN-SUFFIX,uu.netease.com,DIRECT',
  'DOMAIN-SUFFIX,uu.126.net,DIRECT',
  'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
  'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
  'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
  'IP-CIDR,100.64.0.0/10,DIRECT,no-resolve',
]

/** 当前生效规则里有没有 UU 直连那一组。 */
export function hasUuDirectRules(rules = []) {
  const list = rules.map((rule) => String(rule ?? '').trim())
  return UU_DIRECT_RULES.some((rule) => list.includes(rule))
}

/** 从配置里删掉指定规则（U 撤销直连用）。 */
export function removeRulesFromConfig(text, rules) {
  const set = new Set(rules.map((rule) => String(rule).trim()))
  const lines = String(text ?? '').split(/\r?\n/)
  const kept = []
  let removed = 0
  for (const line of lines) {
    const match = line.match(/^\s*- (.+)$/)
    if (match && set.has(match[1].trim())) {
      removed += 1
      continue
    }
    kept.push(line)
  }
  if (removed === 0) return { changed: false, removed: 0 }
  return { changed: true, removed, text: kept.join('\n') }
}

/**
 * 写入 / 撤销 UU 直连规则。
 *
 * 和 Claude 规则同一个落点：规则增强文件（订阅更新不覆盖）+ 生效配置（立刻生效）。
 */
export function setUuDirectRules(
  dir,
  enable,
  {
    exists = existsSync,
    readFile = (p) => readFileSync(p, 'utf8'),
    writeFile = (p, t) => writeFileSync(p, t),
    programData = process.env.ProgramData ?? 'C:\\ProgramData',
  } = {},
) {
  const effective = readClashRules(dir, { exists, readFile })
  const present = hasUuDirectRules(effective)
  if (enable === present) {
    return { changed: false, enabled: present, reason: enable ? '已经写入过了' : '本来就没有' }
  }

  const results = []
  const targets = []
  const path = ruleEnhancementPath(dir, { exists, readFile })
  if (path) targets.push(path)
  for (const file of clashConfigTargets(dir, { exists, programData })) {
    if (file !== path) targets.push(file)
  }

  for (const file of targets) {
    let text
    try {
      text = readFile(file)
    } catch (error) {
      results.push({ file, changed: false, reason: `读取失败：${error.code ?? error.message}` })
      continue
    }
    // 三种改写函数的返回形状不一样，先归一成 { changed, text, reason }。
    let outcome
    if (enable && file === path) {
      outcome = { changed: true, text: insertPrependRules(text, UU_DIRECT_RULES) }
    } else if (enable) {
      outcome = prependRulesToConfig(text, UU_DIRECT_RULES)
    } else {
      outcome = removeRulesFromConfig(text, UU_DIRECT_RULES)
    }
    if (!outcome.changed) {
      results.push({ file, changed: false, reason: outcome.reason ?? '没有匹配的规则' })
      continue
    }
    try {
      writeFile(file, outcome.text)
      results.push({ file, changed: true })
    } catch (error) {
      results.push({ file, changed: false, reason: `写入失败：${error.code ?? error.message}` })
    }
  }

  const changedFiles = results.filter((item) => item.changed)
  return {
    changed: changedFiles.length > 0,
    enabled: enable,
    durable: Boolean(path),
    files: changedFiles.map((item) => item.file),
    results,
  }
}

/** 把规则插到配置 `rules:` 段的最前面（两份配置都要，见 applyClaudeRules）。 */
export function prependRulesToConfig(text, rules) {
  const lines = String(text ?? '').split(/\r?\n/)
  const start = lines.findIndex((line) => /^rules:\s*$/.test(line))
  if (start < 0) return { changed: false, reason: '没有 rules 段' }

  let pad = ''
  for (let i = start + 1; i < lines.length; i += 1) {
    const match = lines[i].match(/^(\s*)- /)
    if (match) {
      pad = match[1]
      break
    }
    if (/^\S/.test(lines[i])) break
  }

  lines.splice(start + 1, 0, ...rules.map((rule) => `${pad}- ${rule}`))
  return { changed: true, text: lines.join('\n') }
}

/**
 * 规则模式下补齐 Claude 的规则。已经是覆盖状态就什么都不写。
 *
 * 写两处，各管一件事：
 *  - 增强文件 `profiles/<option.rules>.yaml`：长期，订阅更新不会覆盖；
 *  - 生效配置（clash-verge.yaml + 运行时副本）：立刻生效 —— 服务模式重启内核
 *    未必会重新合并 profile，只写增强文件会出现"配置看着对、内核里没这条规则"。
 */
export function applyClaudeRules(dir, options = {}) {
  const {
    exists = existsSync,
    readFile = (p) => readFileSync(p, 'utf8'),
    writeFile = (p, t) => writeFileSync(p, t),
    group,
    programData = process.env.ProgramData ?? 'C:\\ProgramData',
  } = options

  // 覆盖判定用生效配置（订阅 + 增强合并后的结果），不是增强文件本身。
  const effective = readClashRules(dir, { exists, readFile })
  if (claudeRuleCoverage(effective).ok) return { changed: false, reason: 'Claude 规则已覆盖' }

  const target = claudeRuleBlock(group ?? claudeRuleGroup(effective))
  const results = []

  const path = ruleEnhancementPath(dir, { exists, readFile })
  if (path) {
    try {
      writeFile(path, insertPrependRules(readFile(path), target))
      results.push({ file: path, changed: true })
    } catch (error) {
      results.push({ file: path, changed: false, reason: `写入失败：${error.code ?? error.message}` })
    }
  }

  for (const file of clashConfigTargets(dir, { exists, programData })) {
    if (file === path) continue
    let text
    try {
      text = readFile(file)
    } catch (error) {
      results.push({ file, changed: false, reason: `读取失败：${error.code ?? error.message}` })
      continue
    }
    const outcome = prependRulesToConfig(text, target)
    if (!outcome.changed) {
      results.push({ file, changed: false, reason: outcome.reason })
      continue
    }
    try {
      writeFile(file, outcome.text)
      results.push({ file, changed: true })
    } catch (error) {
      results.push({ file, changed: false, reason: `写入失败：${error.code ?? error.message}` })
    }
  }

  const changed = results.filter((item) => item.changed)
  if (changed.length === 0) {
    return { changed: false, reason: results.map((item) => item.reason).filter(Boolean).join('；') || '没有可写的文件' }
  }
  return {
    changed: true,
    files: changed.map((item) => item.file),
    // 没写进增强文件就意味着订阅更新会冲掉，界面要提示。
    durable: Boolean(path),
    path,
    after: target,
    results,
  }
}

/** 读出生效配置里的规则（就是用户当前真正在跑的这套）。 */
export function readClashRules(dir, options = {}) {
  const { exists = existsSync, readFile = (p) => readFileSync(p, 'utf8') } = options
  for (const name of ['clash-verge.yaml', 'config.yaml', 'clash.yaml']) {
    const path = join(dir, name)
    if (!exists(path)) continue
    try {
      const rules = parseRules(readFile(path))
      if (rules.length > 0) return rules
    } catch {
      // 换下一个
    }
  }
  return []
}

export { CORE_PROCESS_NAMES, SAFE_NAMESERVERS }
