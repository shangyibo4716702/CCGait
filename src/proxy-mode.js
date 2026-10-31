import { existsSync, readFileSync, readdirSync } from 'node:fs'
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
export function judgeProxyMode({ checked, mode, requireGlobal = true }) {
  if (!checked || mode === 'unknown') return { block: false, warn: false }
  if (!requireGlobal) return { block: false, warn: false }
  if (mode === 'global') return { block: false, warn: false }
  return { block: true, warn: false, mode }
}
