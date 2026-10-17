import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

/**
 * 配置加载与校验。配置只放白名单与执行策略，不含任何会自动生效的隐式默认值 ——
 * 缺项一律按"更严格"的方向兜底，并在 check 报告里说明用了哪个兜底值。
 */

export const PROJECT_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
export const CONFIG_PATH = process.env.CCGAIT_CONFIG?.trim() || join(PROJECT_ROOT, 'config.json')

/** 检查项的默认严重度：block = 不通过即拦；warn = 只报告。 */
/**
 * 默认严重度。
 *
 * 硬门槛（block）只有两类，任一不满足就打不开客户端、也上不了网：
 *   1. 出口白名单：IP / CIDR / 国家 / ASN / 要求住宅出口，以及多源一致性与 failClosed；
 *   2. Claude 域名解析是否落到被禁地区。
 *
 * 中文用户环境相关各项（时区 / 语言 / 字体 / Emoji 国旗渲染 / 本机 DNS / 系统代理）
 * **只提示、不门控**：它们衡量的是"这台机器的特征"，而改时区、删系统字体属于改系统设置，
 * 不该由闸门替用户决定能不能用。需要更严时，在界面「检查项严重度」里把某一项改成「阻断」。
 */
export const DEFAULT_SEVERITY = {
  egressIp: 'block',
  claudeDns: 'block',
  timezone: 'warn',
  language: 'warn',
  fonts: 'warn',
  emojiFlags: 'warn',
  dnsServers: 'warn',
  proxyEnvLeak: 'warn',
}

export const DEFAULT_CONFIG = {
  whitelist: {
    ips: [],
    cidrs: [],
    countries: [],
    asns: [],
    requireResidential: true,
  },
  checks: Object.fromEntries(
    Object.entries(DEFAULT_SEVERITY).map(([name, severity]) => [
      name,
      { enabled: true, severity },
    ]),
  ),
  enforcement: {
    killProcesses: true,
    // 是否阻断其网络。真正的断网由 WFP 完成（不依赖系统防火墙开关）。
    blockNetwork: true,
    // 第二层：Windows 防火墙按程序阻断。默认打开 = "阻断网络全开"。
    firewallRules: true,
    // 防火墙规则只在 profile 启用时才生效；默认允许闸门自己打开三个 profile，
    // 否则这一层静默失效。不想让闸门碰系统防火墙开关就设为 false。
    enableFirewallProfiles: true,
    failClosed: true,
    pollIntervalMs: 2000,
    recheckIntervalMs: 30000,
  },
  network: {
    proxy: { enabled: false, url: '', required: false },
  },
  runtime: {
    stateDir: '',
    logRetentionDays: 7,
  },
}

const EXAMPLE_PATH = join(PROJECT_ROOT, 'config.example.json')

/** 去掉 `$comment*` 键：示例文件用它们写说明，不进配置语义。 */
function stripComments(value) {
  if (Array.isArray(value)) return value.map(stripComments)
  if (value && typeof value === 'object') {
    const out = {}
    for (const [key, item] of Object.entries(value)) {
      if (key.startsWith('$comment')) continue
      out[key] = stripComments(item)
    }
    return out
  }
  return value
}

function asBoolean(value, fallback) {
  return typeof value === 'boolean' ? value : fallback
}

function asStringArray(value) {
  if (!Array.isArray(value)) return []
  return value
    .filter((item) => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean)
}

function asPositiveInt(value, fallback, minimum) {
  return Number.isInteger(value) && value >= minimum ? value : fallback
}

/** 把任意输入规整成完整配置；无法识别的字段忽略而不是报错（避免阻塞闸门启动）。 */
export function normalizeConfig(input = {}) {
  const raw = stripComments(input)
  const whitelist = raw.whitelist ?? {}
  const enforcement = raw.enforcement ?? {}
  const runtime = raw.runtime ?? {}
  const proxy = raw.network?.proxy ?? {}

  const checks = {}
  for (const name of Object.keys(DEFAULT_SEVERITY)) {
    const item = raw.checks?.[name]
    const configured = typeof item === 'object' && item !== null ? item : {}
    const severity = configured.severity
    checks[name] = {
      enabled: asBoolean(configured.enabled, true),
      severity:
        severity === 'block' || severity === 'warn' ? severity : DEFAULT_SEVERITY[name],
    }
  }
  // Claude 域名解析反查时，落到这些国家即视为解析被污染。
  const deniedCountries = asStringArray(raw.checks?.claudeDns?.deniedCountries).map((item) =>
    item.toUpperCase(),
  )
  checks.claudeDns.deniedCountries = deniedCountries.length > 0 ? deniedCountries : ['CN']

  return {
    whitelist: {
      ips: asStringArray(whitelist.ips),
      cidrs: asStringArray(whitelist.cidrs),
      countries: asStringArray(whitelist.countries).map((item) => item.toUpperCase()),
      asns: asStringArray(whitelist.asns).map((item) => item.toUpperCase()),
      requireResidential: asBoolean(whitelist.requireResidential, true),
    },
    checks,
    enforcement: {
      killProcesses: asBoolean(enforcement.killProcesses, true),
      blockNetwork: asBoolean(enforcement.blockNetwork, true),
      // 第二层：Windows 防火墙按程序阻断。默认打开（"阻断网络全开"）。
      firewallRules: asBoolean(enforcement.firewallRules, true),
      // 防火墙规则只在 profile 启用时才生效；默认允许闸门自己把三个 profile 打开，
      // 否则这一层会静默失效——那正是最坑人的"看着在拦、其实没拦"。
      enableFirewallProfiles: asBoolean(enforcement.enableFirewallProfiles, true),
      failClosed: asBoolean(enforcement.failClosed, true),
      pollIntervalMs: asPositiveInt(enforcement.pollIntervalMs, 2000, 500),
      recheckIntervalMs: asPositiveInt(enforcement.recheckIntervalMs, 30000, 5000),
    },
    network: {
      proxy: {
        enabled: asBoolean(proxy.enabled, false),
        url: typeof proxy.url === 'string' ? proxy.url.trim() : '',
        required: asBoolean(proxy.required, false),
      },
    },
    runtime: {
      stateDir: typeof runtime.stateDir === 'string' ? runtime.stateDir.trim() : '',
      logRetentionDays: asPositiveInt(runtime.logRetentionDays, 7, 1),
    },
  }
}

/** 白名单里一个可判定的条件都没有时，闸门等于空转 —— 必须让用户知道。 */
export function validateConfig(config) {
  const problems = []
  const whitelist = config.whitelist
  const hasWhitelist =
    whitelist.ips.length > 0 ||
    whitelist.cidrs.length > 0 ||
    whitelist.countries.length > 0 ||
    whitelist.asns.length > 0
  if (!hasWhitelist) {
    problems.push('白名单为空（whitelist.ips / cidrs / countries / asns 至少要填一项），否则任何出口都会被判为不允许')
  }
  for (const cidr of whitelist.cidrs) {
    if (!isValidCidr(cidr)) problems.push(`cidrs 里的 "${cidr}" 不是合法 CIDR`)
  }
  for (const ip of whitelist.ips) {
    if (!isValidIpv4(ip)) problems.push(`ips 里的 "${ip}" 不是合法 IPv4`)
  }
  for (const asn of whitelist.asns) {
    if (!/^AS\d+$/i.test(asn)) problems.push(`asns 里的 "${asn}" 应形如 AS15169`)
  }
  for (const code of whitelist.countries) {
    if (!/^[A-Z]{2}$/.test(code)) problems.push(`countries 里的 "${code}" 应是两位国家代码，如 US`)
  }
  if (config.network.proxy.enabled && !config.network.proxy.url) {
    problems.push('network.proxy.enabled 为 true 但 url 为空')
  }
  if (config.checks.egressIp.enabled === false) {
    problems.push('checks.egressIp 被关闭：IP/国家白名单将不再生效，闸门失去意义')
  }
  return problems
}

export function loadConfig(path = CONFIG_PATH) {
  if (!existsSync(path)) {
    return {
      path,
      exists: false,
      config: normalizeConfig({}),
      raw: {},
    }
  }
  const raw = JSON.parse(readFileSync(path, 'utf8'))
  return { path, exists: true, config: normalizeConfig(raw), raw }
}

/** 首次使用：把示例配置复制成 config.json（不覆盖已有文件）。 */
export function initConfig(path = CONFIG_PATH) {
  if (existsSync(path)) return { created: false, path }
  mkdirSync(dirname(path), { recursive: true })
  const template = existsSync(EXAMPLE_PATH)
    ? readFileSync(EXAMPLE_PATH, 'utf8')
    : `${JSON.stringify(DEFAULT_CONFIG, null, 2)}\n`
  writeFileSync(path, template, 'utf8')
  return { created: true, path }
}

export function resolveStateDir(config, configPath = CONFIG_PATH) {
  const configured = config.runtime.stateDir
  const base = configured ? resolve(configured) : join(dirname(configPath), '.ccgait')
  mkdirSync(base, { recursive: true })
  return base
}

// ------------------------------------------------------------------ IP 工具

export function isValidIpv4(value) {
  const parts = String(value).split('.')
  if (parts.length !== 4) return false
  return parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

function ipv4ToInt(ip) {
  return String(ip)
    .split('.')
    .reduce((acc, part) => acc * 256 + Number(part), 0)
}

export function isValidCidr(value) {
  const [network, prefix] = String(value).split('/')
  if (!isValidIpv4(network) || prefix === undefined) return false
  const bits = Number(prefix)
  return Number.isInteger(bits) && bits >= 0 && bits <= 32
}

export function ipInCidr(ip, cidr) {
  if (!isValidIpv4(ip) || !isValidCidr(cidr)) return false
  const [network, prefix] = String(cidr).split('/')
  const bits = Number(prefix)
  if (bits === 0) return true
  const mask = bits === 32 ? 0xffffffff : (0xffffffff << (32 - bits)) >>> 0
  return (ipv4ToInt(ip) & mask) >>> 0 === (ipv4ToInt(network) & mask) >>> 0
}
