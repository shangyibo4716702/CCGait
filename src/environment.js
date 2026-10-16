import { execFile } from 'node:child_process'
import { existsSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'

/**
 * 环境特征检测：时区 / 界面语言 / 中文字体 / 解析服务器 / 系统代理。
 *
 * 这些维度来自对 Claude 客户端区域识别的公开分析（ippure.com/claude.html 等）：
 * 一个"看起来在中国"的系统环境，与账号地区不一致时是封号风险因素之一。
 *
 * 本模块**只读取**，不修改任何系统设置：发现问题是把结论交给人去决定，
 * 而不是偷偷改时区或语言。
 */

const execFileAsync = promisify(execFile)

/** 需要关注的时区（系统物理时区）。 */
export const DOMESTIC_TIMEZONES = [
  'Asia/Shanghai',
  'Asia/Urumqi',
  'Asia/Chongqing',
  'Asia/Harbin',
  'Asia/Kashgar',
  'PRC',
  'China Standard Time',
]

/** 国内公共 DNS（解析服务器落地在国内 = 解析可能被本地化处理）。 */
export const DOMESTIC_DNS_SERVERS = [
  '114.114.114.114',
  '114.114.115.115',
  '223.5.5.5',
  '223.6.6.6',
  '180.76.76.76',
  '119.29.29.29',
  '1.2.4.8',
  '210.2.4.8',
  '101.226.4.6',
  '123.125.81.6',
  '39.156.66.10',
]

/**
 * 中文字体指纹。strong = 国内厂商/发行版专有字体（出现即说明装了中文环境）；
 * weak = 中文 Windows 常见字体（单独出现不构成强证据，仅提示）。
 */
export const DOMESTIC_FONT_PATTERNS = [
  { pattern: /^har\s?mon?y\s?os/i, label: 'HarmonyOS Sans（鸿蒙）', strong: true },
  { pattern: /^alibaba[-_]?puhuiti/i, label: 'Alibaba PuHuiTi（阿里普惠体）', strong: true },
  { pattern: /^misans/i, label: 'MiSans（小米）', strong: true },
  { pattern: /^deng[blz]?\.ttf$/i, label: '等线 DengXian', strong: true },
  { pattern: /^source\s?han\s?(sans|serif)\s?cn/i, label: '思源黑体/宋体 CN', strong: true },
  { pattern: /^simfang\.ttf$/i, label: '仿宋', strong: false },
  { pattern: /^simkai\.ttf$/i, label: '楷体', strong: false },
  { pattern: /^simsun\.ttc$/i, label: '宋体', strong: false },
  { pattern: /^msyh/i, label: '微软雅黑', strong: false },
  { pattern: /^youyuan\.ttf$/i, label: '幼圆', strong: false },
  { pattern: /^STZHONGS\.TTF$/i, label: '华文中宋', strong: false },
  { pattern: /^STXIHEI\.TTF$/i, label: '华文细黑', strong: false },
]

async function runPowerShell(script, timeoutMs = 12_000) {
  const { stdout } = await execFileAsync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', script],
    { windowsHide: true, timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 },
  )
  return stdout.trim()
}

/** 系统物理时区（Windows 的 tzutil 名称 + Node 的 IANA 名称）。 */
export async function probeTimezone() {
  const intl = Intl.DateTimeFormat().resolvedOptions().timeZone
  let windowsName
  if (process.platform === 'win32') {
    try {
      windowsName = await runPowerShell('tzutil /g')
    } catch {
      windowsName = undefined
    }
  }
  const offsetMinutes = -new Date().getTimezoneOffset()
  const candidates = [intl, windowsName].filter(Boolean)
  const hit = candidates.find((value) =>
    DOMESTIC_TIMEZONES.some((zone) => zone.toLowerCase() === String(value).toLowerCase()),
  )
  return {
    intl,
    windows: windowsName,
    offsetMinutes,
    domestic: hit !== undefined,
    matched: hit,
  }
}

/** 界面语言：只要有 zh-CN / zh-Hans 在列即视为中文环境。 */
export async function probeLanguage() {
  if (process.platform !== 'win32') {
    const env = process.env.LANG ?? process.env.LC_ALL ?? ''
    return {
      uiLanguages: env ? [env] : [],
      culture: undefined,
      chinese: /zh[-_]?(CN|Hans|SG)/i.test(env),
      matched: /zh[-_]?(CN|Hans|SG)/i.test(env) ? env : undefined,
    }
  }
  try {
    const stdout = await runPowerShell(
      "$list = (Get-WinUserLanguageList).LanguageTag -join ','; $culture = (Get-Culture).Name; Write-Output \"$list|$culture\"",
    )
    const [listRaw, culture] = stdout.split('|')
    const uiLanguages = (listRaw ?? '')
      .split(',')
      .map((item) => item.trim())
      .filter(Boolean)
    const matched = uiLanguages.find((tag) => /^zh[-_]?(CN|Hans|SG)?$/i.test(tag))
    return {
      uiLanguages,
      culture,
      chinese: matched !== undefined || /^zh[-_]?(CN|Hans)/i.test(culture ?? ''),
      matched,
    }
  } catch (error) {
    return {
      uiLanguages: [],
      culture: undefined,
      chinese: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

/** 中文字体指纹：扫描系统与用户字体目录。 */
export function probeFonts() {
  const directories = ['C:\\Windows\\Fonts', join(process.env.LOCALAPPDATA ?? '', 'Microsoft', 'Windows', 'Fonts')]
  const found = []
  for (const directory of directories) {
    if (!directory || !existsSync(directory)) continue
    let entries = []
    try {
      entries = readdirSync(directory)
    } catch {
      continue
    }
    for (const entry of entries) {
      for (const rule of DOMESTIC_FONT_PATTERNS) {
        if (rule.pattern.test(entry)) {
          found.push({ file: entry, label: rule.label, strong: rule.strong, directory })
        }
      }
    }
  }
  return {
    found,
    strong: found.some((item) => item.strong),
  }
}

/** 系统配置的 DNS 服务器（落地在国内 = 解析可能被本地化）。 */
export async function probeDnsServers() {
  if (process.platform !== 'win32') return { servers: [], domestic: [] }
  try {
    const stdout = await runPowerShell(
      "Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses } | ForEach-Object { $_.ServerAddresses } | Sort-Object -Unique",
    )
    const servers = stdout
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter((line) => /^\d+\.\d+\.\d+\.\d+$/.test(line))
    const domestic = servers.filter((server) => DOMESTIC_DNS_SERVERS.includes(server))
    return { servers, domestic }
  } catch (error) {
    return { servers: [], domestic: [], error: error instanceof Error ? error.message : String(error) }
  }
}

/**
 * 系统代理与代理环境变量。
 *
 * 关注点不是"有没有代理"，而是**代理是否真的覆盖到 CLI**：系统代理只对走 WinINET 的
 * 程序生效，Claude Code CLI 直连时看到的是物理网卡出口。如果这里显示系统代理开着、
 * 但出口检测拿到的是物理 IP，就说明分流没覆盖到 CLI。
 */
export async function probeSystemProxy() {
  const envVars = {}
  for (const key of ['HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'https_proxy', 'http_proxy', 'all_proxy']) {
    if (process.env[key]) envVars[key] = process.env[key]
  }
  let system = { enabled: false }
  if (process.platform === 'win32') {
    try {
      const stdout = await runPowerShell(
        "$k = Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -ErrorAction SilentlyContinue; Write-Output ($k.ProxyEnable.ToString() + '|' + $k.ProxyServer + '|' + $k.ProxyOverride)",
      )
      const [enabled, server, override] = stdout.split('|')
      system = {
        enabled: enabled === '1',
        server: server || undefined,
        override: override || undefined,
      }
    } catch (error) {
      system = { enabled: false, error: error instanceof Error ? error.message : String(error) }
    }
  }
  return {
    system,
    envVars,
    hasAny: system.enabled || Object.keys(envVars).length > 0,
  }
}
