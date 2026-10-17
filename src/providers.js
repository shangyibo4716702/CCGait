import { lookup } from 'node:dns/promises'
import { fetchJson, fetchText, parseKeyValueText } from './http.js'

/**
 * 出口身份检测：出口 IP / 国家 / ASN / 是否机房或代理，以及 Claude 域名的解析落地。
 *
 * 设计要点：
 * - **多源交叉**。单个 IP 库可能过期或被中间设备篡改；这里同时问 Cloudflare、
 *   ip-api、ipinfo、ip.sb，只有一致才认为可信。不一致本身就是"流量被改造"的信号。
 * - **测的是真实路径**。所有请求都走 proxyUrl（若配置了），与客户端实际出口一致。
 * - **不做任何伪装**。只读取，不改写请求或环境。
 */

const IP_API_FIELDS = [
  'status',
  'message',
  'query',
  'country',
  'countryCode',
  'regionName',
  'city',
  'isp',
  'org',
  'as',
  'asname',
  'proxy',
  'hosting',
  'mobile',
].join(',')

/** Claude 生态需要落地正确的域名（解析被污染会导致请求绕道/失败）。 */
export const CLAUDE_HOSTS = ['claude.ai', 'claude.com', 'api.anthropic.com']

/** 机房/代理特征的机构名关键词（按需增补）。 */
const HOSTING_KEYWORDS = [
  'cloud',
  'vps',
  'hosting',
  'host',
  'datacenter',
  'data center',
  'server',
  'idc',
  'colo',
  'amazon',
  'aws',
  'google',
  'microsoft',
  'azure',
  'digitalocean',
  'vultr',
  'linode',
  'ovh',
  'hetzner',
  'contabo',
  'oracle',
  'alibaba',
  'aliyun',
  'tencent',
  'huawei',
  'cloudflare',
  'akamai',
  'fastly',
  'leaseweb',
  'm247',
  'proxy',
  'vpn',
]

function looksLikeHosting(text) {
  const value = String(text ?? '').toLowerCase()
  return HOSTING_KEYWORDS.some((keyword) => value.includes(keyword))
}

/** 单个数据源的结果。失败不抛出，返回 { source, error }。 */
async function querySource(sourceInfo, options) {
  try {
    return { source: sourceInfo.name, ...(await sourceInfo.query(options)) }
  } catch (error) {
    return { source: sourceInfo.name, error: error instanceof Error ? error.message : String(error) }
  }
}

const SOURCES = [
  {
    name: 'cloudflare-trace',
    query: async ({ proxyUrl }) => {
      const { status, text } = await fetchText('https://www.cloudflare.com/cdn-cgi/trace', {
        proxyUrl,
      })
      if (status !== 200) throw new Error(`HTTP ${status}`)
      const kv = parseKeyValueText(text)
      if (!kv.ip) throw new Error('缺少 ip 字段')
      return {
        ip: kv.ip,
        country: (kv.loc ?? '').toUpperCase(),
        colo: kv.colo,
        warp: kv.warp === 'on',
        // trace 里没有 ASN，交给其它源补。
      }
    },
  },
  {
    name: 'ip-api',
    query: async ({ proxyUrl }) => {
      const data = await fetchJson(`http://ip-api.com/json/?fields=${IP_API_FIELDS}`, { proxyUrl })
      if (data.status !== 'success') throw new Error(String(data.message ?? '查询失败'))
      return {
        ip: data.query,
        country: String(data.countryCode ?? '').toUpperCase(),
        countryName: data.country,
        city: data.city,
        isp: data.isp,
        org: data.org,
        asn: data.as,
        asnName: data.asname,
        proxy: data.proxy === true,
        hosting: data.hosting === true,
        mobile: data.mobile === true,
      }
    },
  },
  {
    name: 'ipinfo',
    query: async ({ proxyUrl }) => {
      const data = await fetchJson('https://ipinfo.io/json', { proxyUrl })
      return {
        ip: data.ip,
        country: String(data.country ?? '').toUpperCase(),
        city: data.city,
        org: data.org,
        timezone: data.timezone,
      }
    },
  },
  {
    name: 'ip.sb',
    query: async ({ proxyUrl }) => {
      const data = await fetchJson('https://api.ip.sb/geoip', { proxyUrl })
      return {
        ip: data.ip,
        country: String(data.country_code ?? '').toUpperCase(),
        isp: data.isp,
        asn: data.asn ? `AS${data.asn}` : undefined,
        asnName: data.asn_organization,
      }
    },
  },
]

/**
 * 出口身份：多源查询 + 一致性判定。
 * 返回 { confident, ip, country, sources, flags, asnText }。
 */
export async function probeEgress(options = {}) {
  const primary = await probeEgressOnce(options)

  // 配了代理但代理连不上时的回退。
  //
  // `network.proxy.required = false` 的语义就是"不强制走代理"：既然代理没在跑，
  // 就该按**真实出口**（直连）来判，而不是把整轮检测判成"出口未知"。
  // 本机实测过这个坑：代理进程关了，网站（浏览器直连）显示出口正常，闸门却因为
  // 探针走死代理而一律拦截，看起来像"策略判错了"。
  //
  // required = true 时不回退：用户明确要求必须走代理，拿不到就按拦截处理（failClosed）。
  const proxyUrl = options.proxyUrl
  const proxyFailed = primary.ip === undefined && primary.failedSources.length > 0
  const looksLikeProxyError = /ECONNREFUSED|ETIMEDOUT|ECONNRESET|socket hang up|ENOTFOUND|EPROTO/i.test(
    primary.failedSources.join(' '),
  )
  if (!proxyUrl || options.proxyRequired || !proxyFailed || !looksLikeProxyError) {
    return primary
  }

  const fallback = await probeEgressOnce({ ...options, proxyUrl: undefined })
  if (fallback.ip === undefined) return primary
  return { ...fallback, proxyFallback: true, proxyUrl, proxyErrors: primary.failedSources }
}

/** 单次探测：按给定出口（可带代理）问一遍所有数据源。 */
async function probeEgressOnce(options = {}) {
  const results = await Promise.all(SOURCES.map((source) => querySource(source, options)))
  const usable = results.filter((item) => item.ip && !item.error)
  const failed = results.filter((item) => item.error)

  const ipVotes = new Map()
  for (const item of usable) ipVotes.set(item.ip, (ipVotes.get(item.ip) ?? 0) + 1)
  const countryVotes = new Map()
  for (const item of usable) {
    const code = item.country || '??'
    countryVotes.set(code, (countryVotes.get(code) ?? 0) + 1)
  }

  const topIp = [...ipVotes.entries()].sort((a, b) => b[1] - a[1])[0]
  const topCountry = [...countryVotes.entries()].sort((a, b) => b[1] - a[1])[0]
  const ipConsistent = topIp !== undefined && ipVotes.size === 1
  const countryConsistent = topCountry !== undefined && countryVotes.size === 1

  // 机房/代理判定：优先用 ip-api 的显式标记，其次用机构名关键词，最后看 Cloudflare WARP。
  const explicit = usable.find((item) => item.source === 'ip-api')
  const asnText = [explicit?.org, explicit?.isp, explicit?.asnName, explicit?.asn]
    .filter(Boolean)
    .join(' · ')
  const warp = usable.some((item) => item.warp === true)
  const cloudflareOrg = usable.find((item) => item.source === 'ipinfo')?.org
  const hosting =
    explicit?.hosting === true ||
    explicit?.proxy === true ||
    looksLikeHosting(asnText) ||
    looksLikeHosting(cloudflareOrg)

  return {
    confident: usable.length >= 2 && ipConsistent && countryConsistent,
    ip: topIp?.[0],
    ipVotes: Object.fromEntries(ipVotes),
    country: topCountry?.[0],
    countryVotes: Object.fromEntries(countryVotes),
    countryName: explicit?.countryName,
    city: explicit?.city,
    asn: explicit?.asn,
    org: explicit?.org ?? cloudflareOrg,
    isp: explicit?.isp,
    hosting,
    proxyFlag: explicit?.proxy === true,
    mobile: explicit?.mobile === true,
    warp,
    asnText,
    sources: results.map((item) => ({
      source: item.source,
      ip: item.ip,
      country: item.country,
      error: item.error,
    })),
    failedSources: failed.map((item) => `${item.source}: ${item.error}`),
    usableSourceCount: usable.length,
  }
}

/**
 * Claude 域名解析落地：只做 DNS 解析（不连接 Anthropic），再把解析结果反查归属地。
 * 若解析到被禁地区（默认 CN），说明解析被污染或流量被劫持到国内节点。
 */
export async function probeClaudeDns({ proxyUrl, deniedCountries = ['CN'] } = {}) {
  const hosts = []
  for (const host of CLAUDE_HOSTS) {
    try {
      const records = await lookup(host, { all: true, verbatim: true })
      hosts.push({
        host,
        addresses: records.map((record) => record.address).filter((ip) => ip.includes('.')),
        error: undefined,
      })
    } catch (error) {
      hosts.push({ host, addresses: [], error: error instanceof Error ? error.message : String(error) })
    }
  }

  const addresses = [...new Set(hosts.flatMap((item) => item.addresses))]
  const geo = new Map()
  if (addresses.length > 0) {
    try {
      // 批量查询（一次最多 100 个），避免逐条触发限流。
      const body = JSON.stringify(addresses.map((ip) => ({ query: ip, fields: 'status,query,countryCode,isp,as' })))
      const { status, text } = await fetchText('http://ip-api.com/batch', { proxyUrl, body })
      if (status === 200) {
        const rows = JSON.parse(text)
        for (const row of rows) {
          if (row?.status === 'success') {
            geo.set(row.query, { country: String(row.countryCode ?? '').toUpperCase(), isp: row.isp, asn: row.as })
          }
        }
      }
    } catch {
      // 反查失败只降低置信度，不影响解析结果本身。
    }
  }

  const deniedHits = []
  for (const host of hosts) {
    for (const ip of host.addresses) {
      const info = geo.get(ip)
      if (info && deniedCountries.includes(info.country)) {
        deniedHits.push({ host: host.host, ip, country: info.country, isp: info.isp })
      }
    }
  }

  return {
    hosts: hosts.map((item) => ({
      host: item.host,
      addresses: item.addresses,
      ...(geo.get(item.addresses[0] ?? '') ?? {}),
      error: item.error,
    })),
    deniedHits,
    resolved: hosts.some((item) => item.addresses.length > 0),
    hasResolutionError: hosts.some((item) => item.error !== undefined),
  }
}
