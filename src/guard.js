import { existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { probeClaudeDns, probeEgress, probeResolverEgress } from './providers.js'
import {
  probeDnsServers,
  probeEmojiFont,
  probeFonts,
  probeLanguage,
  probeSystemProxy,
  probeTimezone,
} from './environment.js'
import { decide } from './verdict.js'
import {
  applyBlockForPaths,
  enableProfiles,
  firewallProfileState,
  firewallRulesUpToDate,
  listManagedRules,
  removeAllBlocks,
} from './firewall.js'
import {
  claudeExecutablePaths,
  killAllClaudeProcesses,
  listClaudeProcesses,
} from './process-guard.js'
import { isWfpBlocking, requestWfpStop, resolveWfpHelper, startWfpBlock, stopWfpBlock } from './win/wfp.js'
import { browserBlockTargets, discoverDefaultBrowser } from './browser-targets.js'

/**
 * 闸门执行器：周期性跑检测 → 判定 → 执行（终止进程 / 阻断网络）。
 *
 * 状态机很简单：
 * - allow  = true  → 撤掉自己加的防火墙阻断，让客户端正常工作；
 * - allow  = false → 杀掉正在运行的 Claude 客户端，并给它们加上出站阻断。
 *
 * 一个重要的取舍：闸门只在运行时执法。守卫被用户主动停掉或进程被强杀后，若阻断规则
 * 还在，用户会莫名其妙地连不上网 —— 所以正常退出时会撤掉阻断，并把这一点写进日志与
 * status 输出。要长期生效请用 `ccgait install-startup` 让它随登录常驻。
 */

export const STATE_FILE = 'state.json'
export const GUARD_PID_FILE = 'guard.pid'
export const GUARD_STOP_FILE = 'guard-stop.request'
export const GUARD_START_FILE = 'guard-start.request'

export function stateFilePath(stateDir) {
  return join(stateDir, STATE_FILE)
}

export function guardPidPath(stateDir) {
  return join(stateDir, GUARD_PID_FILE)
}

export function guardStopRequestPath(stateDir) {
  return join(stateDir, GUARD_STOP_FILE)
}

export function guardStartRequestPath(stateDir) {
  return join(stateDir, GUARD_START_FILE)
}

/**
 * 请求正在运行的闸门优雅停止：写一个请求文件，闸门在下一轮巡检时读到就会自己
 * 收尾（撤掉防火墙阻断 → 清理状态 → 退出）。
 *
 * 为什么不用信号：Windows 上 taskkill 是硬杀，进程没机会清理，会留下阻断规则；
 * 而"文件即请求"这种机制跨进程、跨用户（管理员/普通用户）都可靠，托盘、CLI、UI
 * 都能用同一套语义。
 */
export function requestGuardStop(stateDir) {
  writeFileSync(guardStopRequestPath(stateDir), `${new Date().toISOString()}
`, 'utf8')
}

export function clearGuardStopRequest(stateDir) {
  try {
    rmSync(guardStopRequestPath(stateDir), { force: true })
  } catch {
    // 文件不存在或删不掉都不影响启动。
  }
}

/**
 * 请求常驻服务里的闸门启动 —— 与停止请求同一套"文件即请求"语义。
 *
 * 为什么需要：执法现在跑在**常驻界面服务进程内**，托盘/CLI 无法再靠"起一个
 * `cli.js guard` 进程"来开始执法（那会变成第二个闸门、多一套 WFP 过滤器）。
 * 服务进程在巡检时读到这个请求就把自己的闸门对象建起来。
 */
export function requestGuardStart(stateDir) {
  writeFileSync(guardStartRequestPath(stateDir), `${new Date().toISOString()}
`, 'utf8')
}

export function clearGuardStartRequest(stateDir) {
  try {
    rmSync(guardStartRequestPath(stateDir), { force: true })
  } catch {
    // 同上。
  }
}

/** 读取闸门 PID 并判断进程是否还活着。 */
export function readGuardPid(stateDir) {
  const path = guardPidPath(stateDir)
  if (!existsSync(path)) return undefined
  try {
    const pid = Number(readFileSync(path, 'utf8').trim())
    return Number.isInteger(pid) && pid > 0 ? pid : undefined
  } catch {
    return undefined
  }
}

export function processAlive(pid) {
  if (!pid) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    // EPERM = 进程存在但不属于当前用户；ESRCH = 不存在。
    return error?.code === 'EPERM'
  }
}

/** 跑一轮完整检测（网络 + 环境），返回原始结果与判定。 */
export async function runChecks(config) {
  const proxyUrl =
    config.network.proxy.enabled && config.network.proxy.url ? config.network.proxy.url : undefined
  const proxyRequired = config.network.proxy.required === true
  const deniedCountries = config.checks.claudeDns.deniedCountries

  const [
    egressResult,
    dnsResult,
    timezone,
    language,
    fonts,
    emojiFont,
    dnsServers,
    resolverEgress,
    systemProxy,
  ] = await Promise.all([
      config.checks.egressIp.enabled
        ? probeEgress({ proxyUrl, proxyRequired }).catch((error) => ({
            ip: undefined,
            failedSources: [String(error?.message ?? error)],
          }))
        : Promise.resolve(undefined),
      config.checks.claudeDns.enabled
        ? probeClaudeDns({ proxyUrl, deniedCountries }).catch(() => undefined)
        : Promise.resolve(undefined),
      config.checks.timezone.enabled ? probeTimezone().catch(() => undefined) : Promise.resolve(undefined),
      config.checks.language.enabled ? probeLanguage().catch(() => undefined) : Promise.resolve(undefined),
      config.checks.fonts.enabled ? Promise.resolve(probeFonts()) : Promise.resolve(undefined),
      config.checks.emojiFlags.enabled ? Promise.resolve(probeEmojiFont()) : Promise.resolve(undefined),
      config.checks.dnsServers.enabled ? probeDnsServers().catch(() => undefined) : Promise.resolve(undefined),
      config.checks.resolverEgress.enabled
        ? probeResolverEgress({ deniedCountries }).catch(() => undefined)
        : Promise.resolve(undefined),
      config.checks.proxyEnvLeak.enabled ? probeSystemProxy().catch(() => undefined) : Promise.resolve(undefined),
    ])

  const environment = { timezone, language, fonts, emojiFont, dnsServers, resolverEgress, systemProxy }
  const verdict = decide({
    config,
    egress: egressResult,
    dns: dnsResult,
    environment,
    deniedCountries,
  })
  return { egress: egressResult, dns: dnsResult, environment, verdict }
}

/** 打印一轮检测结果（CLI 与 guard 共用）。 */
export function formatCheckReport({ egress, dns, environment, verdict }, logger) {
  const log = logger ?? {
    info: (m, d) => console.log(`${m}${d ? ` ${d}` : ''}`),
    ok: (m, d) => console.log(`OK   ${m}${d ? ` ${d}` : ''}`),
    warn: (m, d) => console.log(`WARN ${m}${d ? ` ${d}` : ''}`),
    block: (m, d) => console.log(`BLOCK ${m}${d ? ` ${d}` : ''}`),
  }

  if (egress) {
    if (egress.ip === undefined) {
      log.block('出口检测失败', `数据源：${(egress.failedSources ?? []).join('；')}`)
    } else {
      log.info(
        '出口',
        `${egress.ip} · ${egress.country ?? '??'}${egress.countryName ? `（${egress.countryName}）` : ''} · ${egress.asnText || egress.asn || 'ASN 未知'}${egress.hosting ? ' · 机房/代理' : ''}${egress.mobile ? ' · 移动网络' : ''}`,
      )
      log.info(
        '多源一致性',
        egress.confident ? '一致（可信）' : `不一致 → IP ${JSON.stringify(egress.ipVotes)} / 国家 ${JSON.stringify(egress.countryVotes)}`,
      )
    }
  }

  if (dns) {
    log.info(
      'Claude 域名解析',
      dns.hosts
        .map((item) => `${item.host} → ${item.addresses[0] ?? item.error ?? '无结果'}${item.country ? `(${item.country})` : ''}`)
        .join(' · '),
    )
  }

  if (environment?.timezone) {
    log.info(
      '系统时区',
      `${environment.timezone.intl}${environment.timezone.windows ? ` / ${environment.timezone.windows}` : ''}${environment.timezone.domestic ? ' ← 国内时区' : ''}`,
    )
  }
  if (environment?.language) {
    log.info(
      '界面语言',
      `${(environment.language.uiLanguages ?? []).join('、') || '未知'}${environment.language.chinese ? ' ← 含中文' : ''}`,
    )
  }
  if (environment?.fonts) {
    const strong = environment.fonts.found.filter((item) => item.strong)
    log.info(
      '国内字体',
      strong.length > 0
        ? `命中 ${strong.map((item) => item.label).join('、')}`
        : environment.fonts.found.length > 0
          ? `仅有常见中文字体（${environment.fonts.found.length} 个）`
          : '未命中',
    )
  }
  if (environment?.dnsServers) {
    log.info(
      'DNS 服务器',
      `${(environment.dnsServers.servers ?? []).join('、') || (Number(environment.dnsServers.filtered) > 0 ? '只有路由器/链路本地地址' : '未读取')}${environment.dnsServers.domestic?.length ? ` ← 国内 ${environment.dnsServers.domestic.join('、')}` : ''}`,
    )
  }
  if (environment?.resolverEgress) {
    const resolvers = environment.resolverEgress.resolvers ?? []
    log.info(
      '解析出口（实测）',
      resolvers.length > 0
        ? resolvers.map((item) => `${item.ip}${item.country ? ` ${item.country}` : ''}`).join('、')
        : `无法确认（${environment.resolverEgress.error ?? '查询没拿到应答'}）`,
    )
  }
  if (environment?.systemProxy?.hasAny) {
    log.info(
      '系统代理',
      `系统代理${environment.systemProxy.system?.enabled ? `开启（${environment.systemProxy.system.server ?? '—'}）` : '关闭'}${
        Object.keys(environment.systemProxy.envVars ?? {}).length > 0
          ? ` · 环境变量 ${Object.keys(environment.systemProxy.envVars).join('、')}`
          : ''
      }`,
    )
  }

  for (const item of verdict.blockedBy) log.block(item.title, item.detail)
  for (const item of verdict.warnings) log.warn(item.title, item.detail)
  if (verdict.failedClosed) {
    log.block('判定不通过（failClosed）', '出口身份无法确认，按拦截处理；如需放宽请把 enforcement.failClosed 设为 false')
  }
  if (verdict.allow) {
    log.ok('判定：放行', '环境命中白名单')
  } else {
    log.block('判定：拦截', '白名单未命中，阻止客户端启动并阻断其网络')
  }
}

/**
 * 把"为什么判拦截"压成一行可读原因。
 *
 * 单独抽出来有两个理由：日志、状态文件、界面都要用同一套口径（三处各写一遍必然
 * 漂移）；而且它是纯函数，能被单元测试钉住 —— 早先这里完全没有记录，
 * 事后只能看到"已处理 N 个进程"，查不出到底哪一项没通过。
 */
export function describeBlockReason(verdict, egress) {
  const causes = (verdict?.blockedBy ?? []).map((item) => item.title).filter(Boolean)
  if (verdict?.failedClosed && causes.length === 0) {
    return 'failClosed：出口身份不可信（查询失败或多源矛盾），按拦截处理'
  }
  const head = causes.length > 0 ? causes.join('；') : '白名单未命中'
  if (!verdict?.failedClosed) return head
  return `${head}；failClosed：出口身份不可信`
}

/** 出口摘要：日志里必须带上当时的 IP/国家，否则无法复盘。 */
export function describeEgress(egress) {
  if (!egress || egress.ip === undefined) {
    const failed = (egress?.failedSources ?? []).join('；')
    return failed ? `出口：查询失败（${failed}）` : '出口：查询失败'
  }
  const bits = [`${egress.ip}`, egress.country ?? '??']
  if (egress.hosting) bits.push('机房/代理')
  if (egress.confident === false) bits.push('多源不一致')
  return `出口 ${bits.join(' · ')}`
}

/**
 * 这一轮该不该终止进程。
 *
 * 关键区分：`blockedBy` 非空 = 我们**确认**它违规；只有 failClosed（出口查不到、
 * 多源矛盾）= 我们**没测出来**。后者绝不该杀进程 —— 网络抖动一次就把用户的编辑器
 * 全关掉，是实测发生过的误杀（一轮 18 个 Claude 进程）。
 *
 * 抽成纯函数是为了能被单测钉住：这类判断一旦写错，代价是用户正在干活的进程没了。
 */
export function shouldKillProcesses(config, verdict) {
  if (!config?.enforcement?.killProcesses) return false
  return (verdict?.blockedBy ?? []).length > 0
}

/** 执行一轮：按判定结果终止进程 / 建立或撤掉网络阻断。 */
export async function enforce(config, verdict, options = {}) {
  const logger = options.logger
  const stateDir = options.stateDir
  const result = {
    killed: [],
    killedCount: 0,
    blockedPaths: [],
    unblocked: false,
    errors: [],
  }

  const targets = claudeExecutablePaths({
    localAppData: process.env.LOCALAPPDATA,
    appData: process.env.APPDATA,
    home: process.env.USERPROFILE,
  })

  // 登录链路会打开系统默认浏览器做 OAuth：只掐 Claude 自己的进程不够，
  // 浏览器照样上外网、那条流量同样会出去。所以浏览器纳入**网络**管控，
  // 但永不终止它的进程（用户可能正开着几十个标签页）。
  const browserPaths = options.browserPaths ?? []

  if (verdict.allow) {
    // 放行：撤掉 WFP 阻断与防火墙规则（两者都要撤，避免任一残留继续拦用户）。
    const wfpStopped = await stopWfpBlock({ stateDir })
    if (wfpStopped.stopped) result.unblocked = true

    const existing = await listManagedRules()
    if (existing.length > 0) {
      const removal = await removeAllBlocks()
      if (removal.error) result.errors.push(removal.error)
      else result.unblocked = true
    }
    return result
  }

  // 终止进程只在「确实违规」时执行。
  //
  // 为什么要把 failClosed 排除在外：出口探测是走网络的，一次抖动、一个数据源超时，
  // 就会让 confident 变成 false，进而 failClosed=true。那种情况下我们**并不知道**
  // 用户在违规，只知道"这一轮没测出来"。据此杀进程就是误杀 —— 实测发生过：
  // 网络抖动一轮，18 个 Claude 进程全被终止。
  // 正确做法是"证据不足时只断网"：网络先封死（不露馅），但不动用户的进程。
  if (shouldKillProcesses(config, verdict)) {
    const running = await listClaudeProcesses()
    if (running.length > 0) {
      const killed = await killAllClaudeProcesses()
      result.killed = killed
      result.killedCount = killed.filter((item) => item.killed).length
      // "本来就已经退出"要和"我们杀掉的"分开报：否则会出现"已终止 0 个"却列着 PID 的怪话。
      result.goneCount = killed.filter((item) => item.gone).length
      for (const item of killed) {
        if (item.error) result.errors.push(`终止 PID ${item.pid} 失败：${item.error}`)
      }
      // 每条终止记录都带上"为什么被终止"：只写"已处理 N 个进程"的话，事后完全
      // 无法区分是白名单不通过、出口查不到（failClosed），还是别的维度触发的。
      logger?.block(
        `已处理 ${killed.length} 个 Claude 进程`,
        `原因：${describeBlockReason(verdict)}｜${killed
          .map((item) => `${item.name}#${item.pid}${item.gone ? '（执行时已自行退出）' : ''}`)
          .join('、')}`,
      )
    }
  } else if (config.enforcement.killProcesses && verdict.failedClosed) {
    // 证据不足：只断网、不杀进程，并把这一点写清楚，免得用户以为闸门没在干活。
    logger?.warn(
      '证据不足，只断网不终止进程',
      '出口身份无法确认（查询失败或多源矛盾）。已封死网络防止外泄，但不动正在运行的 Claude 进程。',
    )
  }
  if (config.enforcement.blockNetwork) {
    // 第一层：WFP 内核过滤器 —— 不依赖 Windows 防火墙是否开启。
    if (resolveWfpHelper()) {
      const wfp = await startWfpBlock({
        paths: targets,
        browserPaths,
        stateDir,
        timeoutMs: 20_000,
      })
      if (wfp.ok) {
        result.wfp = { pid: wfp.pid, filters: wfp.filters ?? null }
        logger?.block(
          '已断网（WFP 内核过滤器）',
          wfp.alreadyRunning
            ? '复用已在生效的过滤器'
            : `${wfp.filters} 条过滤器生效${browserPaths.length > 0 ? `（含默认浏览器 ${browserPaths.length} 个程序，仅断外网、保留本地界面）` : ''}`,
        )
        if (browserPaths.length > 0) {
          result.browserBlocked = browserPaths
          logger?.block(
            '已管控默认浏览器网络',
            `${browserPaths.join('、')}（只断外网，不终止浏览器进程）`,
          )
        }
      } else {
        result.errors.push(`WFP 阻断失败：${wfp.error}`)
      }
    } else {
      result.errors.push('未找到 CCGaitWfp.exe，无法使用不依赖防火墙的断网方式')
    }
  }

  // 第二层（默认关闭）：Windows 防火墙规则。默认不用它 —— 用户不必为了拦 Claude
  // 去打开系统防火墙，WFP 已经把这件事做了。需要双保险时把 enforcement.firewallRules 设为 true。
  if (config.enforcement.firewallRules) {
    if (targets.length === 0) {
      result.errors.push(
        '没有找到 Claude 客户端的可执行文件，无法建立防火墙阻断（客户端未安装时属正常）',
      )
    } else {
      // 稳态（规则齐全且都在拦截）不重写：重写那条路实测十几秒，每轮复检都跑一次
      // 会把一轮从约 3 秒拖到十几秒，还顺带推迟"客户端被终止"的时刻。
      const upToDate = await firewallRulesUpToDate(targets)
      if (upToDate.current) {
        result.applied = []
        result.verified = upToDate.verified
        result.removed = []
        result.failed = []
      } else {
        const applied = await applyBlockForPaths(targets)
        if (applied.error) {
          result.errors.push(applied.error)
        } else {
          // 只把「回查确认已阻断」的路径算作生效，失败的必须如实上报。
          result.applied = applied.applied
          result.verified = applied.verified
          result.removed = applied.removed
          result.failed = applied.failed
          if (applied.verified.length > 0) {
            logger?.block('已阻断网络（防火墙出站）', `${applied.verified.length}/${targets.length} 个程序已生效`)
          }
          for (const item of applied.failed) {
            result.errors.push(`阻断失败 ${item.path}：${item.error}`)
          }
        }
      }
    }
  }

  if (stateDir) {
    try {
      const profile = await firewallProfileState()
      if (profile.supported && !profile.anyEnabled) {
        // 防火墙规则只在 profile 启用时才生效。既然配置要求"阻断网络全开"，
        // 就在这里把 profile 打开——否则这一层是静默失效的，用户以为拦住了其实没有。
        if (config.enforcement.firewallRules && config.enforcement.enableFirewallProfiles) {
          const enabled = await enableProfiles()
          if (enabled.ok) {
            logger?.block(
              '已开启 Windows 防火墙配置文件',
              '防火墙规则只在 profile 启用时生效；如不想让闸门改这个开关，把 enforcement.enableFirewallProfiles 设为 false',
            )
          } else {
            result.errors.push(`防火墙规则不会生效：三个 profile 都是关闭状态，且自动开启失败（${enabled.error}）`)
          }
        } else {
          result.errors.push(
            'Windows 防火墙三个配置文件都是关闭状态，防火墙规则不会生效：请在「Windows 安全中心 → 防火墙和网络保护」里开启，或改用只终止进程的策略',
          )
        }
      }
    } catch {
      // 读取失败不影响主流程。
    }
  }

  return result
}

/** 守护循环。 */
export function createGuard({ config, stateDir, logger, onState, onStopRequest }) {
  let timer = null
  let processTimer = null
  let stopping = false
  let checking = false
  let lastFullCheckAt = 0
  let lastState = null

  // 默认浏览器只解析一次：它不会在运行期间变来变去，每轮都去读注册表纯属浪费
  // （一次 PowerShell 要几百毫秒）。解析失败的结论也缓存，避免每轮都卡一下。
  let browserCache

  const resolveBrowserTargets = async () => {
    if (browserCache !== undefined) return browserCache
    try {
      const browser = await discoverDefaultBrowser()
      if (!browser.path) {
        logger?.warn(
          '未找到默认浏览器，无法管控登录链路',
          'Claude 登录会打开默认浏览器；找不到它的可执行文件时，那条流量不受本闸门管控。',
        )
        browserCache = []
      } else {
        browserCache = browserBlockTargets(browser)
        logger?.info(
          '默认浏览器已纳入网络管控',
          `${browser.label ?? browser.name ?? browser.path}${browser.inferred ? '（按安装位置推断）' : ''}`,
        )
      }
    } catch {
      browserCache = []
    }
    return browserCache
  }

  const persist = (state) => {
    lastState = state
    if (!stateDir) return
    try {
      writeFileSync(stateFilePath(stateDir), `${JSON.stringify(state, null, 2)}\n`, 'utf8')
    } catch {
      // 状态文件写失败不影响执法。
    }
    onState?.(state)
  }

  /**
   * block-first：判定还没出来之前，先把网络阻断挂上。
   *
   * 为什么需要：闸门是"跑完判定再拦"，那第一轮判定（网络探测要跑一两秒）出结果之前是
   * 没有任何拦截的 —— 客户端恰好在这几秒里启动，它的请求会直接出去。先挂过滤器，
   * 判定通过时紧跟其后的 enforce() 会立刻把它撤掉。
   *
   * 只挂 WFP 这一层：它在内核里、起停约一秒；防火墙规则那层要写 N 条系统规则（实测 11 条
   * 要十几秒），放在每轮判定前做会把一次复检拖成十几秒，而且规则本来就会一直留到判定通过。
   */
  const preBlock = async () => {
    // 已经有宿主在挂过滤器就别再起一个：多出来的宿主各挂一套自己的过滤器，
    // 撤的时候只会撤到其中一个，剩下的会让用户"莫名其妙上不了网"。
    if (isWfpBlocking(stateDir)) return undefined
    const targets = claudeExecutablePaths({
      localAppData: process.env.LOCALAPPDATA,
      appData: process.env.APPDATA,
      home: process.env.USERPROFILE,
    })
    if (targets.length === 0) return undefined
    if (!resolveWfpHelper()) return undefined
    // block-first 也要连浏览器一起挂上：登录窗口弹出时正好是"判定还没出结果"的
    // 那几秒，浏览器若不在名单里，OAuth 请求就直接出去了。
    return startWfpBlock({
      paths: targets,
      browserPaths: await resolveBrowserTargets(),
      stateDir,
      timeoutMs: 20_000,
    })
  }

  /**
   * 一轮 = 判定 + 执行。**必须串行**：触发它的有两个定时器（复检 5 秒一跳、
   * 进程巡检 2 秒一跳），而一轮要跑十几秒（判定约 2 秒 + 写 11 条防火墙规则十几秒）。
   *
   * 不加这道锁会并发跑同一轮，各自去挂 WFP 过滤器：第 2 个在第一个还没写好 pid 文件时
   * 看不到已有宿主，于是又 spawn 一个 —— 实测一口气堆出 7 个宿主进程，防火墙规则也会
   * 写成两份（日志里出现过"已撤掉 22 条 CCGait 防火墙规则"，正是 11×2）。
   */
  const checkAndEnforce = async (reason) => {
    if (checking) return lastState
    checking = true
    const started = Date.now()
    // 复检间隔从「这一轮开始」算，而不是从它结束算：否则一轮跑了十几秒后，
    // 定时器的下一个检查点会立刻又起一轮，间隔形同虚设。
    lastFullCheckAt = started
    try {
      if (config.enforcement.blockFirst && config.enforcement.blockNetwork) {
        // 只在「当前不是已放行状态」时才先行封网。
        //
        // 为什么不能每轮都封：判定通过后网络是开着的，下一轮一进来又封上、检测完再撤，
        // 等于每 10 秒给用户断一次网（实测一次约 3 秒）。表现就是"网络明明没变，
        // 却一会儿可访问一会儿不可访问"——下载、流式输出都会被打断。
        // 真正需要 block-first 的是「第一轮」和「上一轮判拦截」这两种情况：
        // 那时网络本来就该是关的，先封再判不会伤害任何正在进行的连接。
        const previouslyAllowed = lastState?.allow === true
        if (!previouslyAllowed) {
          try {
            const pre = await preBlock()
            if (pre && !pre.ok) logger?.warn('先行阻断未建立', pre.error)
          } catch (error) {
            // 先行阻断失败不能拖住判定：判定本身还是照跑，该拦的由 enforce() 兜住。
            logger?.warn('先行阻断失败', error instanceof Error ? error.message : String(error))
          }
        }
      }
      const result = await runChecks(config)
      // 每次判拦截都必须把「为什么」写进日志和状态文件，而且要写在执行动作之前：
      // 早先只记录执行动作（已断网/已处理 N 个进程），事后翻日志根本看不出是哪一项
      // 不通过、出口当时是多少 —— 用户看到"Claude Code 被终止很多次"却查不出原因。
      // 顺序上先原因后动作，读日志时一眼就是"为什么 → 做了什么"。
      if (!result.verdict.allow) {
        const detail = [
          describeEgress(result.egress),
          result.verdict.failedClosed ? 'failClosed：出口身份不可信，按拦截处理' : undefined,
          `触发：${reason}`,
        ]
          .filter(Boolean)
          .join('；')
        logger?.block(`判定拦截：${describeBlockReason(result.verdict)}`, detail)
      }
      const enforcement = await enforce(config, result.verdict, {
        logger,
        stateDir,
        browserPaths: await resolveBrowserTargets(),
      })
      const state = {
        guardPid: process.pid,
        updatedAt: new Date().toISOString(),
        reason,
        allow: result.verdict.allow,
        failedClosed: result.verdict.failedClosed,
        // 原因写全（title + detail）：状态文件是事后复盘的主要证据，只留 title
        // 会丢掉"白名单只允许什么、当前是什么"这类关键比对信息。
        blocked: result.verdict.blockedBy.map((item) => ({
          id: item.id,
          title: item.title,
          detail: item.detail,
        })),
        warnings: result.verdict.warnings.map((item) => ({
          id: item.id,
          title: item.title,
          detail: item.detail,
        })),
        egress: result.egress
          ? {
              ip: result.egress.ip,
              country: result.egress.country,
              asn: result.egress.asn,
              org: result.egress.org,
              hosting: result.egress.hosting,
              confident: result.egress.confident,
            }
          : undefined,
        enforcement,
        durationMs: Date.now() - started,
      }
      persist(state)
      return state
    } finally {
      // 无论判定/执行成功与否都要解锁，否则一次异常会让闸门再也不复检。
      checking = false
    }
  }

  const pollProcesses = async () => {
    if (stopping) return

    // 外部请求停止（托盘 / ccgait guard-stop）：优雅收尾，撤掉阻断后再退出。
    if (stateDir && existsSync(guardStopRequestPath(stateDir))) {
      clearGuardStopRequest(stateDir)
      logger?.info('收到停止请求', '闸门即将收尾退出')
      stopping = true
      onStopRequest?.()
      return
    }

    const state = lastState
    if (!state || state.allow) return
    // 已判定拦截时高频巡检：只要客户端被启动，立即处理。
    if (config.enforcement.killProcesses) {
      const running = await listClaudeProcesses()
      if (running.length > 0) {
        await checkAndEnforce('process-detected')
      }
    }
  }

  return {
    get lastState() {
      return lastState
    },
    /** 启动：先做一轮完整判定，然后按两个周期循环。 */
    async start() {
      stopping = false
      if (stateDir) {
        clearGuardStopRequest(stateDir)
        clearGuardStartRequest(stateDir)
        try {
          writeFileSync(guardPidPath(stateDir), `${process.pid}
`, 'utf8')
        } catch {
          // PID 文件只是给状态展示用，写不了不影响执法。
        }
      }
      logger?.info(
        '闸门已启动',
        `巡检 ${config.enforcement.pollIntervalMs}ms · 复检 ${config.enforcement.recheckIntervalMs}ms · failClosed=${config.enforcement.failClosed}`,
      )
      await checkAndEnforce('startup')
      timer = setInterval(() => {
        if (stopping) return
        if (Date.now() - lastFullCheckAt >= config.enforcement.recheckIntervalMs) {
          void checkAndEnforce('recheck')
        }
      }, Math.min(config.enforcement.recheckIntervalMs, 5000))
      processTimer = setInterval(() => {
        void pollProcesses()
      }, config.enforcement.pollIntervalMs)
      return lastState
    },
    /** 停止：撤掉阻断，避免留下"莫名其妙上不了网"的残留。 */
    async stop({ keepBlocks = false } = {}) {
      stopping = true
      // WFP 是会话作用域：让宿主收尾，过滤器随会话消失。
      try {
        requestWfpStop(stateDir)
      } catch {
        // 收尾失败不阻塞退出：宿主不在时过滤器本来也会随会话消失。
      }
      if (stateDir) {
        try {
          rmSync(guardPidPath(stateDir), { force: true })
        } catch {
          // 忽略。
        }
      }
      if (timer) clearInterval(timer)
      if (processTimer) clearInterval(processTimer)
      timer = null
      processTimer = null
      let removal = { removed: 0 }
      if (!keepBlocks) {
        removal = await removeAllBlocks()
      }
      persist({
        ...(lastState ?? { updatedAt: new Date().toISOString() }),
        guardPid: process.pid,
        running: false,
        stoppedAt: new Date().toISOString(),
        removedRules: removal.removed,
      })
      logger?.info(
        '闸门已停止',
        keepBlocks ? '保留了防火墙阻断规则（--keep-blocks）' : `已撤掉 ${removal.removed} 条 CCGait 防火墙规则`,
      )
      return removal
    },
    checkOnce: () => checkAndEnforce('manual'),
  }
}
