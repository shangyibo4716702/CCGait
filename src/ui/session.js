import { existsSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { CONFIG_PATH, loadConfig, normalizeConfig, resolveStateDir, validateConfig } from '../config.js'
import { createGuard, readGuardPid, runChecks } from '../guard.js'
import {
  applyBlockForPaths,
  enableProfiles,
  firewallProfileState,
  isElevated,
  listManagedRules,
  removeAllBlocks,
} from '../firewall.js'
import { claudeDiscovery, killAllClaudeProcesses, listClaudeProcesses } from '../process-guard.js'
import { startupStatus } from '../startup.js'
import { isWfpBlocking, listWfpHosts, readWfpPid, startWfpBlock, stopWfpBlock } from '../win/wfp.js'

/**
 * UI 会话层：把 CLI 已有的能力包成一组可调用的动作 + 一个事件流，供 Web 前端使用。
 *
 * 关键设计：
 * - **单一真相**。配置、闸门实例、最近一次检测结果、日志都在这里，UI 只是它的视图。
 * - **动作串行化**。启动/停止闸门、改配置都会互相影响，用一个内部的 promise 队列保证
 *   同一时刻只有一个动作在跑，避免"边启动边改配置"导致状态错乱。
 * - **可注入依赖**。检测、闸门工厂、防火墙操作都可以替换，方便在没有管理员权限、
 *   或不想动系统状态的情况下测试。
 */

const LOG_RING_SIZE = 500
const INTERCEPTION_RING_SIZE = 80

/**
 * 从日志文件里回填拦截记录。
 *
 * 为什么要读文件而不是只留内存：拦截记录的价值在于"事后回看"，
 * 而界面进程重启后内存里的东西就没了。日志文件本来就有 ISO 时间戳与级别，
 * 直接复用即可，不需要另建一套存储。
 */
function readInterceptionsFromLog(stateDir, limit = INTERCEPTION_RING_SIZE) {
  try {
    const dir = stateDir
    if (!existsSync(dir)) return []
    const files = readdirSync(dir)
      .filter((name) => name.startsWith('ccgait-') && name.endsWith('.log'))
      .sort()
    const picked = []
    for (const name of files.slice(-2)) {
      const text = readFileSync(join(dir, name), 'utf8')
      for (const line of text.split(/\r?\n/)) {
        // 形如：2026-10-17T01:52:08.144Z BLOCK 已阻断网络（防火墙出站） 11/11 个程序已生效
        const match = /^(\S+) (OK|WARN|BLOCK|INFO|ERR)\s+(.*)$/.exec(line.trim())
        if (!match) continue
        const [, at, tag, rest] = match
        const level = tag === 'BLOCK' ? 'block' : tag === 'WARN' ? 'warn' : tag === 'ERR' ? 'error' : tag === 'OK' ? 'ok' : 'info'
        if (level !== 'block' && level !== 'warn') continue
        picked.push({ at, level, message: rest })
      }
    }
    return picked.slice(-limit)
  } catch {
    return []
  }
}

function nowIso() {
  return new Date().toISOString()
}

/** 只取可写入配置的字段，并做一次规范化：UI 传什么都不会把配置写坏。 */
export function applyConfigPatch(current, patch) {
  const merged = {
    whitelist: { ...current.whitelist, ...(patch.whitelist ?? {}) },
    checks: { ...current.checks },
    enforcement: { ...current.enforcement, ...(patch.enforcement ?? {}) },
    network: {
      proxy: { ...current.network.proxy, ...(patch.network?.proxy ?? {}) },
    },
    runtime: { ...current.runtime, ...(patch.runtime ?? {}) },
  }
  for (const [name, value] of Object.entries(patch.checks ?? {})) {
    if (!value || typeof value !== 'object') continue
    const base = current.checks[name] ?? { enabled: true, severity: 'warn' }
    merged.checks[name] = { ...base, ...value }
  }
  return normalizeConfig(merged)
}

/**
 * Claude 客户端此刻的可用性结论。
 *
 * 两个问题分开回答，因为它们的成因不同：
 *  - **能不能打开**：取决于闸门是否在执法 + 判定是否通过 + 是否配置了"终止进程"。
 *    闸门没在跑时没有任何东西拦它，所以能打开 —— 但要如实说明"没有执法在生效"，
 *    否则用户会误以为有闸门在保护。
 *  - **能不能联网**：只看当前有没有生效中的阻断（WFP 或防火墙规则）。它与判定无关：
 *    即使闸门没跑，之前手动建的阻断依然会让它连不上网。
 */
function buildClaudeAccess({ check, guardRunning, networkBlocked, networkLayers, externalBlock, config }) {
  const killEnabled = config?.enforcement?.killProcesses !== false
  const verdictKnown = Boolean(check)
  const verdictDeny = verdictKnown && check.allow === false

  let canLaunch
  let launchReason
  if (!guardRunning) {
    canLaunch = true
    launchReason = verdictKnown && verdictDeny
      ? '闸门未运行，没有执法在生效（但当前环境判定为不通过）'
      : '闸门未运行，没有执法在生效'
  } else if (!verdictKnown) {
    canLaunch = true
    launchReason = '闸门运行中，但还没跑过检测；点「立即检测」后才有结论'
  } else if (verdictDeny && killEnabled) {
    canLaunch = false
    launchReason = `判定不通过，启动就会被终止：${check.blocked.map((item) => item.title).join('；') || '见下方拦截记录'}`
  } else if (verdictDeny && !killEnabled) {
    canLaunch = true
    launchReason = '判定不通过，但配置里关闭了「终止客户端进程」，所以不会被终止'
  } else {
    canLaunch = true
    launchReason = '闸门运行中且判定通过，可以正常启动'
  }

  return {
    canLaunch,
    launchReason,
    canNetwork: !networkBlocked,
    networkReason: networkBlocked
      ? `已被阻断，连不上网（${networkLayers.join(' + ') || '阻断生效中'}）` +
        (externalBlock ? '。注意：这个阻断不是本界面建立的（很可能是安装版托盘的闸门在维持），点「解除阻断」后可能被它立刻重建 —— 要彻底解除，请先在托盘里停止闸门。' : '')
      : '当前没有生效中的阻断，网络可用',
    externalBlock: Boolean(externalBlock),
    verdict: verdictKnown ? (check.allow ? 'allow' : 'deny') : 'unknown',
    guardRunning,
  }
}

export function createUiSession(options = {}) {
  const configPath = options.configPath ?? CONFIG_PATH
  const logger = options.logger
  const deps = {
    runChecks: options.deps?.runChecks ?? runChecks,
    createGuard: options.deps?.createGuard ?? createGuard,
    applyBlockForPaths: options.deps?.applyBlockForPaths ?? applyBlockForPaths,
    removeAllBlocks: options.deps?.removeAllBlocks ?? removeAllBlocks,
    listManagedRules: options.deps?.listManagedRules ?? listManagedRules,
    firewallProfileState: options.deps?.firewallProfileState ?? firewallProfileState,
    isElevated: options.deps?.isElevated ?? isElevated,
    enableProfiles: options.deps?.enableProfiles ?? enableProfiles,
    listClaudeProcesses: options.deps?.listClaudeProcesses ?? listClaudeProcesses,
    killAllClaudeProcesses: options.deps?.killAllClaudeProcesses ?? killAllClaudeProcesses,
    claudeDiscovery: options.deps?.claudeDiscovery ?? claudeDiscovery,
    startupStatus: options.deps?.startupStatus ?? startupStatus,
    isWfpBlocking: options.deps?.isWfpBlocking ?? isWfpBlocking,
    listWfpHosts: options.deps?.listWfpHosts ?? listWfpHosts,
    readWfpPid: options.deps?.readWfpPid ?? readWfpPid,
    startWfpBlock: options.deps?.startWfpBlock ?? startWfpBlock,
    stopWfpBlock: options.deps?.stopWfpBlock ?? stopWfpBlock,
  }

  const listeners = new Set()
  const logs = []
  // 拦截记录：从日志文件里回填历史（跨重启保留），之后与 pushLog 同步增长。
  const interceptions = readInterceptionsFromLog(resolveStateDir(loadConfig(configPath).config, configPath))
  let loaded = loadConfig(configPath)
  let stateDir = resolveStateDir(loaded.config, configPath)
  let configProblems = validateConfig(loaded.config)
  let guard = null
  let guardStartedAt = undefined
  let lastCheck = null
  let lastEnforcement = null
  let lastError = undefined
  let queue = Promise.resolve()
  let watchTimer = null
  let watchSignature = null

  const emit = (event) => {
    for (const listener of listeners) {
      try {
        listener(event)
      } catch {
        // 单个订阅者出错不能影响其它订阅者。
      }
    }
  }

  const pushLog = (level, message, detail) => {
    const entry = {
      at: nowIso(),
      level,
      message,
      ...(detail === undefined ? {} : { detail }),
    }
    logs.push(entry)
    if (logs.length > LOG_RING_SIZE) logs.splice(0, logs.length - LOG_RING_SIZE)
    // 拦截记录与日志走同一个漏斗：block/warn 级别就是"发生过拦截/被拦下的动作"，
    // 统一在这里登记，避免每个动作各写一遍而漏掉（闸门内部的执法也经 logger 落到这里）。
    if (level === 'block' || level === 'warn') {
      interceptions.push(entry)
      if (interceptions.length > INTERCEPTION_RING_SIZE) {
        interceptions.splice(0, interceptions.length - INTERCEPTION_RING_SIZE)
      }
      emit({ type: 'interception', entry })
    }
    emit({ type: 'log', entry })
    // 同时写文件，便于事后排查。
    logger?.[level]?.(message, detail)
    return entry
  }

  /** 串行执行动作：任何动作都在前一个动作完成后才开始。 */
  const serialize = (operation) => {
    const result = queue.then(operation, operation)
    queue = result.then(
      () => undefined,
      () => undefined,
    )
    return result
  }

  const clientDiscoveryOptions = () => ({
    localAppData: process.env.LOCALAPPDATA,
    appData: process.env.APPDATA,
    home: process.env.USERPROFILE,
  })

  const getConfig = () => loaded.config

  /** 当前完整状态快照（UI 的主要数据源）。 */
  const getStatus = async () => {
    const [elevated, profile, rules, processes, startup] = await Promise.all([
      deps.isElevated(),
      deps.firewallProfileState(),
      deps.listManagedRules(),
      deps.listClaudeProcesses(),
      deps.startupStatus(),
    ])
    const discovery = deps.claudeDiscovery(clientDiscoveryOptions())

    // 网络阻断到底有没有生效：这是界面上最容易看不出来、也最该看出来的一个状态。
    // WFP 是第一层（不依赖防火墙开关），防火墙规则是第二层；任一层在生效就算"阻断中"。
    // WFP 用**实际在跑的宿主进程**为准，而不是只看 pid 文件 —— pid 文件可能被删掉，
    // 那时候只看文件会报"未生效"，而内核里其实还挂着过滤器（实测踩过）。
    const wfpHosts = await deps.listWfpHosts()
    const wfpPid = deps.readWfpPid(stateDir)
    const wfpOrphan = wfpHosts.length > 0 && !wfpHosts.includes(wfpPid)
    const activeRules = rules.filter((rule) => rule.enabled)

    return {
      at: nowIso(),
      configPath,
      stateDir,
      configExists: loaded.exists,
      config: getConfig(),
      configProblems,
      elevated,
      firewallProfile: profile,
      rules,
      processes,
      targets: discovery.entries,
      targetNotes: discovery.notes,
      startup,
      networkBlock: {
        blocked: wfpHosts.length > 0 || activeRules.length > 0,
        wfp: wfpHosts.length > 0,
        wfpHosts,
        wfpPid,
        wfpOrphan,
        firewallRules: activeRules.length,
        programs: discovery.entries.length,
      },
      // Claude 此刻能不能打开、能不能联网 —— 用户最关心的两个结论。
      // 由服务端按「判定结果 + 执法开关 + 实际阻断状态」算好，界面直接显示，不在前端猜。
      claudeAccess: buildClaudeAccess({
        check: lastCheck,
        guardRunning: guard !== null,
        networkBlocked: wfpHosts.length > 0 || activeRules.length > 0,
        networkLayers: [wfpHosts.length > 0 ? 'WFP 内核过滤器' : undefined, activeRules.length > 0 ? `防火墙规则 ${activeRules.length} 条` : undefined].filter(Boolean),
        // 阻断不是本界面建立的（例如安装版托盘的闸门在维持）：要说清楚，
        // 否则用户点「解除阻断」会被对方立刻重建，看起来像"点了没反应"。
        externalBlock: guard === null && (wfpHosts.length > 0 || activeRules.length > 0),
        config: getConfig(),
      }),
      interceptions: interceptions.slice(-INTERCEPTION_RING_SIZE).reverse(),
      guard: {
        // 以内存里的闸门对象为准（UI 自己启停的就是它）；另外给出 pid 一致性信号：
        // 闸门跑在本进程里时 pid 文件应当就是本进程 PID，对不上就说明状态可疑
        // （进程被任务管理器结束、或另有闸门在跑），界面据此提示而不是笼统显示"运行中"。
        running: guard !== null,
        pid: readGuardPid(stateDir),
        pidMatches: guard === null ? null : readGuardPid(stateDir) === process.pid,
        startedAt: guardStartedAt,
        lastState: guard?.lastState ?? null,
      },
      lastCheck,
      lastEnforcement,
      ...(lastError ? { lastError } : {}),
      logs: logs.slice(-LOG_RING_SIZE),
    }
  }

  /** 跑一轮完整检测并广播。 */
  const checkNow = () =>
    serialize(async () => {
      try {
        const result = await deps.runChecks(getConfig())
        lastCheck = {
          at: nowIso(),
          allow: result.verdict.allow,
          failedClosed: result.verdict.failedClosed,
          blocked: result.verdict.blockedBy.map((item) => ({ id: item.id, title: item.title, detail: item.detail })),
          warnings: result.verdict.warnings.map((item) => ({ id: item.id, title: item.title, detail: item.detail })),
          // 白名单原文：界面要拿它把"为什么通过/不通过"显示成可比对的一行，
          // 而不是只给一个孤零零的 GB 让人猜。
          whitelist: result.verdict.whitelistSummary,
          egress: result.egress,
          dns: result.dns,
          environment: result.environment,
        }
        lastError = undefined
        pushLog(
          result.verdict.allow ? 'ok' : 'block',
          result.verdict.allow ? '检测通过：环境命中白名单' : '检测未通过',
          result.verdict.blockedBy.map((item) => item.title).join('；') || undefined,
        )
        emit({ type: 'check', check: lastCheck })
        return lastCheck
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error)
        pushLog('error', '检测失败', lastError)
        throw error
      }
    })

  /**
   * 闸门启停有两层：Internal 是真正的动作，外层 serialize 负责排队。
   * saveConfig 本身已在队列里执行，必须调用 Internal —— 否则它会去等一个由自己
   * 占用的队列，直接死锁（这个坑被 tests/ui.test.js 抓到过）。
   */
  const startGuardInternal = async () => {
      if (guard) return { running: true, startedAt: guardStartedAt }
      const config = getConfig()
      guard = deps.createGuard({
        config,
        stateDir,
        logger: {
          ok: (m, d) => pushLog('ok', m, d),
          warn: (m, d) => pushLog('warn', m, d),
          block: (m, d) => pushLog('block', m, d),
          info: (m, d) => pushLog('info', m, d),
          error: (m, d) => pushLog('error', m, d),
        },
        onState: (state) => emit({ type: 'guard', state }),
        // 外部停止请求（托盘/CLI 的 guard-stop 写的就是这个请求文件）必须真的走一遍收尾：
        // 不接这个回调的话，闸门会停掉执法循环、但 pid 文件不清、guard 变量不为 null，
        // 界面就一直显示"运行中"而实际什么都没拦 —— 说的和做的不一致，最难发现。
        onStopRequest: () => {
          void stopGuard()
        },
      })
      guardStartedAt = nowIso()
      pushLog('info', '闸门已启动', `巡检 ${config.enforcement.pollIntervalMs}ms`)
      await guard.start()
      emit({ type: 'status' })
      return { running: true, startedAt: guardStartedAt }
  }

  const stopGuardInternal = async (stopOptions = {}) => {
      if (!guard) return { running: false }
      try {
        await guard.stop(stopOptions)
      } finally {
        guard = null
        guardStartedAt = undefined
      }
      pushLog('info', '闸门已停止')
      emit({ type: 'status' })
      return { running: false }
  }

  const startGuard = () => serialize(startGuardInternal)
  const stopGuard = (stopOptions = {}) => serialize(() => stopGuardInternal(stopOptions))

  const setFirewall = (enabled) =>
    serialize(async () => {
      if (!enabled) {
        // 两层都要撤。只删防火墙规则会把 WFP 内核过滤器留在那里继续断网 ——
        // 界面显示"已解除"、程序却依然上不了网，是最难排查的一种残留。
        const wfp = await deps.stopWfpBlock({ stateDir, waitMs: 10_000 })
        const result = await deps.removeAllBlocks()
        if (result.error) {
          pushLog('error', '解除阻断失败', result.error)
          throw new Error(result.error)
        }
        pushLog(
          'warn',
          '已解除网络阻断',
          `防火墙规则 ${result.removed} 条；WFP ${wfp.stopped ? '宿主已退出' : '本就没有宿主'}${wfp.purged ? `，另清理遗留过滤器 ${wfp.purged} 条` : ''}`,
        )
        emit({ type: 'status' })
        return { ...result, wfp }
      }
      const discovery = deps.claudeDiscovery(clientDiscoveryOptions())
      const targets = discovery.entries.map((item) => item.path)
      if (targets.length === 0) throw new Error('没有发现 Claude 客户端，无法建立阻断')

      // 第一层：WFP 内核过滤器（不依赖防火墙开关）。
      const wfp = await deps.startWfpBlock({ paths: targets, stateDir, detached: true })
      if (!wfp.ok) {
        pushLog('error', 'WFP 阻断建立失败', wfp.error)
      } else if (!wfp.alreadyRunning) {
        pushLog('block', '已建立 WFP 内核阻断', `${wfp.filters} 条过滤器生效（宿主 PID ${wfp.pid}）`)
      }

      // 第二层：防火墙规则。
      const result = await deps.applyBlockForPaths(targets)
      if (result.error) {
        pushLog('error', '建立阻断失败', result.error)
        throw new Error(result.error)
      }
      lastEnforcement = { at: nowIso(), kind: 'firewall-manual', verified: result.verified.length, failed: result.failed }
      pushLog('block', '已建立网络阻断', `${result.verified.length}/${targets.length} 个程序已生效`)
      for (const item of result.failed) pushLog('warn', '阻断未生效', `${item.path}：${item.error}`)
      emit({ type: 'status' })
      return { ...result, wfp }
    })

  const killProcesses = () =>
    serialize(async () => {
      const running = await deps.listClaudeProcesses()
      if (running.length === 0) {
        pushLog('info', '没有正在运行的 Claude 客户端')
        return { killed: [] }
      }
      const killed = await deps.killAllClaudeProcesses()
      const ok = killed.filter((item) => item.killed).length
      pushLog(ok > 0 ? 'block' : 'warn', `已终止 ${ok} 个 Claude 进程`, killed.map((item) => `${item.name}#${item.pid}`).join('、'))
      emit({ type: 'status' })
      return { killed }
    })

  const enableFirewallProfiles = () =>
    serialize(async () => {
      const result = await deps.enableProfiles()
      if (!result.ok) {
        pushLog('error', '启用防火墙配置文件失败', result.error)
        throw new Error(result.error)
      }
      pushLog('ok', '已启用 Windows 防火墙配置文件', result.profiles.map((item) => item.name).join('、'))
      emit({ type: 'status' })
      return result
    })

  /** 保存配置：写盘 → 重新加载 → 校验 → 若闸门在运行则用新配置重启它。 */
  const saveConfig = (patch) =>
    serialize(async () => {
      const next = applyConfigPatch(getConfig(), patch ?? {})
      const problems = validateConfig(next)
      if (problems.length > 0 && patch?.allowInvalid !== true) {
        const error = new Error(`配置校验未通过：${problems.join('；')}`)
        pushLog('warn', '配置未保存', problems.join('；'))
        throw error
      }
      writeFileSync(configPath, `${JSON.stringify(next, null, 2)}\n`, 'utf8')
      loaded = { path: configPath, exists: true, config: next, raw: next }
      configProblems = problems
      stateDir = resolveStateDir(next, configPath)
      pushLog('ok', '配置已保存', configPath)
      if (guard) {
        // 闸门在跑：先停（撤掉旧阻断）再按新配置重启，保证执法用的是最新白名单。
        // 这里只能用 Internal 版本：当前动作已占用串行队列，不能再入队。
        pushLog('info', '配置变更，正在按新配置重启闸门')
        try {
          await stopGuardInternal()
        } catch {
          // 停不下来也要继续重启。
        }
        await startGuardInternal()
      }
      emit({ type: 'status' })
      return next
    })

  const reloadConfig = () =>
    serialize(async () => {
      loaded = loadConfig(configPath)
      configProblems = validateConfig(loaded.config)
      pushLog('info', '已从磁盘重新读取配置')
      emit({ type: 'status' })
      return getConfig()
    })

  return {
    getStateDir: () => stateDir,
    getConfig,
    getProblems: () => configProblems,
    getStatus,
    getLogs: () => logs.slice(),
    checkNow,
    startGuard,
    stopGuard,
    setFirewall,
    killProcesses,
    enableFirewallProfiles,
    saveConfig,
    reloadConfig,
    subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    /**
     * 监视"阻断状态"的变化并广播，让界面不必等轮询。
     *
     * 为什么需要：阻断可能是**别的实例**建立的（例如安装版托盘的闸门在跑），
     * 那种变化不会触发本会话的任何事件，界面只能靠轮询发现 —— 实测出现过
     * "托盘已经把网络断掉了、界面还写着可以访问网络"的过期显示。
     * 这里只比对两个便宜的信号（常驻宿主数量、生效规则数），变了才推事件。
     */
    startWatching(intervalMs = 6_000) {
      if (watchTimer) return
      const snapshot = async () => {
        try {
          const hosts = await deps.listWfpHosts()
          const rules = await deps.listManagedRules()
          const enabled = rules.filter((rule) => rule.enabled).length
          const blocked = hosts.length > 0 || enabled > 0
          const signature = `${hosts.length}|${enabled}`
          if (watchSignature !== null && watchSignature !== signature) {
            emit({ type: 'status' })
          }
          watchSignature = signature
          void blocked
        } catch {
          // 探测失败不改状态：下一次再比。
        }
      }
      void snapshot()
      watchTimer = setInterval(() => void snapshot(), intervalMs)
      if (typeof watchTimer.unref === 'function') watchTimer.unref()
    },
    /** 退出时收尾：停掉闸门并撤掉阻断，避免留下"上不了网"的残留。 */
    async dispose() {
      if (watchTimer) {
        clearInterval(watchTimer)
        watchTimer = null
      }
      if (guard) {
        try {
          await guard.stop()
        } catch {
          // 忽略：退出流程不阻塞。
        }
        guard = null
      }
      for (const listener of listeners) {
        try {
          listener({ type: 'closed' })
        } catch {
          // 忽略。
        }
      }
      listeners.clear()
    },
  }
}

/** 供 UI 展示：当前配置文件是否存在、示例文件路径。 */
export function describeConfigFile(configPath) {
  return {
    path: configPath,
    exists: existsSync(configPath),
    raw: existsSync(configPath) ? readFileSync(configPath, 'utf8') : '',
  }
}
