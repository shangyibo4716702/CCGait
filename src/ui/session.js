import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { CONFIG_PATH, loadConfig, normalizeConfig, resolveStateDir, validateConfig } from '../config.js'
import { createGuard, runChecks } from '../guard.js'
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
  }

  const listeners = new Set()
  const logs = []
  let loaded = loadConfig(configPath)
  let stateDir = resolveStateDir(loaded.config, configPath)
  let configProblems = validateConfig(loaded.config)
  let guard = null
  let guardStartedAt = undefined
  let lastCheck = null
  let lastEnforcement = null
  let lastError = undefined
  let queue = Promise.resolve()

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
      guard: {
        running: guard !== null,
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
        const result = await deps.removeAllBlocks()
        if (result.error) {
          pushLog('error', '解除阻断失败', result.error)
          throw new Error(result.error)
        }
        pushLog('warn', '已解除网络阻断', `${result.removed} 条规则`)
        emit({ type: 'status' })
        return result
      }
      const discovery = deps.claudeDiscovery(clientDiscoveryOptions())
      const targets = discovery.entries.map((item) => item.path)
      if (targets.length === 0) throw new Error('没有发现 Claude 客户端，无法建立阻断')
      const result = await deps.applyBlockForPaths(targets)
      if (result.error) {
        pushLog('error', '建立阻断失败', result.error)
        throw new Error(result.error)
      }
      lastEnforcement = { at: nowIso(), kind: 'firewall-manual', verified: result.verified.length, failed: result.failed }
      pushLog(
        'block',
        '已建立网络阻断',
        `${result.verified.length}/${targets.length} 个程序已生效`,
      )
      for (const item of result.failed) pushLog('warn', '阻断未生效', `${item.path}：${item.error}`)
      emit({ type: 'status' })
      return result
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
    /** 退出时收尾：停掉闸门并撤掉阻断，避免留下"上不了网"的残留。 */
    async dispose() {
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
