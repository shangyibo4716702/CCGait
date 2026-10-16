import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * Windows 客户端（托盘/快捷方式）读取的状态文件。
 *
 * 托盘不直接调 HTTP 接口，而是读这里落盘的 JSON —— 好处有三个：
 * 1. 不需要把会话令牌交给另一个进程；
 * 2. 托盘、CLI、Web 界面看到的是同一份事实；
 * 3. 进程重启后状态不丢，用户随时能看到"上次判定是什么"。
 */

export const LAST_CHECK_FILE = 'last-check.json'

export function lastCheckPath(stateDir) {
  return join(stateDir, LAST_CHECK_FILE)
}

/** 把一次检测结果落盘（供托盘/状态查看使用）。 */
export function writeLastCheck(stateDir, result) {
  const payload = {
    at: new Date().toISOString(),
    allow: result.verdict.allow,
    failedClosed: result.verdict.failedClosed,
    blocked: result.verdict.blockedBy.map((item) => ({ id: item.id, title: item.title })),
    warnings: result.verdict.warnings.map((item) => ({ id: item.id, title: item.title })),
    egress: result.egress
      ? {
          ip: result.egress.ip,
          country: result.egress.country,
          org: result.egress.org,
          asn: result.egress.asn,
          hosting: result.egress.hosting === true,
          confident: result.egress.confident === true,
        }
      : undefined,
    whitelist: {
      countries: result.verdict.whitelistSummary?.countries ?? [],
      ips: result.verdict.whitelistSummary?.ips ?? [],
    },
  }
  writeFileSync(lastCheckPath(stateDir), `${JSON.stringify(payload, null, 2)}\n`, 'utf8')
  return payload
}

function readJson(path) {
  if (!existsSync(path)) return undefined
  try {
    return JSON.parse(readFileSync(path, 'utf8'))
  } catch {
    return undefined
  }
}

/** 汇总托盘需要的信息：最近一次检测 + 闸门状态。 */
export function readStatusSnapshot(stateDir) {
  const lastCheck = readJson(lastCheckPath(stateDir))
  const guardState = readJson(join(stateDir, 'state.json'))
  const guardRunning = Boolean(
    guardState && guardState.running !== false && guardState.stoppedAt === undefined,
  )
  return { lastCheck, guardState, guardRunning }
}

/** 托盘悬停提示（WinForms 要求 ≤ 63 字符）。 */
export function trayTooltip(snapshot) {
  const check = snapshot.lastCheck
  const parts = ['CCGait']
  if (check) {
    parts.push(check.allow ? '放行' : '拦截')
    if (check.egress?.ip) parts.push(check.egress.ip)
    if (check.egress?.country) parts.push(check.egress.country)
  } else {
    parts.push('尚未检测')
  }
  parts.push(snapshot.guardRunning ? '闸门运行中' : '闸门未运行')
  const text = parts.join(' · ')
  return text.length <= 63 ? text : `${text.slice(0, 60)}…`
}

/** 气泡通知内容（检测完成 / 状态变化时用）。 */
export function traySummary(snapshot) {
  const check = snapshot.lastCheck
  if (!check) return { title: 'CCGait', text: '尚未检测：右键菜单可立即检测' }
  if (check.allow) {
    const where = [check.egress?.ip, check.egress?.country].filter(Boolean).join(' · ')
    return {
      title: '环境命中白名单，已放行',
      text: `${where || '出口已确认'}${check.warnings.length > 0 ? `；${check.warnings.length} 项提示` : ''}`,
    }
  }
  const first = check.blocked[0]?.title ?? (check.failedClosed ? '出口身份无法确认' : '白名单未命中')
  return {
    title: '环境不符，已拦截',
    text: `${first}${check.blocked.length > 1 ? ` 等 ${check.blocked.length} 项` : ''}`,
  }
}

/** 判定是否发生了「放行 → 拦截」的变化，用于只在变化时弹气泡，避免打扰。 */
export function verdictChanged(previous, current) {
  if (!previous || !current) return false
  return Boolean(previous.allow) !== Boolean(current.allow)
}
