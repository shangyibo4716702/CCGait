import { appendFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'

/**
 * 极简日志：控制台（带颜色）+ 追加写文件。不引入任何依赖，方便直接审阅代码。
 */

const LEVEL_TAG = { ok: 'OK  ', warn: 'WARN', block: 'BLOCK', info: 'INFO', error: 'ERR ' }
const LEVEL_COLOR = {
  ok: '\u001b[32m',
  warn: '\u001b[33m',
  block: '\u001b[31m',
  info: '\u001b[36m',
  error: '\u001b[31m',
}

const useColor = process.stdout.isTTY === true && !process.env.NO_COLOR

export function createLogger({ logFile, quiet = false } = {}) {
  if (logFile) mkdirSync(dirname(logFile), { recursive: true })

  const write = (level, message, detail) => {
    const stamp = new Date().toISOString()
    const tag = LEVEL_TAG[level] ?? level.toUpperCase()
    const line = detail === undefined ? message : `${message} ${detail}`
    if (!quiet) {
      const colored = useColor ? `${LEVEL_COLOR[level] ?? ''}${tag}\u001b[0m` : tag
      process.stdout.write(`${stamp} ${colored} ${line}\n`)
    }
    if (logFile) {
      try {
        appendFileSync(logFile, `${stamp} ${tag} ${line}\n`, 'utf8')
      } catch {
        // 日志写不进去不能影响判定与执行。
      }
    }
  }

  return {
    logFile,
    ok: (message, detail) => write('ok', message, detail),
    warn: (message, detail) => write('warn', message, detail),
    block: (message, detail) => write('block', message, detail),
    info: (message, detail) => write('info', message, detail),
    error: (message, detail) => write('error', message, detail),
    /** 只写文件不打印（用于高频巡检）。 */
    file: (level, message, detail) => {
      if (!logFile) return
      const stamp = new Date().toISOString()
      const line = detail === undefined ? message : `${message} ${detail}`
      try {
        appendFileSync(logFile, `${stamp} ${LEVEL_TAG[level] ?? level} ${line}\n`, 'utf8')
      } catch {
        // 同上。
      }
    },
  }
}

export function defaultLogFile(stateDir) {
  return join(stateDir, `ccgait-${new Date().toISOString().slice(0, 10)}.log`)
}
