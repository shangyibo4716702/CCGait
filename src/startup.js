import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { PROJECT_ROOT } from './config.js'

/**
 * 开机自启：让闸门在登录后常驻，否则"禁止打开/禁止联网"只在手动运行期间有效。
 *
 * 用计划任务（ONLOGON + 最高权限）而不是启动文件夹：防火墙规则的创建与删除需要
 * 管理员权限，启动文件夹里的脚本拿不到。计划任务只需注册时有一次管理员权限。
 * 任务执行的是一个隐藏窗口的 VBS 启动器，避免每次登录弹黑框。
 */

const execFileAsync = promisify(execFile)
export const TASK_NAME = 'CCGait Guard'

export function launcherPath(stateDir) {
  return join(stateDir, 'run-guard.vbs')
}

/** 生成隐藏窗口启动器（内容完全可读，卸载时删除即可）。 */
export function writeLauncher(stateDir) {
  mkdirSync(stateDir, { recursive: true })
  const path = launcherPath(stateDir)
  const nodePath = process.execPath
  const cliPath = join(PROJECT_ROOT, 'src', 'cli.js')
  const logPath = join(stateDir, 'guard-stdout.log')
  const script = [
    "' 由 CCGait 生成：以隐藏窗口启动闸门。",
    'Set shell = CreateObject("WScript.Shell")',
    `command = """${nodePath}"" ""${cliPath}"" guard >> ""${logPath}"" 2>&1"`,
    'shell.Run command, 0, False',
    '',
  ].join('\r\n')
  writeFileSync(path, script, 'utf8')
  return path
}

function quoteForTaskManager(value) {
  return `\\"${value}\\"`
}

/** 注册计划任务。需要管理员权限。 */
export async function installStartup(stateDir) {
  if (process.platform !== 'win32') {
    return { ok: false, error: '开机自启目前只支持 Windows' }
  }
  const launcher = writeLauncher(stateDir)
  const command = `wscript.exe ${quoteForTaskManager(launcher)}`
  try {
    await execFileAsync(
      'schtasks.exe',
      [
        '/Create',
        '/TN',
        TASK_NAME,
        '/TR',
        command,
        '/SC',
        'ONLOGON',
        '/RL',
        'HIGHEST',
        '/DELAY',
        '0000:30',
        '/F',
      ],
      { windowsHide: true, timeout: 30_000 },
    )
    return { ok: true, launcher, taskName: TASK_NAME }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    const denied = /access is denied|拒绝访问|权限|elevat/i.test(message)
    return {
      ok: false,
      launcher,
      error: denied
        ? '注册计划任务被拒绝：请以管理员身份运行「ccgait install-startup」'
        : message,
    }
  }
}

export async function uninstallStartup(stateDir) {
  if (process.platform !== 'win32') return { ok: true, removed: false }
  let removedTask = false
  try {
    await execFileAsync('schtasks.exe', ['/Delete', '/TN', TASK_NAME, '/F'], {
      windowsHide: true,
      timeout: 20_000,
    })
    removedTask = true
  } catch {
    // 任务不存在时同样按"已清理"处理。
  }
  const launcher = launcherPath(stateDir)
  let removedLauncher = false
  if (existsSync(launcher)) {
    try {
      unlinkSync(launcher)
      removedLauncher = true
    } catch {
      // 忽略：文件被占用时下次再删。
    }
  }
  return { ok: true, removedTask, removedLauncher }
}

export async function startupStatus() {
  if (process.platform !== 'win32') return { supported: false, installed: false }
  try {
    const { stdout } = await execFileAsync(
      'schtasks.exe',
      ['/Query', '/TN', TASK_NAME, '/V', '/FO', 'LIST'],
      { windowsHide: true, timeout: 20_000 },
    )
    const state = /Status:\s+(\S+)/i.exec(stdout)?.[1]
    return { supported: true, installed: true, state }
  } catch {
    return { supported: true, installed: false }
  }
}
