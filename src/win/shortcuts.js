import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { PROJECT_ROOT } from '../config.js'

/**
 * 编码坑（踩过）：Windows PowerShell 5.1 用 `-Command` 传脚本时按控制台代码页
 * （中文系统是 GBK）解析，脚本里任何非 ASCII 字符（含快捷方式名里的中文）都会被
 * 破坏 —— `$sc.Save()` 不报错、脚本继续输出成功，结果文件压根没生成。
 * 所以这里改成：把脚本写成带 UTF-8 BOM 的 .ps1 文件，用 `-File` 执行，
 * 并且**回查文件是否真的存在**，绝不把没落盘当成成功。
 */

/**
 * 开始菜单 / 桌面快捷方式。
 *
 * 快捷方式指向一个隐藏窗口的 VBS 启动器（不弹黑框），启动器再执行
 * `ccgait desktop` —— 所以双击快捷方式的效果是：拉起后台服务 + 打开应用窗口。
 * 卸载时按自己的名字删除，不碰用户其它快捷方式。
 */

const execFileAsync = promisify(execFile)

/**
 * 快捷方式名必须是纯 ASCII。
 *
 * 实测坑：WScript.Shell 是遗留 ANSI COM 组件，在非中文 ANSI 代码页（本机 ACP=1252）
 * 上创建含中文的 .lnk 会失败（中文被转成 ?，Save() 抛 FileNotFoundException）。
 * 所以名字与描述保持 ASCII，中文只出现在应用自己的界面里（那是 Unicode，不受影响）。
 */
export const SHORTCUT_NAME = 'CCGait.lnk'
export const DESKTOP_SHORTCUT_NAME = 'CCGait.lnk'

export function launcherPath(stateDir, name) {
  return join(stateDir, `${name}.vbs`)
}

/** 生成隐藏窗口启动器（内容可读，卸载时删除）。 */
export function writeLauncher(stateDir, name, args) {
  mkdirSync(stateDir, { recursive: true })
  const path = launcherPath(stateDir, name)
  const nodePath = process.execPath
  const cliPath = join(PROJECT_ROOT, 'src', 'cli.js')
  const command = [nodePath, cliPath, ...args]
    .map((part) => `""${part}""`)
    .join(' ')
  const script = [
    "' 由 CCGait 生成：以隐藏窗口执行命令。",
    'Set shell = CreateObject("WScript.Shell")',
    `shell.Run "${command}", 0, False`,
    '',
  ].join('\r\n')
  writeFileSync(path, script, 'utf8')
  return path
}

function startMenuDir() {
  const appData = process.env.APPDATA ?? ''
  return join(appData, 'Microsoft', 'Windows', 'Start Menu', 'Programs')
}

function desktopDir() {
  const profile = process.env.USERPROFILE ?? ''
  return join(profile, 'Desktop')
}

/** 快捷方式的目标必须是完整路径：只写 'wscript.exe' 会在 Save() 时抛
 * FileNotFoundException（WScript.Shell 不做 PATH 解析）。 */
export function scriptHostPath(env = process.env) {
  const systemRoot = env.SystemRoot ?? 'C:\Windows'
  return join(systemRoot, 'System32', 'wscript.exe')
}

function psQuote(value) {
  return `'${String(value).replace(/'/g, "''")}'`
}

async function createShortcut({ linkPath, launcher, iconPath, workingDirectory, scriptDir }) {
  const script = [
    '$ErrorActionPreference = "Stop"',
    '$ws = New-Object -ComObject WScript.Shell',
    `$sc = $ws.CreateShortcut(${psQuote(linkPath)})`,
    `$sc.TargetPath = ${psQuote(scriptHostPath())}`,
    `$sc.Arguments = '"' + ${psQuote(launcher)} + '"'`,
    `$sc.WorkingDirectory = ${psQuote(workingDirectory)}`,
    `$sc.IconLocation = ${psQuote(`${iconPath},0`)}`,
    "$sc.Description = 'CCGait - Claude client environment gate'",
    '$sc.Save()',
    'if (Test-Path -LiteralPath ' + psQuote(linkPath) + ') { "OK" } else { "MISSING" }',
    '',
  ].join(String.fromCharCode(13, 10))
  mkdirSync(scriptDir, { recursive: true })
  const scriptPath = join(scriptDir, 'create-shortcut.ps1')
  // UTF-8 BOM：让 PowerShell 5.1 正确识别中文路径，而不是按 GBK 乱解。
  writeFileSync(scriptPath, String.fromCharCode(0xfeff) + script, 'utf8')
  const { stdout } = await execFileAsync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', scriptPath],
    { windowsHide: true, timeout: 20_000 },
  )
  // 双重确认：脚本自报 + 文件确实存在。
  return stdout.includes('OK') && existsSync(linkPath)
}

/**
 * 安装快捷方式。
 * options: { stateDir, iconPath, alsoDesktop }
 */
export async function installShortcuts({ stateDir, iconPath, alsoDesktop = false }) {
  if (process.platform !== 'win32') return { ok: false, error: '仅支持 Windows' }

  const launcher = writeLauncher(stateDir, 'ccgait-desktop', ['desktop'])
  const created = []

  const targets = [{ path: join(startMenuDir(), SHORTCUT_NAME), label: '开始菜单' }]
  if (alsoDesktop) targets.push({ path: join(desktopDir(), DESKTOP_SHORTCUT_NAME), label: '桌面' })

  for (const target of targets) {
    try {
      const ok = await createShortcut({
        linkPath: target.path,
        launcher,
        iconPath,
        workingDirectory: PROJECT_ROOT,
        scriptDir: stateDir,
      })
      if (ok) created.push({ ...target, ok: true })
      else
        return {
          ok: false,
          created,
          error: `创建${target.label}快捷方式失败：文件未生成（${target.path}）`,
        }
    } catch (error) {
      return {
        ok: false,
        created,
        error: `创建${target.label}快捷方式失败：${error instanceof Error ? error.message : String(error)}`,
      }
    }
  }
  return { ok: true, created, launcher }
}

export async function uninstallShortcuts({ stateDir }) {
  if (process.platform !== 'win32') return { ok: true, removed: [] }
  const removed = []
  for (const path of [
    join(startMenuDir(), SHORTCUT_NAME),
    join(desktopDir(), DESKTOP_SHORTCUT_NAME),
  ]) {
    if (!existsSync(path)) continue
    try {
      rmSync(path, { force: true })
      removed.push(path)
    } catch {
      // 被占用时下次再删。
    }
  }
  const launcher = launcherPath(stateDir, 'ccgait-desktop')
  if (existsSync(launcher)) {
    try {
      rmSync(launcher, { force: true })
    } catch {
      // 忽略。
    }
  }
  return { ok: true, removed }
}
