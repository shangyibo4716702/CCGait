import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join, relative, sep } from 'node:path'
import { promisify } from 'node:util'
import { PROJECT_ROOT } from '../config.js'
import { writeIconFiles } from './icon.js'

/**
 * 打包 Windows 安装包：编译客户端 exe → 生成内嵌载荷 → 编译安装程序。
 *
 * 不引入任何外部工具链：编译器用 .NET Framework 自带的 csc.exe（Windows 10/11 都有）。
 * 载荷用自定义文本格式（`##FILE <相对路径>` + 一行 base64）内嵌进安装程序，这样
 * 安装程序不需要 JSON 解析库，也不需要解压库。
 *
 * 中文源码必须带 UTF-8 BOM 再交给 csc：否则 csc 按系统 ANSI 代码页（本机是 1252）
 * 读源码，界面里的中文会变成乱码 —— 与快捷方式那次是同一类编码坑。
 */

const execFileAsync = promisify(execFile)

const CSC_CANDIDATES = [
  'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe',
  'C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\csc.exe',
]

export const CLIENT_EXE_NAME = 'CCGaitClient.exe'

export function resolveCsc() {
  for (const candidate of CSC_CANDIDATES) {
    if (existsSync(candidate)) return candidate
  }
  return undefined
}

/** 需要打进安装包的运行时文件（源码 + 示例配置 + 文档）。 */
export function collectPayloadSources(rootDir = PROJECT_ROOT) {
  const files = []
  const skipDirs = new Set(['node_modules', 'dist', '.ccgait', 'tests', 'native', 'release'])

  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.name.startsWith('.')) continue
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        if (skipDirs.has(entry.name)) continue
        walk(full)
        continue
      }
      if (/\.(js|ps1|cjs|mjs|json|md)$/i.test(entry.name)) files.push(full)
    }
  }
  walk(join(rootDir, 'src'))
  for (const name of ['package.json', 'config.example.json', 'README.md', '.gitignore']) {
    const full = join(rootDir, name)
    if (existsSync(full)) files.push(full)
  }
  return files
}

/** 自定义载荷格式：`##FILE <相对路径>` 后跟一行 base64。 */
export function buildPayload(entries) {
  const lines = []
  for (const entry of entries) {
    const content = readFileSync(entry.absolute)
    lines.push(`##FILE ${entry.relative.replace(/\\/g, '/')}`)
    lines.push(content.toString('base64'))
  }
  return `${lines.join('\n')}\n`
}

/** 写入带 BOM 的 UTF-8 源码（csc 需要 BOM 才能正确解析中文）。 */
function writeSourceWithBom(sourcePath, targetPath) {
  const text = readFileSync(sourcePath, 'utf8')
  writeFileSync(targetPath, String.fromCharCode(0xfeff) + text, 'utf8')
}

async function compile({ csc, target, output, sources, resources = [], icon, references = [] }) {
  const args = [
    '/nologo',
    '/utf8output',
    `/target:${target}`,
    '/platform:anycpu',
    '/optimize+',
    `/out:${output}`,
    ...(icon ? [`/win32icon:${icon}`] : []),
    ...references.map((item) => `/reference:${item}`),
    ...resources.map((item) => `/resource:${item}`),
    ...sources,
  ]
  try {
    const { stdout, stderr } = await execFileAsync(csc, args, {
      windowsHide: true,
      timeout: 180_000,
      maxBuffer: 16 * 1024 * 1024,
    })
    return { ok: true, output: `${stdout}${stderr}`.trim() }
  } catch (error) {
    const message = [
      error instanceof Error ? error.message : String(error),
      error?.stdout ? String(error.stdout) : '',
      error?.stderr ? String(error.stderr) : '',
    ]
      .filter(Boolean)
      .join('\n')
    return { ok: false, output: message }
  }
}

/**
 * 构建安装包。返回 { ok, setupExe, clientExe, distDir, sizeBytes, log }。
 */
export async function buildInstaller({ rootDir = PROJECT_ROOT, distDir } = {}) {
  const csc = resolveCsc()
  if (!csc) {
    return { ok: false, error: '未找到 csc.exe（.NET Framework 编译器），无法编译 Windows 可执行文件' }
  }

  const dist = distDir ?? join(rootDir, 'dist')
  const buildDir = join(dist, 'build')
  rmSync(buildDir, { recursive: true, force: true })
  mkdirSync(buildDir, { recursive: true })

  const log = []
  const icons = writeIconFiles(buildDir)
  log.push(`图标：${icons.ico}`)

  // 1) 客户端 exe：源码经 BOM 处理后再编译。
  const clientSource = join(rootDir, 'src', 'win', 'native', CLIENT_EXE_NAME.replace('.exe', '.cs'))
  const clientSourceCopy = join(buildDir, 'CCGaitClient.cs')
  writeSourceWithBom(clientSource, clientSourceCopy)
  const clientExe = join(dist, CLIENT_EXE_NAME)
  const clientResult = await compile({
    csc,
    target: 'winexe',
    output: clientExe,
    sources: [clientSourceCopy],
    icon: icons.ico,
    references: ['System.dll', 'System.Drawing.dll', 'System.Windows.Forms.dll'],
  })
  if (!clientResult.ok) {
    return { ok: false, error: `客户端编译失败：\n${clientResult.output}`, log }
  }
  log.push(`客户端：${clientExe}（${Math.round(statSync(clientExe).size / 1024)} KB）`)

  // 2) 载荷：运行时源码 + 刚编译的客户端 + 图标。
  const entries = collectPayloadSources(rootDir).map((absolute) => ({
    absolute,
    relative: relative(rootDir, absolute),
  }))
  for (const extra of [
    { absolute: clientExe, relative: CLIENT_EXE_NAME },
    { absolute: icons.ico, relative: join('.ccgait', 'ccgait.ico').replace(/\\/g, '/') },
    { absolute: icons.png, relative: join('.ccgait', 'ccgait.png').replace(/\\/g, '/') },
  ]) {
    entries.push({ absolute: extra.absolute, relative: extra.relative.split(sep).join('/') })
  }
  const payload = buildPayload(entries)
  const payloadPath = join(buildDir, 'payload.txt')
  writeFileSync(payloadPath, payload, 'utf8')
  log.push(`载荷：${entries.length} 个文件 / ${Math.round(Buffer.byteLength(payload) / 1024)} KB`)

  // 3) 安装程序：把载荷与图标一起内嵌。
  const setupSource = join(rootDir, 'src', 'win', 'native', 'CCGaitSetup.cs')
  const setupSourceCopy = join(buildDir, 'CCGaitSetup.cs')
  writeSourceWithBom(setupSource, setupSourceCopy)
  const setupExe = join(dist, 'CCGaitSetup.exe')
  const setupResult = await compile({
    csc,
    target: 'winexe',
    output: setupExe,
    sources: [setupSourceCopy],
    icon: icons.ico,
    resources: [`${payloadPath},CcgaitPayload`],
    references: ['System.dll', 'System.Drawing.dll', 'System.Windows.Forms.dll'],
  })
  if (!setupResult.ok) {
    return { ok: false, error: `安装程序编译失败：\n${setupResult.output}`, log }
  }
  log.push(`安装程序：${setupExe}（${Math.round(statSync(setupExe).size / 1024)} KB）`)

  return {
    ok: true,
    setupExe,
    clientExe,
    distDir: dist,
    sizeBytes: statSync(setupExe).size,
    log,
  }
}
