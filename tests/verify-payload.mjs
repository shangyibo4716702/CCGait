#!/usr/bin/env node
/**
 * 安装包完整性检查（无需管理员）：
 *   node tests/verify-payload.mjs
 *
 * 为什么需要它：`dist/build/payload.txt` 里文件内容是 **base64** 的，所以"用 grep 在载荷里
 * 搜源码字符串"本身查不到东西（看起来像"缺失"，其实是查法错了）。这个脚本解码后再核对，
 * 用来防一类很容易发生的事故：改了源码但忘了重新打包，装出来的还是旧版本。
 *
 * 检查三类东西：
 *   1. JS 源码 → 解码后按文本核对关键实现；
 *   2. C# 客户端 / WFP 助手 → 核对**编译后的 exe**（.NET 字符串是 UTF-16，要按 UTF-16 搜）；
 *      .cs 源文件本来就不进载荷，它们被编进 exe 了。
 *   3. README → 核对文档里的关键说明。
 */
import { existsSync, readFileSync } from 'node:fs'

const payloadPath = new URL('../dist/build/payload.txt', import.meta.url)
if (!existsSync(payloadPath)) {
  console.log('跳过：没有 dist/build/payload.txt（先执行 node src/cli.js build-installer）')
  process.exit(0)
}

const raw = readFileSync(payloadPath, 'utf8')
const files = new Map()
let current = null
let buffer = []
const flush = () => {
  if (current) files.set(current, Buffer.from(buffer.join(''), 'base64'))
  buffer = []
}
for (const line of raw.split(/\r?\n/)) {
  if (line.startsWith('##FILE ')) {
    flush()
    current = line.slice(7).trim()
    continue
  }
  if (current && line.trim()) buffer.push(line.trim())
}
flush()

const textHas = (name, needle) => Boolean(files.get(name)?.toString('utf8').includes(needle))
const binaryHas = (name, needle) => {
  const data = files.get(name)
  if (!data) return false
  // .NET 字符串字面量是 UTF-16LE；中文与 ASCII 都按 UTF-16 查。
  return data.includes(Buffer.from(needle, 'utf16le'))
}

const checks = [
  ['src/firewall.js', 'normalizeProfileEnabled', '防火墙状态读数修复（GpoBoolean 被序列化成 1）'],
  ['src/config.js', 'enableFirewallProfiles', '第二层防火墙规则自动开启 profile'],
  ['src/config.js', 'emojiFlags', 'Emoji 国旗渲染检查项'],
  ['src/providers.js', 'proxyFallback', '代理连不上时回退直连'],
  ['src/guard.js', '已开启 Windows 防火墙配置文件', '闸门开启防火墙 profile'],
  ['src/guard.js', '已处理 ', '进程处理日志（不再报"已终止 0 个"）'],
  ['src/verdict.js', 'emoji-flags-suspect', 'Emoji 判定规则'],
  ['src/environment.js', 'probeEmojiFont', 'Emoji 字体资产探测'],
  ['src/win/wfp.js', 'purgeWfpFilters', '遗留过滤器清理'],
  ['src/ui/public/app.js', '白名单比对', '界面：白名单逐项命中'],
  ['src/ui/public/app.js', 'tag-detail', '界面：每行状态标签'],
  ['src/ui/public/app.js', 'proxyFallback', '界面：代理回退说明'],
  ['README.md', '不拦截、不门控', '文档：环境项只提示'],
  ['README.md', 'Emoji 国旗渲染', '文档：Emoji 检查项'],
]

const binaryChecks = [
  ['CCGaitClient.exe', '启动托盘时自动开闸门', '托盘启动即开闸门'],
  ['CCGaitClient.exe', 'AutoStartGuard', '自动开闸门开关'],
  ['CCGaitWfp.exe', 'PURGED', 'purge 模式'],
  ['CCGaitWfp.exe', '--stop-file', '宿主常驻与停止信号'],
  ['CCGaitWfp.exe', 'list-filters', '过滤器自检'],
]

console.log(`载荷文件数：${files.size}\n`)
let missing = 0
for (const [file, needle, why] of checks) {
  const ok = textHas(file, needle)
  if (!ok) missing++
  console.log(`  ${ok ? '有' : '缺'}  ${file} ← ${needle}　（${why}）`)
}

console.log('\n编译产物（.cs 源不进载荷，功能在 exe 里）：')
for (const [file, needle, why] of binaryChecks) {
  const ok = binaryHas(file, needle)
  if (!ok) missing++
  console.log(`  ${ok ? '有' : '缺'}  ${file} ← ${needle}　（${why}）`)
}

console.log(`\n结论：${missing === 0 ? '载荷与编译产物均包含全部关键修复' : `有 ${missing} 项缺失 —— 很可能改了源码但没重新打包`}`)
process.exitCode = missing === 0 ? 0 : 1
