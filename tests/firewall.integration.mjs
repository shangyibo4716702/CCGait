#!/usr/bin/env node
/**
 * 防火墙集成测试（可选，需管理员权限）：
 *   node tests/firewall.integration.mjs
 *
 * 为什么单独放一个脚本而不是进 `node --test`：它会真的创建/删除系统防火墙规则，
 * 属于会改变机器状态的测试，不适合每次跑单测都执行。
 *
 * 它专门钉住一个真实踩过的坑：Windows PowerShell 5.1 下
 * `$json | ConvertFrom-Json` / `@(ConvertFrom-Json -InputObject ...)` 的数组折叠
 * 会让循环只跑一轮、规则一条都没建成，而旧实现会对外报"已阻断 N 个程序"。
 * 因此这里的断言是**回查系统真实状态**，而不是信任函数返回的 applied。
 */
import { applyBlockForPaths, isElevated, listManagedRules, removeAllBlocks } from '../src/firewall.js'

// 用系统自带程序做探针：只验证规则机制本身，不碰真实的 Claude 客户端。
const PROBES = ['C:\\Windows\\System32\\notepad.exe', 'C:\\Windows\\System32\\calc.exe']

async function main() {
  if (process.platform !== 'win32') {
    console.log('跳过：仅支持 Windows')
    return 0
  }
  if (!(await isElevated())) {
    console.log('跳过：需要管理员权限（右键 → 以管理员身份运行）')
    return 0
  }

  await removeAllBlocks() // 先清干净，保证断言可复现

  const result = await applyBlockForPaths(PROBES)
  const actual = await listManagedRules()
  const actualPrograms = actual
    .filter((rule) => rule.enabled && rule.direction === 'Outbound' && rule.action === 'Block')
    .map((rule) => rule.program)

  console.log('函数返回：', JSON.stringify(result))
  console.log('系统实际：', JSON.stringify(actualPrograms))

  const problems = []
  if (result.error) problems.push(`返回错误：${result.error}`)
  for (const path of PROBES) {
    if (!actualPrograms.includes(path)) problems.push(`系统里没有 ${path} 的阻断规则`)
  }
  if (result.verified.length !== PROBES.length) {
    problems.push(`verified 数量 ${result.verified.length} ≠ ${PROBES.length}（回查前后不一致）`)
  }

  const removal = await removeAllBlocks()
  const after = await listManagedRules()
  if (after.length !== 0) problems.push(`清理后仍残留 ${after.length} 条规则`)
  console.log('清理：', JSON.stringify(removal))

  if (problems.length > 0) {
    for (const problem of problems) console.error(`✗ ${problem}`)
    return 1
  }
  console.log('✓ 防火墙阻断：建立、回查、清理全部一致')
  return 0
}

main().then((code) => {
  process.exitCode = code
})
