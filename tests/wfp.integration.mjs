#!/usr/bin/env node
/**
 * WFP 内核拦截集成测试（可选，需管理员权限）：
 *   node tests/wfp.integration.mjs
 *
 * 为什么单独放一个脚本而不进 `node --test`：它会真的往 Windows 过滤平台里挂过滤器，
 * 属于会改变机器状态的测试，不适合每次跑单测都执行。
 *
 * 它钉住三件实测踩过的事：
 *   1. WFP 断网**不依赖 Windows 防火墙**——防火墙三个 profile 全关也照样断得掉；
 *   2. 阻断期间宿主进程必须活着（过滤器随会话消失，宿主一死阻断就没了）；
 *   3. 解除后必须恢复联网且不留宿主与文件残留，不能出现"莫名其妙上不了网"。
 *
 * 另外两件是"残留"类事故的防线：重复建立不会出现两个宿主并存；pid 文件丢了（被删、
 * 被上一轮覆盖）时 off 仍要按进程名把孤儿宿主收干净。
 *
 * 探针用系统自带的 curl，只验证机制本身，不碰真实的 Claude 客户端。
 */
import { execFile } from 'node:child_process'
import { existsSync, rmSync, copyFileSync } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { PROJECT_ROOT } from '../src/config.js'
import { isElevated } from '../src/firewall.js'
import {
  isWfpBlocking,
  purgeWfpFilters,
  listWfpHosts,
  resolveWfpHelper,
  startWfpBlock,
  stopWfpBlock,
  wfpPidPath,
  wfpStopPath,
} from '../src/win/wfp.js'

const run = promisify(execFile)
const SYSTEM_CURL = 'C:\\Windows\\System32\\curl.exe'
const URL = 'https://www.baidu.com'
const stateDir = join(PROJECT_ROOT, '.ccgait')

// 探针用"自己复制出来的 curl"，不用 System32 里那个。
// 原因（本机实测）：System32\curl.exe 可能被**其它软件**按路径定向拦截 —— 本机就出现过
// 同一个 curl 复制到别处能联网（200）、原路径却 connect 直接 WSAEACCES（Bad access），
// 而内核里既没有我们的过滤器也没有引用该路径的过滤器。用副本可以避开这类外来干扰，
// 让这个测试只反映 CCGait 自己的行为；副本本身不通时基线检查会立刻失败并说明原因。
const PROBE = join(stateDir, 'probe-curl.exe')

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function ensureProbe() {
  if (existsSync(PROBE)) return
  copyFileSync(SYSTEM_CURL, PROBE)
}

async function probeOnce() {
  try {
    const { stdout } = await run(PROBE, ['-s', '-m', '8', '-o', 'NUL', '-w', '%{http_code}', URL], {
      windowsHide: true,
      timeout: 20_000,
    })
    return stdout.trim() === '200'
  } catch {
    return false
  }
}

/**
 * 多次尝试才算"能联网"。
 *
 * 为什么不能只探一次：家用/移动网络的出口会偶发超时。只探一次的话，
 * ① 基线可能因为一次抖动而判定"本来就不通"，整个测试直接废掉；
 * ② 更糟的是阻断期间的断言——一次失败就报"拦截成功"，而真相可能只是网络刚好抖了。
 * 所以基线要求「N 次里至少一次成功」，而"被拦"要求「N 次全失败」，方向正好相反。
 */
async function probeOnline(attempts = 3) {
  for (let index = 0; index < attempts; index++) {
    if (await probeOnce()) return true
    if (index < attempts - 1) await sleep(1_500)
  }
  return false
}

async function helperCount() {
  try {
    const { stdout } = await run(
      'powershell.exe',
      ['-NoProfile', '-Command', "(Get-Process -Name CCGaitWfp -ErrorAction SilentlyContinue | Measure-Object).Count"],
      { windowsHide: true, timeout: 15_000 },
    )
    return Number(stdout.trim()) || 0
  } catch {
    return 0
  }
}

async function firewallProfiles() {
  try {
    const { stdout } = await run(
      'powershell.exe',
      ['-NoProfile', '-Command', '(Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled) -join ","'],
      { windowsHide: true, timeout: 15_000 },
    )
    return stdout.trim()
  } catch {
    return 'unknown'
  }
}

async function main() {
  if (process.platform !== 'win32') {
    console.log('跳过：仅支持 Windows')
    return 0
  }
  if (!resolveWfpHelper()) {
    console.log('跳过：未找到 CCGaitWfp.exe（先执行 node src/cli.js build-installer）')
    return 0
  }
  if (!(await isElevated())) {
    console.log('跳过：需要管理员权限（右键 → 以管理员身份运行）')
    return 0
  }
  if (!existsSync(SYSTEM_CURL)) {
    console.log(`跳过：找不到用于复制探针的 ${SYSTEM_CURL}`)
    return 0
  }
  ensureProbe()

  rmSync(wfpPidPath(stateDir), { force: true })
  rmSync(wfpStopPath(stateDir), { force: true })
  await stopWfpBlock({ stateDir, waitMs: 8_000 })

  const problems = []
  const firewallBefore = await firewallProfiles()
  const onlineBefore = await probeOnline()

  // 基线不成立就直接停：网络本身不通时，"阻断期间不通"证明不了任何事，
  // 而"解除后还不通"会被误判成"过滤器残留"——那是把网络故障栽给我们的过滤器。
  if (onlineBefore !== true) {
    console.log('基线不成立：本机当前连不上网（与 CCGait 无关），无法证明拦截是否生效。')
    console.log('请先恢复网络（本机代理端口 7890 未监听时尤其容易如此），再重跑本脚本。')
    return 1
  }

  const started = await startWfpBlock({ paths: [PROBE], stateDir, detached: true })
  await sleep(1_500)
  // 被拦的判定要求 3 次全失败，避免把一次网络抖动误判成拦截成功。
  const offlineDuring = !(await probeOnline(3))
  const aliveDuring = (await helperCount()) >= 1
  const firewallDuring = await firewallProfiles()

  const stopped = await stopWfpBlock({ stateDir, waitMs: 10_000 })
  await sleep(1_500)
  const onlineAfter = await probeOnline()
  const aliveAfter = await helperCount()
  const leftovers = [wfpPidPath(stateDir), wfpStopPath(stateDir)].filter((path) => existsSync(path))

  // 残留防线一：重复建立不该出现两个宿主并存。
  const restarted = await startWfpBlock({ paths: [PROBE], stateDir, detached: true })
  await sleep(1_000)
  const hostsWhileBlocking = (await listWfpHosts()).length
  const second = await startWfpBlock({ paths: [PROBE], stateDir, detached: true })
  await sleep(1_000)
  const hostsAfterSecond = (await listWfpHosts()).length

  // 残留防线二：pid 文件丢了，off 仍要按进程名把孤儿收掉。
  rmSync(wfpPidPath(stateDir), { force: true })
  const orphanStop = await stopWfpBlock({ stateDir, waitMs: 10_000 })
  await sleep(1_000)
  const hostsAfterOrphan = (await listWfpHosts()).length

  // 假成功防线：一个过滤器都没建上时必须报失败，不能回 ok=true 让上层打印"已断网"。
  // 用不存在的可执行文件路径触发（助手会打印 SKIP 并 READY 0）。
  const nothingBlocked = await startWfpBlock({
    paths: ['C:\\CCGait-does-not-exist\\nothing.exe'],
    stateDir,
    detached: true,
  })
  await sleep(1_000)
  const hostsAfterNothing = (await listWfpHosts()).length

  // 泄漏防线（本机真出过事故）：宿主被**硬杀**时过滤器必须自动消失。
  // 早期版本没用动态会话，硬杀后过滤器永久留在内核里：本机因此留下 30 条，
  // 覆盖 15 个可执行文件（含 System32\curl.exe），表现为"某个程序莫名其妙上不了网"，
  // 而进程列表里看不到任何宿主。这里用硬杀复现并断言网络立刻恢复。
  await stopWfpBlock({ stateDir, waitMs: 8_000 })
  const leakBlock = await startWfpBlock({ paths: [PROBE], stateDir, detached: true })
  await sleep(1_500)
  const blockedBeforeKill = !(await probeOnline(2))
  for (const hostPid of await listWfpHosts()) {
    try {
      process.kill(hostPid)
    } catch {
      // 忽略
    }
  }
  await sleep(2_500)
  const onlineAfterKill = await probeOnline(3)
  const leakedAfterKill = await purgeWfpFilters()

  console.log(`防火墙状态：前 ${firewallBefore} → 阻断中 ${firewallDuring}`)
  console.log(`探针联网：前 ${onlineBefore ? '在线' : '离线'} → 阻断中 ${offlineDuring ? '离线' : '在线'} → 解除后 ${onlineAfter ? '在线' : '离线'}`)
  console.log(`WFP 宿主：阻断中 ${aliveDuring ? '存活' : '已死'} → 解除后 ${aliveAfter} 个残留`)
  console.log(`建立结果：${JSON.stringify({ ok: started.ok, filters: started.filters, pid: started.pid })}`)
  console.log(`解除结果：${JSON.stringify(stopped)}`)
  console.log(`重复建立：宿主 ${hostsWhileBlocking} → ${hostsAfterSecond}（第二次 ${second.alreadyRunning ? '复用' : '新建'}）`)
  console.log(`孤儿清理：${JSON.stringify(orphanStop)} → 剩余宿主 ${hostsAfterOrphan}`)
  console.log(`空目标：ok=${nothingBlocked.ok} filters=${nothingBlocked.filters} 错误=${JSON.stringify(nothingBlocked.error ?? '')}`)
  console.log(`空目标后宿主数：${hostsAfterNothing}`)
  console.log(`硬杀泄漏：阻断中=${blockedBeforeKill ? '离线' : '在线'} → 硬杀后=${onlineAfterKill ? '在线' : '仍离线'}，事后 purge 发现遗留 ${leakedAfterKill.removed} 条`)

  if (!started.ok || !started.filters) problems.push('未能建立任何 WFP 过滤器')
  if (offlineDuring !== true) problems.push('阻断期间探针仍能联网 → 过滤器未生效')
  if (aliveDuring !== true) problems.push('阻断期间宿主进程已退出 → 过滤器随之消失，拦截不可靠')
  if (onlineAfter !== true) problems.push('解除后未恢复联网 → 有过滤器残留')
  if (aliveAfter !== 0) problems.push(`解除后仍有 ${aliveAfter} 个 WFP 宿主进程`)
  if (leftovers.length > 0) problems.push(`残留文件：${leftovers.join('、')}`)
  if (firewallDuring !== firewallBefore) problems.push('测试改动了 Windows 防火墙状态')
  if (!restarted.ok || hostsWhileBlocking !== 1) problems.push(`阻断期间宿主数应为 1，实际 ${hostsWhileBlocking}`)
  if (hostsAfterSecond !== 1) problems.push(`重复建立后宿主数应仍为 1，实际 ${hostsAfterSecond}（两个宿主并存会让 off 漏掉一个）`)
  if (hostsAfterOrphan !== 0) problems.push(`pid 文件缺失时 off 未收干净，仍有 ${hostsAfterOrphan} 个孤儿宿主`)
  if (nothingBlocked.ok !== false) problems.push('没有任何过滤器建立时仍返回成功 → 上层会误报"已断网"')
  if (hostsAfterNothing !== 0) problems.push(`空目标尝试后仍留下 ${hostsAfterNothing} 个宿主进程`)
  if (!leakBlock.ok) problems.push('硬杀泄漏检查的阻断没能建立')
  if (blockedBeforeKill !== true) problems.push('硬杀泄漏检查的前置条件不成立：阻断期间探针仍在线')
  if (onlineAfterKill !== true) problems.push('硬杀宿主后探针仍上不了网 → 过滤器泄漏在内核里（早期版本的严重缺陷）')
  if (leakedAfterKill.removed !== 0) problems.push(`硬杀后仍残留 ${leakedAfterKill.removed} 条过滤器`)

  if (problems.length > 0) {
    console.log('\n未通过：')
    for (const problem of problems) console.log(`  - ${problem}`)
    return 1
  }
  console.log('\n全部通过：WFP 断网不依赖防火墙，阻断期间宿主存活，解除后网络与文件状态完全恢复。')
  return 0
}

main()
  .then((code) => {
    process.exitCode = code
  })
  .catch((error) => {
    console.error('验证异常：', error)
    process.exitCode = 2
  })
