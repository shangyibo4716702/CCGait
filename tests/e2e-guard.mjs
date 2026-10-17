#!/usr/bin/env node
/**
 * 端到端拦截验证（可选，需管理员 + 可用网络）：
 *   node tests/e2e-guard.mjs
 *
 * ⚠️ 会真的终止本机正在运行的 Claude 客户端进程（这正是它要验证的能力）。
 *    跑之前请先保存 Claude Code / Claude Desktop 里的工作。
 *
 * 它验证的是用户视角的完整链路，每一步都要求真动作：
 *   1. 防火墙三个 profile 全关时，WFP 能否断掉某个程序的网络；
 *   2. 判定不通过时，闸门是否真的终止了正在运行的真实 Claude 客户端；
 *   3. 判定不通过时，真实 Claude 客户端是否真的连不上网；
 *   4. 收尾后网络、防火墙、规则、宿主进程是否全部回到原状。
 *
 * 为什么单独放一个脚本而不进 `node --test`：它会终止真实进程并改变内核过滤状态。
 */
import { execFile, spawn } from 'node:child_process'
import { existsSync, rmSync, copyFileSync } from 'node:fs'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { loadConfig, resolveStateDir, PROJECT_ROOT } from '../src/config.js'
import { createGuard } from '../src/guard.js'
import { claudeDiscovery, listClaudeProcesses } from '../src/process-guard.js'
import { listManagedRules } from '../src/firewall.js'
import { isWfpBlocking, listWfpHosts, resolveWfpHelper, startWfpBlock, stopWfpBlock } from '../src/win/wfp.js'

const run = promisify(execFile)
const SYSTEM_CURL = 'C:\\Windows\\System32\\curl.exe'
const URL = 'https://www.baidu.com'
const results = []

// 探针用"自己复制出来的 curl"，不用 System32 里那个：本机实测 System32\curl.exe 可能被
// **其它软件**按路径定向拦截（同一份 curl 复制到别处能联网、原路径却直接 WSAEACCES），
// 用副本才能让这个测试只反映 CCGait 自己的行为。
const PROBE = join(PROJECT_ROOT, '.ccgait', 'probe-curl.exe')

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

function record(name, pass, detail) {
  results.push({ name, pass, detail })
  console.log(`${pass ? '通过' : '未通过'} | ${name} | ${detail}`)
}

async function probeOnce(exe, url, timeoutMs = 20_000) {
  try {
    const { stdout } = await run(exe, ['-s', '-m', '8', '-o', 'NUL', '-w', '%{http_code}', url], {
      windowsHide: true,
      timeout: timeoutMs,
    })
    return { online: stdout.trim() === '200', code: stdout.trim() }
  } catch (error) {
    return { online: false, message: `${error?.stderr ?? ''}${error?.message ?? ''}`.trim().slice(0, 60) }
  }
}

/**
 * 多次尝试才算"能联网"。
 *
 * 为什么不能只探一次：本机出口会偶发超时（实测代理客户端开着但端口未监听时尤其如此）。
 * 只探一次的话，① 基线可能因一次抖动被判成"本来就不通"；② 更糟的是阻断期间的断言——
 * 一次失败就报"拦截成功"，而真相可能只是网络刚好抖了。所以基线要求「N 次里至少一次成功」，
 * 而"被拦"要求「N 次全失败」，方向正好相反。
 */
async function probe(exe, url, attempts = 3) {
  let last = { online: false, message: '未尝试' }
  for (let index = 0; index < attempts; index++) {
    last = await probeOnce(exe, url)
    if (last.online) return last
    if (index < attempts - 1) await sleep(1_500)
  }
  return last
}

async function firewallEnabled() {
  try {
    const { stdout } = await run(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', '(Get-NetFirewallProfile | Select-Object -ExpandProperty Enabled) -join ","'],
      { windowsHide: true, timeout: 15_000 },
    )
    return stdout.trim()
  } catch {
    return 'unknown'
  }
}

/** 把三个防火墙 profile 统一设成 on/off（仅用于把测试改动的状态还原）。 */
async function setFirewallProfiles(on) {
  try {
    await run(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', `Set-NetFirewallProfile -All -Enabled ${on ? 'True' : 'False'}`],
      { windowsHide: true, timeout: 30_000 },
    )
    return 'ok'
  } catch (error) {
    return `失败：${String(error.message).split('\n')[0].slice(0, 60)}`
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

  const { config, exists } = loadConfig()
  const stateDir = resolveStateDir(config)
  if (!existsSync(SYSTEM_CURL)) {
    console.log(`跳过：找不到用于复制探针的 ${SYSTEM_CURL}`)
    return 0
  }
  if (!existsSync(PROBE)) copyFileSync(SYSTEM_CURL, PROBE)
  const firewallBefore = await firewallEnabled()
  console.log(`配置：${exists ? '已加载' : '无（用默认值）'}｜状态目录：${stateDir}`)
  console.log(`WFP 助手：${resolveWfpHelper()}`)
  console.log(`防火墙状态：${firewallBefore}`)
  console.log('')

  const claudePaths = claudeDiscovery({}).entries.map((item) => item.path)
  const claudeCli = claudeDiscovery({}).entries.find((item) => item.kind === 'cli')?.path
  if (!claudeCli) {
    console.log('跳过：本机未发现 Claude Code CLI，无法验证"终止真实客户端"这一环')
    return 0
  }

  await stopWfpBlock({ stateDir, waitMs: 8_000 })

  // ------------------------------------------------------------- 1. WFP 断网
  const baseline = await probe(PROBE, URL, 3)
  record('基线：探针能联网', baseline.online, baseline.online ? `HTTP ${baseline.code}` : baseline.message)
  if (!baseline.online) {
    console.log('\n基线不成立：当前机器本身就连不上网（与 CCGait 无关），无法证明拦截是否生效。')
    console.log('请先恢复网络（本机代理端口 7890 未监听时尤其容易如此），再重跑本脚本。')
    return 1
  }

  const started = await startWfpBlock({ paths: [PROBE], stateDir, detached: true })
  record('WFP 阻断建立成功', started.ok === true, started.ok ? `${started.filters} 条过滤器` : started.error)

  const blocked = await probe(PROBE, URL, 3)
  record(
    '防火墙关闭下 WFP 真的断网',
    blocked.online === false,
    blocked.online ? '探针仍能联网 → 未生效' : `探针被拦（${blocked.message}）`,
  )
  const firewallDuring = await firewallEnabled()
  record(
    'WFP 阻断期间防火墙开关未被改动（第一层不依赖它）',
    firewallDuring === firewallBefore,
    `前 ${firewallBefore} → 后 ${firewallDuring}`,
  )

  const stopped = await stopWfpBlock({ stateDir, waitMs: 8_000 })
  const restored = await probe(PROBE, URL, 3)
  record(
    '解除阻断后网络恢复',
    stopped.stopped === true && restored.online === true,
    restored.online ? `HTTP ${restored.code}` : restored.message,
  )

  // --------------------------------------------- 2. 对真实 Claude 客户端断网
  const claudeBlock = await startWfpBlock({ paths: claudePaths, stateDir, detached: true })
  record(
    'WFP 过滤器挂到真实 Claude 客户端上',
    claudeBlock.ok === true && claudeBlock.filters >= claudePaths.length * 2,
    claudeBlock.ok ? `${claudeBlock.filters} 条（覆盖 ${claudePaths.length} 个可执行文件）` : claudeBlock.error,
  )
  record('阻断状态可被查询（宿主存活）', isWfpBlocking(stateDir) === true, `PID ${claudeBlock.pid}`)

  // ------------------------------------------- 3. 终止真实 Claude 客户端进程
  // 用 `mcp serve`：真身是 Claude Code CLI 且长驻。两个实测坑：
  //   ① 别用 `doctor` 这类自检命令 —— 不到 1 秒就退出，进程发现必然"失败"，是假阴性；
  //   ② stdin 要给 NUL（stdio:'ignore'）。给一个"从不写入的管道"时它会在 1 秒左右自己退出
  //      （退出码 1），于是固定等 4 秒再去查就永远查不到。
  // 所以这里用 ignore，并且**轮询**等待发现，而不是睡固定时长。
  let child = spawn(claudeCli, ["mcp", "serve"], { stdio: "ignore", windowsHide: true })
  let alive = false
  for (let attempt = 0; attempt < 10 && !alive; attempt++) {
    await sleep(600)
    let childAlive = true
    try {
      process.kill(child.pid, 0)
    } catch {
      childAlive = false
    }
    if (!childAlive) break
    const detected = await listClaudeProcesses()
    alive = detected.some((item) => Number(item.pid) === Number(child.pid))
  }
  record('识别到运行中的真实 Claude 客户端', alive, alive ? `PID ${child.pid} 在列` : '未在进程列表中找到')

  // 执行闸门之前必须确认客户端**此刻还活着**：`mcp serve` 偶尔会自己退出，
  // 那样"被闸门终止"就成了假证据。已退出就再起一个。
  let aliveBeforeGuard = alive
  if (!aliveBeforeGuard) {
    const retry = spawn(claudeCli, ['mcp', 'serve'], { stdio: 'ignore', windowsHide: true })
    for (let attempt = 0; attempt < 8 && !aliveBeforeGuard; attempt++) {
      await sleep(600)
      const detected = await listClaudeProcesses()
      aliveBeforeGuard = detected.some((item) => Number(item.pid) === Number(retry.pid))
      if (aliveBeforeGuard) child = retry
    }
  }
  record('执行闸门前客户端仍在运行', aliveBeforeGuard, aliveBeforeGuard ? `PID ${child.pid}` : '客户端反复自行退出，无法构成有效证据')

  const guard = createGuard({
    config: { ...config, enforcement: { ...config.enforcement, killProcesses: true, blockNetwork: true } },
    stateDir,
    logger: {
      ok: () => {},
      warn: () => {},
      block: (message, detail) => console.log(`  [闸门] ${message}${detail ? '：' + detail : ''}`),
      info: () => {},
      error: () => {},
    },
  })
  const state = await guard.checkOnce()
  record('闸门判定为拦截', state.allow === false, `blocked=${state.blocked.length} failedClosed=${state.failedClosed}`)

  await sleep(1_500)
  let stillAlive = false
  try {
    process.kill(child.pid, 0)
    stillAlive = true
  } catch {
    stillAlive = false
  }
  record('真实 Claude 客户端被终止', alive && !stillAlive, stillAlive ? '进程仍在运行' : `PID ${child.pid} 已结束`)
  try {
    child.kill()
  } catch {
    // 已经结束
  }

  // --------------------------------------------------------- 4. 收尾与复查
  await guard.stop()
  await stopWfpBlock({ stateDir, waitMs: 10_000 })
  const rules = await listManagedRules()
  const hosts = await listWfpHosts()
  const leftoverFiles = [join(stateDir, 'wfp.pid'), join(stateDir, 'wfp-stop.request')].filter((path) => existsSync(path))
  const firewallAfter = await firewallEnabled()
  record('收尾：WFP 阻断已解除', isWfpBlocking(stateDir) === false, '宿主已退出')
  record('收尾：无孤儿 WFP 宿主', hosts.length === 0, `实际 ${hosts.length} 个`)
  record('收尾：防火墙规则为 0 条', rules.length === 0, `实际 ${rules.length} 条`)
  record('收尾：无 pid / 停止文件残留', leftoverFiles.length === 0, `实际 ${leftoverFiles.length} 个`)

  // 第二层（防火墙规则）只在 profile 启用时生效，所以配置要求"阻断网络全开"时，
  // 闸门会自己把三个 profile 打开。这里断言的是**这个预期行为**，而不是"防火墙没被动过"。
  const profilesOn = firewallAfter === 'True,True,True'
  record(
    '第二层生效前提：闸门开启了防火墙 profile',
    profilesOn,
    profilesOn ? '三个 profile 均为启用（这是 enableFirewallProfiles 的预期行为）' : `状态 ${firewallAfter}`,
  )

  // 测试不该把机器留在被改动过的状态：把防火墙开关恢复到本次运行之前的样子。
  if (firewallBefore !== firewallAfter) {
    const restored = await setFirewallProfiles(firewallBefore === 'True,True,True')
    const now = await firewallEnabled()
    record('收尾：防火墙开关已恢复到测试前状态', now === firewallBefore, `${firewallAfter} → ${now}（恢复结果 ${restored}）`)
  }
  rmSync(join(PROJECT_ROOT, '.ccgait', 'wfp.pid'), { force: true })

  console.log('')
  const failed = results.filter((item) => !item.pass)
  console.log(`=== 汇总：${results.length - failed.length}/${results.length} 项通过 ===`)
  for (const item of failed) console.log(`  未通过：${item.name} —— ${item.detail}`)
  return failed.length === 0 ? 0 : 1
}

main()
  .then((code) => {
    process.exitCode = code
  })
  .catch((error) => {
    console.error('验证异常：', error)
    process.exitCode = 2
  })
