import { execFile } from 'node:child_process'
import { promisify } from 'node:util'

/**
 * 网络阻断层：用 Windows 防火墙给 Claude 客户端加"按程序阻断出站"的规则。
 *
 * 为什么用防火墙而不是 hosts/代理：hosts 只能挡域名且对 IP 直连无效；改系统代理会
 * 影响整机。按程序出站阻断是唯一既精准又可逆的做法 —— 规则名统一带前缀，卸载时按
 * 前缀一次性清除，不会碰用户自己的任何规则。
 *
 * 权限：创建/删除防火墙规则需要管理员。非管理员时这里返回明确错误，由上层降级为
 * "只终止进程"，绝不假装已经阻断。
 */

export const RULE_PREFIX = 'CCGait :: block :: '

const execFileAsync = promisify(execFile)

async function runPowerShell(script, timeoutMs = 30_000) {
  const { stdout } = await execFileAsync(
    'powershell.exe',
    ['-NoProfile', '-NonInteractive', '-Command', script],
    { windowsHide: true, timeout: timeoutMs, maxBuffer: 8 * 1024 * 1024 },
  )
  return stdout.trim()
}

/** 把任意字符串安全地送进 PowerShell（base64 → UTF8 解码，避免引号/路径转义问题）。 */
function encodePayload(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64')
}

export function firewallSupported() {
  return process.platform === 'win32'
}

/** 当前进程是否有管理员权限。 */
export async function isElevated() {
  if (!firewallSupported()) return false
  try {
    const stdout = await runPowerShell(
      '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)',
    )
    return stdout.trim().toLowerCase() === 'true'
  } catch {
    return false
  }
}

/**
 * 把 PowerShell 报回来的 Enabled 归一成布尔。
 *
 * 坑：`Get-NetFirewallProfile` 的 Enabled 类型是 `GpoBoolean` 枚举，`ConvertTo-Json`
 * 会把它序列化成**整数 1/0**（不是 true/false）。因此 `item.Enabled === true` 永远为假 ——
 * 防火墙关着时"看起来是对的"，一旦打开就变成"明明开着却报关闭"。
 * 本机实测：Windows 报 True,True,True，这里却报 False,False,False。
 */
export function normalizeProfileEnabled(value) {
  if (value === true || value === 1) return true
  const text = String(value ?? '').trim().toLowerCase()
  return text === 'true' || text === '1' || text === 'on' || text === 'enabled'
}

/** 防火墙各配置文件的启用状态（全部关闭时规则不生效，必须告知用户）。 */
export async function firewallProfileState() {
  if (!firewallSupported()) return { supported: false, profiles: [], anyEnabled: false }
  try {
    // 同样走 COM：`Get-NetFirewallProfile` 本机实测 2.3 秒，COM 属性读取是毫秒级。
    // FirewallEnabled 的入参是 profile 位：1=Domain 2=Private 4=Public。
    const script = `
$policy = New-Object -ComObject HNetCfg.FwPolicy2
$out = foreach ($pair in @(@{n='Domain';b=1}, @{n='Private';b=2}, @{n='Public';b=4})) {
  [pscustomobject]@{ Name = $pair.n; Enabled = [bool]$policy.FirewallEnabled($pair.b) }
}
$out | ConvertTo-Json -Compress`
    const stdout = await runPowerShell(script)
    const parsed = stdout ? JSON.parse(stdout) : []
    const profiles = (Array.isArray(parsed) ? parsed : [parsed]).map((item) => ({
      name: item.Name,
      enabled: normalizeProfileEnabled(item.Enabled),
    }))
    return { supported: true, profiles, anyEnabled: profiles.some((item) => item.enabled) }
  } catch (error) {
    return {
      supported: true,
      profiles: [],
      anyEnabled: false,
      error: error instanceof Error ? error.message : String(error),
    }
  }
}

/**
 * 当前由 CCGait 创建的阻断规则。
 *
 * 用 COM（HNetCfg.FwPolicy2）而不是 `Get-NetFirewallRule`：
 * 后者会把**全部**防火墙规则拉出来在 PowerShell 侧过滤，本机实测要 **13.7 秒**，
 * 而界面每次刷新状态都要调它 —— 结果是面板永远显示十几秒前的状态（用户会认为"状态不准"）。
 * 换成 COM 枚举是 **0.46 秒**，快 30 倍。
 */
export async function listManagedRules() {
  if (!firewallSupported()) return []
  const script = `
$policy = New-Object -ComObject HNetCfg.FwPolicy2
$out = foreach ($rule in $policy.Rules) {
  if ($rule.Name -like '${RULE_PREFIX}*') {
    # COM 的方向/动作是枚举：Direction 1=入站 2=出站；Action 0=阻止 1=允许
    [pscustomobject]@{
      Name = [string]$rule.Name
      Enabled = [bool]$rule.Enabled
      Direction = $(if ($rule.Direction -eq 2) { 'Outbound' } else { 'Inbound' })
      Action = $(if ($rule.Action -eq 0) { 'Block' } else { 'Allow' })
      Program = [string]$rule.ApplicationName
    }
  }
}
if (-not $out) { Write-Output '[]'; exit 0 }
$out | ConvertTo-Json -Compress -Depth 3`
  try {
    const stdout = await runPowerShell(script)
    if (!stdout || stdout === 'null') return []
    const parsed = JSON.parse(stdout)
    return (Array.isArray(parsed) ? parsed : [parsed]).map((item) => ({
      name: String(item.Name ?? ''),
      enabled: item.Enabled === true,
      direction: String(item.Direction ?? ''),
      action: String(item.Action ?? ''),
      program: String(item.Program ?? ''),
    }))
  } catch {
    return []
  }
}

/**
 * 把阻断规则对齐到指定程序清单：
 * - 清单里的路径 → 确保存在一条 Outbound/Block 规则；
 * - 不在清单里的 CCGait 规则 → 删除（客户端路径变化或环境恢复正常时用得到）。
 *
 * 两条实现上的硬约束，都是踩过坑才写的：
 * 1. 解析数组必须用 `ConvertFrom-Json -InputObject`。Windows PowerShell 5.1 下
 *    `$json | ConvertFrom-Json` 把数组当成**单个对象**输出（不枚举），会让后续
 *    foreach 只跑一轮、-Program 收到一个数组而报错。用管道写法时 PowerShell 只会
 *    写一条非终止错误，脚本继续往下走 —— 于是"看起来建了 N 条，实际 0 条"。
 * 2. 每条规则单独 try/catch 且 `-ErrorAction Stop`，并且**回查**实际结果。任何
 *    失败都要如实上报，绝不能把没建成的规则算成已阻断。
 */
export async function applyBlockForPaths(paths) {
  if (!firewallSupported()) return { applied: [], removed: [], failed: [], error: '仅支持 Windows' }
  if (paths.length === 0) return { applied: [], removed: [], failed: [], error: undefined }

  const script = `
$payload = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${encodePayload(paths)}'))
# 必须用 -InputObject 且**不要**再套 @()：PowerShell 5.1 下 @(... | ConvertFrom-Json)
# 会把整个数组当成单个元素，@(ConvertFrom-Json -InputObject ...) 会多套一层数组。
$wanted = ConvertFrom-Json -InputObject $payload
if ($wanted -isnot [array]) { $wanted = @($wanted) }
$prefix = '${RULE_PREFIX}'
$existing = @(Get-NetFirewallRule -DisplayName ($prefix + '*') -ErrorAction SilentlyContinue)
$applied = @()
$failed = @()
$removed = @()

foreach ($path in $wanted) {
  $name = $prefix + $path
  $hit = @($existing | Where-Object { $_.DisplayName -eq $name })
  if ($hit.Count -gt 0) {
    if ($hit[0].Enabled -ne 'True') {
      try { Enable-NetFirewallRule -DisplayName $name -ErrorAction Stop; $applied += $path }
      catch { $failed += [pscustomobject]@{ path = $path; error = $_.Exception.Message } }
    }
    continue
  }
  try {
    New-NetFirewallRule -DisplayName $name -Direction Outbound -Program $path -Action Block -Profile Any -Enabled True -Description 'Created by CCGait: blocks Claude clients when the environment is not whitelisted' -ErrorAction Stop | Out-Null
    $applied += $path
  } catch {
    $failed += [pscustomobject]@{ path = $path; error = $_.Exception.Message }
  }
}

foreach ($rule in $existing) {
  $program = ($rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program
  if ($wanted -notcontains $program) {
    try { Remove-NetFirewallRule -DisplayName $rule.DisplayName -ErrorAction Stop; $removed += $program }
    catch { $failed += [pscustomobject]@{ path = $program; error = $_.Exception.Message } }
  }
}

# 回查：只有系统里确实存在且启用的规则才算成功。
$verified = @()
$blocked = @(Get-NetFirewallRule -DisplayName ($prefix + '*') -ErrorAction SilentlyContinue)
foreach ($rule in $blocked) {
  $program = ($rule | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue).Program
  if ($rule.Enabled -eq 'True' -and $rule.Direction -eq 'Outbound' -and $rule.Action -eq 'Block') {
    $verified += $program
  }
}

[pscustomobject]@{
  applied = @($applied)
  verified = @($verified)
  removed = @($removed)
  failed = @($failed)
} | ConvertTo-Json -Compress -Depth 4`

  try {
    const stdout = await runPowerShell(script)
    const parsed = stdout ? JSON.parse(stdout) : {}
    const asArray = (value) => (value === undefined || value === null ? [] : Array.isArray(value) ? value : [value])
    const failed = asArray(parsed.failed).map((item) =>
      typeof item === 'string' ? { path: item, error: '未知错误' } : { path: item.path, error: item.error },
    )
    const verified = asArray(parsed.verified)
    // 以回查结果为准：请求的路径里有多少条现在真的处于阻断状态。
    const stillUnblocked = paths.filter((path) => !verified.includes(path))
    for (const path of stillUnblocked) {
      if (!failed.some((item) => item.path === path)) {
        failed.push({ path, error: '规则未出现在系统里（回查未通过）' })
      }
    }
    return {
      applied: asArray(parsed.applied),
      verified,
      removed: asArray(parsed.removed),
      failed,
      error: undefined,
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    const denied = /access is denied|拒绝访问|权限/i.test(message)
    return {
      applied: [],
      verified: [],
      removed: [],
      failed: [],
      error: denied
        ? '创建防火墙规则被拒绝：需要以管理员身份运行（右键 → 以管理员身份运行）'
        : message,
    }
  }
}

/** 清除 CCGait 创建的全部阻断规则（恢复正常/卸载时调用）。 */
export async function removeAllBlocks() {
  if (!firewallSupported()) return { removed: 0, error: '仅支持 Windows' }
  const script = `
$rules = @(Get-NetFirewallRule -DisplayName '${RULE_PREFIX}*' -ErrorAction SilentlyContinue)
$count = $rules.Count
if ($count -gt 0) { $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
[pscustomobject]@{ removed = $count } | ConvertTo-Json -Compress`
  try {
    const stdout = await runPowerShell(script)
    const parsed = stdout ? JSON.parse(stdout) : {}
    return { removed: Number(parsed.removed ?? 0), error: undefined }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    const denied = /access is denied|拒绝访问|权限/i.test(message)
    return {
      removed: 0,
      error: denied ? '删除防火墙规则被拒绝：需要管理员权限' : message,
    }
  }
}

/**
 * 启用 Windows 防火墙的三个配置文件。
 *
 * 为什么需要这一步：防火墙规则只有在配置文件启用时才会生效。如果用户机器上
 * Windows 防火墙被整体关闭（或被第三方安全软件接管），按程序阻断就是空转 ——
 * 这是"禁止联网"能否真正落地的前提，所以提供一个显式命令，而不是偷偷打开。
 */
export async function enableProfiles() {
  if (!firewallSupported()) return { ok: false, error: '仅支持 Windows' }
  const script = `
$before = @(Get-NetFirewallProfile | Select-Object -ExpandProperty Name)
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -ErrorAction Stop
$after = Get-NetFirewallProfile | Select-Object Name,Enabled
$after | ConvertTo-Json -Compress`
  try {
    const stdout = await runPowerShell(script)
    const parsed = stdout ? JSON.parse(stdout) : []
    const profiles = (Array.isArray(parsed) ? parsed : [parsed]).map((item) => ({
      name: item.Name,
      enabled: item.Enabled === true,
    }))
    return { ok: true, profiles }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    const denied = /access is denied|拒绝访问|权限/i.test(message)
    return {
      ok: false,
      error: denied ? '启用防火墙需要管理员权限' : message,
    }
  }
}
