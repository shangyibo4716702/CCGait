# CCGait 托盘客户端（Windows）
#
# 由 `ccgait tray` 启动，界面外的常驻入口：托盘图标实时显示判定与环境，右键菜单
# 可以直接检测/启停闸门/阻断网络。
#
# 设计约束：
# - 只读状态文件（last-check.json / guard.pid），**不持有 Web 会话令牌**；
# - 所有动作都转发给 CLI（与命令行完全同一套语义，不重复实现业务逻辑）；
# - 只在判定从「放行」变「拦截」时弹气泡，避免持续打扰。

param(
  [Parameter(Mandatory = $true)][string]$NodePath,
  [Parameter(Mandatory = $true)][string]$CliPath,
  [Parameter(Mandatory = $true)][string]$StateDir,
  [Parameter(Mandatory = $true)][string]$IconPath,
  [Parameter(Mandatory = $true)][string]$ConfigPath,
  [int]$Port = 17890
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$script:lastCheckFile = Join-Path $StateDir 'last-check.json'
$script:pidFile = Join-Path $StateDir 'guard.pid'
$script:previousAllow = $null

function Invoke-Ccgait {
  param([string[]]$Arguments, [switch]$Wait)
  # 所有动作交给 CLI：界面、托盘、命令行行为完全一致。
  $argList = @($CliPath) + $Arguments
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $NodePath
  $psi.Arguments = ($argList | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
  $psi.WorkingDirectory = Split-Path -Parent (Split-Path -Parent $CliPath)
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $process = [System.Diagnostics.Process]::Start($psi)
  if ($Wait) { $process.WaitForExit(120000) | Out-Null }
  return $process
}

function Get-GuardPid {
  if (-not (Test-Path $script:pidFile)) { return $null }
  try {
    $raw = (Get-Content -LiteralPath $script:pidFile -Raw).Trim()
    $pidValue = 0
    if ([int]::TryParse($raw, [ref]$pidValue)) { return $pidValue }
  } catch {
    return $null
  }
  return $null
}

function Test-GuardRunning {
  $pidValue = Get-GuardPid
  if (-not $pidValue) { return $false }
  $process = Get-Process -Id $pidValue -ErrorAction SilentlyContinue
  return $null -ne $process
}

function Get-Status {
  $check = $null
  if (Test-Path $script:lastCheckFile) {
    try { $check = Get-Content -LiteralPath $script:lastCheckFile -Raw | ConvertFrom-Json } catch { $check = $null }
  }
  return [pscustomobject]@{
    Check   = $check
    Running = (Test-GuardRunning)
  }
}

function Get-Tooltip {
  $status = Get-Status
  $parts = @('CCGait')
  if ($status.Check) {
    if ($status.Check.allow) { $parts += '放行' } else { $parts += '拦截' }
    if ($status.Check.egress.ip) { $parts += $status.Check.egress.ip }
    if ($status.Check.egress.country) { $parts += $status.Check.egress.country }
  } else {
    $parts += '尚未检测'
  }
  $parts += $(if ($status.Running) { '闸门运行中' } else { '闸门未运行' })
  $text = $parts -join ' · '
  if ($text.Length -gt 63) { $text = $text.Substring(0, 60) + '…' }
  return $text
}

function Show-Balloon {
  param([string]$Title, [string]$Text, [System.Windows.Forms.ToolTipIcon]$Icon = 'Info')
  $notify.BalloonTipTitle = $Title
  $notify.BalloonTipText = $Text
  $notify.BalloonTipIcon = $Icon
  $notify.ShowBalloonTip(6000)
}

# ------------------------------------------------------------------ 托盘构建

$notify = New-Object System.Windows.Forms.NotifyIcon
if (Test-Path $IconPath) { $notify.Icon = New-Object System.Drawing.Icon($IconPath) } else { $notify.Icon = [System.Drawing.SystemIcons]::Shield }
$notify.Text = 'CCGait'
$notify.Visible = $true

$menu = New-Object System.Windows.Forms.ContextMenuStrip
$menu.ShowImageMargin = $false

$itemOpen = $menu.Items.Add('打开界面')
$itemOpen.add_Click({ Invoke-Ccgait @('desktop') -Wait | Out-Null })

$menu.Items.Add('-') | Out-Null

$itemCheck = $menu.Items.Add('立即检测')
$itemCheck.add_Click({
  $before = Get-Status
  $process = Invoke-Ccgait @('check') -Wait
  $after = Get-Status
  $exitCode = $process.ExitCode
  if ($after.Check) {
    $icon = if ($after.Check.allow) { 'Info' } else { 'Warning' }
    $text = if ($after.Check.allow) {
      "$($after.Check.egress.ip) · $($after.Check.egress.country)；$($after.Check.warnings.Count) 项提示"
    } else {
      $first = $after.Check.blocked[0].title
      if (-not $first) { $first = '白名单未命中' }
      "$first（共 $($after.Check.blocked.Count) 项）"
    }
    Show-Balloon -Title $(if ($after.Check.allow) { '环境命中白名单，已放行' } else { '环境不符，已拦截' }) -Text $text -Icon $icon
  } elseif ($exitCode -ne 0) {
    Show-Balloon -Title '检测失败' -Text '请打开界面查看详情' -Icon Error
  }
  $script:previousAllow = $after.Check.allow
  Update-Tray
})

$itemStart = $menu.Items.Add('启动闸门')
$itemStart.add_Click({
  if (Test-GuardRunning) { Show-Balloon -Title '闸门已在运行' -Text '无需重复启动' ; return }
  Invoke-Ccgait @('guard') | Out-Null
  Start-Sleep -Milliseconds 1500
  Update-Tray
  if (Test-GuardRunning) { Show-Balloon -Title '闸门已启动' -Text '不满足白名单时将阻止 Claude 客户端并阻断其网络' }
})

$itemStop = $menu.Items.Add('停止闸门')
$itemStop.add_Click({
  if (-not (Test-GuardRunning)) { Show-Balloon -Title '闸门未运行' -Text '无需停止' ; return }
  Invoke-Ccgait @('guard-stop') -Wait | Out-Null
  Update-Tray
  Show-Balloon -Title '闸门已停止' -Text '已撤掉 CCGait 建立的防火墙阻断'
})

$menu.Items.Add('-') | Out-Null

$itemBlock = $menu.Items.Add('阻断网络')
$itemBlock.add_Click({
  Invoke-Ccgait @('firewall', 'on') -Wait | Out-Null
  Update-Tray
  Show-Balloon -Title '已阻断' -Text 'Claude 客户端已禁止出站（需要系统防火墙开启）'
})

$itemUnblock = $menu.Items.Add('解除阻断')
$itemUnblock.add_Click({
  Invoke-Ccgait @('firewall', 'off') -Wait | Out-Null
  Update-Tray
  Show-Balloon -Title '已解除阻断' -Text '已移除 CCGait 建立的防火墙规则'
})

$itemKill = $menu.Items.Add('终止 Claude 进程')
$itemKill.add_Click({
  Invoke-Ccgait @('kill') -Wait | Out-Null
  Show-Balloon -Title '已处理' -Text '正在运行的 Claude 客户端已终止'
})

$menu.Items.Add('-') | Out-Null

$itemConfig = $menu.Items.Add('打开配置文件')
$itemConfig.add_Click({ Start-Process -FilePath 'notepad.exe' -ArgumentList "`"$ConfigPath`"" })

$itemLogs = $menu.Items.Add('打开状态目录')
$itemLogs.add_Click({ Start-Process -FilePath 'explorer.exe' -ArgumentList "`"$StateDir`"" })

$menu.Items.Add('-') | Out-Null

$itemQuit = $menu.Items.Add('退出托盘（闸门不受影响）')
$itemQuit.add_Click({
  $notify.Visible = $false
  $notify.Dispose()
  [System.Windows.Forms.Application]::Exit()
})

$notify.ContextMenuStrip = $menu
$notify.add_DoubleClick({ Invoke-Ccgait @('desktop') -Wait | Out-Null })

function Update-Tray {
  $status = Get-Status
  $notify.Text = Get-Tooltip

  $itemStart.Enabled = -not $status.Running
  $itemStop.Enabled = $status.Running
  $itemStart.Text = if ($status.Running) { '启动闸门（已运行）' } else { '启动闸门' }

  if ($status.Check) {
    $allowNow = [bool]$status.Check.allow
    # 只在「放行 → 拦截」的翻转时提醒：持续拦截不重复打扰。
    if ($null -ne $script:previousAllow -and $script:previousAllow -and -not $allowNow) {
      $text = $status.Check.blocked[0].title
      if (-not $text) { $text = '出口不满足白名单' }
      Show-Balloon -Title '环境不符，已拦截' -Text $text -Icon Warning
    }
    $script:previousAllow = $allowNow
  }
}

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 10000
$timer.add_Tick({ Update-Tray })
$timer.Start()

Update-Tray

# 首次启动给一次状态提示，让人知道托盘已经在了。
$initial = Get-Status
if ($initial.Check) {
  Show-Balloon -Title 'CCGait 托盘已就绪' -Text (Get-Tooltip)
} else {
  Show-Balloon -Title 'CCGait 托盘已就绪' -Text '右键图标可检测环境、启停闸门'
}

[System.Windows.Forms.Application]::Run()
$timer.Stop()
$timer.Dispose()
