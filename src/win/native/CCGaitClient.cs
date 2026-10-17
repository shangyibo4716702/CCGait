// CCGait 桌面客户端（C# / WinForms，.NET Framework 自带编译器即可构建）
//
// 两种模式：
//   CCGaitClient.exe          启动本地服务（若未运行）并打开应用窗口
//   CCGaitClient.exe tray     常驻托盘：状态图标 + 右键菜单 + 判定变化气泡
//
// 为什么自己写 exe 而不是继续用 PowerShell 脚本：打包后的客户端不应依赖脚本宿主，
// 托盘也应是一个真正的 Windows 程序（有图标、有消息循环、可被任务栏识别）。

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace Ccgait
{
    internal static class Program
    {
        private const int UiPort = 17890;

        internal static string AppRoot;
        internal static string CliPath;
        internal static string StateDir;
        internal static string ConfigPath;
        internal static string IconPath;

        [STAThread]
        private static void Main(string[] args)
        {
            AppRoot = AppDomain.CurrentDomain.BaseDirectory.TrimEnd('\\');
            CliPath = Path.Combine(AppRoot, "src", "cli.js");
            StateDir = Path.Combine(AppRoot, ".ccgait");
            ConfigPath = Path.Combine(AppRoot, "config.json");
            IconPath = Path.Combine(StateDir, "ccgait.ico");

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            string mode = args.Length > 0 ? args[0].ToLowerInvariant() : "desktop";
            switch (mode)
            {
                case "tray":
                    Application.Run(new TrayContext());
                    return;
                case "startup":
                    // 供安装程序与脚本调用：startup on|off|status
                    Environment.ExitCode = Startup.Handle(args);
                    return;
                case "desktop":
                default:
                    OpenDesktop();
                    return;
            }
        }

        /// <summary>Node 运行时：优先 PATH 上的 node，其次安装目录内自带的 runtime。</summary>
        internal static string ResolveNode()
        {
            string bundled = Path.Combine(AppRoot, "runtime", "node.exe");
            if (File.Exists(bundled)) return bundled;

            string path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (string dir in path.Split(';'))
            {
                if (dir.Trim().Length == 0) continue;
                try
                {
                    string candidate = Path.Combine(dir.Trim(), "node.exe");
                    if (File.Exists(candidate)) return candidate;
                }
                catch (ArgumentException) { /* 非法路径段忽略 */ }
            }
            return null;
        }

        /// <summary>隐藏窗口执行 CLI，返回退出码；-1 表示无法启动。</summary>
        internal static int RunCli(string arguments, bool wait, int timeoutMs)
        {
            string node = ResolveNode();
            if (node == null) return -1;
            var info = new ProcessStartInfo(node)
            {
                Arguments = Quote(CliPath) + " " + arguments,
                WorkingDirectory = AppRoot,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };

            // 重定向与编码必须成对出现：设了 StandardOutputEncoding 却没开
            // RedirectStandardOutput，.NET 会在 Process.Start 直接抛
            // InvalidOperationException（托盘一启动就崩，且是未捕获异常弹框）。
            //
            // 只有需要等结果的调用才重定向：不等待的调用（如拉起本地界面服务）必须让子进程
            // 独立存活，重定向后我们这边一释放 Process，子进程的管道就断了。
            if (wait)
            {
                info.RedirectStandardOutput = true;
                info.RedirectStandardError = true;
                info.StandardOutputEncoding = Encoding.UTF8;
                info.StandardErrorEncoding = Encoding.UTF8;
            }

            using (Process process = Process.Start(info))
            {
                if (process == null) return -1;
                if (!wait) return 0;

                // 必须先开始读、再等退出：子进程写满管道缓冲区会阻塞，先 WaitForExit 会死锁。
                // 这里只取退出码，输出读干即丢，避免子进程卡在写管道上。
                Task<string> stdout = process.StandardOutput.ReadToEndAsync();
                Task<string> stderr = process.StandardError.ReadToEndAsync();
                bool exited = process.WaitForExit(timeoutMs);
                try { Task.WaitAll(new Task[] { stdout, stderr }, 2000); } catch { }
                return exited ? process.ExitCode : -1;
            }
        }

        internal static string Quote(string value)
        {
            return "\"" + value + "\"";
        }

        internal static bool PortOpen(int port)
        {
            try
            {
                using (var client = new TcpClient())
                {
                    IAsyncResult result = client.BeginConnect("127.0.0.1", port, null, null);
                    bool ok = result.AsyncWaitHandle.WaitOne(400);
                    if (ok) client.EndConnect(result);
                    return ok;
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>启动服务（隐藏）并等待端口就绪。</summary>
        internal static bool EnsureServer()
        {
            if (PortOpen(UiPort)) return true;
            RunCli("ui --port " + UiPort + " --no-open", false, 0);
            for (int attempt = 0; attempt < 24; attempt++)
            {
                System.Threading.Thread.Sleep(500);
                if (PortOpen(UiPort)) return true;
            }
            return false;
        }

        /// <summary>用 Edge/Chrome 的 APP 模式打开无边框应用窗口。</summary>
        private static bool OpenWindow()
        {
            string[] candidates = new[]
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft", "Edge", "Application", "msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Microsoft", "Edge", "Application", "msedge.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Google", "Chrome", "Application", "chrome.exe"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Google", "Chrome", "Application", "chrome.exe"),
            };
            foreach (string browser in candidates)
            {
                if (!File.Exists(browser)) continue;
                string profile = Path.Combine(StateDir, "app-window-profile");
                string args = "--app=http://127.0.0.1:" + UiPort + "/"
                    + " --window-size=1440,1040"
                    + " --user-data-dir=" + Quote(profile)
                    + " --no-first-run --no-default-browser-check";
                Process.Start(new ProcessStartInfo(browser) { Arguments = args, UseShellExecute = false });
                return true;
            }
            return false;
        }

        private static void OpenDesktop()
        {
            // 打开软件就该在执法。执法者现在由**常驻界面服务进程**自己承担（进程内闸门、
            // 界面服务自己的线程），所以这里只需要把服务拉起来 —— 不再另起一个独立的
            // `cli.js guard` 进程：那会变成"别的实例"，界面上写"运行中（别的实例）"且停不掉，
            // 而且两个闸门各守一套 WFP 过滤器，停掉其中一个也解不掉另一个的阻断。
            // 已经有闸门在跑时（另一个界面服务起的、或上一次留下的），服务自己也不会再起第二个。
            bool serverReady = EnsureServer();
            if (serverReady && GuardAutoStart.IsEnabled())
            {
                // 等闸门登记进 guard.pid（服务一启动就建自己的闸门），
                // 这样窗口第一次渲染时状态条就能如实写"运行中"。
                for (int attempt = 0; attempt < 12 && !Program.ReadStatus().GuardRunning; attempt++)
                {
                    System.Threading.Thread.Sleep(250);
                }
            }

            bool windowOpened = serverReady && OpenWindow();
            if (!windowOpened)
            {
                MessageBox.Show(
                    serverReady
                        ? "未找到 Microsoft Edge 或 Google Chrome，无法打开应用窗口。"
                        : "本地服务未能启动。请确认已安装 Node.js 20 以上版本，然后重试。",
                    "CCGait",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
        }

        // ------------------------------------------------------------ 状态读取

        /// <summary>托盘要显示的状态：最近一次判定 + 闸门是否在运行。</summary>
        internal sealed class Status
        {
            internal bool HasCheck;
            internal bool Allow;
            internal string Ip = "";
            internal string Country = "";
            internal int BlockedCount;
            internal int WarningCount;
            internal string FirstBlockedTitle;
            internal bool GuardRunning;

            internal string Tooltip()
            {
                var sb = new StringBuilder("CCGait");
                if (HasCheck)
                {
                    sb.Append(Allow ? " · 放行" : " · 拦截");
                    if (Ip.Length > 0) sb.Append(" · ").Append(Ip);
                    if (Country.Length > 0) sb.Append(" · ").Append(Country);
                }
                else
                {
                    sb.Append(" · 尚未检测");
                }
                sb.Append(GuardRunning ? " · 闸门运行中" : " · 闸门未运行");
                string text = sb.ToString();
                // NotifyIcon.Text 上限 63 字符，超出会直接抛异常。
                return text.Length <= 63 ? text : text.Substring(0, 60) + "…";
            }

            internal string BalloonTitle()
            {
                if (!HasCheck) return "尚未检测";
                return Allow ? "环境命中白名单，已放行" : "环境不符，已拦截";
            }

            internal string BalloonText()
            {
                if (!HasCheck) return "右键图标可立即检测环境";
                if (Allow)
                {
                    string where = (Ip + " · " + Country).Trim(' ', '·');
                    return where.Length > 0 ? where : "出口已确认";
                }
                string first = FirstBlockedTitle ?? "白名单未命中";
                return BlockedCount > 1 ? first + "（共 " + BlockedCount + " 项）" : first;
            }
        }

        internal static Status ReadStatus()
        {
            var status = new Status();
            try
            {
                string checkPath = Path.Combine(StateDir, "last-check.json");
                if (File.Exists(checkPath))
                {
                    string json = File.ReadAllText(checkPath, Encoding.UTF8);
                    status.HasCheck = true;
                    status.Allow = Regex.IsMatch(json, "\"allow\"\\s*:\\s*true");
                    status.Ip = FirstGroup(json, "\"ip\"\\s*:\\s*\"([^\"]*)\"");
                    status.Country = FirstGroup(json, "\"country\"\\s*:\\s*\"([^\"]*)\"");
                    status.FirstBlockedTitle = FirstGroup(json, "\"blocked\"\\s*:\\s*\\[\\s*\\{[^}]*\"title\"\\s*:\\s*\"([^\"]*)\"");
                    status.BlockedCount = CountOccurrences(json, "\"title\"");
                    MatchCollection warnings = Regex.Matches(json, "\"warnings\"\\s*:\\s*\\[([^\\]]*)\\]");
                    status.WarningCount = warnings.Count > 0 ? Regex.Matches(warnings[0].Groups[1].Value, "\"title\"").Count : 0;
                    // blocked 段里也有 title，扣掉它才是拦截项数。
                    MatchCollection blocked = Regex.Matches(json, "\"blocked\"\\s*:\\s*\\[([^\\]]*)\\]");
                    status.BlockedCount = blocked.Count > 0 ? Regex.Matches(blocked[0].Groups[1].Value, "\"title\"").Count : 0;
                }

                string pidPath = Path.Combine(StateDir, "guard.pid");
                if (File.Exists(pidPath))
                {
                    int pid;
                    if (int.TryParse(File.ReadAllText(pidPath).Trim(), out pid))
                    {
                        try
                        {
                            Process.GetProcessById(pid);
                            status.GuardRunning = true;
                        }
                        catch (ArgumentException) { /* 进程已退出 */ }
                    }
                }
            }
            catch
            {
                // 状态文件损坏时按"未知"处理，不影响托盘可用性。
            }
            return status;
        }

        private static string FirstGroup(string text, string pattern)
        {
            Match match = Regex.Match(text, pattern);
            return match.Success ? match.Groups[1].Value : "";
        }

        private static int CountOccurrences(string text, string token)
        {
            int count = 0;
            int index = text.IndexOf(token, StringComparison.Ordinal);
            while (index >= 0)
            {
                count++;
                index = text.IndexOf(token, index + token.Length, StringComparison.Ordinal);
            }
            return count;
        }
    }

    /// <summary>
    /// 开机自启：写 HKCU 的 Run 项。
    ///
    /// 选注册表 Run 而不是计划任务：按用户生效、**不需要管理员权限**，也会出现在
    /// 「任务管理器 → 启动应用」里让用户随时关掉 —— 对客户端来说这是最容易被审阅和
    /// 撤销的做法。命令带 tray 参数，登录后直接进托盘常驻。
    /// </summary>
    internal static class Startup
    {
        private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
        private const string ValueName = "CCGait";

        internal static string Command()
        {
            return "\"" + Path.Combine(Program.AppRoot, "CCGaitClient.exe") + "\" tray";
        }

        internal static string CurrentValue()
        {
            try
            {
                using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunKeyPath, false))
                {
                    if (key == null) return null;
                    return key.GetValue(ValueName) as string;
                }
            }
            catch
            {
                return null;
            }
        }

        internal static bool IsEnabled()
        {
            string value = CurrentValue();
            return !string.IsNullOrEmpty(value);
        }

        internal static bool Enable()
        {
            try
            {
                using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(RunKeyPath))
                {
                    if (key == null) return false;
                    key.SetValue(ValueName, Command());
                }
                return IsEnabled();
            }
            catch
            {
                return false;
            }
        }

        /// <summary>关闭自启。只删除指向本程序的那一条，不动其它自启项。</summary>
        internal static bool Disable()
        {
            try
            {
                using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(RunKeyPath, true))
                {
                    if (key == null) return true;
                    key.DeleteValue(ValueName, false);
                }
                return !IsEnabled();
            }
            catch
            {
                return false;
            }
        }

        /// <summary>startup on|off|status 的实现，返回进程退出码。</summary>
        internal static int Handle(string[] args)
        {
            string action = args.Length > 1 ? args[1].ToLowerInvariant() : "status";
            switch (action)
            {
                case "on":
                    return Enable() ? 0 : 1;
                case "off":
                    return Disable() ? 0 : 1;
                case "status":
                default:
                    return IsEnabled() ? 0 : 1;
            }
        }
    }

    /// <summary>
    /// "启动托盘时自动开闸门"的开关。
    ///
    /// 默认**开启**：用户要的是"打开软件就在执法"，而不是每次手动点一次菜单。
    /// 只存一个 HKCU 值，缺省即视为开启；只有显式关掉才写 0。
    /// </summary>
    internal static class GuardAutoStart
    {
        private const string KeyPath = @"Software\CCGait";
        private const string ValueName = "AutoStartGuard";

        internal static bool IsEnabled()
        {
            try
            {
                using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(KeyPath, false))
                {
                    if (key == null) return true; // 没写过 = 默认开启
                    object raw = key.GetValue(ValueName);
                    if (raw == null) return true;
                    return Convert.ToInt32(raw) != 0;
                }
            }
            catch
            {
                return true;
            }
        }

        internal static void Set(bool enabled)
        {
            try
            {
                using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(KeyPath))
                {
                    // 这里不能用 ?.（null 条件运算符）：随 .NET Framework 一起的 csc 只支持到 C# 5。
                    if (key != null)
                    {
                        key.SetValue(ValueName, enabled ? 1 : 0, Microsoft.Win32.RegistryValueKind.DWord);
                    }
                }
            }
            catch
            {
                // 写不进去就维持默认行为，不影响其它功能。
            }
        }
    }

    /// <summary>托盘：状态图标 + 右键菜单。所有动作转交 CLI，行为和命令行完全一致。</summary>
    internal sealed class TrayContext : ApplicationContext
    {
        private readonly NotifyIcon _icon;
        private readonly System.Windows.Forms.Timer _timer;
        private readonly ToolStripMenuItem _startItem;
        private readonly ToolStripMenuItem _stopItem;
        private bool? _previousAllow;

        internal TrayContext()
        {
            _icon = new NotifyIcon
            {
                Visible = true,
                Icon = LoadIcon(),
                Text = "CCGait",
            };

            var menu = new ContextMenuStrip { ShowImageMargin = false };

            var open = new ToolStripMenuItem("打开界面");
            open.Click += (s, e) => Run("desktop", true);
            menu.Items.Add(open);

            menu.Items.Add(new ToolStripSeparator());

            var check = new ToolStripMenuItem("立即检测");
            check.Click += (s, e) =>
            {
                int code = Run("check", true);
                Program.Status status = Program.ReadStatus();
                if (status.HasCheck)
                {
                    ShowBalloon(
                        status.BalloonTitle(),
                        status.BalloonText(),
                        status.Allow ? ToolTipIcon.Info : ToolTipIcon.Warning);
                    _previousAllow = status.Allow;
                }
                else if (code != 0)
                {
                    ShowBalloon("检测失败", "请打开界面查看详情", ToolTipIcon.Error);
                }
                Refresh();
            };
            menu.Items.Add(check);

            _startItem = new ToolStripMenuItem("启动闸门");
            _startItem.Click += (s, e) =>
            {
                if (Program.ReadStatus().GuardRunning)
                {
                    ShowBalloon("闸门已在运行", "无需重复启动", ToolTipIcon.Info);
                    return;
                }
                // 执法由常驻界面服务进程承担：先把服务拉起来（它启动即建自己的闸门），
                // 再写一个"启动请求"——服务在跑但闸门被停过时，靠这个请求把它建回来。
                Program.EnsureServer();
                Run("guard-start", true);
                System.Threading.Thread.Sleep(1500);
                Refresh();
                if (Program.ReadStatus().GuardRunning)
                {
                    ShowBalloon("闸门已启动", "不满足白名单时将阻止 Claude 客户端并阻断其网络", ToolTipIcon.Info);
                }
            };
            menu.Items.Add(_startItem);

            _stopItem = new ToolStripMenuItem("停止闸门");
            _stopItem.Click += (s, e) =>
            {
                if (!Program.ReadStatus().GuardRunning)
                {
                    ShowBalloon("闸门未运行", "无需停止", ToolTipIcon.Info);
                    return;
                }
                Run("guard-stop", true);
                Refresh();
                ShowBalloon("闸门已停止", "已撤掉 CCGait 建立的防火墙阻断", ToolTipIcon.Info);
            };
            menu.Items.Add(_stopItem);

            menu.Items.Add(new ToolStripSeparator());

            var block = new ToolStripMenuItem("阻断网络");
            block.Click += (s, e) =>
            {
                Run("firewall on", true);
                ShowBalloon("已阻断", "Claude 客户端已禁止出站（需要系统防火墙开启）", ToolTipIcon.Warning);
                Refresh();
            };
            menu.Items.Add(block);

            var unblock = new ToolStripMenuItem("解除阻断");
            unblock.Click += (s, e) =>
            {
                Run("firewall off", true);
                ShowBalloon("已解除阻断", "已移除 CCGait 建立的防火墙规则", ToolTipIcon.Info);
                Refresh();
            };
            menu.Items.Add(unblock);

            var kill = new ToolStripMenuItem("终止 Claude 进程");
            kill.Click += (s, e) =>
            {
                Run("kill", true);
                ShowBalloon("已处理", "正在运行的 Claude 客户端已终止", ToolTipIcon.Info);
            };
            menu.Items.Add(kill);

            menu.Items.Add(new ToolStripSeparator());

            var startupItem = new ToolStripMenuItem("开机自启（登录时启动托盘）")
            {
                CheckOnClick = true,
                Checked = Startup.IsEnabled(),
            };
            startupItem.CheckedChanged += (s, e) =>
            {
                bool ok = startupItem.Checked ? Startup.Enable() : Startup.Disable();
                startupItem.Checked = Startup.IsEnabled(); // 以注册表实际状态为准
                if (!ok)
                {
                    ShowBalloon("开机自启设置失败", "请检查注册表权限", ToolTipIcon.Warning);
                }
                else
                {
                    ShowBalloon(
                        startupItem.Checked ? "已开启开机自启" : "已关闭开机自启",
                        startupItem.Checked ? "下次登录将自动启动托盘" : "登录时不再自动启动",
                        ToolTipIcon.Info);
                }
            };
            menu.Items.Add(startupItem);

            var autoGuardItem = new ToolStripMenuItem("启动时自动开闸门（常驻界面服务执法）")
            {
                CheckOnClick = true,
                Checked = GuardAutoStart.IsEnabled(),
            };
            autoGuardItem.CheckedChanged += (s, e) =>
            {
                GuardAutoStart.Set(autoGuardItem.Checked);
                ShowBalloon(
                    autoGuardItem.Checked ? "已开启自动开闸门" : "已关闭自动开闸门",
                    autoGuardItem.Checked
                        ? "下次启动会自动拉起界面服务并开始执法"
                        : "启动后需要手动点「启动闸门」",
                    ToolTipIcon.Info);
            };
            menu.Items.Add(autoGuardItem);

            menu.Items.Add(new ToolStripSeparator());

            var config = new ToolStripMenuItem("打开配置文件");
            config.Click += (s, e) => Launch("notepad.exe", "\"" + Program.ConfigPath + "\"");
            menu.Items.Add(config);

            var logs = new ToolStripMenuItem("打开状态目录");
            logs.Click += (s, e) => Launch("explorer.exe", "\"" + Program.StateDir + "\"");
            menu.Items.Add(logs);

            menu.Items.Add(new ToolStripSeparator());

            var quit = new ToolStripMenuItem("退出托盘（闸门与界面服务继续运行）");
            quit.Click += (s, e) =>
            {
                _icon.Visible = false;
                _icon.Dispose();
                ExitThread();
            };
            menu.Items.Add(quit);

            _icon.ContextMenuStrip = menu;
            _icon.DoubleClick += (s, e) => Run("desktop", true);

            _timer = new System.Windows.Forms.Timer { Interval = 10000 };
            _timer.Tick += (s, e) => Refresh();
            _timer.Start();

            Refresh();

            // 默认行为：托盘一起来就把常驻界面服务拉起来（服务启动即建自己的闸门开始执法），
            // 不用每次手动点「启动闸门」。闸门跑在服务进程里，所以退出托盘、关掉窗口都不会停掉执法。
            if (GuardAutoStart.IsEnabled() && !Program.ReadStatus().GuardRunning)
            {
                StartGuardQuietly();
            }

            if (!Program.ReadStatus().HasCheck)
            {
                ShowBalloon("CCGait 托盘已就绪", "已按默认设置开始执法；右键图标可检测环境、启停闸门", ToolTipIcon.Info);
            }
        }

        /// <summary>启动闸门并把结果告诉用户（失败必须说清楚，不能默默不干活）。</summary>
        private void StartGuardQuietly()
        {
            // 执法由常驻界面服务进程承担：这里把它拉起来（服务一启动就建自己的闸门），
            // 再写一个"启动请求"兜底 —— 服务已经在跑、但闸门被停过时也照样能建回来。
            if (!Program.EnsureServer())
            {
                ShowBalloon(
                    "界面服务未能启动",
                    "未找到 Node.js（需要 20 以上版本），无法开始执法",
                    ToolTipIcon.Warning);
                return;
            }
            Run("guard-start", true);
            for (int attempt = 0; attempt < 12 && !Program.ReadStatus().GuardRunning; attempt++)
            {
                System.Threading.Thread.Sleep(250);
            }
            Refresh();
            if (Program.ReadStatus().GuardRunning)
            {
                ShowBalloon("闸门已启动", "不满足白名单时将终止 Claude 客户端并阻断其网络", ToolTipIcon.Info);
            }
            else
            {
                ShowBalloon(
                    "闸门未能启动",
                    "可能需要管理员权限：右键托盘图标 →「以管理员身份运行」，或打开界面查看日志",
                    ToolTipIcon.Warning);
            }
        }

        private static Icon LoadIcon()
        {
            try
            {
                if (File.Exists(Program.IconPath)) return new Icon(Program.IconPath);
            }
            catch
            {
                // 图标读取失败时退回系统盾牌图标。
            }
            return SystemIcons.Shield;
        }

        private static int Run(string arguments, bool wait)
        {
            int code = Program.RunCli(arguments, wait, 120000);
            if (code == -1)
            {
                MessageBox.Show(
                    "未找到 Node.js（需要 20 以上版本）。请安装后重试，或在安装目录放置自带 runtime。",
                    "CCGait",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
            return code;
        }

        private static void Launch(string file, string arguments)
        {
            try
            {
                Process.Start(new ProcessStartInfo(file) { Arguments = arguments, UseShellExecute = true });
            }
            catch
            {
                // 打不开外部程序不影响托盘。
            }
        }

        internal void ShowBalloon(string title, string text, ToolTipIcon icon)
        {
            _icon.BalloonTipTitle = title;
            _icon.BalloonTipText = text;
            _icon.BalloonTipIcon = icon;
            _icon.ShowBalloonTip(6000);
        }

        private void Refresh()
        {
            Program.Status status = Program.ReadStatus();
            try
            {
                _icon.Text = status.Tooltip();
            }
            catch
            {
                _icon.Text = "CCGait";
            }
            _startItem.Enabled = !status.GuardRunning;
            _stopItem.Enabled = status.GuardRunning;
            _startItem.Text = status.GuardRunning ? "启动闸门（已运行）" : "启动闸门";

            // 只在「放行 → 拦截」翻转时提醒，持续拦截不反复打扰。
            if (status.HasCheck)
            {
                if (_previousAllow == true && !status.Allow)
                {
                    ShowBalloon("环境不符，已拦截", status.BalloonText(), ToolTipIcon.Warning);
                }
                _previousAllow = status.Allow;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _timer.Stop();
                _timer.Dispose();
                _icon.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
