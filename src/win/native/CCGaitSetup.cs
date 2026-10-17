// CCGait 安装程序（C# / WinForms，用 .NET Framework 自带的 csc.exe 构建）
//
//   CCGaitSetup.exe              图形化安装：选择选项 → 解包 → 建快捷方式 → 注册卸载项
//   CCGaitSetup.exe --silent     静默安装（写日志到 %TEMP%\ccgait-setup.log，供自动化验证）
//   CCGaitSetup.exe --uninstall  卸载（可选保留配置）
//
// 安装到 %LOCALAPPDATA%\Programs\CCGait：**按用户安装，不需要管理员权限**，
// 也因此不会碰系统目录与 HKLM。卸载信息写 HKCU，能在「应用和功能」里看到。
//
// 注意（实测坑）：本机 ANSI 代码页是 1252，WScript.Shell 属于遗留 ANSI COM 组件，
// 用它创建**含中文的** .lnk 会失败 —— 所以快捷方式名一律 ASCII，中文只出现在这个
// 安装界面里（WinForms 是 Unicode，不受 ANSI 影响）。

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace CcgaitSetup
{
    internal static class Program
    {
        internal const string ProductName = "CCGait";
        internal const string Publisher = "CCGait";
        internal const string Version = "0.1.0";
        internal const string UninstallKey = @"Software\Microsoft\Windows\CurrentVersion\Uninstall\CCGait";

        internal static string InstallDir
        {
            get
            {
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Programs",
                    "CCGait");
            }
        }

        internal static string ProjectRoot
        {
            get { return InstallDir; }
        }

        [STAThread]
        private static int Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            bool silent = Array.IndexOf(args, "--silent") >= 0;
            bool uninstall = Array.IndexOf(args, "--uninstall") >= 0;

            if (silent)
            {
                var log = new StringBuilder();
                try
                {
                    if (uninstall) Uninstaller.Run(log, true);
                    else Installer.Run(log, new InstallOptions { CreateDesktopShortcut = true, EnableAutoStart = true, StartTray = false });
                    WriteLog(log.ToString());
                    return 0;
                }
                catch (Exception error)
                {
                    log.AppendLine("失败：" + error.Message);
                    WriteLog(log.ToString());
                    return 1;
                }
            }

            if (uninstall)
            {
                Application.Run(new UninstallWindow());
                return 0;
            }
            Application.Run(new InstallWindow());
            return 0;
        }

        internal static void WriteLog(string text)
        {
            try
            {
                string path = Path.Combine(Path.GetTempPath(), "ccgait-setup.log");
                File.WriteAllText(path, text, new UTF8Encoding(false));
            }
            catch
            {
                // 日志写不了不影响安装结果。
            }
        }

        /// <summary>解析内嵌载荷（自定义文本格式，避免引入 JSON 依赖）。</summary>
        internal static List<PayloadFile> ReadPayload()
        {
            var files = new List<PayloadFile>();
            Assembly assembly = Assembly.GetExecutingAssembly();
            using (Stream stream = assembly.GetManifestResourceStream("CcgaitPayload"))
            {
                if (stream == null) throw new InvalidOperationException("安装包缺少内嵌载荷");
                using (var reader = new StreamReader(stream, Encoding.UTF8))
                {
                    string line;
                    string currentPath = null;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.StartsWith("##FILE ", StringComparison.Ordinal))
                        {
                            currentPath = line.Substring(7);
                            continue;
                        }
                        if (currentPath == null || line.Length == 0) continue;
                        byte[] content = Convert.FromBase64String(line);
                        files.Add(new PayloadFile { RelativePath = currentPath, Content = content });
                        currentPath = null;
                    }
                }
            }
            return files;
        }

        internal static string ResolveNode()
        {
            string path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
            foreach (string dir in path.Split(';'))
            {
                if (dir.Trim().Length == 0) continue;
                try
                {
                    string candidate = Path.Combine(dir.Trim(), "node.exe");
                    if (File.Exists(candidate)) return candidate;
                }
                catch (ArgumentException) { }
            }
            return null;
        }

        internal static bool CreateShortcut(string linkPath, string target, string arguments, string iconPath, string workingDirectory)
        {
            try
            {
                Type shellType = Type.GetTypeFromProgID("WScript.Shell");
                if (shellType == null) return false;
                object shell = Activator.CreateInstance(shellType);
                object shortcut = shellType.InvokeMember("CreateShortcut", BindingFlags.InvokeMethod, null, shell, new object[] { linkPath });
                Type shortcutType = shortcut.GetType();
                shortcutType.InvokeMember("TargetPath", BindingFlags.SetProperty, null, shortcut, new object[] { target });
                shortcutType.InvokeMember("Arguments", BindingFlags.SetProperty, null, shortcut, new object[] { arguments });
                shortcutType.InvokeMember("WorkingDirectory", BindingFlags.SetProperty, null, shortcut, new object[] { workingDirectory });
                if (File.Exists(iconPath))
                {
                    shortcutType.InvokeMember("IconLocation", BindingFlags.SetProperty, null, shortcut, new object[] { iconPath + ",0" });
                }
                shortcutType.InvokeMember("Description", BindingFlags.SetProperty, null, shortcut, new object[] { "CCGait - Claude client environment gate" });
                shortcutType.InvokeMember("Save", BindingFlags.InvokeMethod, null, shortcut, null);
                return File.Exists(linkPath);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// 开机自启：与其他 Windows 客户端一致，写 HKCU 的 Run 项 —— 按用户生效、
        /// 不需要管理员，用户可在「任务管理器 → 启动应用」里随时关闭。
        /// </summary>
        internal static bool EnableAutoStart()
        {
            try
            {
                using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run"))
                {
                    if (key == null) return false;
                    key.SetValue("CCGait", "\"" + Path.Combine(Program.InstallDir, "CCGaitClient.exe") + "\" tray");
                }
                return true;
            }
            catch
            {
                return false;
            }
        }

        internal static void DisableAutoStart()
        {
            try
            {
                using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run", true))
                {
                    if (key != null) key.DeleteValue("CCGait", false);
                }
            }
            catch
            {
                // 删不掉时不阻塞卸载。
            }
        }

        internal static bool AutoStartEnabled()
        {
            try
            {
                using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                    @"Software\Microsoft\Windows\CurrentVersion\Run", false))
                {
                    if (key == null) return false;
                    return !string.IsNullOrEmpty(key.GetValue("CCGait") as string);
                }
            }
            catch
            {
                return false;
            }
        }

        internal static string StartMenuLink
        {
            get
            {
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "Microsoft", "Windows", "Start Menu", "Programs", "CCGait.lnk");
            }
        }

        internal static string DesktopLink
        {
            get
            {
                return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
                    "CCGait.lnk");
            }
        }
    }

    /// <summary>
    /// 停闸门：走 CLI 自己的停止语义，而不是直接杀进程。
    ///
    /// 为什么不能直接杀：闸门退出时会撤掉防火墙规则与 WFP 内核过滤器；直接杀进程
    /// 会把这些阻断留在机器上，用户升级/卸载完发现"某个程序还是上不了网"。
    /// </summary>
    internal static class GuardControl
    {
        internal static void Stop(StringBuilder log)
        {
            string node = Program.ResolveNode();
            if (node == null) return;
            try
            {
                var info = new ProcessStartInfo(node)
                {
                    Arguments = "\"" + Path.Combine(Program.InstallDir, "src", "cli.js") + "\" guard-stop",
                    WorkingDirectory = Program.InstallDir,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WindowStyle = ProcessWindowStyle.Hidden,
                };
                using (Process process = Process.Start(info))
                {
                    if (process != null) process.WaitForExit(15000);
                }
                log.AppendLine("已请求闸门停止并清理阻断");
            }
            catch (Exception error)
            {
                log.AppendLine("停止闸门失败：" + error.Message);
            }
        }
    }

    internal sealed class PayloadFile
    {
        internal string RelativePath;
        internal byte[] Content;
    }

    internal sealed class InstallOptions
    {
        internal bool CreateDesktopShortcut;
        internal bool StartTray;
        /// <summary>开机自启（HKCU Run 项）。安装界面默认勾选。</summary>
        internal bool EnableAutoStart = true;
        /// <summary>解包前是否先结束正在运行的 CCGait 进程（托盘 / WFP 宿主）。默认是。</summary>
        internal bool StopRunning = true;
    }

    internal static class Installer
    {
        /// <summary>
        /// 找出正在从安装目录运行的本程序进程（托盘、WFP 阻断宿主）。
        ///
        /// 为什么必须处理：WFP 宿主 `CCGaitWfp.exe` 常驻期间会锁住自己的 exe，
        /// 直接覆盖会抛 "The process cannot access the file ... because it is being
        /// used by another process" —— 那是 .NET 的英文异常，用户看了完全不知道要做什么。
        /// 实测就是这样：升级安装必然失败，除非先手动结束它。
        /// </summary>
        internal static List<Process> RunningInstances()
        {
            var found = new List<Process>();
            string root = Program.InstallDir.TrimEnd('\\') + "\\";
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    string path = process.MainModule.FileName;
                    if (path != null && path.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                    {
                        found.Add(process);
                    }
                }
                catch
                {
                    // 读不到路径（权限/位数不同）就跳过，不影响安装。
                }
            }
            return found;
        }

        /// <summary>结束这些进程并等它们真的退出。返回被结束的数量。</summary>
        internal static int StopRunningInstances(StringBuilder log)
        {
            List<Process> running = RunningInstances();
            if (running.Count == 0)
            {
                log.AppendLine("没有正在运行的 CCGait 进程");
                return 0;
            }

            // 先请闸门按自己的语义收尾（撤掉防火墙规则与 WFP 过滤器），再结束进程。
            // 直接杀进程会把阻断留在机器上，用户会以为"卸载/升级后还上不了网"。
            GuardControl.Stop(log);

            int killed = 0;
            foreach (Process process in running)
            {
                int pid = 0;
                string name = "?";
                try
                {
                    pid = process.Id;
                    name = process.ProcessName;
                    process.Kill();
                    process.WaitForExit(5000);
                    killed++;
                    log.AppendLine("已结束进程：" + name + "（PID " + pid + "）");
                }
                catch (Exception error)
                {
                    // 进程已经自己退出了不算失败 —— 前面的 guard-stop 会让宿主正常收尾，
                    // 等我们动手时它可能已经没了。报"失败"会让人以为没处理干净。
                    if (process.HasExited)
                    {
                        killed++;
                        log.AppendLine("进程已自行退出：" + name + "（PID " + pid + "）");
                    }
                    else
                    {
                        log.AppendLine("结束进程失败：" + pid + " —— " + error.Message);
                    }
                }
                finally
                {
                    process.Dispose();
                }
            }
            // 文件句柄释放有一点点延迟，给系统一点时间，否则紧接着的覆盖仍可能失败。
            Thread.Sleep(600);
            return killed;
        }

        /// <summary>写文件；被占用时重试几次，最后给出中文可操作的报错。</summary>
        private static void WriteFileWithRetry(string destination, byte[] content)
        {
            // 注意：不能用 `catch (...) when (...)` 异常过滤器 —— 那是 C# 6 语法，
            // 随 .NET Framework 附带的 csc 只支持到 C# 5。
            const int attempts = 5;
            Exception last = null;
            for (int attempt = 1; attempt <= attempts; attempt++)
            {
                try
                {
                    File.WriteAllBytes(destination, content);
                    return;
                }
                catch (Exception error)
                {
                    last = error;
                    bool retryable = error is IOException || error is UnauthorizedAccessException;
                    if (!retryable || attempt == attempts) break;
                    Thread.Sleep(400);
                }
            }
            throw new IOException(
                "无法写入 " + destination + "：" + (last == null ? "未知原因" : last.Message) +
                "\n常见原因：CCGait 或它的网络阻断宿主还在运行（托盘图标 / CCGaitWfp.exe）。" +
                "\n请先退出托盘程序再重试；也可以在任务管理器里结束 CCGaitWfp.exe。",
                last);
        }

        /// <summary>执行安装；抛异常表示失败，调用方负责展示与退出码。</summary>
        internal static void Run(StringBuilder log, InstallOptions options)
        {
            log.AppendLine("安装目录：" + Program.InstallDir);

            // 先结束占用安装目录的进程，否则解包必然失败。
            if (options.StopRunning)
            {
                StopRunningInstances(log);
            }

            List<PayloadFile> payload = Program.ReadPayload();
            log.AppendLine("载荷文件数：" + payload.Count);

            Directory.CreateDirectory(Program.InstallDir);
            foreach (PayloadFile file in payload)
            {
                string destination = Path.Combine(Program.InstallDir, file.RelativePath.Replace('/', '\\'));
                Directory.CreateDirectory(Path.GetDirectoryName(destination));
                WriteFileWithRetry(destination, file.Content);
            }
            log.AppendLine("已解包 " + payload.Count + " 个文件");

            // 把安装程序自身复制进安装目录：卸载项指向的就是它，而它不可能被内嵌进
            // 自己的载荷里（编译顺序决定），所以安装时自复制一份。
            try
            {
                string selfPath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                string selfTarget = Path.Combine(Program.InstallDir, "CCGaitSetup.exe");
                if (!string.Equals(selfPath, selfTarget, StringComparison.OrdinalIgnoreCase))
                {
                    File.Copy(selfPath, selfTarget, true);
                    log.AppendLine("已部署卸载程序 CCGaitSetup.exe");
                }
            }
            catch (Exception copyError)
            {
                log.AppendLine("部署卸载程序失败：" + copyError.Message);
            }

            // config.json：首次安装时从示例生成，已有配置不覆盖。
            string configPath = Path.Combine(Program.InstallDir, "config.json");
            string examplePath = Path.Combine(Program.InstallDir, "config.example.json");
            if (!File.Exists(configPath) && File.Exists(examplePath))
            {
                File.Copy(examplePath, configPath);
                log.AppendLine("已生成默认配置 config.json");
            }

            // 首次运行生成图标与状态目录（客户端 exe 也会做，这里提前保证快捷方式有图标）。
            string clientExe = Path.Combine(Program.InstallDir, "CCGaitClient.exe");
            string iconPath = Path.Combine(Program.InstallDir, ".ccgait", "ccgait.ico");
            if (!Directory.Exists(Path.Combine(Program.InstallDir, ".ccgait")))
            {
                Directory.CreateDirectory(Path.Combine(Program.InstallDir, ".ccgait"));
            }
            if (!File.Exists(iconPath))
            {
                string node = Program.ResolveNode();
                if (node != null && File.Exists(clientExe))
                {
                    try
                    {
                        // 让客户端自己生成图标（同一套自绘图标代码，避免两处实现）
                        RunHidden(node, "\"" + Path.Combine(Program.InstallDir, "src", "cli.js") + "\" targets", Program.InstallDir, 20000);
                    }
                    catch { }
                }
            }

            string startMenu = Program.StartMenuLink;
            Directory.CreateDirectory(Path.GetDirectoryName(startMenu));
            bool startMenuOk = Program.CreateShortcut(startMenu, clientExe, "", iconPath, Program.InstallDir);
            log.AppendLine("开始菜单快捷方式：" + (startMenuOk ? "已创建" : "创建失败") + " -> " + startMenu);
            if (!startMenuOk) throw new InvalidOperationException("开始菜单快捷方式创建失败");

            if (options.CreateDesktopShortcut)
            {
                bool desktopOk = Program.CreateShortcut(Program.DesktopLink, clientExe, "", iconPath, Program.InstallDir);
                log.AppendLine("桌面快捷方式：" + (desktopOk ? "已创建" : "创建失败"));
            }

            string uninstaller = Path.Combine(Program.InstallDir, "CCGaitSetup.exe");
            string uninstallString = "\"" + uninstaller + "\" --uninstall";
            using (Microsoft.Win32.RegistryKey key = Microsoft.Win32.Registry.CurrentUser.CreateSubKey(Program.UninstallKey))
            {
                if (key != null)
                {
                    key.SetValue("DisplayName", Program.ProductName);
                    key.SetValue("DisplayVersion", Program.Version);
                    key.SetValue("Publisher", Program.Publisher);
                    key.SetValue("InstallLocation", Program.InstallDir);
                    key.SetValue("DisplayIcon", iconPath);
                    key.SetValue("UninstallString", uninstallString);
                    key.SetValue("NoModify", 1);
                    key.SetValue("NoRepair", 1);
                }
            }
            log.AppendLine("已注册卸载项（HKCU）");

            if (options.EnableAutoStart)
            {
                bool autoStart = Program.EnableAutoStart();
                log.AppendLine("开机自启：" + (autoStart ? "已开启（HKCU Run）" : "开启失败"));
            }
            else
            {
                Program.DisableAutoStart();
                log.AppendLine("开机自启：未开启");
            }

            string nodePath = Program.ResolveNode();
            log.AppendLine("Node.js：" + (nodePath ?? "未检测到（客户端需要 Node 20+）"));

            if (options.StartTray && nodePath != null)
            {
                Process.Start(new ProcessStartInfo(clientExe) { Arguments = "tray", UseShellExecute = false });
                log.AppendLine("已启动托盘");
            }
            log.AppendLine("安装完成");
        }

        private static void RunHidden(string file, string arguments, string workingDirectory, int timeoutMs)
        {
            var info = new ProcessStartInfo(file)
            {
                Arguments = arguments,
                WorkingDirectory = workingDirectory,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            using (Process process = Process.Start(info))
            {
                if (process != null) process.WaitForExit(timeoutMs);
            }
        }
    }

    internal static class Uninstaller
    {
        /// <summary>卸载：删快捷方式与注册项；keepConfig 为真时保留 config.json 与 .ccgait。</summary>
        internal static void Run(StringBuilder log, bool keepConfig)
        {
            string startMenu = Program.StartMenuLink;
            if (File.Exists(startMenu))
            {
                File.Delete(startMenu);
                log.AppendLine("已删除开始菜单快捷方式");
            }
            string desktop = Program.DesktopLink;
            if (File.Exists(desktop))
            {
                File.Delete(desktop);
                log.AppendLine("已删除桌面快捷方式");
            }

            if (Program.AutoStartEnabled())
            {
                Program.DisableAutoStart();
                log.AppendLine("已移除开机自启项");
            }

            try
            {
                Microsoft.Win32.Registry.CurrentUser.DeleteSubKeyTree(Program.UninstallKey, false);
                log.AppendLine("已移除卸载项注册");
            }
            catch (Exception error)
            {
                log.AppendLine("移除卸载项注册失败：" + error.Message);
            }

            // 先停掉可能还在跑的托盘/服务，否则文件占用导致删不干净。
            StopProcesses(log);

            if (keepConfig)
            {
                log.AppendLine("保留配置：config.json 与 .ccgait 目录（含白名单与状态）");
                DeleteTreeExcept(Program.InstallDir, new[] { "config.json", ".ccgait" });
            }
            else
            {
                if (Directory.Exists(Program.InstallDir))
                {
                    Directory.Delete(Program.InstallDir, true);
                }
                log.AppendLine("已删除安装目录");
            }
            // 卸载程序删不掉自己（正在运行的 exe 无法自删），交给一个延迟启动的 cmd
            // 在进程退出后再删；rmdir 只在目录为空时成功，所以保留的配置不会被误删。
            try
            {
                string selfPath = System.Reflection.Assembly.GetExecutingAssembly().Location;
                string directory = Program.InstallDir;
                if (selfPath.StartsWith(directory, StringComparison.OrdinalIgnoreCase))
                {
                    var cleanup = new ProcessStartInfo("cmd.exe")
                    {
                        Arguments = "/c timeout /t 2 /nobreak >nul & del /f /q \"" + selfPath + "\" & rmdir \"" + directory + "\" 2>nul",
                        UseShellExecute = false,
                        CreateNoWindow = true,
                        WindowStyle = ProcessWindowStyle.Hidden,
                    };
                    Process.Start(cleanup);
                    log.AppendLine("已安排删除卸载程序自身");
                }
            }
            catch (Exception cleanupError)
            {
                log.AppendLine("自删除安排失败：" + cleanupError.Message);
            }

            log.AppendLine("卸载完成");
        }

        private static void StopProcesses(StringBuilder log)
        {
            // 1) 先结束自家的托盘/客户端进程，否则它占着 CCGaitClient.exe，删不干净。
            foreach (string name in new[] { "CCGaitClient" })
            {
                foreach (System.Diagnostics.Process process in System.Diagnostics.Process.GetProcessesByName(name))
                {
                    try
                    {
                        process.Kill();
                        process.WaitForExit(5000);
                        log.AppendLine("已结束客户端进程：" + name + " #" + process.Id);
                    }
                    catch (Exception error)
                    {
                        log.AppendLine("结束进程失败（" + name + " #" + process.Id + "）：" + error.Message);
                    }
                }
            }

            // 2) 用 CLI 自己的停止语义收尾闸门（会撤掉防火墙阻断与 WFP 过滤器）。
            GuardControl.Stop(log);
        }

        private static void DeleteTreeExcept(string root, string[] keep)
        {
            var keepSet = new HashSet<string>(keep, StringComparer.OrdinalIgnoreCase);
            foreach (string file in Directory.GetFiles(root))
            {
                if (keepSet.Contains(Path.GetFileName(file))) continue;
                TryDelete(file);
            }
            foreach (string dir in Directory.GetDirectories(root))
            {
                if (keepSet.Contains(Path.GetFileName(dir))) continue;
                TryDeleteTree(dir);
            }
        }

        private static void TryDelete(string path)
        {
            try { File.Delete(path); } catch { }
        }

        private static void TryDeleteTree(string path)
        {
            try { Directory.Delete(path, true); } catch
            {
                // 文件被占用时逐个尝试，最后留下少量残留也不阻塞卸载。
                try
                {
                    foreach (string file in Directory.GetFiles(path, "*", SearchOption.AllDirectories)) TryDelete(file);
                    Directory.Delete(path, true);
                }
                catch { }
            }
        }
    }

    // ------------------------------------------------------------------ 界面

    internal sealed class InstallWindow : Form
    {
        private readonly TextBox _status;
        private readonly CheckBox _desktop;
        private readonly CheckBox _autoStart;
        private readonly CheckBox _startTray;
        private readonly Button _install;
        private readonly Button _openUi;
        private readonly ProgressBar _progress;
        private bool _installed;
        private bool _startTrayRequested;

        internal InstallWindow()
        {
            Text = "CCGait 安装程序";
            ClientSize = new Size(560, 410);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            BackColor = Color.FromArgb(255, 255, 255);
            ForeColor = Color.FromArgb(28, 28, 28);
            Font = new Font("Microsoft YaHei UI", 9f);

            var title = new Label
            {
                Text = "CCGait · Claude 客户端环境闸门",
                Font = new Font("Microsoft YaHei UI", 13f, FontStyle.Bold),
                Location = new Point(22, 18),
                AutoSize = true,
            };
            var subtitle = new Label
            {
                Text = "出口 IP / 国家不符合白名单时，阻止 Claude Code CLI 与 Claude Desktop 启动并阻断其网络。",
                Location = new Point(24, 50),
                Size = new Size(510, 40),
                ForeColor = Color.FromArgb(138, 138, 138),
            };
            var target = new Label
            {
                Text = "安装位置：" + Program.InstallDir + "（按用户安装，无需管理员）",
                Location = new Point(24, 92),
                Size = new Size(510, 20),
                ForeColor = Color.FromArgb(160, 160, 160),
            };

            _desktop = new CheckBox
            {
                Text = "创建桌面快捷方式",
                Location = new Point(24, 120),
                Size = new Size(240, 24),
                Checked = true,
            };
            _autoStart = new CheckBox
            {
                Text = "开机自启（登录时自动启动托盘）",
                Location = new Point(24, 146),
                Size = new Size(320, 24),
                Checked = true,
            };
            _startTray = new CheckBox
            {
                Text = "安装后启动托盘（常驻状态图标）",
                Location = new Point(24, 172),
                Size = new Size(320, 24),
                Checked = true,
            };

            _install = new Button
            {
                Text = "开始安装",
                Location = new Point(24, 206),
                Size = new Size(140, 34),
                BackColor = Color.FromArgb(31, 31, 31),
                ForeColor = Color.FromArgb(255, 255, 255),
                FlatStyle = FlatStyle.Flat,
            };
            _install.Click += OnInstall;

            _openUi = new Button
            {
                Text = "打开界面",
                Location = new Point(176, 206),
                Size = new Size(120, 34),
                Enabled = false,
                FlatStyle = FlatStyle.Flat,
            };
            _openUi.Click += (s, e) =>
            {
                string exe = Path.Combine(Program.InstallDir, "CCGaitClient.exe");
                if (File.Exists(exe)) Process.Start(new ProcessStartInfo(exe) { UseShellExecute = false });
            };

            _progress = new ProgressBar
            {
                Location = new Point(24, 252),
                Size = new Size(510, 8),
                Style = ProgressBarStyle.Continuous,
                Maximum = 100,
            };

            _status = new TextBox
            {
                Location = new Point(24, 270),
                Size = new Size(510, 92),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(250, 250, 250),
                ForeColor = Color.FromArgb(74, 74, 74),
                // 日志框里有中文。Consolas 没有中文字形，WinForms 在这里不会自动回退，
                // 结果中文全渲染成方块（实测：日志框一片 □，而用微软雅黑的标题正常）。
                Font = new Font("Microsoft YaHei UI", 8.5f),
                BorderStyle = BorderStyle.FixedSingle,
            };

            Controls.AddRange(new Control[] { title, subtitle, target, _desktop, _autoStart, _startTray, _install, _openUi, _progress, _status });
        }

        private void Log(string line)
        {
            _status.AppendText(line + Environment.NewLine);
            _status.SelectionStart = _status.TextLength;
            _status.ScrollToCaret();
            Application.DoEvents();
        }

        private void OnInstall(object sender, EventArgs e)
        {
            if (_installed) return;
            _install.Enabled = false;
            _progress.Value = 15;
            var log = new StringBuilder();
            try
            {
                Log("开始安装到 " + Program.InstallDir);

                // 正在运行就先问一句。不问直接杀、或直接抛英文异常，都不合适：
                // 前者会让用户莫名其妙发现"我的阻断没了"，后者他根本看不懂要做什么。
                List<Process> running = Installer.RunningInstances();
                if (running.Count > 0)
                {
                    var names = new List<string>();
                    foreach (Process process in running)
                    {
                        try
                        {
                            names.Add(process.ProcessName + "（PID " + process.Id + "）");
                        }
                        catch
                        {
                            // 拿不到名字就只报数量。
                        }
                    }
                    string detail = names.Count > 0 ? string.Join("、", names.ToArray()) : ("共 " + running.Count + " 个进程");
                    DialogResult answer = MessageBox.Show(
                        "CCGait 正在运行：\n\n" + detail +
                        "\n\n安装需要覆盖这些正在使用的程序文件，必须先把它们结束。\n" +
                        "结束后：托盘图标会消失，生效中的网络阻断会被撤掉（安装完成后会自动重新启动托盘）。\n\n" +
                        "现在就结束并继续安装吗？",
                        "CCGait 安装程序",
                        MessageBoxButtons.YesNo,
                        MessageBoxIcon.Warning,
                        MessageBoxDefaultButton.Button1);
                    if (answer != DialogResult.Yes)
                    {
                        Log("已取消：CCGait 正在运行，安装需要先结束它。");
                        _progress.Value = 0;
                        _install.Enabled = true;
                        return;
                    }
                    Log("正在结束正在运行的 CCGait 进程…");
                }

                _startTrayRequested = _startTray.Checked;
                Installer.Run(log, new InstallOptions
                {
                    CreateDesktopShortcut = _desktop.Checked,
                    EnableAutoStart = _autoStart.Checked,
                    StartTray = false, // 界面线程里不直接拉起托盘，安装完成后按需启动
                    StopRunning = true,
                });
                _progress.Value = 85;
                foreach (string line in log.ToString().Split('\n'))
                {
                    if (line.Trim().Length > 0) Log(line.TrimEnd());
                }

                if (Program.ResolveNode() == null)
                {
                    Log("");
                    Log("警告：未检测到 Node.js（需要 20 以上版本）。");
                    Log("请先安装 Node.js 后再启动客户端：https://nodejs.org/");
                }

                _installed = true;
                _progress.Value = 100;
                _install.Text = "已安装";
                _openUi.Enabled = true;
                Log("");
                Log("安装完成。可用开始菜单的 CCGait 启动客户端。");

                if (_startTrayRequested && Program.ResolveNode() != null)
                {
                    string exe = Path.Combine(Program.InstallDir, "CCGaitClient.exe");
                    if (File.Exists(exe))
                    {
                        Process.Start(new ProcessStartInfo(exe) { Arguments = "tray", UseShellExecute = false });
                        Log("已启动托盘（通知区域图标）");
                    }
                }
            }
            catch (Exception error)
            {
                _progress.Value = 0;
                _install.Enabled = true;
                Log("安装失败：" + error.Message);
                MessageBox.Show("安装失败：" + error.Message, "CCGait", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }

    internal sealed class UninstallWindow : Form
    {
        private readonly CheckBox _keepConfig;
        private readonly TextBox _status;
        private readonly Button _uninstall;

        internal UninstallWindow()
        {
            Text = "CCGait 卸载";
            ClientSize = new Size(520, 320);
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            BackColor = Color.FromArgb(255, 255, 255);
            ForeColor = Color.FromArgb(28, 28, 28);
            Font = new Font("Microsoft YaHei UI", 9f);

            Controls.Add(new Label
            {
                Text = "卸载 CCGait",
                Font = new Font("Microsoft YaHei UI", 13f, FontStyle.Bold),
                Location = new Point(22, 18),
                AutoSize = true,
            });
            Controls.Add(new Label
            {
                Text = "将移除程序文件、快捷方式与卸载项，并停止正在运行的闸门（含防火墙阻断）。",
                Location = new Point(24, 50),
                Size = new Size(470, 40),
                ForeColor = Color.FromArgb(138, 138, 138),
            });

            _keepConfig = new CheckBox
            {
                Text = "保留配置与日志（config.json、.ccgait 目录）",
                Location = new Point(24, 96),
                Size = new Size(400, 24),
                Checked = true,
            };
            Controls.Add(_keepConfig);

            _uninstall = new Button
            {
                Text = "确认卸载",
                Location = new Point(24, 132),
                Size = new Size(140, 34),
                BackColor = Color.FromArgb(180, 35, 24),
                ForeColor = Color.FromArgb(255, 255, 255),
                FlatStyle = FlatStyle.Flat,
            };
            _uninstall.Click += OnUninstall;
            Controls.Add(_uninstall);

            _status = new TextBox
            {
                Location = new Point(24, 180),
                Size = new Size(470, 116),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(250, 250, 250),
                ForeColor = Color.FromArgb(74, 74, 74),
                // 日志框里有中文。Consolas 没有中文字形，WinForms 在这里不会自动回退，
                // 结果中文全渲染成方块（实测：日志框一片 □，而用微软雅黑的标题正常）。
                Font = new Font("Microsoft YaHei UI", 8.5f),
            };
            Controls.Add(_status);
        }

        private void OnUninstall(object sender, EventArgs e)
        {
            _uninstall.Enabled = false;
            var log = new StringBuilder();
            try
            {
                Uninstaller.Run(log, _keepConfig.Checked);
                _status.AppendText(log.ToString());
            }
            catch (Exception error)
            {
                _status.AppendText("卸载失败：" + error.Message);
            }
            _status.AppendText(Environment.NewLine + "可以关闭此窗口了。" + Environment.NewLine);
            Application.DoEvents();
            MessageBox.Show("卸载完成。", "CCGait", MessageBoxButtons.OK, MessageBoxIcon.Information);
            Close();
        }
    }
}
