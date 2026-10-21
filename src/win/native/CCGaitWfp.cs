// CCGait 网络阻断（WFP 版）：用 Windows Filtering Platform 给指定程序加"禁止出站"过滤器
//
//   CCGaitWfp.exe hold <exe路径> [更多路径...]   加过滤器并常驻（stdin 关闭即退出，过滤器随之消失）
//   CCGaitWfp.exe check <exe路径>                用 curl 探针自测能否阻断（一次性，测完即清理）
//
// 为什么需要它：Windows 防火墙的规则只有在「防火墙配置文件启用」时才生效 —— 如果用户
// 不想打开系统防火墙，按程序阻断就完全空转（已实测：防火墙关闭时规则被忽略）。
// WFP 是防火墙本身使用的内核过滤层，**直接挂过滤器不依赖防火墙配置文件是否开启**，
// 而且动态会话的过滤器在本进程退出时自动消失，不会给机器留下改不回来的状态。
//
// 安全设计（这是内核级过滤，必须保守）：
//   1. 过滤器一律带 ALE_APP_ID 条件，只匹配指定的可执行文件，不可能波及别的程序；
//   2. 取不到 app-id 时直接放弃，绝不添加"没有程序条件"的过滤器；
//   3. 只加 ALE_AUTH_CONNECT（出站连接授权）层的 BLOCK，不碰入站与其它层；
//   4. 会话作用域：本进程一退出过滤器就没了（失败开放，不会把用户网络锁死）；
//   5. 每条过滤器都回查（FwpmFilterGetById0）确认真的写进去了才算成功。

using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace CcgaitWfp
{
    internal static class Program
    {
        private const uint FWP_ACTION_BLOCK = 0x00001001;
        private const uint FWP_MATCH_EQUAL = 0;
        private const uint FWP_BYTE_BLOB_TYPE = 12;
        // FWP_DATA_TYPE：FWP_V4_ADDR_MASK 不是顺序值，等于 FWP_SINGLE_DATA_TYPE_MAX(0xff) + 1。
        private const uint FWP_V4_ADDR_MASK_TYPE = 0x100;
        private const uint FWP_MATCH_NOT_EQUAL = 10;
        private const uint RPC_C_AUTHN_WINNT = 10;
        private const uint RPC_C_AUTHZ_NONE = 0;
        // 会话级作用域：会话结束（含进程被硬杀）时，本会话加的对象由 BFE 自动清理。
        private const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;

        // 值取自本机 Windows SDK：C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\fwpmu.h
        private static readonly Guid LayerAleAuthConnectV4 = new Guid("c38d57d1-05a7-4c33-904f-7fbceee60e82");
        private static readonly Guid LayerAleAuthConnectV6 = new Guid("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");
        private static readonly Guid ConditionAleAppId = new Guid("d78e1e87-8644-4ea5-9437-d809ecefc971");
        // 远端地址条件。实测：ALE_AUTH_CONNECT_V4 接受通用 GUID，传 _V4 变体会返回
        // FWP_E_CONDITION_NOT_FOUND(0x80320002)。详见 .ccgait 下的验证记录。
        private static readonly Guid ConditionIpRemoteAddress = new Guid("b235ae9a-1d64-49b8-a44c-5ff3d9095045");
        private static readonly Guid SubLayerKey = new Guid("9e3b1b0a-2c4d-4f8e-9a11-5c7d3f2b8e01");

        // FWPM_FILTER0（x64）字段偏移。取值依据本机 SDK 的 shared\fwpmtypes.h：
        // filterKey(0) displayData(16) flags(32) providerKey 是指针(40) providerData(48)
        // layerKey(64) subLayerKey(80) weight(96) numFilterConditions(112)
        // filterCondition(120) action(128) union(152) reserved 指针(168) filterId(176)
        private const int OffsetLayerKey = 64;
        private const int OffsetSubLayerKey = 80;
        private const int OffsetNumConditions = 112;
        private const int OffsetActionType = 128;
        private const int OffsetFilterId = 176;

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmEngineOpen0(string serverName, uint authnService, IntPtr authIdentity,
            IntPtr session, out IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmEngineClose0(IntPtr engineHandle);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmSubLayerAdd0(IntPtr engineHandle, IntPtr subLayer, IntPtr sd);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmGetAppIdFromFileName0(string fileName, out IntPtr appId);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmFilterAdd0(IntPtr engineHandle, IntPtr filter, IntPtr sd, out ulong filterId);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmFilterDeleteById0(IntPtr engineHandle, ulong filterId);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmFilterGetById0(IntPtr engineHandle, ulong filterId, out IntPtr filter);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern void FwpmFreeMemory0(ref IntPtr p);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmLayerGetByKey0(IntPtr engineHandle, IntPtr layerKey, out IntPtr layer);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmSubLayerGetByKey0(IntPtr engineHandle, IntPtr subLayerKey, out IntPtr subLayer);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmLayerCreateEnumHandle0(IntPtr engineHandle, IntPtr enumTemplate, out IntPtr enumHandle);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmLayerEnum0(IntPtr engineHandle, IntPtr enumHandle, uint numEntriesRequested,
            out IntPtr entries, out uint numEntriesReturned);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmLayerDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmFilterCreateEnumHandle0(IntPtr engineHandle, IntPtr enumTemplate, out IntPtr enumHandle);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmFilterEnum0(IntPtr engineHandle, IntPtr enumHandle, uint numEntriesRequested,
            out IntPtr entries, out uint numEntriesReturned);

        [DllImport("fwpuclnt.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        private static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

        /// <summary>FWPM_SUBLAYER0（手工布局，只用到前几个字段）。</summary>
        private static IntPtr BuildSubLayer()
        {
            IntPtr buffer = Marshal.AllocHGlobal(256);
            for (int offset = 0; offset < 256; offset += 8) Marshal.WriteInt64(buffer, offset, 0);
            byte[] key = SubLayerKey.ToByteArray();
            Marshal.Copy(key, 0, buffer, 16);
            // displayData.name / .description
            Marshal.WriteIntPtr(buffer, 16, Marshal.StringToHGlobalUni("CCGait"));
            Marshal.WriteIntPtr(buffer, 24, Marshal.StringToHGlobalUni("CCGait environment gate"));
            // flags(32) = 0, providerKey(40) = null, providerData(48) = {0,null}, weight(64) = 0x100
            Marshal.WriteInt16(buffer, 64, 0x100);
            return buffer;
        }

        /// <summary>
        /// FWPM_FILTER0：手工按 x64 自然对齐写前导字段（filterKey…action）。
        /// 尾部（context/filterId/effectiveWeight）保持全零，Add 只读它认识的字段。
        ///
        /// excludeLoopback=true 时追加条件「远端地址 != 127.0.0.1」。
        /// 这是给浏览器用的：浏览器同时承载 CCGait 界面（APP 模式，访问 127.0.0.1），
        /// 一刀切全封会把界面一起打死（实测：阻断程序后连 127.0.0.1 都返回 000）。
        /// 加了这个条件，浏览器上不了外网、但本地界面照常。
        /// </summary>
        private static IntPtr BuildFilter(Guid layerKey, IntPtr appIdBlob, bool excludeLoopback,
            out IntPtr conditionBuffer, out IntPtr addrMaskBuffer)
        {
            bool hasIpCondition = excludeLoopback;
            int conditionCount = hasIpCondition ? 2 : 1;
            // FWPM_FILTER_CONDITION0 是 40 字节：fieldKey(0..16) matchType(16) 填充(20)
            // conditionValue.type(24) 填充(28) conditionValue.union(32..40)。
            const int ConditionStride = 40;
            int conditionBytes = ConditionStride * conditionCount;

            IntPtr filter = Marshal.AllocHGlobal(256);
            for (int offset = 0; offset < 256; offset += 8) Marshal.WriteInt64(filter, offset, 0);

            Marshal.Copy(Guid.NewGuid().ToByteArray(), 0, filter, 16);          // filterKey
            Marshal.WriteIntPtr(filter, 16, Marshal.StringToHGlobalUni("CCGait block"));
            Marshal.WriteIntPtr(filter, 24, Marshal.StringToHGlobalUni("blocked by CCGait"));
            Marshal.WriteInt32(filter, 32, 0);                                  // flags：动态（会话作用域）
            Marshal.WriteIntPtr(filter, 40, IntPtr.Zero);                       // providerKey
            Marshal.WriteInt32(filter, 48, 0);                                  // providerData.size
            Marshal.WriteIntPtr(filter, 56, IntPtr.Zero);                       // providerData.data
            Marshal.Copy(layerKey.ToByteArray(), 0, filter + 64, 16);           // layerKey
            Marshal.Copy(SubLayerKey.ToByteArray(), 0, filter + 80, 16);        // subLayerKey
            Marshal.WriteInt32(filter, 96, 0);                                  // weight.type = FWP_EMPTY
            Marshal.WriteIntPtr(filter, 104, IntPtr.Zero);
            Marshal.WriteInt32(filter, 112, conditionCount);                    // numFilterConditions
            Marshal.WriteIntPtr(filter, 120, IntPtr.Zero);                      // 稍后回填
            Marshal.WriteInt32(filter, 128, unchecked((int)FWP_ACTION_BLOCK));  // action.type

            conditionBuffer = Marshal.AllocHGlobal(conditionBytes);
            for (int offset = 0; offset < conditionBytes; offset += 8) Marshal.WriteInt64(conditionBuffer, offset, 0);
            addrMaskBuffer = IntPtr.Zero;

            // 条件 1：ALE_APP_ID == <我们的程序>
            Marshal.Copy(ConditionAleAppId.ToByteArray(), 0, conditionBuffer, 16);
            Marshal.WriteInt32(conditionBuffer, 16, unchecked((int)FWP_MATCH_EQUAL));
            Marshal.WriteInt32(conditionBuffer, 24, unchecked((int)FWP_BYTE_BLOB_TYPE));
            Marshal.WriteIntPtr(conditionBuffer, 32, appIdBlob);

            if (hasIpCondition)
            {
                // 条件 2：远端地址 != 127.0.0.1（放行本地回环，其余照拦）
                IntPtr second = conditionBuffer + ConditionStride;
                Marshal.Copy(ConditionIpRemoteAddress.ToByteArray(), 0, second, 16);
                Marshal.WriteInt32(second, 16, unchecked((int)FWP_MATCH_NOT_EQUAL));
                Marshal.WriteInt32(second, 24, unchecked((int)FWP_V4_ADDR_MASK_TYPE));
                addrMaskBuffer = Marshal.AllocHGlobal(8);
                Marshal.WriteInt32(addrMaskBuffer, 0, unchecked((int)0x7F000001)); // 127.0.0.1
                Marshal.WriteInt32(addrMaskBuffer, 4, unchecked((int)0xFFFFFFFF)); // 精确匹配
                Marshal.WriteIntPtr(second, 32, addrMaskBuffer);
            }

            Marshal.WriteIntPtr(filter, 120, conditionBuffer);
            return filter;
        }

        /// <summary>给一个程序加 V4/V6 两条阻断过滤器，返回过滤器 id 列表。</summary>
        private static System.Collections.Generic.List<ulong> AddFilters(IntPtr engine, string exePath, bool excludeLoopback = false)
        {
            var ids = new System.Collections.Generic.List<ulong>();
            IntPtr appId;
            uint status = FwpmGetAppIdFromFileName0(exePath, out appId);
            if (status != 0 || appId == IntPtr.Zero)
            {
                throw new InvalidOperationException(
                    "无法为该程序生成 app-id（0x" + status.ToString("X") + "）"
                    + " path=" + exePath
                    + " exists=" + File.Exists(exePath));
            }
            try
            {
                foreach (Guid layer in new[] { LayerAleAuthConnectV4, LayerAleAuthConnectV6 })
                {
                    IntPtr conditionBuffer;
                    IntPtr addrMaskBuffer;
                    // IPv6 层不能配 FWP_V4_ADDR_MASK（实测报 FWP_E_TYPE_MISMATCH 0x80320027，
                    // 整条过滤器建不起来，连程序级阻断都会失效），所以 V6 一律全封。
                    bool layerExcludeLoopback = excludeLoopback && layer == LayerAleAuthConnectV4;
                    IntPtr filter = BuildFilter(layer, appId, layerExcludeLoopback, out conditionBuffer, out addrMaskBuffer);
                    ulong filterId;
                    try
                    {
                        status = FwpmFilterAdd0(engine, filter, IntPtr.Zero, out filterId);
                        if (status != 0)
                        {
                            throw new InvalidOperationException("添加过滤器失败（层 " + layer + "，0x" + status.ToString("X") + "）");
                        }
                        // 回查：确认真的存在于引擎里。
                        IntPtr verify;
                        uint verifyStatus = FwpmFilterGetById0(engine, filterId, out verify);
                        if (verifyStatus == 0 && verify != IntPtr.Zero)
                        {
                            FwpmFreeMemory0(ref verify);
                            ids.Add(filterId);
                        }
                        else
                        {
                            FwpmFilterDeleteById0(engine, filterId);
                            throw new InvalidOperationException("过滤器回查失败（0x" + verifyStatus.ToString("X") + "）");
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(filter);
                        Marshal.FreeHGlobal(conditionBuffer);
                        if (addrMaskBuffer != IntPtr.Zero) Marshal.FreeHGlobal(addrMaskBuffer);
                    }
                }
            }
            finally
            {
                FwpmFreeMemory0(ref appId);
            }
            return ids;
        }

        /// <summary>按偏移尝试读取 UTF-16 字符串；指针无效或内容不像字符串时返回 null。</summary>
        private static string TryReadString(IntPtr buffer, int offset)
        {
            try
            {
                IntPtr pointer = Marshal.ReadIntPtr(buffer, offset);
                if (pointer == IntPtr.Zero) return null;
                string value = Marshal.PtrToStringUni(pointer);
                if (string.IsNullOrEmpty(value)) return null;
                foreach (char character in value)
                {
                    if (character < 0x20 || character > 0x7e) return null;
                }
                return value.Length > 48 ? value.Substring(0, 48) : value;
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// 打开 WFP 引擎。
        ///
        /// 关键：必须用**动态会话**（FWPM_SESSION_FLAG_DYNAMIC）。非动态会话里加的过滤器
        /// 虽然"非持久"，但进程被硬杀（TerminateProcess，例如任务管理器结束进程、
        /// 或我们自己的按名清扫）时，BFE 不保证及时清理——实测结果是过滤器**永久留下**：
        /// 某个程序从此连不上网，而且看不到任何宿主进程在跑，排查起来毫无头绪。
        /// 动态会话由 BFE 跟踪，会话一结束（含进程被硬杀）对象自动消失。
        ///
        /// <paramref name="dynamic"/> = false 仅用于 purge：动态会话只能操作自己的对象，
        /// 要删掉别的会话留下的过滤器必须用普通会话。
        /// </summary>
        private static IntPtr OpenEngine(bool dynamic = true)
        {
            IntPtr engine;
            IntPtr session = IntPtr.Zero;
            if (dynamic)
            {
                // FWPM_SESSION0（x64 布局）：sessionKey(0..16) displayData.name(16) .description(24)
                // flags(32) txnWaitTimeoutInMSec(36) processId(40) sid(48) username(56) kernelMode(64)
                session = Marshal.AllocHGlobal(72);
                for (int offset = 0; offset < 72; offset += 8) Marshal.WriteInt64(session, offset, 0);
                Marshal.WriteInt32(session, 32, unchecked((int)FWPM_SESSION_FLAG_DYNAMIC));
            }
            try
            {
                uint status = FwpmEngineOpen0(null, RPC_C_AUTHN_WINNT, IntPtr.Zero, session, out engine);
                if (status != 0) throw new InvalidOperationException("打开 WFP 引擎失败（0x" + status.ToString("X") + "）");
            }
            finally
            {
                if (session != IntPtr.Zero) Marshal.FreeHGlobal(session);
            }
            IntPtr subLayer = BuildSubLayer();
            try
            {
                // 已存在时会返回 FWP_E_ALREADY_EXISTS，忽略即可。
                FwpmSubLayerAdd0(engine, subLayer, IntPtr.Zero);
            }
            finally
            {
                Marshal.FreeHGlobal(subLayer);
            }
            return engine;
        }

        /// <summary>
        /// 删掉本工具遗留的所有过滤器（按 subLayerKey 认领），并报告删了几条。
        /// 存在的意义：修复动态会话之前的版本会把过滤器永久留在机器上，
        /// 用户遇到"某个程序莫名其妙上不了网"时，这一条命令就能恢复。
        /// </summary>
        private static int RunPurge()
        {
            IntPtr engine = OpenEngine(false);
            IntPtr enumHandle;
            uint openStatus = FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out enumHandle);
            if (openStatus != 0)
            {
                Console.WriteLine("枚举句柄创建失败 status=0x" + openStatus.ToString("X"));
                FwpmEngineClose0(engine);
                return 1;
            }

            byte[] ours = SubLayerKey.ToByteArray();
            var toDelete = new System.Collections.Generic.List<ulong>();
            int scanned = 0;
            int matched = 0;
            while (true)
            {
                IntPtr entries;
                uint returned;
                uint status = FwpmFilterEnum0(engine, enumHandle, 64, out entries, out returned);
                if (status != 0 || returned == 0) break;
                for (int index = 0; index < returned; index++)
                {
                    IntPtr entry = Marshal.ReadIntPtr(entries, index * IntPtr.Size);
                    scanned++;
                    byte[] subLayer = new byte[16];
                    Marshal.Copy(entry + OffsetSubLayerKey, subLayer, 0, 16);
                    if (Matches(subLayer, ours))
                    {
                        matched++;
                        ulong filterId = (ulong)Marshal.ReadInt64(entry, OffsetFilterId);
                        toDelete.Add(filterId);
                    }
                }
                FwpmFreeMemory0(ref entries);
                if (returned < 64) break;
            }
            FwpmFilterDestroyEnumHandle0(engine, enumHandle);

            int removed = 0;
            foreach (ulong id in toDelete)
            {
                if (FwpmFilterDeleteById0(engine, id) == 0) removed++;
            }
            FwpmEngineClose0(engine);
            Console.WriteLine("PURGED " + removed + "（扫描 " + scanned + " 条，命中本工具 " + matched + " 条）");
            return 0;
        }

        /// <summary>排查用：列出本工具名下过滤器的关键字段，并统计总数。</summary>
        private static int RunListFilters()
        {
            IntPtr engine = OpenEngine(false);
            IntPtr enumHandle;
            uint openStatus = FwpmFilterCreateEnumHandle0(engine, IntPtr.Zero, out enumHandle);
            if (openStatus != 0)
            {
                Console.WriteLine("枚举句柄创建失败 status=0x" + openStatus.ToString("X"));
                FwpmEngineClose0(engine);
                return 1;
            }

            byte[] ours = SubLayerKey.ToByteArray();
            int scanned = 0;
            int shown = 0;
            while (true)
            {
                IntPtr entries;
                uint returned;
                uint status = FwpmFilterEnum0(engine, enumHandle, 64, out entries, out returned);
                if (status != 0 || returned == 0) break;
                for (int index = 0; index < returned; index++)
                {
                    IntPtr entry = Marshal.ReadIntPtr(entries, index * IntPtr.Size);
                    scanned++;
                    byte[] subLayer = new byte[16];
                    Marshal.Copy(entry + OffsetSubLayerKey, subLayer, 0, 16);
                    if (!Matches(subLayer, ours)) continue;
                    ulong filterId = (ulong)Marshal.ReadInt64(entry, OffsetFilterId);
                    int actionType = Marshal.ReadInt32(entry, OffsetActionType);
                    int conditions = Marshal.ReadInt32(entry, OffsetNumConditions);
                    byte[] layer = new byte[16];
                    Marshal.Copy(entry + OffsetLayerKey, layer, 0, 16);
                    Console.WriteLine("  filterId=" + filterId + " 层=" + new Guid(layer) +
                        " 条件数=" + conditions + " 动作=0x" + actionType.ToString("X"));
                    shown++;
                }
                FwpmFreeMemory0(ref entries);
                if (returned < 64) break;
            }
            FwpmFilterDestroyEnumHandle0(engine, enumHandle);
            FwpmEngineClose0(engine);
            Console.WriteLine("LISTED " + shown + "（共扫描 " + scanned + " 条）");
            return 0;
        }

        private static bool Matches(byte[] left, byte[] right)
        {
            if (left.Length != right.Length) return false;
            for (int index = 0; index < left.Length; index++)
            {
                if (left[index] != right[index]) return false;
            }
            return true;
        }

        private static bool Probe(string exePath, string url, int timeoutMs)
        {
            var info = new ProcessStartInfo(exePath)
            {
                Arguments = "-s -m 8 -o NUL -w %{http_code} " + url,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            using (Process process = Process.Start(info))
            {
                string stdout = process.StandardOutput.ReadToEnd();
                string stderr = process.StandardError.ReadToEnd();
                if (!process.WaitForExit(timeoutMs))
                {
                    Console.WriteLine("probe-timeout");
                    try { process.Kill(); } catch { }
                    return false;
                }
                if (process.ExitCode != 0)
                {
                    Console.WriteLine("probe-exit=" + process.ExitCode + " err=" + stderr.Trim().Replace("\r", " ").Replace("\n", " "));
                    return false;
                }
                Console.WriteLine("probe-code=" + stdout.Trim());
                return true;
            }
        }

        private static int Main(string[] args)
        {
            try
            {
                string mode = args.Length > 0 ? args[0].ToLowerInvariant() : "";
                if (mode == "list-layers")
                {
                    // 直接问系统要真实存在的层，避免依赖记忆里的 GUID 常量。
                    IntPtr enumEngine = OpenEngine();
                    IntPtr enumHandle;
                    uint openStatus = FwpmLayerCreateEnumHandle0(enumEngine, IntPtr.Zero, out enumHandle);
                    if (openStatus != 0)
                    {
                        Console.WriteLine("enum-open status=0x" + openStatus.ToString("X"));
                        return 1;
                    }
                    uint total = 0;
                    while (true)
                    {
                        IntPtr entries;
                        uint returned;
                        uint status = FwpmLayerEnum0(enumEngine, enumHandle, 64, out entries, out returned);
                        if (status != 0 || returned == 0) break;
                        for (int index = 0; index < returned; index++)
                        {
                            IntPtr entry = Marshal.ReadIntPtr(entries, index * IntPtr.Size);
                            byte[] raw = new byte[16];
                            Marshal.Copy(entry, raw, 0, 16);
                            string name = TryReadString(entry, 16);
                            if (name != null && name.ToUpperInvariant().Contains("AUTH_CONNECT"))
                            {
                                Console.WriteLine(name + " = " + new Guid(raw));
                            }
                        }
                        FwpmFreeMemory0(ref entries);
                        total += returned;
                        if (returned < 64) break;
                    }
                    FwpmLayerDestroyEnumHandle0(enumEngine, enumHandle);
                    Console.WriteLine("total-layers=" + total);
                    FwpmEngineClose0(enumEngine);
                    return 0;
                }
                if (mode == "probe-layer")
                {
                    IntPtr probeEngine = OpenEngine();
                    foreach (var pair in new[]
                    {
                        new { Name = "ALE_AUTH_CONNECT_V4", Key = LayerAleAuthConnectV4 },
                        new { Name = "ALE_AUTH_CONNECT_V6", Key = LayerAleAuthConnectV6 },
                    })
                    {
                        IntPtr keyBuffer = Marshal.AllocHGlobal(16);
                        Marshal.Copy(pair.Key.ToByteArray(), 0, keyBuffer, 16);
                        IntPtr layer;
                        uint status = FwpmLayerGetByKey0(probeEngine, keyBuffer, out layer);
                        Console.WriteLine(pair.Name + " status=0x" + status.ToString("X") +
                            (status == 0 ? " name=" + Marshal.PtrToStringUni(Marshal.ReadIntPtr(layer, 16)) : ""));
                        if (status == 0) FwpmFreeMemory0(ref layer);
                        Marshal.FreeHGlobal(keyBuffer);
                    }
                    IntPtr subKey = Marshal.AllocHGlobal(16);
                    Marshal.Copy(SubLayerKey.ToByteArray(), 0, subKey, 16);
                    IntPtr sub;
                    uint subStatus = FwpmSubLayerGetByKey0(probeEngine, subKey, out sub);
                    Console.WriteLine("SUBLAYER status=0x" + subStatus.ToString("X") + (subStatus == 0 ? " OK" : ""));
                    if (subStatus == 0) FwpmFreeMemory0(ref sub);
                    Marshal.FreeHGlobal(subKey);
                    FwpmEngineClose0(probeEngine);
                    return 0;
                }
                if (mode == "purge")
                {
                    return RunPurge();
                }
                if (mode == "list-filters")
                {
                    return RunListFilters();
                }
                if (mode == "hold" || mode == "check")
                {
                    if (args.Length < 2)
                    {
                        Console.WriteLine("用法：CCGaitWfp.exe hold|check <exe路径> [更多路径...]");
                        return 2;
                    }
                    return mode == "hold" ? RunHold(args) : RunCheck(args);
                }
                Console.WriteLine("用法：CCGaitWfp.exe hold|check <exe路径> [更多路径...] | purge | list-layers | probe-layer");
                return 2;
            }
            catch (Exception error)
            {
                Console.WriteLine("FAIL " + error.Message);
                return 1;
            }
        }

        /// <summary>常驻：过滤器在会话里生效，直到本进程退出。</summary>
        private static int RunHold(string[] args)
        {
            // 支持 --stop-file <路径>：宿主进程在被要求停止时写这个文件。
            // 为什么不用 stdin：以 detached 方式启动时 stdin 是 NUL，ReadLine() 立刻返回
            // null，会导致过滤器刚挂上就随进程退出而消失（实测踩过）。
            string stopFile = null;
            // --loopback-exempt <exe...> 之前的部分按"全封"处理；
            // 这个开关之后列出的路径，阻断时放行 127.0.0.1（给浏览器用）。
            bool loopbackExempt = false;
            var plainPaths = new System.Collections.Generic.List<string>();
            var exemptPaths = new System.Collections.Generic.List<string>();
            for (int index = 1; index < args.Length; index++)
            {
                if (args[index] == "--stop-file" && index + 1 < args.Length)
                {
                    stopFile = args[index + 1];
                    index++;
                    continue;
                }
                if (args[index] == "--loopback-exempt")
                {
                    loopbackExempt = true;
                    continue;
                }
                if (loopbackExempt) exemptPaths.Add(args[index]);
                else plainPaths.Add(args[index]);
            }

            IntPtr engine = OpenEngine();
            var allIds = new System.Collections.Generic.List<ulong>();
            var plainValid = new System.Collections.Generic.List<string>();
            var exemptValid = new System.Collections.Generic.List<string>();
            foreach (string candidate in plainPaths)
            {
                string exePath = Path.GetFullPath(candidate);
                if (!File.Exists(exePath))
                {
                    Console.WriteLine("SKIP " + exePath + "（文件不存在）");
                    continue;
                }
                plainValid.Add(exePath);
            }
            foreach (string candidate in exemptPaths)
            {
                string exePath = Path.GetFullPath(candidate);
                if (!File.Exists(exePath))
                {
                    Console.WriteLine("SKIP " + exePath + "（文件不存在）");
                    continue;
                }
                exemptValid.Add(exePath);
            }

            // Claude 客户端：全封（它们不需要访问本地服务）。
            foreach (string exePath in plainValid)
            {
                try
                {
                    System.Collections.Generic.List<ulong> ids = AddFilters(engine, exePath, false);
                    allIds.AddRange(ids);
                    Console.WriteLine("BLOCKED " + exePath + " (" + ids.Count + " filters)");
                }
                catch (Exception addError)
                {
                    Console.WriteLine("FAIL " + exePath + " " + addError.Message);
                }
            }
            // 浏览器：只封外网、放行 127.0.0.1 —— 否则 CCGait 自己的界面窗口
            // （Edge APP 模式）会被一起打死，用户连状态都看不到。
            foreach (string exePath in exemptValid)
            {
                try
                {
                    System.Collections.Generic.List<ulong> ids = AddFilters(engine, exePath, true);
                    allIds.AddRange(ids);
                    Console.WriteLine("BLOCKED-EXT " + exePath + " (" + ids.Count + " filters)");
                }
                catch (Exception addError)
                {
                    Console.WriteLine("FAIL " + exePath + " " + addError.Message);
                }
            }
            Console.WriteLine("READY " + allIds.Count);
            Console.Out.Flush();

            // 三种收尾条件：出现停止文件、stdin 关闭、进程收到退出信号。
            // 过滤器随引擎关闭自动消失，不会给机器留下持久状态。
            if (stopFile != null && File.Exists(stopFile))
            {
                try { File.Delete(stopFile); } catch { }
            }
            try
            {
                while (true)
                {
                    if (stopFile != null && File.Exists(stopFile))
                    {
                        try { File.Delete(stopFile); } catch { }
                        break;
                    }
                    if (stopFile == null && Console.In.Peek() == -1)
                    {
                        // 没有停止文件时退回 stdin 语义（交互/测试场景）
                        break;
                    }
                    System.Threading.Thread.Sleep(300);
                }
            }
            catch
            {
                // stdin 被关闭或不可用 → 继续常驻，由停止文件或进程退出决定生命周期
                while (true)
                {
                    if (stopFile != null && File.Exists(stopFile))
                    {
                        try { File.Delete(stopFile); } catch { }
                        break;
                    }
                    System.Threading.Thread.Sleep(300);
                }
            }
            foreach (ulong id in allIds)
            {
                FwpmFilterDeleteById0(engine, id);
            }
            FwpmEngineClose0(engine);
            Console.WriteLine("RELEASED " + allIds.Count);
            return 0;
        }

        /// <summary>一次性自测：加过滤器 → 探针 → 清理 → 再探针，用真实结果说话。</summary>
        private static int RunCheck(string[] args)
        {
            string probe = args[1];
            string target = args.Length > 2 ? args[2] : probe;

            string url = args.Length > 3 ? args[3] : "https://www.baidu.com";
            bool before = Probe(probe, url, 20000);
            Console.WriteLine("target=" + url);
            Console.WriteLine("before=" + (before ? "online" : "offline"));

            string targetPath = Path.GetFullPath(target);
            Console.WriteLine("target-path=" + targetPath + " exists=" + File.Exists(targetPath));
            if (!File.Exists(targetPath))
            {
                Console.WriteLine("RESULT=FAIL 目标文件不存在");
                return 1;
            }

            IntPtr engine = OpenEngine();
            System.Collections.Generic.List<ulong> ids = AddFilters(engine, targetPath);
            Console.WriteLine("filters=" + ids.Count);

            bool during = Probe(probe, url, 20000);
            Console.WriteLine("during=" + (during ? "online" : "offline"));

            foreach (ulong id in ids)
            {
                FwpmFilterDeleteById0(engine, id);
            }
            FwpmEngineClose0(engine);
            Thread.Sleep(500);

            bool after = Probe(probe, url, 20000);
            Console.WriteLine("after=" + (after ? "online" : "offline"));

            bool ok = before && !during && after;
            Console.WriteLine(ok ? "RESULT=PASS" : "RESULT=FAIL");
            return ok ? 0 : 1;
        }
    }
}
