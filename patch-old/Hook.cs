using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

    internal static class StartupHook
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr h, IntPtr addr, byte[] buf, IntPtr size, out IntPtr read);
        [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr addr, IntPtr size, uint type, uint prot);
        [DllImport("kernel32.dll")] static extern IntPtr AddVectoredExceptionHandler(uint first, IntPtr handler);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenThread(uint access, bool inherit, uint tid);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetThreadContext(IntPtr h, IntPtr ctx);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetThreadContext(IntPtr h, IntPtr ctx);
        [DllImport("kernel32.dll")] static extern uint SuspendThread(IntPtr h);
        [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualQueryEx(IntPtr h, IntPtr addr, out MBI mbi, IntPtr len);
        [StructLayout(LayoutKind.Sequential)]
        struct MBI { public IntPtr BaseAddress, AllocationBase; public uint AllocationProtect, _p1; public IntPtr RegionSize; public uint State, Protect, Type; }

        const uint THREAD_ALL_ACCESS = 0x1F03FF;
        const long CTX_FLAGS = 0x30, CTX_Dr0 = 0x48, CTX_Dr6 = 0x68, CTX_Dr7 = 0x70, CTX_Rax = 0x78, CTX_Rip = 0xF8;

        // ===== 2026-10-02 fork (patch-old): make the hookout dir selectable =====
        // Set DP_HOOKOUT to point at a private config/log dir so this fork can run
        // side by side with the deployed baseline without fighting over its files.
        // Env var unset -> original behaviour, byte-for-byte.
        internal static readonly string HO =
            System.Environment.GetEnvironmentVariable("DP_HOOKOUT") ?? @"C:/s/oldhook/hookout";


        static IntPtr _h;
        static long _bpAddr, _resolverLo, _resolverHi;
        static readonly Dictionary<int, long> _realEpMap = new Dictionary<int, long>();
        static readonly Dictionary<int, long> _slotMap = new Dictionary<int, long>();
        static readonly List<(long addr, string name)> _watchList = new List<(long, string)>();
        static long scratch, logArea;
        internal delegate string D7411(byte[] data);
        static DStrSelf _dStrSelf;
        static bool _replaced7411;
        static bool _trampInstalled;
        // ===== v41: 批量记录 trampoline =====
        static bool _traceInstalled;
        static bool _licLoaded;
        static bool _asmInstalled;
        static System.Collections.Generic.Dictionary<int, long> _cntMap = new System.Collections.Generic.Dictionary<int, long>();
        internal delegate bool DBoolP(IntPtr self);
        internal delegate int DIntP(IntPtr self);
        internal delegate void DVoid2P(IntPtr a, IntPtr b);
        static System.Collections.Generic.Dictionary<int, DBoolP> _origB = new System.Collections.Generic.Dictionary<int, DBoolP>();
        static System.Collections.Generic.Dictionary<int, DIntP> _origI = new System.Collections.Generic.Dictionary<int, DIntP>();
        static System.Collections.Generic.List<object> _keepAlive = new System.Collections.Generic.List<object>();
        static readonly object _trLock = new object();
        static void Tr(string s) { lock (_trLock) { try { File.AppendAllText(HO + "/trace.log", s + "\r\n"); } catch { } } }
        static bool RecB(int tok, IntPtr self)
        {
            bool r = false;
            try { r = _origB[tok](self); } catch (Exception e) { Tr($"{tok:X} EX {e.Message}"); return false; }
            Tr($"{DateTime.Now:HH:mm:ss.fff}\t{tok:X}\t-> {r}");
            return r;
        }
        static int RecI(int tok, IntPtr self)
        {
            int r = 0;
            try { r = _origI[tok](self); } catch (Exception e) { Tr($"{tok:X} EX {e.Message}"); return 0; }
            Tr($"{DateTime.Now:HH:mm:ss.fff}\t{tok:X}\t-> {r}");
            return r;
        }
        // trampoline 区：保存原 12 字节 + jmp 回 body+12
        static long _tramp = 0;
        internal delegate string DStrSelf(object self);
        static DStrSelf _origClone;
        static string CloneDriverTramp(object self)
        {
            string r = null;
            try { r = _origClone(self); } catch (Exception e) { File.AppendAllText(HO + "/clone.log", "EX " + e.Message + "\r\n"); }
            try { File.AppendAllText(HO + "/clone.log", $"[CloneDriver] ret={(r == null ? "null" : "\"" + r + "\"")}\r\n"); } catch { }
            return r;
        }
        static bool _replShutdown;
        internal delegate void DShutdown(object app);
        internal delegate void DShutdownI(object app, int code);
        static DShutdown _dShutdown; static DShutdownI _dShutdownI;
        static void ReplShutdown(object app)
        {
            try { System.IO.File.AppendAllText(HO + "/shutdown.log",
                "[Shutdown() called]\r\n" + Environment.StackTrace + "\r\n---\r\n"); } catch { }
        }
        static void ReplShutdownI(object app, int code)
        {
            try { System.IO.File.AppendAllText(HO + "/shutdown.log",
                $"[Shutdown({code}) called]\r\n" + Environment.StackTrace + "\r\n---\r\n"); } catch { }
        }
        static D7411 _repl7411Del;
        static readonly object _log7411Lock = new object();
        static string Repl7411(byte[] data)
        {
            try
            {
                string hexIn = data == null ? "null" : BitConverter.ToString(data);
                lock (_log7411Lock) { System.IO.File.AppendAllText(HO + "/repl7411.log", $"[7411] in({(data?.Length ?? 0)})={hexIn}\r\n"); }
            }
            catch { }
            return "ERESULT=1";
        }
        static IntPtr _hThreadSelf;
        static string outDir;
        static volatile bool _sweeping;

        static string DumpKeyStatics()
        {
            var sb = new System.Text.StringBuilder();
            try
            {
                var asm = AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(a => a.GetName().Name == "Deepchart");
                if (asm == null) return "assembly not loaded\r\n";
                Type[] tss; try { tss = asm.GetTypes(); } catch (ReflectionTypeLoadException e3) { tss = e3.Types.Where(x => x != null).ToArray(); }
                foreach (var tname in new[] { "License.Status", "VolAnalysis.Handling.ScheduledHandler" })
                {
                    var t = tss.FirstOrDefault(x => x.FullName == tname);
                    if (t == null) { sb.AppendLine($"{tname}: TYPE NOT FOUND"); continue; }
                    sb.AppendLine($"---- statics of {tname} ----");
                    foreach (var f in t.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
                    {
                        object v = null;
                        try { v = f.GetValue(null); } catch (Exception fe) { sb.AppendLine($"  {f.Name}: <throw {fe.GetType().Name}>"); continue; }
                        string vs;
                        if (v == null) vs = "<null>";
                        else if (v is byte[] ba) vs = "byte[" + ba.Length + "] " + BitConverter.ToString(ba.Take(16).ToArray());
                        else if (v is MulticastDelegate md) vs = "<delegate " + md.GetType().Name + ">";
                        else if (v is System.Collections.IEnumerable en && !(v is string))
                        {
                            int c = 0; var it = en.GetEnumerator(); while (it.MoveNext() && c < 1000) c++;
                            vs = v.GetType().Name + " count=" + c;
                        }
                        else vs = v.ToString();
                        if (vs.Length > 150) vs = vs.Substring(0, 150);
                        sb.AppendLine($"  {f.Name} : {f.FieldType.Name} = {vs}");
                    }
                }
            }
            catch (Exception de) { sb.AppendLine("dump fail: " + de); }
            return sb.ToString();
        }

        internal static void Initialize()
        {
            // 崩溃捕获：任何到达域级的 .NET 异常都落盘
            try
            {
                AppDomain.CurrentDomain.UnhandledException += (s, e) =>
                {
                    try { File.AppendAllText(HO + "/crash.txt", $"\r\n==== AppDomain.UnhandledException {DateTime.Now:HH:mm:ss} ====\r\n{e.ExceptionObject}\r\nIsTerminating={e.IsTerminating}\r\n{DumpKeyStatics()}"); } catch { }
                };
                System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (s, e) =>
                {
                    try { File.AppendAllText(HO + "/crash.txt", $"\r\n==== UnobservedTask {DateTime.Now:HH:mm:ss} ====\r\n{e.Exception}\r\n"); e.SetObserved(); } catch { }
                };
                // 等 WPF Application 起来再挂 Dispatcher 级
                new Thread(() =>
                {
                    for (int i = 0; i < 600; i++)
                    {
                        try
                        {
                            var app = System.Windows.Application.Current;
                            if (app != null)
                            {
                                app.DispatcherUnhandledException += (s2, e2) =>
                                {
                                    try { File.AppendAllText(HO + "/crash.txt", $"\r\n==== DispatcherUnhandledException {DateTime.Now:HH:mm:ss} ====\r\n{e2.Exception}\r\n"); } catch { }
                                };
                                File.AppendAllText(HO + "/crash.txt", $"[hook] Dispatcher handler installed {DateTime.Now:HH:mm:ss}\r\n");
                                return;
                            }
                        } catch { }
                        Thread.Sleep(500);
                    }
                }) { IsBackground = true }.Start();
            }
            catch { }
            AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
            {
                if (e.Name.StartsWith("dnlib"))
                    return Assembly.LoadFrom(@"C://s//dnlib.dll");
                return null;
            };
            try { Directory.CreateDirectory(HO); File.WriteAllText(@"C://s//hookout//init.txt", "hook initialize ran " + DateTime.Now); } catch { }
            // 在后台线程跑提取，绝不阻塞应用
            var t = new Thread(() =>
            {
                try { Run(); } catch (Exception ex) { try { File.WriteAllText(HO + "/fatal.txt", ex.ToString()); } catch { } }
            });
            t.IsBackground = false;
            t.Start();
        }

        static byte[] Rd(long addr, int n) { var b = new byte[n]; ReadProcessMemory(_h, (IntPtr)addr, b, (IntPtr)n, out _); return b; }
        static long Q(long addr) => BitConverter.ToInt64(Rd(addr, 8), 0);

        // ===== 原生栈抓取桩：记录调用者返回地址链后原样继续 =====
        static long _stkSlot = 0, _stkSeq = 0;
        static int _stkStarted = 0;
        static void InstallStackStub(long body, string tag, StreamWriter log2)
        {
            const int FRAMES = 14;
            if (_stkSlot == 0)
            {
                _stkSlot = VirtualAlloc(IntPtr.Zero, (IntPtr)0x1000, 0x3000, 0x40).ToInt64();
                _stkSeq = _stkSlot + 0x800;
                if (_stkSlot == 0) throw new Exception("slot alloc fail");
            }
            if (Interlocked.CompareExchange(ref _stkStarted, 1, 0) == 0)
                new Thread(StackStubDrain) { IsBackground = true }.Start();
            byte[] orig = Rd(body, 12);
            if (orig.Length != 12) throw new Exception("read fail");
            if (orig[0] == 0xE9 || (orig[0] == 0x48 && orig[1] == 0xB8)) throw new Exception("already patched");
            long stub = VirtualAlloc(IntPtr.Zero, (IntPtr)512, 0x3000, 0x40).ToInt64();
            if (stub == 0) throw new Exception("stub alloc fail");
            var code = new List<byte>();
            code.Add(0x50);                                                     // push rax
            code.Add(0x48); code.Add(0xB8); AddImm64(code, (ulong)_stkSlot);     // mov rax, slot
            for (int i = 0; i < FRAMES; i++)
            {
                int d = 8 + i * 8;
                code.AddRange(new byte[] { 0x4C, 0x8B, 0x5C, 0x24, (byte)d });   // mov r11,[rsp+d]
                int d2 = i * 8;
                code.AddRange(new byte[] { 0x4C, 0x89, 0x58, (byte)d2 });        // mov [rax+d2], r11
            }
            code.Add(0x49); code.Add(0xBB); AddImm64(code, (ulong)_stkSeq);      // mov r11, seq
            code.AddRange(new byte[] { 0x49, 0xFF, 0x03 });                      // inc qword [r11]
            code.Add(0x58);                                                      // pop rax
            code.AddRange(orig);                                                 // 执行原 12 字节
            code.Add(0x48); code.Add(0xB8); AddImm64(code, (ulong)(body + 12));  // mov rax, body+12
            code.AddRange(new byte[] { 0xFF, 0xE0 });                            // jmp rax
            Marshal.Copy(code.ToArray(), 0, (IntPtr)stub, code.Count);
            var jmp = new List<byte> { 0x48, 0xB8 };
            AddImm64(jmp, (ulong)stub);
            jmp.AddRange(new byte[] { 0xFF, 0xE0 });
            while (jmp.Count < 12) jmp.Add(0x90);
            uint op; VirtualProtect((IntPtr)body, (IntPtr)12, 0x40, out op);
            Marshal.Copy(jmp.ToArray(), 0, (IntPtr)body, 12);
            VirtualProtect((IntPtr)body, (IntPtr)12, op, out _);
            lock (log2) { log2.WriteLine($"[stkstub] {tag} body=0x{body:X}"); log2.Flush(); }
        }
        static void StackStubDrain()
        {
            long last = -1;
            var mods = new List<Tuple<long, long, string>>();
            while (true)
            {
                try
                {
                    long seq = BitConverter.ToInt64(Rd(_stkSeq, 8), 0);
                    if (seq != last && seq > 0)
                    {
                        last = seq;
                        mods.Clear();
                        try
                        {
                            foreach (System.Diagnostics.ProcessModule m in System.Diagnostics.Process.GetCurrentProcess().Modules)
                                mods.Add(Tuple.Create(m.BaseAddress.ToInt64(), m.BaseAddress.ToInt64() + m.ModuleMemorySize, m.ModuleName));
                        }
                        catch { }
                        var sb = new System.Text.StringBuilder();
                        sb.Append($"==== 退出调用链 #{seq} {DateTime.Now:HH:mm:ss.fff} ====\r\n");
                        for (int i = 0; i < 14; i++)
                        {
                            long v = BitConverter.ToInt64(Rd(_stkSlot + i * 8, 8), 0);
                            if (v == 0) continue;
                            string r = "0x" + v.ToString("X");
                            foreach (var md in mods)
                                if (v >= md.Item1 && v < md.Item2) { r = md.Item3 + "+0x" + (v - md.Item1).ToString("X"); break; }
                            sb.Append($"  [{i:D2}] {r}\r\n");
                        }
                        File.AppendAllText(HO + "/exit_stack.log", sb.ToString());
                    }
                }
                catch { }
                Thread.Sleep(40);
            }
        }

        // ===== 崩溃现场捕获 VEH =====
        static readonly object _vcLock = new object();
        static readonly List<string> _vcLog = new List<string>();
        static VEHDel2 _vcKeep;
        internal delegate int VEHDel2(IntPtr ep);
        static long _vcCount = 0;
        static int VEH2(IntPtr ep)
        {
            try
            {
                if (ep == IntPtr.Zero) return 0;
                var er = Marshal.ReadIntPtr(ep);
                var ctx = Marshal.ReadIntPtr(ep, 8);
                if (er == IntPtr.Zero || ctx == IntPtr.Zero) return 0;
                uint code = (uint)Marshal.ReadInt32(er, 0);
                // 只关心致命/异常类
                bool interesting = code == 0x80000003 || code == 0xC0000005 || code == 0x80131623
                                || code == 0xC00000FD || code == 0xE06D7363 || code == 0xC0000409
                                || code == 0x80000004 || code == 0xC000001D || code == 0x80000001;
                if (!interesting) return 0;
                long addr = Marshal.ReadIntPtr(er, 16).ToInt64();
                long nparam = Marshal.ReadInt32(er, 24);
                long p0 = nparam > 0 ? Marshal.ReadIntPtr(er, 32).ToInt64() : 0;
                long rip = Marshal.ReadInt64(ctx, 0xF8);
                long rsp = Marshal.ReadInt64(ctx, 0x98);
                var sb = new System.Text.StringBuilder();
                sb.Append($"[{DateTime.Now:HH:mm:ss.fff}] code=0x{code:X8} addr=0x{addr:X} nparam={nparam} p0=0x{p0:X} rip=0x{rip:X} rsp=0x{rsp:X}\r\n");
                sb.Append("   rcx=0x" + Marshal.ReadInt64(ctx, 0x80).ToString("X") + " rdx=0x" + Marshal.ReadInt64(ctx, 0x88).ToString("X") + "\r\n");
                for (int i = 0; i < 64; i++)
                {
                    long v = Marshal.ReadInt64((IntPtr)(rsp + i * 8));
                    if (v != 0) sb.Append($"   stk[{i:D2}] 0x{v:X}\r\n");
                }
                lock (_vcLock) { if (_vcLog.Count < 4000) { _vcLog.Add(sb.ToString()); _vcCount++; } }
                if (code == 0x80000003 && Flag("vehskip", "0") == "1")
                {
                    Marshal.WriteInt64(ctx, 0xF8, rip + 1);   // 跳过 int3（中和 FailFast）
                    return -1;                                 // EXCEPTION_CONTINUE_EXECUTION
                }
            }
            catch { }
            return 0; // EXCEPTION_CONTINUE_SEARCH
        }
        static void VehCrashDrain()
        {
            var mods = new List<(long lo, long hi, string nm)>();
            var swm = System.Diagnostics.Stopwatch.StartNew();
            long written = 0;
            while (true)
            {
                try
                {
                    if (swm.ElapsedMilliseconds > 3000)
                    {
                        swm.Restart();
                        mods.Clear();
                        try
                        {
                            foreach (System.Diagnostics.ProcessModule m in System.Diagnostics.Process.GetCurrentProcess().Modules)
                                mods.Add((m.BaseAddress.ToInt64(), m.BaseAddress.ToInt64() + m.ModuleMemorySize, m.ModuleName));
                        }
                        catch { }
                        try
                        {
                            var msb = new System.Text.StringBuilder();
                            foreach (var md in mods) msb.Append($"{md.nm}\t0x{md.lo:X}\t0x{md.hi:X}\r\n");
                            File.WriteAllText(HO + "/veh_modules.txt", msb.ToString());
                        }
                        catch { }
                    }
                    List<string> take = null;
                    lock (_vcLock) { if (_vcLog.Count > written) { take = _vcLog.GetRange((int)written, _vcLog.Count - (int)written); written = _vcLog.Count; } }
                    if (take != null)
                    {
                        var sb = new System.Text.StringBuilder();
                        foreach (var t in take)
                        {
                            foreach (var line in t.Split('\n'))
                            {
                                var l = line.TrimEnd('\r');
                                int p = l.IndexOf("0x", StringComparison.Ordinal);
                                if (p >= 0 && (l.Contains("addr=") || l.Contains("stk[") || l.Contains("rip=") || l.Contains("rcx=")))
                                {
                                    // 解析行内所有 0x 值并尝试解析模块
                                    sb.Append(l).Append("  |  ");
                                    foreach (System.Text.RegularExpressions.Match mm in System.Text.RegularExpressions.Regex.Matches(l, @"0x[0-9A-Fa-f]{6,}"))
                                    {
                                        long hv; try { hv = Convert.ToInt64(mm.Value.Substring(2), 16); } catch { continue; }
                                        foreach (var md in mods)
                                            if (hv >= md.lo && hv < md.hi) { sb.Append(md.nm + "+0x" + (hv - md.lo).ToString("X")).Append(' '); break; }
                                    }
                                    sb.Append("\r\n");
                                }
                                else sb.Append(l).Append("\r\n");
                            }
                        }
                        File.AppendAllText(HO + "/veh_crash.log", sb.ToString());
                    }
                }
                catch { }
                Thread.Sleep(300);
            }
        }

        // ===== 返回已完成的 Task 对象（避开网络调用）=====
        static object _kTNullBytes, _kTVoid, _kTBoolFalse, _kTBoolTrue;
        static bool _kTNullBytesReady;
        // 每个返回对象持有 GCHandle.Normal → 槽内指针由 GC 自动更新（压缩 GC 后依然有效）
        static readonly List<GCHandle> _retHandles = new List<GCHandle>();
        static readonly Dictionary<int, (long body, long slot)> _retTasks = new Dictionary<int, (long, long)>();
        static long ObjAddr(object o)
        {
            object ro = o;
            return System.Runtime.CompilerServices.Unsafe.As<object, IntPtr>(ref ro).ToInt64();
        }
        // 桩：计数 + 双间接返回
        //   mov rax,<counter> ; inc qword [rax]
        //   mov rax,<handleSlot> ; mov rax,[rax] ; ret
        static long _retCntPage = 0;
        static int _retCntUsed = 0;
        static readonly List<Tuple<int, string, long>> _retCntMap = new List<Tuple<int, string, long>>();
        static long AllocCounter(int tok, string name)
        {
            if (_retCntPage == 0)
            {
                _retCntPage = VirtualAlloc(IntPtr.Zero, (IntPtr)0x1000, 0x3000, 0x40).ToInt64();
                if (Interlocked.CompareExchange(ref _retCntStarted, 1, 0) == 0)
                    new Thread(RetCountDrain) { IsBackground = true }.Start();
            }
            long a = _retCntPage + _retCntUsed * 8;
            _retCntUsed++;
            if (_retCntUsed >= 500) _retCntUsed = 0;
            _retCntMap.Add(Tuple.Create(tok, name, a));
            return a;
        }
        static int _retCntStarted = 0;
        static void WriteRetStub(long body, object retObj, long counter)
        {
            var h = GCHandle.Alloc(retObj, GCHandleType.Normal);
            _retHandles.Add(h);
            long slot = GCHandle.ToIntPtr(h).ToInt64();
            var code = new List<byte>();
            if (counter != 0)
            {
                code.Add(0x48); code.Add(0xB8); AddImm64(code, (ulong)counter);   // mov rax, counter
                code.AddRange(new byte[] { 0x48, 0xFF, 0x00 });                    // inc qword [rax]
            }
            code.Add(0x48); code.Add(0xB8); AddImm64(code, (ulong)slot);           // mov rax, slot
            code.AddRange(new byte[] { 0x48, 0x8B, 0x00 });                        // mov rax, [rax]
            code.Add(0xC3);                                                        // ret
            uint op; VirtualProtect((IntPtr)body, (IntPtr)code.Count, 0x40, out op);
            Marshal.Copy(code.ToArray(), 0, (IntPtr)body, code.Count);
            VirtualProtect((IntPtr)body, (IntPtr)code.Count, op, out _);
        }
        static void RetCountDrain()
        {
            while (true)
            {
                try
                {
                    var sb = new System.Text.StringBuilder();
                    sb.Append($"==== {DateTime.Now:HH:mm:ss} 被调用的 retall 方法 ====\r\n");
                    foreach (var t in _retCntMap)
                    {
                        long c = BitConverter.ToInt64(Rd(t.Item3, 8), 0);
                        if (c > 0) sb.Append($"  {t.Item1:X8} {t.Item2} x{c}\r\n");
                    }
                    File.WriteAllText(HO + "/ret_counts.txt", sb.ToString());
                }
                catch { }
                Thread.Sleep(1500);
            }
        }
        static void InstallRetTask(int tok, long body, string kind, StreamWriter log2)
        {
            if (_kTNullBytes == null)
            {
                _kTNullBytes = System.Threading.Tasks.Task.FromResult<byte[]>(null);
                _kTVoid = System.Threading.Tasks.Task.CompletedTask;
                _kTBoolFalse = System.Threading.Tasks.Task.FromResult(false);
                _kTBoolTrue = System.Threading.Tasks.Task.FromResult(true);
                _keepAlive.Add(_kTNullBytes); _keepAlive.Add(_kTBoolFalse); _keepAlive.Add(_kTBoolTrue);
                new Thread(RetCountDrain) { IsBackground = true }.Start();
            }
            object o = kind == "void" ? _kTVoid : kind == "booltrue" ? _kTBoolTrue : kind == "boolfalse" ? _kTBoolFalse : _kTNullBytes;
            long cnt = AllocCounter(tok, "tok");
            WriteRetStub(body, o, cnt);
            long slot = GCHandle.ToIntPtr(_retHandles[_retHandles.Count - 1]).ToInt64();
            _retTasks[tok] = (body, slot);
            lock (log2) { log2.WriteLine($"[retask] tok={tok:X} body=0x{body:X} -> {kind} slot=0x{slot:X} cnt=0x{cnt:X}"); log2.Flush(); }
        }

        // ===== 参数记录桩安装 =====
        // 布局：body 入口写 12 字节绝对跳转 -> stub；stub 内保存 rcx/rdx/r8/r9 到共享槽、
        // 自增序号、执行被覆盖的原 12 字节、再绝对跳回 body+12。
        static void InstallArgStub(int tok, long body, StreamWriter log2)
        {
            const int OV = 12;   // 覆盖 12 字节（3 条完整指令通常够，含 4C 8B D1 等）
            if (_argSlot == 0)
            {
                _argSlot = VirtualAlloc(IntPtr.Zero, (IntPtr)64, 0x1000 | 0x2000, 0x40).ToInt64();
                _argSeq = _argSlot + 48;
                if (_argSlot == 0) throw new Exception("arg slot alloc failed");
            }
            if (Interlocked.CompareExchange(ref _argPollerStarted, 1, 0) == 0)
                new Thread(ArgPoller) { IsBackground = true }.Start();

            byte[] orig = Rd(body, OV);
            if (orig.Length != OV) throw new Exception("read body failed");
            // 安全性：若已是 jmp（E9/FF25），跳过
            if (orig[0] == 0xE9 || (orig[0] == 0xFF && orig[1] == 0x25)) throw new Exception("body already patched");

            long stub = VirtualAlloc(IntPtr.Zero, (IntPtr)256, 0x1000 | 0x2000, 0x40).ToInt64();
            if (stub == 0) throw new Exception("stub alloc failed");

            // ---- 构造 stub 机器码 ----
            var code = new List<byte>();
            // mov r11, rcx ; mov [r11slot], r11  —— 用 rax 做临时基址更简单
            // push rax ; mov rax, _argSlot ; mov [rax+0], rcx ; mov [rax+8], rdx ;
            // mov [rax+16], r8 ; mov [rax+24], r9 ; mov r11, _argSeq ; inc qword [r11] ; pop rax
            code.AddRange(new byte[] { 0x50 });                                   // push rax
            // mov rax, imm64 (_argSlot)
            code.Add(0x48); code.Add(0xB8); AddImm64(code, (ulong)_argSlot);
            code.AddRange(new byte[] { 0x48, 0x89, 0x08 });                        // mov [rax], rcx
            code.AddRange(new byte[] { 0x48, 0x89, 0x50, 0x08 });                  // mov [rax+8], rdx
            code.AddRange(new byte[] { 0x4C, 0x89, 0x40, 0x10 });                  // mov [rax+16], r8
            code.AddRange(new byte[] { 0x4C, 0x89, 0x48, 0x18 });                  // mov [rax+24], r9
            // mov r11, imm64 (_argSeq) ; inc qword [r11]
            code.Add(0x49); code.Add(0xBB); AddImm64(code, (ulong)_argSeq);
            code.AddRange(new byte[] { 0x49, 0xFF, 0x03 });                        // inc qword [r11]
            code.AddRange(new byte[] { 0x58 });                                    // pop rax
            // 执行原 12 字节
            code.AddRange(orig);
            // jmp body+OV（绝对）
            code.Add(0x48); code.Add(0xB8); AddImm64(code, (ulong)(body + OV));    // mov rax, body+OV
            code.AddRange(new byte[] { 0xFF, 0xE0 });                              // jmp rax

            Marshal.Copy(code.ToArray(), 0, (IntPtr)stub, code.Count);
            // body 入口：mov rax, stub ; jmp rax  （12 字节）
            var jmp = new List<byte>();
            jmp.Add(0x48); jmp.Add(0xB8); AddImm64(jmp, (ulong)stub);
            jmp.AddRange(new byte[] { 0xFF, 0xE0 });
            if (jmp.Count != 12) throw new Exception("jmp size " + jmp.Count);
            uint op; VirtualProtect((IntPtr)body, (IntPtr)OV, 0x40, out op);
            Marshal.Copy(jmp.ToArray(), 0, (IntPtr)body, 12);
            VirtualProtect((IntPtr)body, (IntPtr)OV, op, out _);

            _argStubMap[tok] = stub;
            _argMeta[tok] = (stub, OV);
            lock (log2) { log2.WriteLine($"[argcap] tok={tok:X} body=0x{body:X} stub=0x{stub:X} orig={BitConverter.ToString(orig)}"); log2.Flush(); }
        }
        static void AddImm64(List<byte> c, ulong v) { for (int i = 0; i < 8; i++) c.Add((byte)((v >> (8 * i)) & 0xFF)); }

        // ===== 2026-10-02 fork (patch-old): ZP —— 纯观察用 pass-through trampoline =====
        // 在方法真 body 指针 [ep+0x4000] 上装跳板：先把入参抄进共享槽，再跳到**未被修改的**原 body。
        // 与 retall 的"返回常量"不同，这里完全不改变行为，只做记录。
        // Eazfuscator 只在首次调用时把真 IL 写进 [ep+0x4000]，所以用后台线程轮询安装；
        // 只有槽里已经是一个已解析的地址时才安装，避免抢在解析器之前占槽导致方法永远无法还原。
        static readonly List<long> _pasSlots = new List<long>();
        static void InstallPassThrough(MethodBase mi, string label, string kind)
        {
            long ep = mi.MethodHandle.GetFunctionPointer().ToInt64();
            if (ep < 0x10000) throw new Exception("ep too low 0x" + ep.ToString("X"));
            // precode = FF 25 <rel32>  →  jmp [rip+rel32]，真 body 指针放在 ep+6+rel32 处。
            // Eazfuscator 的 Deepchart.dll 用 rel32=0x3FFA（即 ep+0x4000）；BCL 方法 rel32 不同。
            byte[] eh = Rd(ep, 6);
            if (eh.Length != 6 || eh[0] != 0xFF || eh[1] != 0x25)
            {
                Console.WriteLine($"[zprobe] {label} ep=0x{ep:X} 非 FF25 precode 形态（head={BitConverter.ToString(eh)}）→ 跳过");
                File.AppendAllText(HO + "/zprobe.txt", $"[skip] {label} ep=0x{ep:X} head={BitConverter.ToString(eh)}\r\n");
                return;
            }
            long slot = ep + 6 + BitConverter.ToInt32(eh, 2);
            long page = VirtualAlloc(IntPtr.Zero, (IntPtr)0x2000, 0x3000, 0x40).ToInt64();
            if (page == 0) throw new Exception("pass-through page alloc failed");
            long buf = page + 0x100;    // rcx/rdx/r8/r9 落点
            long seq = page + 0x200;    // 调用计数
            _pasSlots.Add(page);
            Console.WriteLine($"[zprobe] {label} ep=0x{ep:X} slot=0x{slot:X} page=0x{page:X}");
            File.AppendAllText(HO + "/zprobe.txt", $"[install] {label} ep=0x{ep:X}\r\n");
            new Thread(() =>
            {
                long lastSeq = 0, installedFor = -1;
                int hits = 0;
                while (true)
                {
                    Thread.Sleep(20);
                    try
                    {
                        long cur = Q(slot);
                        if (cur > 0x10000 && cur != page && (cur >> 47) == 0 && cur != installedFor)
                        {
                            var code = new List<byte>();
                            void Qw(long v) { code.AddRange(BitConverter.GetBytes(v)); }
                            code.Add(0x50);                                  // push rax
                            code.Add(0x48); code.Add(0xB8); Qw(buf);         // mov rax, buf
                            code.Add(0x48); code.Add(0x89); code.Add(0x08);  // mov [rax], rcx
                            code.Add(0x48); code.Add(0x89); code.Add(0x50); code.Add(0x08);   // mov [rax+8], rdx
                            code.Add(0x4C); code.Add(0x89); code.Add(0x40); code.Add(0x10);   // mov [rax+16], r8
                            code.Add(0x4C); code.Add(0x89); code.Add(0x48); code.Add(0x18);   // mov [rax+24], r9
                            code.Add(0x49); code.Add(0xBB); Qw(seq);         // mov r11, seq
                            code.Add(0x49); code.Add(0xFF); code.Add(0x03);  // inc qword [r11]
                            code.Add(0x58);                                  // pop rax
                            code.Add(0x48); code.Add(0xB8); Qw(cur);         // mov rax, origBody
                            code.Add(0xFF); code.Add(0xE0);                  // jmp rax
                            Marshal.Copy(code.ToArray(), 0, (IntPtr)page, code.Count);
                            uint op; VirtualProtect((IntPtr)slot, (IntPtr)8, 0x40, out op);
                            Marshal.WriteInt64((IntPtr)slot, page);
                            VirtualProtect((IntPtr)slot, (IntPtr)8, op, out _);
                            installedFor = cur;
                            Console.WriteLine($"[zprobe] {label} trampoline -> orig 0x{cur:X}");
                        }
                        long s = Marshal.ReadInt64((IntPtr)seq);
                        if (s > 0 && s != lastSeq)
                        {
                            lastSeq = s; hits++;
                            long rcx = Marshal.ReadInt64((IntPtr)buf);
                            long rdx = Marshal.ReadInt64((IntPtr)(buf + 8));
                            long r8v = Marshal.ReadInt64((IntPtr)(buf + 16));
                            long r9v = Marshal.ReadInt64((IntPtr)(buf + 24));
                            string detail;
                            if (kind == "seg" || kind == "seg2" || kind == "asa")
                            {
                                // ArraySegment<byte> 16B 结构体 → 按引用传递：指向 {byte[] Array; int Offset; int Count}
                                long sv = (kind == "seg2") ? rdx : ((kind == "asa") ? rcx : r8v);
                                long arrPtr = BitConverter.ToInt64(Rd(sv, 8), 0);
                                int so = BitConverter.ToInt32(Rd(sv + 8, 4), 0);
                                int sc = BitConverter.ToInt32(Rd(sv + 12, 4), 0);
                                if (LooksArray(arrPtr) && so >= 0 && sc > 0 && sc <= 0x1000000)
                                {
                                    byte[] hd = Rd(arrPtr + 16 + so, Math.Min(sc, 48));
                                    detail = $"SEG arr=0x{arrPtr:X} off={so} cnt={sc} head={BitConverter.ToString(hd)}";
                                    if (hits <= 4) DumpToFile($"zprobe_seg_{label}_{hits}.bin", arrPtr + 16 + so, sc);
                                    // ObserveActiveSolver：把**每一帧**都追加到一个文件里，
                                    // 目的是找到 IsPartial=0 的那一帧（只有它会走 LogId 校验 → "Connection lost"）
                                    if (label == "ObserveActiveSolver")
                                    {
                                        try
                                        {
                                            byte[] fr = Rd(arrPtr + 16 + so, 1200);
                                            using (var fs = new FileStream(HO + "/hist_frames.bin", FileMode.Append, FileAccess.Write, FileShare.ReadWrite))
                                            {
                                                byte[] hdr = System.Text.Encoding.ASCII.GetBytes($"[{hits}] ");
                                                fs.Write(hdr, 0, hdr.Length);
                                                fs.Write(fr, 0, fr.Length);
                                                fs.Write(new byte[] { 0x0A }, 0, 1);
                                            }
                                        }
                                        catch { }
                                    }
                                }
                                else
                                {
                                    detail = $"SEG? raw=0x{sv:X} A=0x{arrPtr:X} off={so} cnt={sc} altIsArr={LooksArray(sv)}";
                                    if (LooksArray(sv) && hits <= 4)
                                        DumpToFile($"zprobe_seg_{label}_{hits}_alt.bin", sv + 16,
                                            Math.Min(Math.Max(BitConverter.ToInt32(Rd(sv + 8, 4), 0), 0), 8192));
                                }
                            }
                            else if (kind == "str") detail = $"rcx={DescribeString(rcx)}";
                            else if (kind == "str2") detail = $"rdx={DescribeString(rdx)}";
                            else if (kind == "path") detail = $"path={DescribePathArg(rcx)}";
                            else if (kind == "obj") detail = $"obj={DescribeObjectStrings(rdx)}";
                            else if (kind == "objc") detail = $"objc={DescribeObjectStrings(rcx)} rdx={(int)rdx} r8={(int)r8v}";
                            else if (kind == "str8") detail = $"r8={DescribeString(r8v)}";
                            else if (kind == "arr8")
                            {                                // 托管 byte[] 在 r8 —— ConcreteAllocatorTask.ExecuteInterruptibleModel(WebSocket, byte[], ...)
                                if (LooksArray(r8v))
                                {
                                    int alen = BitConverter.ToInt32(Rd(r8v + 8, 4), 0);
                                    if (alen >= 0 && alen <= 0x1000000)
                                    {
                                        byte[] hd = Rd(r8v + 16, Math.Min(Math.Max(alen, 1), 64));
                                        detail = $"ARR r8=0x{r8v:X} len={alen} r9={(int)r9v} head={BitConverter.ToString(hd)}";
                                        if (hits <= 8) DumpToFile($"zprobe_send_{label}_{hits}.bin", r8v + 16, Math.Max(alen, 1));
                                    }
                                    else detail = $"ARR? r8=0x{r8v:X} bad-len={alen}";
                                }
                                else detail = $"ARR? r8=0x{r8v:X} not-array";
                            }
                            else if (kind == "objdeep")
                            {
                                // 两级字符串扫描：rcx = 任务对象（ConcreteAllocatorTask），rdx = 待发消息
                                // 目的：① 看这个任务挂在哪个 URL 上（能区分是到 Bridge 还是到历史服务器）
                                //       ② 把消息对象引用的子对象里的字符串也挖出来（请求体内容）
                                var sbD = new System.Text.StringBuilder();
                                sbD.Append("TASK ").Append(DescribeObjectStrings(rcx));
                                sbD.Append(" | MSG ").Append(DescribeObjectStrings(rdx));
                                try
                                {
                                    foreach (var pr in new[] { new long[] { rcx, 0 }, new long[] { rdx, 1 } })
                                    {
                                        long root = pr[0]; bool isMsg = pr[1] == 1;
                                        if (root == 0) continue;
                                        for (int off = 0; off < 0x60; off += 8)
                                        {
                                            long cand = BitConverter.ToInt64(Rd(root + off, 8), 0);
                                            if (cand < 0x10000 || (cand >> 47) != 0 || cand == root) continue;
                                            int l2 = BitConverter.ToInt32(Rd(cand + 8, 4), 0);
                                            if (l2 > 0 && l2 <= 2048) continue;   // 字符串本身，一级已覆盖
                                            string d2 = DescribeObjectStrings(cand);
                                            if (d2.IndexOf('[') >= 0) sbD.Append($" {(isMsg ? "m" : "t")}+{off:X} {d2}");
                                        }
                                    }
                                }
                                catch { }
                                detail = sbD.ToString();
                            }
                            else if (kind == "rom")
                            {
                                long romObj = BitConverter.ToInt64(Rd(rdx, 8), 0);
                                int romIdx = BitConverter.ToInt32(Rd(rdx + 8, 4), 0);
                                int romLen = BitConverter.ToInt32(Rd(rdx + 12, 4), 0);
                                if (LooksArray(romObj) && romIdx >= 0 && romLen > 0 && romLen <= 0x1000000)
                                {
                                    byte[] hd = Rd(romObj + 16 + romIdx, Math.Min(romLen, 64));
                                    detail = $"ROM len={romLen} type={(int)r8v} eom={(int)r9v} head={BitConverter.ToString(hd)}";
                                    if (hits <= 6) DumpToFile($"zprobe_out_{label}_{hits}.bin", romObj + 16 + romIdx, romLen);
                                }
                                else detail = $"ROM? obj=0x{romObj:X} idx={romIdx} len={romLen} type={(int)r8v} eom={(int)r9v}";
                            }
                            else
                            {
                                detail = $"rcx={DescribeManaged(rcx)}";
                                if (hits <= 3 && LooksArray(rcx))
                                {
                                    int plen = BitConverter.ToInt32(Rd(rcx + 8, 4), 0);
                                    if (plen > 0 && plen <= 65536) DumpToFile($"zprobe_pl_{hits}.bin", rcx + 16, plen);
                                }
                            }
                            var line = $"[{DateTime.Now:HH:mm:ss.fff}] {label}#{hits} seq={s} {detail}";
                            Console.WriteLine("[zprobe] " + line);
                            if (hits <= 60) File.AppendAllText(HO + "/zprobe.txt", line + "\r\n");
                            else if (hits == 61) File.AppendAllText(HO + "/zprobe.txt", "(... 后续略)\r\n");
                        }
                    }
                    catch { }
                }
            }) { IsBackground = true }.Start();
        }

        // 把托管字符串的裸地址转成可读文本
        static string DescribeString(long p)
        {
            if (p == 0) return "<null>";
            try
            {
                int len = Marshal.ReadInt32((IntPtr)(p + 8));
                if (len < 0 || len > 4096) return $"0x{p:X} bogus-strlen={len}";
                byte[] b = Rd(p + 12, Math.Min(len, 200) * 2);
                return "\"" + System.Text.Encoding.Unicode.GetString(b) + "\" (len=" + len + ")";
            }
            catch (Exception e) { return $"0x{p:X} ERR {e.Message}"; }
        }

        // 把托管数组的裸地址转成可读描述（含 Zstd 魔数判定 + 可打印文本猜测）
        static string DescribeManaged(long p)
        {
            if (p == 0) return "<null>";
            try
            {
                long mt = Marshal.ReadInt64((IntPtr)p);
                int len = Marshal.ReadInt32((IntPtr)(p + 8));
                if (len < 0 || len > 0x4000000) return $"0x{p:X} bogus-len={len}";
                int n = Math.Min(len, 32);
                byte[] head = new byte[Math.Max(n, 1)];
                if (n > 0) Marshal.Copy((IntPtr)(p + 16), head, 0, n);
                bool zstd = n >= 4 && head[0] == 0x28 && head[1] == 0xB5 && head[2] == 0x2F && head[3] == 0xFD;
                string asText = "";
                if (n > 0)
                {
                    int printable = 0;
                    for (int i = 0; i < n; i++) if (head[i] >= 0x20 && head[i] < 0x7F) printable++;
                    if (printable * 100 / n >= 80)
                    {
                        var cs = new System.Text.StringBuilder();
                        for (int i = 0; i < n; i++) cs.Append((char)head[i]);
                        asText = " text=\"" + cs + "\"";
                    }
                }
                return $"arr=0x{p:X} mt=0x{mt:X} len={len} head={BitConverter.ToString(head, 0, n)} {(zstd ? "ZSTD-OK" : "NOT-ZSTD")}{asText}";
            }
            catch (Exception e) { return $"0x{p:X} ERR {e.Message}"; }
        }

        // 判断一个裸地址是否像一个托管数组（MethodTable 合理 + 长度合理）
        static bool LooksArray(long p)
        {
            if (p < 0x10000) return false;
            byte[] h = Rd(p, 16);
            if (h.Length != 16) return false;
            long mt = BitConverter.ToInt64(h, 0);
            int len = BitConverter.ToInt32(h, 8);
            return mt > 0x10000 && (mt >> 47) == 0 && len >= 0 && len < 0x4000000;
        }
        static string HexOfArray(long arrPtr, int off, int cnt, int maxBytes)
        {
            int n = Math.Min(Math.Max(cnt, 0), maxBytes);
            if (n <= 0) return "len=0";
            byte[] b = Rd(arrPtr + 16 + off, n);
            return $"len={cnt} head={BitConverter.ToString(b)}";
        }
        // 把目标内存原样落盘，供离线解析（protobuf / 熵分析）
        static void DumpToFile(string name, long addr, int n)
        {
            try
            {
                n = Math.Min(n, 65536);
                if (n <= 0) return;
                byte[] b = Rd(addr, n);
                File.WriteAllBytes(HO + "/" + name, b);
            }
            catch { }
        }
        // 扫描一个托管对象内部，找出它引用的字符串（用于 Uri —— 拿不到 Uri 内部字段名，就按指针扫）
        static string DescribeObjectStrings(long p)
        {
            if (p == 0) return "<null>";
            var sb = new System.Text.StringBuilder();
            try
            {
                long mt = BitConverter.ToInt64(Rd(p, 8), 0);
                sb.Append($"0x{p:X} mt=0x{mt:X}");
                int nstr = 0;
                for (int off = 0; off < 0x80; off += 8)
                {
                    long cand = BitConverter.ToInt64(Rd(p + off, 8), 0);
                    if (cand < 0x10000 || (cand >> 47) != 0) continue;
                    int len = BitConverter.ToInt32(Rd(cand + 8, 4), 0);
                    if (len <= 0 || len > 2048) continue;
                    string s = System.Text.Encoding.Unicode.GetString(Rd(cand + 12, len * 2));
                    bool printable = true;
                    for (int i = 0; i < s.Length; i++) { if (s[i] < 0x20 || s[i] >= 0x7F) { printable = false; break; } }
                    if (!printable) continue;
                    int alnum = 0, digits = 0;
                    for (int i = 0; i < s.Length; i++) { char c = s[i]; if (char.IsLetter(c)) alnum++; else if (char.IsDigit(c)) digits++; }
                    if (alnum + digits < 2) continue;
                    if (nstr++ >= 8) break;
                    sb.Append($" [{off:X}]=\"{s}\"");
                }
            }
            catch (Exception e) { sb.Append(" ERR " + e.Message); }
            return sb.ToString();
        }
        static void ZLog(string s)
        {
            try { Console.WriteLine("[zprobe] " + s); } catch { }
            try { File.AppendAllText(HO + "/zprobe.txt", $"[{DateTime.Now:HH:mm:ss.fff}] {s}\r\n"); } catch { }
        }
        // 把一个"路径字符串"参数描述出来：是否存在于磁盘、大小、前 4 字节是不是 Zstd 魔数
        static string DescribePathArg(long p)
        {
            string s = DescribeString(p);
            try
            {
                if (p == 0) return s;
                int len = Marshal.ReadInt32((IntPtr)(p + 8));
                if (len <= 0 || len > 1024) return s;
                string path = System.Text.Encoding.Unicode.GetString(Rd(p + 12, len * 2));
                if (string.IsNullOrEmpty(path)) return s;
                var fi = new System.IO.FileInfo(path);
                if (!fi.Exists) return s + " | exists=FALSE";
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    byte[] h4 = new byte[4];
                    int got = fs.Read(h4, 0, 4);
                    bool z = got == 4 && h4[0] == 0x28 && h4[1] == 0xB5 && h4[2] == 0x2F && h4[3] == 0xFD;
                    return s + $" | exists=TRUE size={fs.Length} {(z ? "ZSTD-OK" : "NOT-ZSTD(" + BitConverter.ToString(h4, 0, got) + ")")}";
                }
            }
            catch (Exception e) { return s + " | statERR " + e.Message; }
        }
        // 把某方法的真 body 换成"固定返回 retObj"的原生桩（返回引用类型常量）
        static void StubMethodReturn(MethodBase mi, object retObj, string tag)
        {
            try { RuntimeHelpers.PrepareMethod(mi.MethodHandle); } catch { }
            long ep = mi.MethodHandle.GetFunctionPointer().ToInt64();
            byte[] eh = Rd(ep, 6);
            if (eh.Length != 6 || eh[0] != 0xFF || eh[1] != 0x25) { ZLog($"{tag}: 非 precode head={BitConverter.ToString(eh)}"); return; }
            long slot = ep + 6 + BitConverter.ToInt32(eh, 2);
            long body = Q(slot);
            if (body < 0x10000 || (body >> 47) != 0) { ZLog($"{tag}: body=0x{body:X} 无效"); return; }
            byte[] h2 = Rd(body, 2);
            if (h2[0] == 0xFF && h2[1] == 0x25) { ZLog($"{tag}: body 仍是 precode，跳过"); return; }
            if (h2[0] == 0x48 && h2[1] == 0xB8) { ZLog($"{tag}: 已打过桩，跳过"); return; }
            long cnt = AllocCounter(0x7A01, tag);
            WriteRetStub(body, retObj, cnt);
            ZLog($"{tag}: body=0x{body:X} -> 固定返回 {retObj?.GetType().Name ?? "null"}");
        }
        // ArraySegment<byte> 参数：r8 可能是"指向结构体的指针"，也可能是"数组指针本身"，两种都试
        static string DumpSeg(long p)
        {
            if (p == 0) return "<null>";
            try
            {
                if (LooksArray(p))
                {
                    int len = BitConverter.ToInt32(Rd(p + 8, 4), 0);
                    return "byval " + HexOfArray(p, 0, len, 96);
                }
                long arrPtr = BitConverter.ToInt64(Rd(p, 8), 0);
                int off = BitConverter.ToInt32(Rd(p + 8, 4), 0);
                int cnt = BitConverter.ToInt32(Rd(p + 12, 4), 0);
                if (LooksArray(arrPtr) && off >= 0 && cnt >= 0 && cnt < 0x4000000)
                    return $"byref arr=0x{arrPtr:X} off={off} cnt={cnt} " + HexOfArray(arrPtr, off, cnt, 96);
                return $"0x{p:X} <unrecognized>";
            }
            catch (Exception e) { return $"0x{p:X} ERR {e.Message}"; }
        }

        // ===== ArgCapture: 记录真 body 入口的参数（rcx/rdx）=====
        // 纯 asm 桩：把 rcx/rdx 写入共享槽，执行原字节，跳回 body+N。C# 侧轮询读取解析字符串。
        static long _argSlot = 0;                 // 共享槽（VirtualAlloc，读写）
        static long _argSeq = 0;                  // 序号计数器地址（asm inc）
        static readonly Dictionary<int, long> _argStubMap = new Dictionary<int, long>();  // tok -> stub 地址
        static readonly Dictionary<int, (long slot, int nbytes)> _argMeta = new Dictionary<int, (long, int)>();
        static int _argPollerStarted = 0;
        static void ArgPoller()
        {
            long lastSeq = -1;
            var swc = System.Diagnostics.Stopwatch.StartNew();
            while (true)
            {
                try
                {
                    if (_argSlot != 0 && _argSeq != 0)
                    {
                        long seq = BitConverter.ToInt64(Rd(_argSeq, 8), 0);
                        if (seq != lastSeq)
                        {
                            lastSeq = seq;
                            long a1 = BitConverter.ToInt64(Rd(_argSlot, 8), 0);
                            long a2 = BitConverter.ToInt64(Rd(_argSlot + 8, 8), 0);
                            long a3 = BitConverter.ToInt64(Rd(_argSlot + 16, 8), 0);
                            long a4 = BitConverter.ToInt64(Rd(_argSlot + 24, 8), 0);
                            if (Flag("argonlynull", "0") == "1" && a1 != 0) continue;   // 只记录第一个参数为 null 的情况
                            string s1 = TryReadStr(a1), s2 = TryReadStr(a2), s3 = TryReadStr(a3), s4 = TryReadStr(a4);
                            File.AppendAllText(HO + "/args.log",
                                $"[{DateTime.Now:HH:mm:ss.fff}] seq={seq}\r\n  rcx=0x{a1:X} {(s1 != null ? "\"" + s1 + "\"" : "<nonstr>")}\r\n  rdx=0x{a2:X} {(s2 != null ? "\"" + s2 + "\"" : "<nonstr>")}\r\n  r8 =0x{a3:X} {(s3 != null ? "\"" + s3 + "\"" : "<nonstr>")}\r\n  r9 =0x{a4:X} {(s4 != null ? "\"" + s4 + "\"" : "<nonstr>")}\r\n");
                        }
                    }
                }
                catch { }
                Thread.Sleep(5);
            }
        }
        // 尝试把 gc 堆上的 String 对象指针解析为 .NET 字符串（length@+8, firstchar@+0xC）
        static string TryReadStr(long ptr)
        {
            try
            {
                if (ptr < 0x10000 || (ptr >> 47) != 0) return null;
                long mt = BitConverter.ToInt64(Rd(ptr, 8), 0);
                if (mt < 0x10000 || (mt >> 47) != 0) return null;
                int len = BitConverter.ToInt32(Rd(ptr + 8, 4), 0);
                if (len < 0 || len > 4096) return null;
                if (len == 0) return "";
                byte[] buf = Rd(ptr + 0xC, Math.Min(len, 512) * 2);
                if (buf.Length < 2) return null;
                return System.Text.Encoding.Unicode.GetString(buf, 0, buf.Length);
            }
            catch { return null; }
        }

        static bool IsTramp(long a)
        {
            if (a == 0) return true;
            var b = Rd(a, 2);
            if (b[0] == 0xFF && b[1] == 0x25) return true;
            var m = Rd(a, 18);
            var s = new byte[] {0x4C,0x8B,0x15,0xFB,0x3F,0,0,0xFF,0x25,0xFD,0x3F,0,0,0x90,0x66,0x66,0x66,0x66};
            for (int i = 0; i < 18; i++) if (m[i] != s[i]) return false;
            return true;
        }

        static System.Diagnostics.Stopwatch _sw = System.Diagnostics.Stopwatch.StartNew();
                [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)] static extern IntPtr LoadLibrary(string lpFileName);
        static void Stage(string s) => Console.WriteLine($"[t+{_sw.ElapsedMilliseconds}ms] {s}");

        static void Run()
        {
            outDir = HO;
            Directory.CreateDirectory(outDir);
            LoadFlags();
            if (Flag("runbody", "1") == "0") { File.AppendAllText(HO + "/hook.log", "[hook] runbody=0 - observer only\r\n"); return; }
            if (Flag("runbody", "1") == "2")
            {
                // 纯观察 + 被动收集：零侵入（用应用自身程序集，不 LoadFile / 不 PEB / 不 Console 重定向）
                _h = GetCurrentProcess();
                var log2 = new StreamWriter(Path.Combine(outDir, "hook.log"), false) { AutoFlush = true };
                log2.WriteLine("[hook] runbody=2 pure observer + passive");
                Assembly asm2 = null;
                while (asm2 == null) { Thread.Sleep(5); asm2 = AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(a => a.GetName().Name == "Deepchart"); }
                log2.WriteLine("[hook] app assembly found");
                // ===== 早期补丁线程：不等 35s，尽快对 priority.txt 里的 token 落盘 =====
                {
                    var asmCap = asm2;
                    new Thread(() =>
                    {
                        var swc0 = System.Diagnostics.Stopwatch.StartNew();
                        var capList = new List<(int tok, string hex)>();
                        try
                        {
                            foreach (var l in File.ReadAllLines(HO + "/priority.txt"))
                            {
                                var p = l.Trim().Split(':');
                                if (p.Length >= 2 && p[0].Length == 8) { try { capList.Add((Convert.ToInt32(p[0], 16), p[1])); } catch { } }
                            }
                        }
                        catch { }
                        var done = new HashSet<int>();
                        int tries = 0;
                        while (swc0.ElapsedMilliseconds < 120000)
                        {
                            tries++;
                            foreach (var it in capList)
                            {
                                int tk = it.tok;
                                if (done.Contains(tk)) continue;
                                try
                                {
                                    var mi = asmCap.ManifestModule.ResolveMethod(0x06000000 | tk) as MethodInfo;
                                    if (mi == null) continue;
                                    long ep0 = 0;
                                    try { RuntimeHelpers.PrepareMethod(mi.MethodHandle); } catch { }
                                    ep0 = mi.MethodHandle.GetFunctionPointer().ToInt64();
                                    if (ep0 < 0x10000) continue;
                                    // ep 必须是 precode（FF 25）才能取槽
                                    byte[] eh = Rd(ep0, 2);
                                    long body = 0;
                                    if (eh.Length == 2 && eh[0] == 0xFF && eh[1] == 0x25)
                                        body = BitConverter.ToInt64(Rd(ep0 + 0x4000, 8), 0);
                                    else
                                        body = ep0;      // 已是真 body
                                    if (body < 0x10000 || (body >> 47) != 0) continue;
                                    byte[] head = Rd(body, 2);
                                    if (head.Length < 2) continue;
                                    if (head[0] == 0xFF && head[1] == 0x25) continue;   // 还是 precode，等下一轮
                                    if (head[0] == 0xE9 || (head[0] == 0x48 && head[1] == 0xB8)) { done.Add(tk); continue; } // 已补丁
                                    string gateE = ""; try { gateE = File.ReadAllText(HO + "/patchgate").Trim(); } catch { }
                                    if (Flag("argcap", "0") == "1")
                                    {
                                        InstallArgStub(tk, body, log2);
                                    }
                                    else
                                    {
                                        if (gateE != "1") continue;
                                        int nb = it.hex.Length / 2;
                                        byte[] pb = new byte[nb];
                                        for (int bi = 0; bi < nb; bi++) pb[bi] = Convert.ToByte(it.hex.Substring(bi * 2, 2), 16);
                                        byte[] oldb = Rd(body, nb);
                                        uint po; VirtualProtect((IntPtr)body, (IntPtr)nb, 0x40, out po);
                                        Marshal.Copy(pb, 0, (IntPtr)body, nb);
                                        VirtualProtect((IntPtr)body, (IntPtr)nb, po, out _);
                                        lock (log2) { log2.WriteLine($"[earlypatch] tok={tk:X} body=0x{body:X} {BitConverter.ToString(oldb)} -> {it.hex} (t={swc0.ElapsedMilliseconds}ms)"); log2.Flush(); }
                                    }
                                    done.Add(tk);
                                }
                                catch (Exception ex) { lock (log2) { log2.WriteLine($"[earlypatch] tok={tk:X} fail: {ex.Message}"); log2.Flush(); } }
                            }
                            if (done.Count >= capList.Count && capList.Count > 0) break;
                            Thread.Sleep(100);
                        }
                        lock (log2) { log2.WriteLine($"[earlypatch] done {done.Count}/{capList.Count} tries={tries}"); log2.Flush(); }
                    }) { IsBackground = true }.Start();
                }
                // ===== RestSharp.Ensure.NotNull 处理（1=参数记录诊断 / 2=改为不抛异常）=====
                if (Flag("resthook", "0") != "0")
                {
                    new Thread(() =>
                    {
                        string mode = Flag("resthook", "0");
                        int installed = 0;
                        for (int i = 0; i < 1800; i++)
                        {
                            try
                            {
                                if (installed == 0)
                                {
                                    Assembly rs = null;
                                    foreach (var a in AppDomain.CurrentDomain.GetAssemblies())
                                    {
                                        var an = a.GetName().Name;
                                        if (an == "RestSharp") { rs = a; break; }
                                    }
                                    if (rs != null)
                                    {
                                        var et = rs.GetType("RestSharp.Ensure");
                                        if (et != null)
                                        {
                                            foreach (var m0 in et.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static))
                                            {
                                                if (m0.Name != "NotNull") continue;
                                                MethodInfo mi = m0;
                                                try
                                                {
                                                    if (m0.IsGenericMethodDefinition)
                                                    {
                                                        var gp = m0.GetGenericArguments();
                                                        if (gp.Length != 1) continue;
                                                        mi = m0.MakeGenericMethod(typeof(object));
                                                    }
                                                    RuntimeHelpers.PrepareMethod(mi.MethodHandle);
                                                    long ep = mi.MethodHandle.GetFunctionPointer().ToInt64();
                                                    if (ep < 0x10000) continue;
                                                    long body = ep;
                                                    byte[] eh = Rd(ep, 2);
                                                    if (eh.Length == 2 && eh[0] == 0xFF && eh[1] == 0x25)
                                                        body = BitConverter.ToInt64(Rd(ep + 0x4000, 8), 0);
                                                    if (body < 0x10000) continue;
                                                    byte[] h2 = Rd(body, 2);
                                                    if (h2[0] == 0xFF && h2[1] == 0x25) continue;
                                                    if (mode == "2")
                                                    {
                                                        // Ensure.NotNull(value, name) -> mov rax, rcx ; ret  （不再抛异常）
                                                        byte[] pb = new byte[] { 0x48, 0x8B, 0xC1, 0xC3 };
                                                        byte[] oldb = Rd(body, 4);
                                                        uint po; VirtualProtect((IntPtr)body, (IntPtr)4, 0x40, out po);
                                                        Marshal.Copy(pb, 0, (IntPtr)body, 4);
                                                        VirtualProtect((IntPtr)body, (IntPtr)4, po, out _);
                                                        installed++;
                                                        lock (log2) { log2.WriteLine($"[resthook] PATCHED Ensure.NotNull ({m0}) ep=0x{ep:X} body=0x{body:X} {BitConverter.ToString(oldb)} -> 488BC1C3 (ret value)"); log2.Flush(); }
                                                    }
                                                    else
                                                    {
                                                        int fake = 0x00F00000 + installed;
                                                        InstallArgStub(fake, body, log2);
                                                        installed++;
                                                        lock (log2) { log2.WriteLine($"[resthook] Ensure.NotNull#{installed} ({m0}) ep=0x{ep:X} body=0x{body:X}"); log2.Flush(); }
                                                    }
                                                }
                                                catch (Exception ex1) { lock (log2) { log2.WriteLine($"[resthook] {m0}: {ex1.Message}"); log2.Flush(); } }
                                            }
                                        }
                                    }
                                }
                            }
                            catch { }
                            if (installed > 0 && i > 20) break;
                            Thread.Sleep(100);
                        }
                        lock (log2) { log2.WriteLine($"[resthook] total {installed} (mode={mode})"); log2.Flush(); }
                    }) { IsBackground = true }.Start();
                }
                // ===== 合成许可状态：直接调用 Status 的 setter + BridgeTransformer.InterceptFlexibleViewer =====
                if (Flag("seed", "0") == "1")
                {
                    var asmS = asm2;
                    new Thread(() =>
                    {
                        Thread.Sleep(1200);
                        try
                        {
                            var st = asmS.GetType("License.Status", false);
                            if (st == null) { lock (log2) { log2.WriteLine("[seed] License.Status 未找到"); log2.Flush(); } return; }
                            try { RuntimeHelpers.RunClassConstructor(st.TypeHandle); } catch (Exception ce) { lock (log2) { log2.WriteLine("[seed] cctor: " + ce.Message); log2.Flush(); } }
                            var sbLog = new System.Text.StringBuilder();
                            object Inv1(string nm, object v)
                            {
                                try
                                {
                                    var m = st.GetMethod(nm, BindingFlags.Public | BindingFlags.Static);
                                    if (m == null) return "no-method";
                                    var ps = m.GetParameters();
                                    if (ps.Length != 1) return "arity" + ps.Length;
                                    var pt = ps[0].ParameterType;
                                    object cv = v;
                                    if (v != null && !pt.IsInstanceOfType(v))
                                    {
                                        try { cv = Convert.ChangeType(v, pt); } catch { }
                                    }
                                    m.Invoke(null, new object[] { cv });
                                    return "ok";
                                }
                                catch (Exception e) { return "ex:" + e.GetType().Name + ":" + (e.InnerException?.Message ?? e.Message); }
                            }
                            sbLog.AppendLine("[seed] GetMember(true)=" + Inv1("CollectFilteredProvider", true));
                            // ★ 锁死总闸：把 CollectFilteredProvider 补成空操作，防止应用自己的许可失败流程把它拉回 false
                            if (Flag("lockgetmember", "1") == "1")
                            {
                                try
                                {
                                    var cm = st.GetMethod("CollectFilteredProvider", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                                    if (cm != null)
                                    {
                                        long ce = cm.MethodHandle.GetFunctionPointer().ToInt64();
                                        uint cop; VirtualProtect((IntPtr)ce, (IntPtr)16, 0x40, out cop);
                                        Marshal.WriteByte((IntPtr)ce, 0xC3);
                                        VirtualProtect((IntPtr)ce, (IntPtr)16, cop, out _);
                                        sbLog.AppendLine($"[seed] CollectFilteredProvider(tok=0x{cm.MetadataToken:X}) @0x{ce:X} -> ret (总闸已锁)");
                                    }
                                    else sbLog.AppendLine("[seed] CollectFilteredProvider 未找到");
                                }
                                catch (Exception le) { sbLog.AppendLine("[seed] lockgetmember ex: " + le.Message); }
                            }
                            // ★ 字段级保活：原生 stub 会绕过 setter 直接写字段，所以每 200ms 用反射把字段写回 true
                                try
                                {
                                    var gf = st.GetField("m_IsGroupedRole", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
                                    // 有效产品表也纳入保活（应用会重算回 {1,44,62}）
                                    var lcK = asmS.GetType("Deepchart.Decorators.LocatorCollectionDecorator", false);
                                    var omK = lcK?.GetField("orderedMatcherExplorerElements", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
                                    if (gf != null)
                                    {
                                        gf.SetValue(null, true);   // 先立即纠正一次
                                        var gfKeep = gf;
                                        var omKeep = omK;
                                        var arr44 = new int[] { 44 };
                                        new Thread(() =>
                                        {
                                            for (int k = 0; k < 30000; k++)
                                            {
                                                try { gfKeep.SetValue(null, true); } catch { }
                                                try { omKeep?.SetValue(null, arr44); } catch { }
                                                Thread.Sleep(200);
                                            }
                                        }) { IsBackground = true }.Start();
                                        sbLog.AppendLine("[seed] m_IsGroupedRole + 产品表{44} 保活线程已启动 (200ms)");
                                    }
                                    else sbLog.AppendLine("[seed] m_IsGroupedRole 字段未找到");
                                }
                            catch (Exception ke) { sbLog.AppendLine("[seed] keepalive ex: " + ke.Message); }
                            sbLog.AppendLine("[seed] hwid=" + Inv1("DecompressSharer", "00155D018B22"));
                            sbLog.AppendLine("[seed] sess=" + Inv1("SaveEditor", "00000000-0000-0000-0000-000000000001"));
                            sbLog.AppendLine("[seed] trial=" + Inv1("InterpretIntegratedAttribute", 0));
                            try { var mDT = st.GetMethod("WaitForScheduledConnection", BindingFlags.Public | BindingFlags.Static); if (mDT != null) { mDT.Invoke(null, new object[] { DateTime.Now.AddYears(10) }); sbLog.AppendLine("[seed] exp=ok"); } else sbLog.AppendLine("[seed] exp=no-method"); } catch (Exception e) { sbLog.AppendLine("[seed] exp ex:" + e.Message); }
                            sbLog.AppendLine("[seed] depth(100)=" + Inv1("WaitForLiteralProgram", 100));
                            sbLog.AppendLine("[seed] state(100)=" + Inv1("WaitForCentralState", 100));
                            sbLog.AppendLine("[seed] cap(100)=" + Inv1("CalcIterableCache", 100));
                            sbLog.AppendLine("[seed] pkw=" + Inv1("ProxyHiddenEvent", 100));
                            sbLog.AppendLine("[seed] ppt=" + Inv1("TransmitPortableToken", 100));
                            sbLog.AppendLine("[seed] b1=" + Inv1("WaitForEditableStruct", true));
                            sbLog.AppendLine("[seed] b2=" + Inv1("InterceptStatelessFinalizer", true));
                            sbLog.AppendLine("[seed] b3=" + Inv1("ProxyOperationalServer", true));
                            sbLog.AppendLine("[seed] b4=" + Inv1("InterruptRequest", true));
                            sbLog.AppendLine("[seed] b5=" + Inv1("TerminateSimpleSorter", true));
                            sbLog.AppendLine("[seed] b6=" + Inv1("WaitForInterruptibleManager", true));
                            sbLog.AppendLine("[seed] b7=" + Inv1("ResumeExtractor", true));
                            // 许可字段字典
                            try
                            {
                                var mSL = st.GetMethod("InterceptExternalWorker", BindingFlags.Public | BindingFlags.Static);
                                if (mSL != null)
                                {
                                    var sl = new System.Collections.SortedList();
                                    // product：BridgeTransformer.EncodeVisitor / ConvertibleConfig 读它，必须 44 或 62
                                    sl["product"] = "44";   // 44 = 高配套餐（内置授权 {1,99,102,103,1002}+追加），62 是低配
                                    // 以下键名取自许可文案占位符（RunnerPolicySelector 的 nag 文本）
                                    sl["hardwareID"] = "00155D018B22";
                                    sl["expdate_days_left"] = "3650";
                                    sl["uses_left"] = "9999";
                                    sl["max_processes"] = "10";
                                    sl["current_uses"] = "1";
                                    sl["max_uses"] = "9999";
                                    sl["current_minutes_days"] = "1";
                                    sl["max_minutes_days"] = "3650";
                                    sl["minutes_days_left"] = "3650";
                                    sl["username"] = "user";
                                    sl["email"] = "user@localhost";
                                    sl["type"] = "1";
                                    sl["mode"] = "1";
                                    sl["company"] = "local";
                                    sl["key"] = "0000-0000-0000-0000-0000";
                                    sl["expiration_date"] = DateTime.Now.AddYears(10).ToString("yyyy-MM-dd");
                                    mSL.Invoke(null, new object[] { sl });
                                    sbLog.AppendLine($"[seed] dict=ok ({sl.Count} keys)");
                                }
                                else sbLog.AppendLine("[seed] dict=no-method");
                            }
                            catch (Exception e) { sbLog.AppendLine("[seed] dict ex:" + e.Message); }
                            // BridgeTransformer.InterceptFlexibleViewer 填充字符串
                            try
                            {
                                var bt = asmS.GetType("VolAnalysis.Proxies.BridgeTransformer", false);
                                if (bt != null)
                                {
                                    var mi = bt.GetMethod("InterceptFlexibleViewer", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                                    if (mi != null)
                                    {
                                        var ps = mi.GetParameters();
                                        var ids = new List<int> { 1, 99, 102, 103, 1002 };
                                        var args = new object[ps.Length];
                                        for (int ai = 0; ai < ps.Length; ai++)
                                        {
                                            var pt = ps[ai].ParameterType;
                                            if (pt == typeof(string)) args[ai] = "00155D018B22";
                                            else if (pt.IsAssignableFrom(ids.GetType())) args[ai] = ids;
                                            else args[ai] = pt.IsValueType ? Activator.CreateInstance(pt) : null;
                                        }
                                        mi.Invoke(null, args);
                                        sbLog.AppendLine("[seed] InterceptFlexibleViewer=ok");
                                        // 复核
                                        foreach (var gn in new[] { "TrackSynchronizer", "InterceptIdentifiableRecord", "WaitForExtendedCompiler", "ProxyStatelessTask", "AdaptRecommender" })
                                        {
                                            try { var gm = bt.GetMethod(gn, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static); var rv = gm?.Invoke(null, null); sbLog.AppendLine($"[seed] check {gn}={(rv == null ? "<null>" : "\"" + rv + "\"")}"); } catch (Exception ge) { sbLog.AppendLine($"[seed] check {gn} ex:{ge.Message}"); }
                                        }
                                    }
                                    else sbLog.AppendLine("[seed] IFV=no-method");
                                }
                                else sbLog.AppendLine("[seed] BridgeTransformer 未找到");
                            }
                            catch (Exception e) { sbLog.AppendLine("[seed] IFV ex:" + (e.InnerException?.Message ?? e.Message)); }
                            // ★ 2026-10-05：历史响应校验能不能本地满足？
                            //   检查式： DeflateDynamicSorter(HistRespV2.LogId, label)
                            //            == _CheckerWriterStr + "-" + explorerExplorerTxt
                            //   实测服务器**从不**下发 LogId（89 帧逐字节解析，全部只有 f1..f4），
                            //   所以左边恒为 DeflateDynamicSorter(null, label)。
                            //   若这个返回值是常量、且中间含 "-"，就能把 _CheckerWriterStr / explorerExplorerTxt
                            //   拆成两半去精确匹配 —— 那就有机会让校验通过、把协议往下推一步。
                            try
                            {
                                var efcT = asmS.GetType("VolAnalysis.Compression.ExpandableFilterCompressor", false);
                                var dds = efcT?.GetMethod("DeflateDynamicSorter", BindingFlags.Public | BindingFlags.Static);
                                if (dds == null) sbLog.AppendLine("[seed] DeflateDynamicSorter 未找到");
                                else
                                {
                                    string[] probes = new string[] { null, "", "x" };
                                    foreach (var pr in probes)
                                    {
                                        string lbl = (pr == null) ? "null" : ("\"" + pr + "\"");
                                        try
                                        {
                                            var v = dds.Invoke(null, new object[] { pr, "Deepchart" }) as string;
                                            sbLog.AppendLine($"[seed] DDS({lbl},\"Deepchart\") = {(v == null ? "<null>" : "\"" + v + "\" len=" + v.Length)}");
                                        }
                                        catch (Exception de) { sbLog.AppendLine($"[seed] DDS({lbl}) 抛 {de.InnerException?.Message ?? de.Message}"); }
                                    }
                                    try
                                    {
                                        var btT = asmS.GetType("VolAnalysis.Proxies.BridgeTransformer", false);
                                        if (btT != null)
                                        {
                                            var g1 = btT.GetMethod("TrackSynchronizer", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                                            var g2 = btT.GetMethod("InterceptIdentifiableRecord", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                                            var v1 = g1?.Invoke(null, null); var v2 = g2?.Invoke(null, null);
                                            sbLog.AppendLine($"[seed] 当前会话串: _CheckerWriterStr={v1 ?? "<null>"}  explorerExplorerTxt={v2 ?? "<null>"}");
                                        }
                                    }
                                    catch { }
                                }
                            }
                            catch (Exception e) { sbLog.AppendLine("[seed] DDS ex: " + e.Message); }
                            // 看门狗：把 subscriberDistributor 直接设为空委托（防 null 调用），并确保类型已初始化
                            try
                            {
                                var lc = asmS.GetType("Deepchart.Decorators.LocatorCollectionDecorator", false);
                                if (lc != null)
                                {
                                    try { RuntimeHelpers.RunClassConstructor(lc.TypeHandle); } catch (Exception ce2) { sbLog.AppendLine("[seed] lc cctor: " + ce2.Message); }
                                    Action noop = () => { };
                                    int setn = 0; bool found = false;
                                    foreach (var f in lc.GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public))
                                    {
                                        if (f.FieldType != typeof(Action)) continue;
                                        if (f.Name == "subscriberDistributor") { found = true; f.SetValue(null, noop); setn++; }
                                    }
                                    if (!found)
                                    {
                                        foreach (var f in lc.GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public))
                                        {
                                            if (f.FieldType != typeof(Action)) continue;
                                            f.SetValue(null, noop); setn++;
                                        }
                                    }
                                    sbLog.AppendLine($"[seed] watchdog subscriberDistributor set x{setn} (named={found})");
                                }
                                else sbLog.AppendLine("[seed] LocatorCollectionDecorator 未找到");
                            }
                            catch (Exception e) { sbLog.AppendLine("[seed] watchdog ex:" + (e.InnerException?.Message ?? e.Message)); }
                            // ★ 解锁全部功能：把全部功能标识注入 AutomatedSelectorWrapper.wrapperDecoratorAdapter
                            //    （正常由 CallChooser() 从服务器取回授权清单后填充，我们离线化后为空 → 功能/数据源被砍）
                            try
                            {
                                var aw = asmS.GetType("Deepchart.Wrapping.AutomatedSelectorWrapper", false);
                                if (aw != null)
                                {
                                    try { RuntimeHelpers.RunClassConstructor(aw.TypeHandle); } catch (Exception ce3) { sbLog.AppendLine("[seed] aw cctor: " + ce3.Message); }
                                    var fld = aw.GetField("wrapperDecoratorAdapter", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
                                    if (fld != null)
                                    {
                                        if (Flag("featunlock", "1") != "1") { sbLog.AppendLine("[seed] 功能解锁: 已暂停 (featunlock=0)"); }
                                        else
                                        {
                                        var set = fld.GetValue(null) as System.Collections.Generic.HashSet<string>;
                                        if (set == null) { set = new System.Collections.Generic.HashSet<string>(); fld.SetValue(null, set); }
                                        int added = 0, total = 0;
                                        try
                                        {
                                            foreach (var ln in File.ReadAllLines(HO + "/features.txt"))
                                            {
                                                var s = ln.Trim();
                                                if (s.Length == 0) continue;
                                                total++;
                                                if (set.Add(s)) added++;
                                            }
                                        }
                                        catch (Exception fe2) { sbLog.AppendLine("[seed] features 读取失败: " + fe2.Message); }
                                        sbLog.AppendLine($"[seed] 功能解锁: 注入 {added}/{total} 项，集合现有 {set.Count}");
                                        }
                                    }
                                    else sbLog.AppendLine("[seed] wrapperDecoratorAdapter 字段未找到");
                                }
                                else sbLog.AppendLine("[seed] AutomatedSelectorWrapper 未找到");
                            }
                            catch (Exception e) { sbLog.AppendLine("[seed] unlock ex: " + (e.InnerException?.Message ?? e.Message)); }
                            // ===== License.Status 运行时状态探针 =====
                            if (Flag("licprobe", "0") == "1")
                            {
                                var asmP = asmS;
                                new Thread(() =>
                                {
                                    for (int k = 0; k < 60; k++)
                                    {
                                        try
                                        {
                                            var st2 = asmP.GetType("License.Status", false);
                                            if (st2 != null)
                                            {
                                                var sb2 = new System.Text.StringBuilder();
                                                sb2.Append($"==== {DateTime.Now:HH:mm:ss} License.Status 快照 ====\r\n");
                                                foreach (var mm in st2.GetMethods(BindingFlags.Public | BindingFlags.Static))
                                                {
                                                    if (mm.GetParameters().Length != 0) continue;
                                                    if (mm.ReturnType == typeof(void)) continue;
                                                    if (mm.Name.StartsWith("get_")) continue;
                                                    try
                                                    {
                                                        var v = mm.Invoke(null, null);
                                                        string vs;
                                                        if (v == null) vs = "<null>";
                                                        else if (v is System.Collections.IDictionary dd) vs = "dict[" + dd.Count + "]";
                                                        else if (v is string ss) vs = ss.Length > 60 ? "\"" + ss.Substring(0, 60) + "…\"" : "\"" + ss + "\"";
                                                        else if (v is byte[] ba2) vs = "byte[" + ba2.Length + "]";
                                                        else vs = v.ToString();
                                                        sb2.Append($"  {mm.ReturnType.Name,-12} {mm.Name,-32} = {vs}\r\n");
                                                    }
                                                    catch (Exception ie) { sb2.Append($"  {"?",-12} {mm.Name,-32} ERR {ie.InnerException?.Message ?? ie.Message}\r\n"); }
                                                }
                                                File.WriteAllText(HO + "/lic_status.txt", sb2.ToString());
                                            }
                                        }
                                        catch { }
                                        Thread.Sleep(8000);
                                    }
                                }) { IsBackground = true }.Start();
                            }
                            // ===== 加密往返验证：用应用自己的 ConfigTransaction 造合法密文 =====
                            if (Flag("cryptotest", "0") == "1")
                            {
                                var asmC = asmS;
                                new Thread(() =>
                                {
                                    Thread.Sleep(12000);   // 等 ConfigTransaction 建好 aeskey.dat
                                    var sb3 = new System.Text.StringBuilder();
                                    try
                                    {
                                        var ct = asmC.GetType("VolAnalysis.Configuration.ConfigTransaction", false);
                                        if (ct == null) { sb3.AppendLine("ConfigTransaction 未找到"); }
                                        else
                                        {
                                            var enc = ct.GetMethod("ConfigureIsolatedExplorer", BindingFlags.Public | BindingFlags.Static);
                                            var dec = ct.GetMethod("SetCentralDecider", BindingFlags.Public | BindingFlags.Static);
                                            sb3.AppendLine($"enc={(enc != null)} dec={(dec != null)}");
                                            string plain = "[{\"ConnectionId\":\"abc\",\"Name\":\"测试连接\",\"Broker\":4,\"Param\":\"{}\"}]";
                                            var cipher = enc?.Invoke(null, new object[] { plain }) as string;
                                            sb3.AppendLine($"密文长度={cipher?.Length} 前60={ (cipher != null && cipher.Length > 60 ? cipher.Substring(0, 60) : cipher) }");
                                            var back = cipher == null ? null : dec?.Invoke(null, new object[] { cipher }) as string;
                                            sb3.AppendLine($"回解结果={back}");
                                            sb3.AppendLine($"往返一致={back == plain}");
                                        }
                                    }
                                    catch (Exception ce) { sb3.AppendLine("异常: " + (ce.InnerException?.Message ?? ce.Message)); }
                                    try { File.WriteAllText(HO + "/crypto_test.txt", sb3.ToString()); } catch { }
                                }) { IsBackground = true }.Start();
                            }
                            // ===== 权限门控探针：读 m_SimpleConfig / m_AdaptableStub =====
                            if (Flag("gateprobe", "0") == "1")
                            {
                                var asmG = asmS;
                                new Thread(() =>
                                {
                                    for (int k = 0; k < 12; k++)
                                    {
                                        Thread.Sleep(4000);
                                        try
                                        {
                                            var sb4 = new System.Text.StringBuilder();
                                            sb4.Append($"==== {DateTime.Now:HH:mm:ss} 权限门控快照 ====\r\n");
                                            var cc = asmG.GetType("VolAnalysis.Configuration.ConvertibleConfig", false);
                                            if (cc != null)
                                            {
                                                var f = cc.GetField("m_SimpleConfig", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
                                                var set = f?.GetValue(null) as System.Collections.IEnumerable;
                                                var vals = new List<int>();
                                                if (set != null) foreach (var o in set) { try { vals.Add(Convert.ToInt32(o)); } catch { } }
                                                vals.Sort();
                                                sb4.Append($"  m_SimpleConfig({vals.Count}) = {string.Join(",", vals)}\r\n");
                                                foreach (var nm in new[] { "m_AlphabeticConfigNum", "_ModularAnalyzerStep", "attachedConfigCount", "_ConfigAdapterFlag", "_ControllerEvaluatorCap", "m_SortedConfigScore", "m_ConfigTagSize", "automatedConfigPerc" })
                                                {
                                                    var ff = cc.GetField(nm, BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
                                                    sb4.Append($"  {nm} = {ff?.GetValue(null)}\r\n");
                                                }
                                            }
                                            else sb4.AppendLine("  ConvertibleConfig 未找到");
                                            var sn = asmG.GetType("VolAnalysis.Stubs.SynchronizerNode", false);
                                            var af = sn?.GetField("m_AdaptableStub", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
                                            var av = af?.GetValue(null) as System.Collections.IEnumerable;
                                            if (av == null) sb4.AppendLine("  m_AdaptableStub = <null> (不限制=全部券商)");
                                            else { var l2 = new List<string>(); foreach (var o in av) l2.Add(o.ToString()); sb4.AppendLine($"  m_AdaptableStub({l2.Count}) = {string.Join(",", l2)}"); }
                                            File.WriteAllText(HO + "/gate_status.txt", sb4.ToString());
                                        }
                                        catch (Exception ge) { try { File.WriteAllText(HO + "/gate_status.txt", "异常: " + (ge.InnerException?.Message ?? ge.Message)); } catch { } }
                                    }
                                }) { IsBackground = true }.Start();
                            }
                            // ★★ 权限门控：m_AdaptableStub 在 SynchronizerNode 静态构造里算好（早于本 seed）
                            if (Flag("brokerunlock", "1") != "1") sbLog.AppendLine("[seed] 券商解锁: 已暂停 (brokerunlock=0)");
                            else try
                            {
                                var sn = asmS.GetType("VolAnalysis.Stubs.SynchronizerNode", false);
                                if (sn != null)
                                {
                                    try { RuntimeHelpers.RunClassConstructor(sn.TypeHandle); } catch (Exception ce4) { sbLog.AppendLine("[seed] sn cctor: " + ce4.Message); }
                                    var af = sn.GetField("m_AdaptableStub", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
                                    if (af != null)
                                    {
                                        var after = af.GetValue(null) as System.Collections.IEnumerable;
                                        var l3 = new List<string>();
                                        if (after != null) foreach (var o in after) l3.Add(o.ToString());
                                        sbLog.AppendLine($"[seed] m_AdaptableStub({l3.Count}) = {string.Join(",", l3)}  (cctor 已在权限注入后重跑)");
                                    }
                                    else sbLog.AppendLine("[seed] m_AdaptableStub 字段未找到");
                                }
                                else sbLog.AppendLine("[seed] SynchronizerNode 未找到");
                            }
                            catch (Exception e) { sbLog.AppendLine("[seed] adaptable ex: " + (e.InnerException?.Message ?? e.Message)); }
                            // ★★ 套餐最高等级：把 RevertInternalTokenizer 补成永远 true（所有权限门直接放行）
                            if (Flag("plangate", "1") == "1")
                            {
                                try
                                {
                                    var ccG = asmS.GetType("VolAnalysis.Configuration.ConvertibleConfig", false);
                                    var rg = ccG?.GetMethod("RevertInternalTokenizer", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                                    if (rg != null)
                                    {
                                        long ge = rg.MethodHandle.GetFunctionPointer().ToInt64();
                                        uint gop; VirtualProtect((IntPtr)ge, (IntPtr)16, 0x40, out gop);
                                        Marshal.WriteByte((IntPtr)ge, 0xB0);   // mov al,1
                                        Marshal.WriteByte((IntPtr)(ge + 1), 0x01);
                                        Marshal.WriteByte((IntPtr)(ge + 2), 0xC3);  // ret
                                        VirtualProtect((IntPtr)ge, (IntPtr)16, gop, out _);
                                        sbLog.AppendLine($"[seed] RevertInternalTokenizer(tok=0x{rg.MetadataToken:X}) @0x{ge:X} -> true (套餐=最高等级)");
                                    }
                                    else sbLog.AppendLine("[seed] RevertInternalTokenizer 未找到");
                                    // ★ 有效产品表收敛为只有 44（62/1 是低配，无用）
                                    var lcT = asmS.GetType("Deepchart.Decorators.LocatorCollectionDecorator", false);
                                    var omf = lcT?.GetField("orderedMatcherExplorerElements", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
                                    if (omf != null)
                                    {
                                        omf.SetValue(null, new int[] { 44 });
                                        sbLog.AppendLine("[seed] orderedMatcherExplorerElements = {44} (仅保留高配套餐)");
                                    }
                                }
                                catch (Exception pe) { sbLog.AppendLine("[seed] plangate ex: " + pe.Message); }
                            }
                            // ★★ 权限整数清单补全：ConvertibleConfig.m_SimpleConfig 填满全部已知索引
                            if (Flag("brokerunlock", "1") == "1") try
                            {
                                var ccT = asmS.GetType("VolAnalysis.Configuration.ConvertibleConfig", false);
                                if (ccT != null)
                                {
                                    try { RuntimeHelpers.RunClassConstructor(ccT.TypeHandle); } catch { }
                                    var sf = ccT.GetField("m_SimpleConfig", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
                                    if (sf != null)
                                    {
                                        var hs = sf.GetValue(null) as System.Collections.Generic.HashSet<int>;
                                        if (hs == null) { hs = new System.Collections.Generic.HashSet<int>(); sf.SetValue(null, hs); }
                                        int before2 = hs.Count;
                                        // 全部已知权限索引（来自 ConvertibleConfig 静态构造的字段赋值）
                                        foreach (var idx in new[] { 1, 10, 11, 12, 13, 14, 80, 81, 99, 102, 103, 104, 105, 106, 1000, 1001, 1002 })
                                            hs.Add(idx);
                                        sbLog.AppendLine($"[seed] 权限清单: {before2} → {hs.Count} 项 ({string.Join(",", hs.OrderBy(x => x))})");
                                    }
                                    else sbLog.AppendLine("[seed] m_SimpleConfig 字段未找到");
                                }
                                else sbLog.AppendLine("[seed] ConvertibleConfig 未找到");
                            }
                            catch (Exception e) { sbLog.AppendLine("[seed] 权限清单 ex: " + (e.InnerException?.Message ?? e.Message)); }
                            // ===== 全量字段清点：所有许可相关类的静态字段 + AppContext =====
                            if (Flag("fulldump", "0") == "1")
                            {
                                var asmF = asmS;
                                new Thread(() =>
                                {
                                    Thread.Sleep(15000);   // 等许可流程跑完
                                    var outSb = new System.Text.StringBuilder();
                                    outSb.AppendLine($"==== 全量静态字段清点 {DateTime.Now:HH:mm:ss} ====");
                                    string[] types = new[]
                                    {
                                        "License.Status",
                                        "VolAnalysis.Configuration.ConvertibleConfig",
                                        "Deepchart.Decorators.LocatorCollectionDecorator",
                                        "Deepchart.Decorators.BridgeTransformer",
                                        "VolAnalysis.Configuration.ConfigTransaction",
                                        "VolAnalysis.Proxies.ProxyProfilePropertyType"
                                    };
                                    foreach (var tn in types)
                                    {
                                        try
                                        {
                                            var t = asmF.GetType(tn, false);
                                            if (t == null) { outSb.AppendLine($"\r\n### {tn}: 未找到"); continue; }
                                            outSb.AppendLine($"\r\n### {tn}");
                                            foreach (var f in t.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.FlattenHierarchy).Where(f => f.DeclaringType == t))
                                            {
                                                try
                                                {
                                                    object v = f.GetValue(null);
                                                    string vs;
                                                    if (v == null) vs = "<null>";
                                                    else if (v is System.Collections.IDictionary d)
                                                    {
                                                        var kv = new List<string>();
                                                        foreach (System.Collections.DictionaryEntry e in d) kv.Add($"{e.Key}={e.Value}");
                                                        vs = $"dict[{kv.Count}] {{{string.Join(", ", kv.Take(40))}}}";
                                                    }
                                                    else if (v is System.Collections.IEnumerable en && !(v is string))
                                                    {
                                                        var items = new List<string>();
                                                        foreach (var o in en) { items.Add(o?.ToString() ?? "<null>"); if (items.Count > 60) break; }
                                                        vs = $"{v.GetType().Name}[{items.Count}] {{{string.Join(", ", items)}}}";
                                                    }
                                                    else if (v is byte[] ba) vs = $"byte[{ba.Length}]";
                                                    else vs = v.ToString();
                                                    if (vs.Length > 900) vs = vs.Substring(0, 900) + "…";
                                                    outSb.AppendLine($"  {f.FieldType.Name} {f.Name} = {vs}");
                                                }
                                                catch (Exception fe) { outSb.AppendLine($"  {f.Name} = <读取失败: {fe.InnerException?.Message ?? fe.Message}>"); }
                                            }
                                        }
                                        catch (Exception te) { outSb.AppendLine($"### {tn} 异常: {te.Message}"); }
                                    }
                                    try
                                    {
                                        outSb.AppendLine("\r\n### AppContext 数据");
                                        foreach (var k in new[] { "License_Init", "License_File_Name", "License_Global_Licensing_Behaviour", "License_HardwareID" })
                                            outSb.AppendLine($"  {k} = {AppContext.GetData(k) ?? "<null>"}");
                                    }
                                    catch { }
                                    try { File.WriteAllText(HO + "/fulldump.txt", outSb.ToString()); } catch { }
                                }) { IsBackground = true }.Start();
                            }
                            // ===== 原生体 dump：激活链方法（供离线定位完整性校验的机器码偏移）=====
                            if (Flag("nativedump", "0") == "1")
                            {
                                try
                                {
                                    var lcN = asmS.GetType("Deepchart.Decorators.LocatorCollectionDecorator", false);
                                    var stN = asmS.GetType("License.Status", false);
                                    foreach (var kv in new[] {
                                        new Tuple<System.Type, string>(lcN, "DecorateVisualTester"),
                                        new Tuple<System.Type, string>(lcN, "VisitIterator"),
                                        new Tuple<System.Type, string>(lcN, "DecorateMonoRunner"),
                                        new Tuple<System.Type, string>(lcN, "ResetProcessor"),
                                        new Tuple<System.Type, string>(lcN, "Exchange"),
                                        new Tuple<System.Type, string>(lcN, "DecorateCombinedConnection"),
                                        new Tuple<System.Type, string>(lcN, "ModifyGeneralWorker"),
                                        new Tuple<System.Type, string>(stN, "WaitForGenericReg")
                                    })
                                    {
                                        try
                                        {
                                            var mm = kv.Item1?.GetMethod(kv.Item2, BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
                                            if (mm == null) { sbLog.AppendLine($"[native] {kv.Item2}: 未找到"); continue; }
                                            RuntimeHelpers.PrepareMethod(mm.MethodHandle);
                                            long epN = mm.MethodHandle.GetFunctionPointer().ToInt64();
                                            long bodyN = BitConverter.ToInt64(Rd(epN + 0x4000, 8), 0);
                                            if (bodyN < 0x10000) { sbLog.AppendLine($"[native] {kv.Item2}: body 无效"); continue; }
                                            byte[] buf = Rd(bodyN, 16384);
                                            File.WriteAllBytes(HO + "/native_" + kv.Item2 + ".bin", buf);
                                            sbLog.AppendLine($"[native] {kv.Item2} tok=0x{mm.MetadataToken:X} ep=0x{epN:X} body=0x{bodyN:X} dump=16KB");
                                        }
                                        catch (Exception ne2) { sbLog.AppendLine($"[native] {kv.Item2} ex: " + ne2.Message); }
                                    }
                                }
                                catch (Exception ne) { sbLog.AppendLine("[native] ex: " + ne.Message); }
                            }
                            // ===== ★★ authresp：从登录源头构造授权响应（重定向 VisitIterator + 捕获请求长度）=====
                            if (Flag("authresp", "0") == "1")
                            {
                                try
                                {
                                    var lcA = asmS.GetType("Deepchart.Decorators.LocatorCollectionDecorator", false);
                                    // 0) 前置 seed：跳过 Exchange 依赖 + 令牌字段
                                    var stField = lcA.GetField("m_CustomizableUserStatus", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
                                    stField?.SetValue(null, "1");
                                    var dsmField = lcA.GetField("decoratorSelectorMemberDescr", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
                                    dsmField?.SetValue(null, "LIC-OK");
                                    // 1) ResetProcessor 捕获 text.Length
                                    var rpM = lcA.GetMethod("ResetProcessor", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
                                    RuntimeHelpers.PrepareMethod(rpM.MethodHandle);
                                    long epR = rpM.MethodHandle.GetFunctionPointer().ToInt64();
                                    long bodyR = BitConverter.ToInt64(Rd(epR + 0x4000, 8), 0);
                                    IntPtr capLen = Marshal.AllocHGlobal(8); Marshal.WriteInt32(capLen, 0);
                                    IntPtr visSlot = Marshal.AllocHGlobal(8); Marshal.WriteInt64(visSlot, 0);
                                    int dispN = 86;   // 前 0x56 字节位置无关（首个 rip 相对在 0x94）
                                    byte[] disp = Rd(bodyR, dispN);
                                    IntPtr tramp = VirtualAlloc(IntPtr.Zero, (IntPtr)128, 0x3000, 0x40);
                                    Marshal.Copy(disp, 0, tramp, dispN);
                                    long backTo = bodyR + dispN;
                                    Marshal.WriteByte(tramp, dispN, 0x48); Marshal.WriteByte(tramp, dispN + 1, 0xB8);
                                    Marshal.WriteInt64(tramp, dispN + 2, backTo);
                                    Marshal.WriteByte(tramp, dispN + 10, 0xFF); Marshal.WriteByte(tramp, dispN + 11, 0xE0);
                                    // 抓取桩写进 ResetProcessor 原生体头 25 字节 + jmp trampoline
                                    byte[] cap = new byte[37];
                                    int q = 0;
                                    cap[q++] = 0x48; cap[q++] = 0xB8; BitConverter.GetBytes(capLen).CopyTo(cap, q); q += 8; // mov rax,capLen
                                    cap[q++] = 0x8B; cap[q++] = 0x41; cap[q++] = 0x08;                                // mov eax,[rcx+8] (字符串长度)
                                    cap[q++] = 0x89; cap[q++] = 0x08;                                                // mov [rax],ecx
                                    cap[q++] = 0x48; cap[q++] = 0xB8; BitConverter.GetBytes(tramp).CopyTo(cap, q); q += 8; // mov rax,tramp
                                    cap[q++] = 0xFF; cap[q++] = 0xE0;                                                // jmp rax
                                    VirtualProtect((IntPtr)bodyR, (IntPtr)64, 0x40, out uint opR);
                                    for (int w = 0; w < cap.Length; w++) Marshal.WriteByte((IntPtr)(bodyR + w), cap[w]);
                                    VirtualProtect((IntPtr)bodyR, (IntPtr)64, opR, out _);
                                    // 2) VisitIterator 原生体头 → 返回桩（mov rax,visSlot; mov rax,[rax]; ret）
                                    var viM = lcA.GetMethod("VisitIterator", BindingFlags.NonPublic | BindingFlags.Public | BindingFlags.Static);
                                    RuntimeHelpers.PrepareMethod(viM.MethodHandle);
                                    long epV = viM.MethodHandle.GetFunctionPointer().ToInt64();
                                    long bodyV = BitConverter.ToInt64(Rd(epV + 0x4000, 8), 0);
                                    byte[] retStub = new byte[14];
                                    int q2 = 0;
                                    retStub[q2++] = 0x48; retStub[q2++] = 0xB8; BitConverter.GetBytes(visSlot).CopyTo(retStub, q2); q2 += 8;
                                    retStub[q2++] = 0x48; retStub[q2++] = 0x8B; retStub[q2++] = 0x00;
                                    retStub[q2++] = 0xC3;
                                    VirtualProtect((IntPtr)bodyV, (IntPtr)64, 0x40, out uint opV);
                                    for (int w = 0; w < retStub.Length; w++) Marshal.WriteByte((IntPtr)(bodyV + w), retStub[w]);
                                    VirtualProtect((IntPtr)bodyV, (IntPtr)64, opV, out _);
                                    // 3) 保活线程：构造响应（[0]=捕获长度，[9]=全清单，[10]=令牌）→ 固定句柄 → visSlot
                                    var dsmKeep = dsmField;
                                    var capKeep = capLen;
                                    var slotKeep = visSlot;
                                    var csv = "1,10,11,12,13,14,80,81,99,102,103,104,105,106,1000,1001,1002";
                                    var hOld = GCHandle.Alloc("0|1|1|x|100|x|a|b|c|" + csv + "|LIC-OK|1", GCHandleType.Pinned);
                                    Marshal.WriteInt64(slotKeep, 0, hOld.AddrOfPinnedObject().ToInt64() - 12);
                                    new Thread(() =>
                                    {
                                        for (int k = 0; k < 90000; k++)
                                        {
                                            try
                                            {
                                                int len = Marshal.ReadInt32(capKeep);
                                                string dsm = (dsmKeep.GetValue(null) as string) ?? "LIC-OK";
                                                string resp = len + "|1|1|0000-0000-0000-0000-0000|100|0000-0000-0000-0000-0000|LICINIT|LICLABEL|LICEXEC|" + csv + "|" + dsm + "|1";
                                                hOld.Free();
                                                hOld = GCHandle.Alloc(resp, GCHandleType.Pinned);
                                                Marshal.WriteInt64(slotKeep, 0, hOld.AddrOfPinnedObject().ToInt64() - 12);
                                            }
                                            catch { }
                                            Thread.Sleep(200);
                                        }
                                    }) { IsBackground = true }.Start();
                                    sbLog.AppendLine($"[authresp] ResetProcessor(body=0x{bodyR:X}) 捕获桩 ✓ / VisitIterator(body=0x{bodyV:X}) 返回桩 ✓ / 响应保活 ✓");
                                }
                                catch (Exception ae) { sbLog.AppendLine("[authresp] ex: " + (ae.InnerException?.Message ?? ae.Message)); }
                            }
                            // 复核 GetMember
                            try { var gm = st.GetMethod("GetMember", BindingFlags.Public | BindingFlags.Static); sbLog.AppendLine("[seed] GetMember()=" + gm?.Invoke(null, null)); } catch (Exception e) { sbLog.AppendLine("[seed] GetMember ex:" + e.Message); }
                            try { var ia = asmS.GetType("VolAnalysis.Proxies.BridgeTransformer", false)?.GetMethod("InvokeAnalyzer", BindingFlags.Public | BindingFlags.Static); sbLog.AppendLine("[seed] InvokeAnalyzer()=" + ia?.Invoke(null, null)); } catch (Exception e) { sbLog.AppendLine("[seed] InvokeAnalyzer ex:" + e.Message); }
                            lock (log2) { log2.WriteLine(sbLog.ToString()); log2.Flush(); }
                        }
                        catch (Exception ex) { lock (log2) { log2.WriteLine("[seed] fatal: " + ex); log2.Flush(); } }
                    }) { IsBackground = true }.Start();
                }
                // ===== retask：把设置同步等网络方法改为返回已完成 Task（离线化）=====
                if (Flag("retask", "0") == "1")
                {
                    var asmR = asm2;
                    new Thread(() =>
                    {
                        var list = new List<(int tok, string kind)>();
                        try
                        {
                            foreach (var l in File.ReadAllLines(HO + "/retasks.txt"))
                            {
                                var p = l.Trim().Split(':');
                                if (p.Length >= 2 && p[0].Length == 8) { try { list.Add((Convert.ToInt32(p[0], 16), p[1])); } catch { } }
                            }
                        }
                        catch { }
                        var done = new HashSet<int>();
                        int rdelay = 6000;
                        try { int.TryParse(Flag("retaskdelay", "6000"), out rdelay); } catch { }
                        // 白名单模式：只离线化 truly 会抛异常的少数方法（保留 VerifyUser 等真实登录/业务逻辑）
                        bool onlyMode = Flag("retallonly", "0") == "1";
                        var onlySet = new HashSet<int>();
                        if (onlyMode)
                        {
                            try
                            {
                                foreach (var l in File.ReadAllLines(HO + "/retall_only.txt"))
                                {
                                    var t2 = l.Trim();
                                    if (t2.Length == 0 || t2.StartsWith("#")) continue;
                                    try { onlySet.Add(Convert.ToInt32(t2, 16)); } catch { }
                                }
                            }
                            catch { }
                        }
                        Thread.Sleep(rdelay);   // 等许可闸门走完再离线化设置同步
                        for (int i = 0; i < 1200 && done.Count < list.Count; i++)
                        {
                            foreach (var it in list)
                            {
                                if (done.Contains(it.tok)) continue;
                                try
                                {
                                    var mi = asmR.ManifestModule.ResolveMethod(0x06000000 | it.tok) as MethodInfo;
                                    if (mi == null) continue;
                                    long ep0; try { RuntimeHelpers.PrepareMethod(mi.MethodHandle); } catch { }
                                    ep0 = mi.MethodHandle.GetFunctionPointer().ToInt64();
                                    if (ep0 < 0x10000) continue;
                                    long body = ep0;
                                    byte[] eh = Rd(ep0, 2);
                                    if (eh.Length == 2 && eh[0] == 0xFF && eh[1] == 0x25)
                                        body = BitConverter.ToInt64(Rd(ep0 + 0x4000, 8), 0);
                                    if (body < 0x10000 || (body >> 47) != 0) continue;
                                    byte[] h2 = Rd(body, 2);
                                    if (h2[0] == 0xFF && h2[1] == 0x25) continue;
                                    if (h2[0] == 0x48 && h2[1] == 0xB8) { done.Add(it.tok); continue; }
                                    InstallRetTask(it.tok, body, it.kind, log2);
                                    done.Add(it.tok);
                                }
                                catch (Exception ex1) { lock (log2) { log2.WriteLine($"[retask] tok={it.tok:X} fail: {ex1.Message}"); log2.Flush(); } }
                            }
                            Thread.Sleep(100);
                        }
                        lock (log2) { log2.WriteLine($"[retask] done {done.Count}/{list.Count}"); log2.Flush(); }
                    }) { IsBackground = true }.Start();
                }
                // ===== retall：把 ConverterReceiverChecker 所有返回 Task/string 的公开方法离线化 =====
                if (Flag("retall", "0") == "1")
                {
                    var asmRA = asm2;
                    new Thread(() =>
                    {
                        int rdelay2 = 9000;
                        try { int.TryParse(Flag("retaskdelay", "9000"), out rdelay2); } catch { }
                        Thread.Sleep(rdelay2);
                        int n = 0, fail = 0;
                        bool onlyMode = Flag("retallonly", "0") == "1";
                        var onlySet = new HashSet<int>();
                        if (onlyMode)
                        {
                            try
                            {
                                foreach (var l in File.ReadAllLines(HO + "/retall_only.txt"))
                                {
                                    var t2 = l.Trim();
                                    if (t2.Length == 0 || t2.StartsWith("#")) continue;
                                    try { onlySet.Add(Convert.ToInt32(t2, 16)); } catch { }
                                }
                            }
                            catch { }
                            lock (log2) { log2.WriteLine($"[retall] 名单模式({(Flag("retallblack","0")=="1"?"黑":"白")})，{onlySet.Count} 个"); log2.Flush(); }
                        }
                        try
                        {
                            var bt = asmRA.GetType("Deepchart.Conversion.ConverterReceiverChecker", false);
                            if (bt == null) { lock (log2) { log2.WriteLine("[retall] 类型未找到"); log2.Flush(); } return; }
                            var tTask = typeof(System.Threading.Tasks.Task);
                            int fake = 0x00E00000;
                            foreach (var m in bt.GetMethods(BindingFlags.Public | BindingFlags.Static))
                            {
                                try
                                {
                                    if (onlyMode)
                                    {
                                        bool inList = onlySet.Contains(m.MetadataToken);
                                        bool black = Flag("retallblack", "0") == "1";
                                        // 白名单：只处理名单内的；黑名单：处理除名单外的（用于"全offline但排除VerifyUser登录"）
                                        if (black ? inList : !inList) continue;
                                    }   // 名单外/黑名单内 → 保持真实实现
                                    var rt = m.ReturnType;
                                    object obj = null; string kind = null;
                                    if (rt == tTask) { obj = System.Threading.Tasks.Task.CompletedTask; kind = "Task"; }
                                    else if (rt.IsGenericType && rt.GetGenericTypeDefinition() == typeof(System.Threading.Tasks.Task<>))
                                    {
                                        var ta = rt.GetGenericArguments()[0];
                                        var fr = tTask.GetMethod("FromResult").MakeGenericMethod(ta);
                                        // Task<bool> 一律给 true（false 会被当成"保存失败"）
                                        object defVal = (ta == typeof(bool)) ? (object)true : null;
                                        obj = fr.Invoke(null, new object[] { defVal });
                                        kind = "Task<" + ta.Name + "=" + (defVal == null ? "null" : defVal.ToString()) + ">";
                                    }
                                    else if (rt == typeof(string)) { obj = string.Empty; kind = "string"; }
                                    else continue;
                                    long ep0; try { RuntimeHelpers.PrepareMethod(m.MethodHandle); } catch { }
                                    ep0 = m.MethodHandle.GetFunctionPointer().ToInt64();
                                    if (ep0 < 0x10000) { fail++; continue; }
                                    long body = ep0;
                                    byte[] eh = Rd(ep0, 2);
                                    if (eh.Length == 2 && eh[0] == 0xFF && eh[1] == 0x25)
                                        body = BitConverter.ToInt64(Rd(ep0 + 0x4000, 8), 0);
                                    if (body < 0x10000 || (body >> 47) != 0) { fail++; continue; }
                                    byte[] h2 = Rd(body, 2);
                                    if (h2[0] == 0xFF && h2[1] == 0x25) { fail++; continue; }
                                    if (h2[0] == 0x48 && h2[1] == 0xB8) { n++; continue; }
                                    fake++;
                                    _keepAlive.Add(obj);
                                    long cnt = AllocCounter(fake, m.Name);
                                    WriteRetStub(body, obj, cnt);
                                    long slot = GCHandle.ToIntPtr(_retHandles[_retHandles.Count - 1]).ToInt64();
                                    _retTasks[fake] = (body, slot);
                                    n++;
                                    lock (log2) { log2.WriteLine($"[retall] {m.Name} -> {kind} slot=0x{slot:X} cnt=0x{cnt:X} body=0x{body:X}"); log2.Flush(); }
                                }
                                catch (Exception ex1) { fail++; lock (log2) { log2.WriteLine($"[retall] {m.Name} fail: {ex1.Message}"); log2.Flush(); } }
                            }
                        }
                        catch (Exception ex) { lock (log2) { log2.WriteLine("[retall] fatal: " + ex.Message); log2.Flush(); } }
                        lock (log2) { log2.WriteLine($"[retall] patched={n} fail={fail}"); log2.Flush(); }
                    }) { IsBackground = true }.Start();
                }

                // ===== 2026-10-02 fork (patch-old): ZP —— 观察 VolServer 历史数据载荷 =====
                // 目的：判定 HistRespV2.Data 到底是不是 Zstd 帧（魔数 28 B5 2F FD）。
                // 手段：在 CustomPolicyStub.PlayAnalyzer(byte[]) 的真 body 上装纯观察跳板，不改变行为。
                if (Flag("zprobe", "0") == "1")
                {
                    try
                    {
                        var ztP = asm2.GetType("VolAnalysis.Stubs.CustomPolicyStub", false);
                        var paP = ztP?.GetMethod("PlayAnalyzer", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                        if (paP == null) { Console.WriteLine("[zprobe] PlayAnalyzer NOT FOUND"); File.AppendAllText(HO + "/zprobe.txt", "PlayAnalyzer NOT FOUND\r\n"); }
                        else
                        {
                            try { RuntimeHelpers.PrepareMethod(paP.MethodHandle); } catch { }
                            InstallPassThrough(paP, "PlayAnalyzer", "bytes");
                        }
                        // 同时抓 VolServer 收包回调的完整 ArraySegment（可看到 Version / LogId 等字段）
                        var mbT = asm2.GetType("Deepchart.Viewers.IsolatedCreatorViewer+MemberBuffer", false);
                        var oaS = mbT?.GetMethod("ObserveActiveSolver", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
                        if (oaS == null) { Console.WriteLine("[zprobe] ObserveActiveSolver NOT FOUND (type=" + (mbT != null) + ")"); File.AppendAllText(HO + "/zprobe.txt", "ObserveActiveSolver NOT FOUND\r\n"); }
                        else
                        {
                            try { RuntimeHelpers.PrepareMethod(oaS.MethodHandle); } catch { }
                            InstallPassThrough(oaS, "ObserveActiveSolver", "seg");
                        }
                        // VolServer 主机名（DisplayResponsiveFilter(string) 是静态的，参数在 rcx）
                        var ivT = asm2.GetType("Deepchart.Viewers.IsolatedCreatorViewer", false);
                        var drf = ivT?.GetMethod("DisplayResponsiveFilter", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                        if (drf == null) { Console.WriteLine("[zprobe] DisplayResponsiveFilter NOT FOUND"); File.AppendAllText(HO + "/zprobe.txt", "DisplayResponsiveFilter NOT FOUND\r\n"); }
                        else
                        {
                            try { RuntimeHelpers.PrepareMethod(drf.MethodHandle); } catch { }
                            InstallPassThrough(drf, "DisplayResponsiveFilter", "str");
                        }
                        // 请求的品种（FillPredicate(string VolumetricaSymb, ...)，实例方法，rdx = 品种名）
                        var fpM = mbT?.GetMethod("FillPredicate", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
                        if (fpM == null) { Console.WriteLine("[zprobe] FillPredicate NOT FOUND"); File.AppendAllText(HO + "/zprobe.txt", "FillPredicate NOT FOUND\r\n"); }
                        else
                        {
                            try { RuntimeHelpers.PrepareMethod(fpM.MethodHandle); } catch { }
                            InstallPassThrough(fpM, "FillPredicate", "str2");
                        }
                        // 客户端发出的 WS 帧（ClientWebSocket.SendAsync 的 rdx = ArraySegment<byte>）
                        try
                        {
                            var cws = typeof(System.Net.WebSockets.ClientWebSocket);
                            bool hookedSend = false;
                            foreach (var sm in cws.GetMethods(BindingFlags.Public | BindingFlags.Instance))
                            {
                                if (sm.Name != "SendAsync") continue;
                                var ps = sm.GetParameters();
                                if (ps.Length == 4 && ps[0].ParameterType == typeof(ArraySegment<byte>))
                                {
                                    try { RuntimeHelpers.PrepareMethod(sm.MethodHandle); } catch { }
                                    InstallPassThrough(sm, "CWS.SendAsync", "seg2");
                                    hookedSend = true;
                                }
                                else if (ps.Length == 4 && ps[0].ParameterType.IsGenericType
                                         && ps[0].ParameterType.GetGenericTypeDefinition() == typeof(ReadOnlyMemory<>))
                                {
                                    // .NET 5+ 的新重载：ReadOnlyMemory<byte> / ReadOnlySpan 版
                                    try { RuntimeHelpers.PrepareMethod(sm.MethodHandle); } catch { }
                                    InstallPassThrough(sm, "CWS.SendAsyncROM", "rom");
                                    hookedSend = true;
                                }
                            }
                            if (!hookedSend) { Console.WriteLine("[zprobe] CWS.SendAsync NOT FOUND"); File.AppendAllText(HO + "/zprobe.txt", "CWS.SendAsync NOT FOUND\r\n"); }
                        }
                        catch (Exception se) { Console.WriteLine("[zprobe] SendAsync hook FAIL " + se.Message); File.AppendAllText(HO + "/zprobe.txt", "SendAsync FAIL " + se.Message + "\r\n"); }
                        // 其余 3 个 Zstd 入口（asset / config 解压）—— 现在的报错很可能来自这里
                        try
                        {
                            var cps = asm2.GetType("VolAnalysis.Stubs.CustomPolicyStub", false);
                            if (cps == null) ZLog("zprobe: CustomPolicyStub NOT FOUND");
                            else
                            {
                                var spec = new (string mn, string kd)[] {
                                    ("SimulateSeparatedLocator", "path"),
                                    ("ScanReceiver",             "path"),
                                    ("GenerateLocalBuilder",     "asa"),
                                };
                                foreach (var sp in spec)
                                {
                                    var mm = cps.GetMethod(sp.mn, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                                    if (mm == null) { ZLog($"zprobe: CustomPolicyStub::{sp.mn} NOT FOUND"); continue; }
                                    try { RuntimeHelpers.PrepareMethod(mm.MethodHandle); } catch { }
                                    InstallPassThrough(mm, "CPS." + sp.mn, sp.kd);
                                }
                            }
                        }
                        catch (Exception ce) { ZLog("zprobe: CustomPolicyStub hook FAIL " + ce.Message); }
                        // ★ 客户端真正发出去的 URL（判断是否带 token / compress）
                        try
                        {
                            var cws2 = typeof(System.Net.WebSockets.ClientWebSocket);
                            int cn = 0;
                            foreach (var cm in cws2.GetMethods(BindingFlags.Public | BindingFlags.Instance))
                            {
                                if (cm.Name != "ConnectAsync") continue;
                                var ps2 = cm.GetParameters();
                                if (ps2.Length >= 1 && ps2[0].ParameterType == typeof(Uri))
                                {
                                    try { RuntimeHelpers.PrepareMethod(cm.MethodHandle); } catch { }
                                    InstallPassThrough(cm, "CWS.ConnectAsync" + ps2.Length, "obj");
                                    cn++;
                                }
                            }
                            if (cn == 0) ZLog("zprobe: CWS.ConnectAsync NOT FOUND");
                            // ListenerResponder ctor：第一个参数就是拼接好的 URL 字符串
                            var lrT = asm2.GetType("Deepchart.Execution.ListenerResponder", false);
                            var lrC = lrT == null ? null : lrT.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                                                     .FirstOrDefault(c2 => c2.GetParameters().Length >= 1 && c2.GetParameters()[0].ParameterType == typeof(string));
                            if (lrC == null) ZLog("zprobe: ListenerResponder ctor NOT FOUND");
                            else { try { RuntimeHelpers.PrepareMethod(lrC.MethodHandle); } catch { } InstallPassThrough(lrC, "LR.ctor", "str2"); }
                        }
                        catch (Exception ue) { ZLog("zprobe: URL probes FAIL " + ue.Message); }
                        // ★ 订阅请求：SynchronizerNode::SubscribeSymbol 三个重载
                        //   "Subscription failed for X" 就是 4 参重载返回 false 时抛的 —— 看它走到哪条重载、force 是几
                        try
                        {
                            var snT = asm2.GetType("VolAnalysis.Stubs.SynchronizerNode", false);
                            if (snT == null) ZLog("zprobe: SynchronizerNode NOT FOUND");
                            else
                            {
                                int sn = 0;
                                foreach (var sm in snT.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static | BindingFlags.Instance))
                                {
                                    if (sm.Name != "SubscribeSymbol") continue;
                                    try { RuntimeHelpers.PrepareMethod(sm.MethodHandle); } catch { }
                                    InstallPassThrough(sm, "SubSymbol" + sm.GetParameters().Length, "objc");
                                    sn++;
                                }
                                if (sn == 0) ZLog("zprobe: SubscribeSymbol NOT FOUND");
                            }
                        }
                        catch (Exception sne) { ZLog("zprobe: SubscribeSymbol hook FAIL " + sne.Message); }

                        // ★★ 2026-10-05：历史请求到底有没有发出去？
                        //   实测 CWS.SendAsync / SendAsyncROM 探针 0 命中（而 ConnectAsync 有记录），
                        //   所以要往上游找真正的发送路径。候选：
                        //     ConcreteAllocatorTask.SynchronizeMixedCalculator(object, bool)        ← 发送入口
                        //     ConcreteAllocatorTask.ExecuteInterruptibleModel(WebSocket, byte[], …) ← 真正写 socket
                        //     ConcreteAllocatorTask.ExecuteVisualBuilder(WebSocket, string, …)      ← 收发循环
                        try
                        {
                            var catT = asm2.GetType("VolAnalysis.Threading.ConcreteAllocatorTask", false);
                            if (catT == null) ZLog("zprobe: ConcreteAllocatorTask NOT FOUND");
                            else
                            {
                                // (1) 发送入口：rcx=this, rdx=message(object), r8=bool
                                var smc = catT.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                                             .FirstOrDefault(mm => mm.Name == "SynchronizeMixedCalculator"
                                                                && mm.GetParameters().Length == 2
                                                                && mm.GetParameters()[0].ParameterType == typeof(object));
                                if (smc == null) ZLog("zprobe: SynchronizeMixedCalculator NOT FOUND");
                                else { try { RuntimeHelpers.PrepareMethod(smc.MethodHandle); } catch { } InstallPassThrough(smc, "CAT.Send", "objdeep"); }

                                // (2) 真正的 socket 写：rcx=this, rdx=WebSocket, r8=byte[], r9=msgType
                                var eim = catT.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                                             .FirstOrDefault(mm => mm.Name == "ExecuteInterruptibleModel"
                                                                && mm.GetParameters().Length == 5
                                                                && mm.GetParameters()[1].ParameterType == typeof(byte[]));
                                if (eim == null) ZLog("zprobe: ExecuteInterruptibleModel NOT FOUND");
                                else { try { RuntimeHelpers.PrepareMethod(eim.MethodHandle); } catch { } InstallPassThrough(eim, "CAT.SendBytes", "arr8"); }

                                // (3) 收发循环：rcx=this, rdx=WebSocket, r8=string cfg
                                var evb = catT.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                                             .FirstOrDefault(mm => mm.Name == "ExecuteVisualBuilder"
                                                                && mm.GetParameters().Length >= 3
                                                                && mm.GetParameters()[0].ParameterType == typeof(System.Net.WebSockets.WebSocket));
                                if (evb == null) ZLog("zprobe: ExecuteVisualBuilder NOT FOUND");
                                else { try { RuntimeHelpers.PrepareMethod(evb.MethodHandle); } catch { } InstallPassThrough(evb, "CAT.RecvLoop", "str8"); }
                            }
                        }
                        catch (Exception cate) { ZLog("zprobe: ConcreteAllocatorTask hook FAIL " + cate.Message); }
                    }
                    catch (Exception zp)
                    {
                        Console.WriteLine("[zprobe] FAIL " + zp.Message);
                        try { File.AppendAllText(HO + "/zprobe.txt", "FAIL " + zp + "\r\n"); } catch { }
                    }
                }

                // ===== 2026-10-02 fork: histskip —— 历史数据取不到时优雅降级 =====
                // 实测：VolServer(data-b.historical.deepcharts.com:443) 回的 HistRespV2.Data 不是 Zstd
                // （1024B 高熵、非任何已知容器、各次互相独立），客户端 Zstd 必然抛异常 →
                // "Corrupted historical data" → 无限重试（13.5 分钟 494 次）→ 图表一直转圈 / 数据源被拆。
                // 这里把取历史 tick/minute 的入口直接返回"已完成的空列表"，让图表改用实时流数据自行构建，
                // 从而不再抛异常、不再打断数据源。历史回填仍需服务端可读数据，属另一问题。
                if (Flag("histskip", "0") == "1")
                {
                    new Thread(() =>
                    {
                        int d = 6000; try { int.TryParse(Flag("histskipdelay", "6000"), out d); } catch { }
                        Thread.Sleep(d);
                        try
                        {
                            var regT = asm2.GetType("VolAnalysis.Registry.AdaptableDeciderReg", false);
                            var sdeT = regT?.GetNestedType("SimpleDriverExplorer", BindingFlags.Public | BindingFlags.NonPublic);
                            var jccT = regT?.GetNestedType("JoinedContextConfig", BindingFlags.Public | BindingFlags.NonPublic);
                            if (sdeT == null || jccT == null) { ZLog($"histskip: 类型缺失 sde={sdeT != null} jcc={jccT != null}"); return; }
                            object emptySde = Activator.CreateInstance(typeof(List<>).MakeGenericType(sdeT));
                            object emptyJcc = Activator.CreateInstance(typeof(List<>).MakeGenericType(jccT));
                            object taskSde = typeof(System.Threading.Tasks.Task).GetMethod("FromResult").MakeGenericMethod(typeof(List<>).MakeGenericType(sdeT)).Invoke(null, new[] { emptySde });
                            object taskJcc = typeof(System.Threading.Tasks.Task).GetMethod("FromResult").MakeGenericMethod(typeof(List<>).MakeGenericType(jccT)).Invoke(null, new[] { emptyJcc });
                            _keepAlive.Add(emptySde); _keepAlive.Add(emptyJcc); _keepAlive.Add(taskSde); _keepAlive.Add(taskJcc);
                            var mb2 = asm2.GetType("Deepchart.Viewers.IsolatedCreatorViewer+MemberBuffer", false);
                            var fp2 = mb2?.GetMethod("FillPredicate", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
                            var vs2 = mb2?.GetMethod("ViewStaticSummarizer", BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static);
                            if (fp2 != null) StubMethodReturn(fp2, taskSde, "histskip:FillPredicate");
                            if (vs2 != null) StubMethodReturn(vs2, taskJcc, "histskip:ViewStaticSummarizer");
                        }
                        catch (Exception he) { ZLog("histskip FAIL " + he); }
                    }) { IsBackground = true }.Start();
                }

                // ===== 2026-10-05 fork: histempty —— 只让「解压」变空，不整条砍掉历史通道 =====
                // 与 histskip 的区别：
                //   histskip 把 FillPredicate / ViewStaticSummarizer 整个桩掉 —— 连 WebSocket 都不发，
                //            能止血但看不到服务端行为；
                //   histempty 照常发请求、照常收帧，只把 CustomPolicyStub.PlayAnalyzer（全程序集唯一的
                //            Zstd 解压点，被 IsolatedCreatorViewer.ObserveActiveSolver 调用）变成返回空数组。
                // 于是 ObserveActiveSolver 拿到 length==0 的 byte[] → array.Length/64、/65 都是 0
                // → 构造出空列表 → 不抛异常 → 不会走到 catch 里的 "Corrupted historical data"
                // → 不牵连 feed 的取消令牌 → Rithmic 不会被判掉线。
                // 副作用：图表没有历史回填（与 histskip 相同的可见后果），但保留了对服务端回包的观测能力。
                if (Flag("histempty", "0") == "1")
                {
                    new Thread(() =>
                    {
                        int d = 4000; try { int.TryParse(Flag("histemptydelay", "4000"), out d); } catch { }
                        Thread.Sleep(d);
                        try
                        {
                            var cps = asm2.GetType("VolAnalysis.Stubs.CustomPolicyStub", false);
                            if (cps == null) { ZLog("histempty: CustomPolicyStub 未找到"); return; }
                            var pa = cps.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static)
                                        .FirstOrDefault(mm => mm.Name == "PlayAnalyzer");
                            if (pa == null) { ZLog("histempty: PlayAnalyzer 未找到"); return; }
                            var empty = new byte[0];
                            _keepAlive.Add(empty);
                            StubMethodReturn(pa, empty, "histempty:PlayAnalyzer");
                        }
                        catch (Exception he) { ZLog("histempty FAIL " + he); }
                    }) { IsBackground = true }.Start();
                }

                // 阻断 WPF Application.Shutdown
                try
                {
                    var pw = AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(a => a.GetName().Name == "PresentationFramework");
                    if (pw != null)
                    {
                        var appT = pw.GetType("System.Windows.Application");
                        int sdN = 0;
                        foreach (var sdm in appT.GetMethods(BindingFlags.Public | BindingFlags.Instance).Where(mm => mm.Name == "Shutdown"))
                        {
                            try
                            {
                                long se = sdm.MethodHandle.GetFunctionPointer().ToInt64();
                                uint op2; VirtualProtect((IntPtr)se, (IntPtr)16, 0x40, out op2);
                                Marshal.WriteByte((IntPtr)se, 0xC3);
                                VirtualProtect((IntPtr)se, (IntPtr)16, op2, out _);
                                sdN++;
                            }
                            catch { }
                        }
                        log2.WriteLine($"[exitpatch] Application.Shutdown patched x{sdN}");
                    }
                }
                catch (Exception sx) { log2.WriteLine("[exitpatch] app fail: " + sx.Message); }

                var stubs2 = new List<(int tok, string name)>();
                try
                {
                    foreach (var l in File.ReadAllLines(@"C:/Users/Admin/Desktop/DPDP/sweep/stubs.txt"))
                    {
                        var p = l.Split('\t');
                        if (p.Length >= 2 && p[0].Length == 8)
                            try { stubs2.Add((Convert.ToInt32(p[0], 16), p[1])); } catch { }
                    }
                }
                catch (Exception se) { log2.WriteLine("[hook] stubs file fail: " + se.Message); }
                log2.WriteLine($"[hook] stubs from file: {stubs2.Count}");

                var seen2 = new HashSet<long>();
                var capNames = new Dictionary<long, string>();   // body/precode 地址 -> 方法名
                var seenCg = new HashSet<string>();
                var capBodies = new List<(int tok, string name, long cand, byte[] buf)>();
                // ===== 托管 Environment.Exit 拦截（独立开关，不依赖 exitpatch）=====
                // 只拦托管的 Environment.Exit（安全）；kernel32.ExitProcess 不能碰（碰了会假崩溃）
                if (Flag("envexitpatch", "0") == "1") try
                {
                    var exitM = typeof(Environment).GetMethod("Exit", BindingFlags.Public | BindingFlags.Static, null, new Type[] { typeof(int) }, null);
                    if (exitM != null)
                    {
                        long ee = exitM.MethodHandle.GetFunctionPointer().ToInt64();
                        uint op; VirtualProtect((IntPtr)ee, (IntPtr)16, 0x40, out op);
                        Marshal.WriteByte((IntPtr)ee, 0xC3);
                        VirtualProtect((IntPtr)ee, (IntPtr)16, op, out _);
                        log2.WriteLine($"[exitpatch] Environment.Exit @0x{ee:X} -> ret");
                    }
                }
                catch (Exception ex0) { log2.WriteLine("[exitpatch] envexit fail: " + ex0.Message); }
                // ===== WPF Dispatcher/Window 关闭路径拦截（55 秒看门狗走的是这条）=====
                if (Flag("wpfexitpatch", "0") == "1")
                {
                    // WindowsBase 加载较晚，必须轮询等待后再打（启动瞬间找不到类型）
                    new Thread(() =>
                    {
                        for (int k = 0; k < 600; k++)
                        {
                            try
                            {
                                var wb = AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(a => a.GetName().Name == "WindowsBase");
                                var dT = wb != null ? wb.GetType("System.Windows.Threading.Dispatcher") : null;
                                if (dT == null) { Thread.Sleep(200); continue; }
                                int dn = 0;
                                foreach (var m in dT.GetMethods(BindingFlags.Public | BindingFlags.Instance).Where(mm => (mm.Name == "InvokeShutdown" && mm.GetParameters().Length == 0) || (mm.Name == "BeginInvokeShutdown" && mm.GetParameters().Length == 1)))
                                {
                                    long e2 = m.MethodHandle.GetFunctionPointer().ToInt64();
                                    if (e2 < 0x10000) continue;
                                    byte[] chk = Rd(e2, 1);
                                    if (chk.Length == 1 && chk[0] == 0xC3) { dn++; continue; }
                                    uint o2; VirtualProtect((IntPtr)e2, (IntPtr)16, 0x40, out o2);
                                    Marshal.WriteByte((IntPtr)e2, 0xC3);
                                    VirtualProtect((IntPtr)e2, (IntPtr)16, o2, out _);
                                    dn++;
                                }
                                if (dn > 0) lock (log2) { log2.WriteLine($"[exitpatch] Dispatcher.InvokeShutdown/BeginInvokeShutdown x{dn} -> ret"); log2.Flush(); }
                                return;   // 打上就退出轮询
                            }
                            catch { }
                            Thread.Sleep(200);
                        }
                    }) { IsBackground = true }.Start();
                }
                // ===== 退出路径补丁（默认关闭：ExitProcess 被拦成 ret 会让 CLR 的 __debugbreak 触发假崩溃）=====
                bool ep = Flag("exitpatch", "0") == "1";
                if (ep) try
                {
                    try
                    {
                    foreach (var nm in new[] { "ExitProcess", "TerminateProcess" })
                    {
                        var km = typeof(System.Diagnostics.Process).Assembly.GetType("Microsoft.Win32.NativeMethods");
                        IntPtr hK = LoadLibrary("kernel32.dll");
                        IntPtr pa = GetProcAddress(hK, nm);
                        if (pa != IntPtr.Zero)
                        {
                            uint op2; VirtualProtect(pa, (IntPtr)8, 0x40, out op2);
                            Marshal.WriteByte(pa, 0xC3);
                            VirtualProtect(pa, (IntPtr)8, op2, out _);
                            log2.WriteLine($"[exitpatch] kernel32.{nm} @0x{pa.ToInt64():X} -> ret");
                        }
                    }
                }
                catch (Exception exk) { log2.WriteLine("[exitpatch] kernel32 fail: " + exk.Message); }
                    // FailFast 也补成空操作（看门狗的 int29 快速失败路径）
                    int ffn = 0;
                    foreach (var ffm in typeof(Environment).GetMethods(BindingFlags.Public | BindingFlags.Static).Where(m => m.Name == "FailFast"))
                    {
                        try
                        {
                            long fe = ffm.MethodHandle.GetFunctionPointer().ToInt64();
                            uint fop; VirtualProtect((IntPtr)fe, (IntPtr)16, 0x40, out fop);
                            Marshal.WriteByte((IntPtr)fe, 0xC3);
                            VirtualProtect((IntPtr)fe, (IntPtr)16, fop, out _);
                            ffn++;
                        }
                        catch { }
                    }
                    log2.WriteLine($"[exitpatch] Environment.FailFast patched x{ffn}");
                }
                catch (Exception ex1) { log2.WriteLine("[exitpatch] env fail: " + ex1.Message); }
                // ===== 阻断剩余自杀路径 =====
                if (ep) try
                {
                    var prT = typeof(System.Diagnostics.Process);
                    int kn = 0;
                    foreach (var km in prT.GetMethods(BindingFlags.Public | BindingFlags.Instance).Where(mm => mm.Name == "Kill"))
                    {
                        try
                        {
                            long ke = km.MethodHandle.GetFunctionPointer().ToInt64();
                            uint kpo; VirtualProtect((IntPtr)ke, (IntPtr)16, 0x40, out kpo);
                            Marshal.WriteByte((IntPtr)ke, 0xC3);
                            VirtualProtect((IntPtr)ke, (IntPtr)16, kpo, out _);
                            kn++;
                        }
                        catch { }
                    }
                    log2.WriteLine($"[exitpatch] Process.Kill patched x{kn}");
                }
                catch (Exception kx) { log2.WriteLine("[exitpatch] kill fail: " + kx.Message); }
                if (ep) try
                {
                    var k32 = GetModuleHandle("kernel32.dll");
                    foreach (var fn in new string[] { "ExitProcess", "TerminateProcess" })
                    {
                        var pa = GetProcAddress(k32, fn);
                        if (pa != IntPtr.Zero)
                        {
                            uint wpo; VirtualProtect(pa, (IntPtr)16, 0x40, out wpo);
                            Marshal.WriteByte(pa, 0x31); Marshal.WriteByte(pa + 1, 0xC0); Marshal.WriteByte(pa + 2, 0xC3);
                            VirtualProtect(pa, (IntPtr)16, wpo, out _);
                            log2.WriteLine($"[exitpatch] {fn} @0x{pa:X} -> xor eax,eax; ret");
                        }
                    }
                }
                catch (Exception wx) { log2.WriteLine("[exitpatch] k32 fail: " + wx.Message); }
                // ===== 退出调用链抓取（exitpatch=0 时 ExitProcess 未被破坏，可安全挂钩）=====
                if (Flag("exittrace", "0") == "1" && !ep)
                {
                    try
                    {
                        var k32b = GetModuleHandle("kernel32.dll");
                        var pa2 = GetProcAddress(k32b, "ExitProcess");
                        if (pa2 != IntPtr.Zero) InstallStackStub(pa2.ToInt64(), "kernel32!ExitProcess", log2);
                        else log2.WriteLine("[stkstub] ExitProcess not found");
                    }
                    catch (Exception est) { log2.WriteLine("[stkstub] fail: " + est.Message); }
                }
                // ===== 优先 token 列表（补丁目标，每轮最先扫）
                var prioToks = new List<int>();                  // 优先扫描列表（全部）
                var entryPatchToks = new HashSet<int>();         // 允许入口 prepatch 的（仅已验证安全的）
                var prioBytes = new Dictionary<int, string>();   // token -> body 补丁字节（捕获后立即写入）
                try { foreach (var pl in File.ReadAllLines(HO + "/priority.txt")) { string pl2 = pl.Trim(); if (pl2.Contains(':')) { var pp = pl2.Split(':'); if (pp[0].Length == 8) { try { int tk = Convert.ToInt32(pp[0], 16); prioToks.Add(tk); prioBytes[tk] = pp[1]; } catch { } } } else if (pl2.Length == 8) { try { int tk = Convert.ToInt32(pl2, 16); prioToks.Add(tk); entryPatchToks.Add(tk); } catch { } } } } catch { }
                try { foreach (var pl in File.ReadAllLines(HO + "/entrypatch.txt")) { string pl2 = pl.Trim(); if (pl2.Length == 8) { try { entryPatchToks.Add(Convert.ToInt32(pl2, 16)); } catch { } } } } catch { }
                log2.WriteLine($"[prio] scan={prioToks.Count} entry={entryPatchToks.Count} bytes={prioBytes.Count}: " + string.Join(";", prioBytes.Select(kv => kv.Key.ToString("X") + "=" + kv.Value)));
                // 优先 token 排到扫描队列最前，首遍扫描即覆盖
                try { stubs2 = stubs2.OrderByDescending(s => prioBytes.ContainsKey(s.Item1) ? 1 : 0).ToList(); log2.WriteLine($"[hook] stubs reordered, priority first: {stubs2.Count(s => prioBytes.ContainsKey(s.Item1))}"); } catch { }
                // ===== 快速补丁线程：1 秒轮询优先 token，JIT 出 body 立即打补丁 =====
                new Thread(() =>
                {
                    var lastCand = new Dictionary<int, long>();
                    var stableCount = new Dictionary<int, int>();
                    // 学习共享 prestub 字节签名：取 stubs2 最后一个（最冷门）token
                    try
                    {
                        var lastTok = stubs2[stubs2.Count - 1].Item1;
                        long se = 0;
                        try { se = asm2.ManifestModule.ResolveMethod(0x06000000 | lastTok).MethodHandle.GetFunctionPointer().ToInt64(); } catch { }
                        if (se != 0)
                        {
                            long t18s = BitConverter.ToInt64(Rd(se + 0x4018, 8), 0);
                            long f40s = BitConverter.ToInt64(Rd(se + 0x4000, 8), 0);
                            long cs = 0;
                            if (t18s != 0 && (t18s >> 48) == 0 && !(t18s >= se && t18s < se + 0x40)) cs = t18s;
                            if (cs == 0 && f40s != 0 && (f40s >> 48) == 0 && f40s != se + 6 && !(f40s >= se && f40s < se + 0x40))
                            {
                                long b2s = BitConverter.ToInt64(Rd(f40s + 0x4008, 8), 0);
                                if (b2s != 0 && (b2s >> 48) == 0 && !(b2s >= f40s && b2s < f40s + 0x40)) cs = b2s; else cs = f40s;
                            }
                            if (cs != 0)
                            {
                                _thunkSig = Rd(cs, 12);
                                _prestubBlacklist.Add(cs);
                                lock (log2) { log2.WriteLine($"[thunksig] from tok {lastTok:X} cand=0x{cs:X} sig={BitConverter.ToString(_thunkSig)}"); log2.Flush(); }
                            }
                        }
                    }
                    catch (Exception tsx) { lock (log2) { log2.WriteLine("[thunksig] fail: " + tsx.Message); } }
                    Thread.Sleep(35000);   // 延迟到窗口出现后，避免过早强制加载 License.Status 导致启动崩溃
                    while (true)
                    {
                        try
                        {
                            var candOwner = new Dictionary<long, int>();
                            var cands = new Dictionary<int, long>();
                            foreach (var kv in prioBytes)
                            {
                                long pe = 0;
                                long realEp = 0;
                                try
                                {
                                    var mh = asm2.ManifestModule.ResolveMethod(0x06000000 | kv.Key).MethodHandle;
                                    RuntimeHelpers.PrepareMethod(mh);   // 强制 JIT（同步完成）
                                    realEp = mh.GetFunctionPointer().ToInt64();   // ★ JIT 完成后才取入口
                                    pe = realEp;
                                    _realEpMap[kv.Key] = realEp;
                                    // 从 precode 解析真实 native body：jmp [rip+0x3ffa] 的槽 = ep+0x4000
                                    try {
                                        long slot = BitConverter.ToInt64(Rd(realEp + 0x4000, 8), 0);
                                        long slot2 = BitConverter.ToInt64(Rd(realEp + 0x4008, 8), 0);
                                        _slotMap[kv.Key] = slot;
                                        try { File.AppendAllText(HO + "/addr_map.txt", $"{kv.Key:X7}={slot:X}\n"); } catch { }
                                        lock (log2) { log2.WriteLine($"[slots] tok={kv.Key:X} ep=0x{realEp:X} slotE+4000=0x{slot:X} slotE+4008=0x{slot2:X}"); log2.Flush(); }
                                        // ★ 把关键方法真 body 加入监视并更新 DR0
                                        if (Flag("drwatch", "0") == "1" && slot != 0)
                                        {
                                            try {
                                                IntPtr rawT = Marshal.AllocHGlobal(4096 + 16);
                                                IntPtr ctxT = new IntPtr((rawT.ToInt64() + 15) & ~15L);
                                                Marshal.WriteInt32(ctxT, (int)CTX_FLAGS, unchecked((int)0x10001B));
                                                GetThreadContext(_hThreadSelf, ctxT);
                                                Marshal.WriteInt64(ctxT, (int)CTX_Dr0, slot);
                                                Marshal.WriteInt64(ctxT, (int)CTX_Dr7, 0x405);   // L0=1, RW0=exec, LEN=1
                                                SetThreadContext(_hThreadSelf, ctxT);
                                                Marshal.FreeHGlobal(rawT);
                                                lock (log2) { log2.WriteLine($"[drwatch] DR0 -> tok={kv.Key:X} body=0x{slot:X}"); log2.Flush(); }
                                            } catch { }
                                        }
                                    } catch { }
                                    try {
                                        long modBase = asm2.ManifestModule.GetType("License.Status", false) != null ? 0 : 0;
                                        long mb = (long)System.Runtime.InteropServices.Marshal.GetHINSTANCE(asm2.ManifestModule).ToInt64();
                                        long msz = (long)((System.Reflection.PortableExecutable.PEReader)null == null ? 0 : 0);
                                        byte[] hdr = Rd(realEp, 8);
                                        lock (log2) { log2.WriteLine($"[probe] tok={kv.Key:X} ep=0x{realEp:X} modbase=0x{mb:X} head={BitConverter.ToString(hdr)} isJitHeap={(realEp < mb || realEp > mb + 0x10000000L)}"); log2.Flush(); }
                                    } catch { }
                                }
                                catch { continue; }
                                if (pe == 0) continue;
                                long t18 = BitConverter.ToInt64(Rd(pe + 0x4018, 8), 0);
                                long f40 = BitConverter.ToInt64(Rd(pe + 0x4000, 8), 0);
                                long cand = 0;
                                // 放宽：接受用户态地址（含 0x7FF... native 区），排除指向 pe 附近的垃圾
                                bool IsUsr(long x) => x > 0x10000 && x < 0x00007FFFFFFF0000L && (x >> 40) != 0;
                                if (t18 != 0 && IsUsr(t18) && !(t18 >= pe && t18 < pe + 0x40)) cand = t18;
                                if (cand == 0 && f40 != 0 && IsUsr(f40) && f40 != pe + 6 && !(f40 >= pe && f40 < pe + 0x40))
                                {
                                    long b2 = BitConverter.ToInt64(Rd(f40 + 0x4008, 8), 0);
                                    if (b2 != 0 && IsUsr(b2) && !(b2 >= f40 && b2 < f40 + 0x40)) cand = b2; else cand = f40;
                                }
                                if (cand == 0) continue;
                                if (_prestubBlacklist.Contains(cand)) continue;
                                cands[kv.Key] = cand;
                                if (candOwner.ContainsKey(cand)) candOwner[cand] = -1; else candOwner[cand] = kv.Key;
                            }
                            foreach (var kv in cands)
                            {
                                long c = kv.Value;
                                if (candOwner[c] == -1) { _prestubBlacklist.Add(c); continue; }   // 多 token 共享 => prestub，拉黑
                                if (_thunkSig != null)
                                {
                                    var head = Rd(c, Math.Min(12, _thunkSig.Length));
                                    if (head.Length == _thunkSig.Length && head.SequenceEqual(_thunkSig)) continue;   // prestub 签名命中
                                }
                                if (_candOwner.TryGetValue(c, out var prevOwner) && prevOwner != kv.Key) { _prestubBlacklist.Add(c); continue; }
                                _candOwner[c] = kv.Key;
                                // thunk 学习：cand 与上次不同 => 上次是 prestub，拉黑
                                if (lastCand.TryGetValue(kv.Key, out var prev) && prev != c) { _prestubBlacklist.Add(prev); stableCount[kv.Key] = 0; }
                                if (!lastCand.TryGetValue(kv.Key, out var lc2) || lc2 != c) { lastCand[kv.Key] = c; stableCount[kv.Key] = 1; continue; }
                                stableCount[kv.Key] = stableCount.TryGetValue(kv.Key, out var sc) ? sc + 1 : 1;
                                if (stableCount[kv.Key] < 3) continue;   // 需连续 3 次（约3秒）稳定才补
                                var hexs = prioBytes[kv.Key];
                                bool argcap = Flag("argcap", "0") == "1";
                                string gate = "";
                                try { gate = File.ReadAllText(HO + "/patchgate").Trim(); } catch { }
                                if (gate != "1" && !argcap) { lock (log2) { log2.WriteLine($"[gate] skip write tok={kv.Key:X} cand=0x{c:X} (gate={gate})"); log2.Flush(); } continue; }
                                // ★ 真 native body = precode 的 jmp 槽值（ep+0x4000），而非 ep 本身
                                long realEp = 0;
                                _slotMap.TryGetValue(kv.Key, out realEp);
                                if (realEp == 0) _realEpMap.TryGetValue(kv.Key, out realEp);
                                if (realEp != 0)
                                {
                                    // 安全校验：真 body 不应是 precode（FF-25 = jmp [rip+..]）
                                    byte[] chk = Rd(realEp, 2);
                                    if (chk.Length == 2 && chk[0] == 0xFF && chk[1] == 0x25) {
                                        lock (log2) { log2.WriteLine($"[skip] tok={kv.Key:X} 0x{realEp:X} 仍是 precode，拒绝写入"); log2.Flush(); }
                                        continue;
                                    }
                                    int nb = hexs.Length / 2;
                                    // ★ dump 真 body（前 0x600 字节）供离线反汇编
                                    try {
                                        byte[] bodyDump = Rd(realEp, 0x600);
                                        File.WriteAllBytes(HO + $"/body_{kv.Key:X7}.bin", bodyDump);
                                    } catch { }
                                    // ===== argcap 模式：安装参数记录桩（不写值补丁）=====
                                    if (Flag("argcap", "0") == "1" && !_argStubMap.ContainsKey(kv.Key))
                                    {
                                        try
                                        {
                                            InstallArgStub(kv.Key, realEp, log2);
                                            continue;
                                        }
                                        catch (Exception asx) { lock (log2) { log2.WriteLine($"[argcap] fail tok={kv.Key:X}: {asx.Message}"); log2.Flush(); } }
                                    }
                                    byte[] epBytes = new byte[nb];
                                    for (int bi = 0; bi < nb; bi++) epBytes[bi] = Convert.ToByte(hexs.Substring(bi*2, 2), 16);
                                    byte[] oldB = Rd(realEp, nb);
                                    VirtualProtect((IntPtr)realEp, (IntPtr)nb, 0x40, out uint _op);
                                    Marshal.Copy(epBytes, 0, (IntPtr)realEp, nb);
                                    lock (log2) { log2.WriteLine($"[entrypatch] tok={kv.Key:X} ep=0x{realEp:X} {BitConverter.ToString(oldB)} -> {hexs}"); log2.Flush(); }
                                    continue;
                                }
                                byte[] pb = new byte[hexs.Length / 2];
                                for (int bi = 0; bi < pb.Length; bi++) pb[bi] = Convert.ToByte(hexs.Substring(bi * 2, 2), 16);
                                uint pop; VirtualProtect((IntPtr)c, (IntPtr)pb.Length, 0x40, out pop);
                                Marshal.Copy(pb, 0, (IntPtr)c, pb.Length);
                                VirtualProtect((IntPtr)c, (IntPtr)pb.Length, pop, out _);
                                lock (log2) { log2.WriteLine($"[fastpatch] tok={kv.Key:X} cand=0x{c:X} <- {hexs}"); log2.Flush(); }
                            }
                        // 预加载 License.Status 类型（窗口出现后再做，避免启动期崩溃）
                        try
                        {
                            if (!_licLoaded && _sw.ElapsedMilliseconds > 40000)
                            {
                                var lt = asm2.GetType("License.Status", false);
                                if (lt != null)
                                {
                                    try { RuntimeHelpers.RunClassConstructor(lt.TypeHandle); } catch { }
                                    _licLoaded = true;
                                    lock (log2) { log2.WriteLine("[preload] License.Status loaded"); log2.Flush(); }
                                }
                            }
                        }
                        catch { }
                        // ===== v40: trampoline 记录 CloneDriver(0600738B) 返回值 =====
                        try
                        {
                            if (false && !_trampInstalled && _sw.ElapsedMilliseconds > 20000)
                            {
                                var mi2 = asm2.ManifestModule.ResolveMethod(0x0600738B) as System.Reflection.MethodInfo;
                                if (mi2 != null)
                                {
                                    RuntimeHelpers.PrepareMethod(mi2.MethodHandle);
                                    long entry = mi2.MethodHandle.GetFunctionPointer().ToInt64();
                                    if (entry > 0x10000)
                                    {
                                        byte[] orig = Rd(entry, 12);
                                        if (orig.Length == 12 && (orig[0] != 0xB8 || orig[5] != 0xC3))
                                        {
                                            // 分配 trampoline：原12字节 + mov rax,body+12 + jmp rax
                                            _tramp = (long)VirtualAlloc(IntPtr.Zero, (IntPtr)64, 0x1000 | 0x2000, 0x40);
                                            byte[] tj = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
                                            ulong back = (ulong)(entry + 12);
                                            for (int bi = 0; bi < 8; bi++) tj[2 + bi] = (byte)((back >> (8 * bi)) & 0xFF);
                                            byte[] full = new byte[12 + tj.Length];
                                            Array.Copy(orig, 0, full, 0, 12);
                                            Array.Copy(tj, 0, full, 12, tj.Length);
                                            Marshal.Copy(full, 0, (IntPtr)_tramp, full.Length);
                                            _origClone = (DStrSelf)Marshal.GetDelegateForFunctionPointer((IntPtr)_tramp, typeof(DStrSelf));
                                            // 入口改为跳托管 tramp
                                            _dStrSelf = CloneDriverTramp;
                                            long fp2 = Marshal.GetFunctionPointerForDelegate(_dStrSelf).ToInt64();
                                            byte[] jm2 = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
                                            for (int bi = 0; bi < 8; bi++) jm2[2 + bi] = (byte)(((ulong)fp2 >> (8 * bi)) & 0xFF);
                                            uint pp2; VirtualProtect((IntPtr)entry, (IntPtr)jm2.Length, 0x40, out pp2);
                                            Marshal.Copy(jm2, 0, (IntPtr)entry, jm2.Length);
                                            VirtualProtect((IntPtr)entry, (IntPtr)jm2.Length, pp2, out _);
                                            _trampInstalled = true;
                                            lock (log2) { log2.WriteLine($"[v40] CloneDriver trampoline installed entry=0x{entry:X} tramp=0x{_tramp:X}"); log2.Flush(); }
                                        }
                                    }
                                }
                            }
                        }
                        catch (Exception e40) { lock (log2) { log2.WriteLine("[v40] fail: " + e40.Message); log2.Flush(); } }
                        // ===== v41: 批量 trampoline 记录（78xx/74xx/06000FC3）=====
                        try
                        {
                            if (false && !_traceInstalled && _sw.ElapsedMilliseconds > 25000)
                            {
                                int nB = 0, nI = 0; int installed = 0;
                                foreach (var kv2 in prioBytes)
                                {
                                    int tok = kv2.Key;
                                    if (tok == 0x0600794C) continue;   // void ret，跳过
                                    if (installed >= 1) break;         // v42: 最小验证只装 1 个
                                    try
                                    {
                                        var mi3 = asm2.ManifestModule.ResolveMethod(0x06000000 | tok) as System.Reflection.MethodInfo;
                                        if (mi3 == null) continue;
                                        RuntimeHelpers.PrepareMethod(mi3.MethodHandle);
                                        long en3 = mi3.MethodHandle.GetFunctionPointer().ToInt64();
                                        if (en3 <= 0x10000) continue;
                                        byte[] o3 = Rd(en3, 12);
                                        if (o3.Length != 12) continue;
                                        // 已被 2 字节补丁的：原样保存（B0xxC3 会作为"原指令"执行，记录值即补丁值）
                                        long tp3 = (long)VirtualAlloc(IntPtr.Zero, (IntPtr)64, 0x1000 | 0x2000, 0x40);
                                        byte[] tj3 = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
                                        ulong back3 = (ulong)(en3 + 12);
                                        for (int bi = 0; bi < 8; bi++) tj3[2 + bi] = (byte)((back3 >> (8 * bi)) & 0xFF);
                                        byte[] full3 = new byte[24];
                                        Array.Copy(o3, 0, full3, 0, 12);
                                        Array.Copy(tj3, 0, full3, 12, 12);
                                        Marshal.Copy(full3, 0, (IntPtr)tp3, 24);
                                        bool isInt = kv2.Value == "B064C3";
                                        int tokC = tok;
                                        if (isInt)
                                        {
                                            var d3 = (DIntP)Marshal.GetDelegateForFunctionPointer((IntPtr)tp3, typeof(DIntP));
                                            _origI[tok] = d3;
                                            int cc = tokC;
                                            DIntP rec = (s) => RecI(cc, s);
                                            _keepAlive.Add(rec);
                                            long fp3 = Marshal.GetFunctionPointerForDelegate(rec).ToInt64();
                                            byte[] jm3 = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
                                            for (int bi = 0; bi < 8; bi++) jm3[2 + bi] = (byte)(((ulong)fp3 >> (8 * bi)) & 0xFF);
                                            uint p3; VirtualProtect((IntPtr)en3, (IntPtr)12, 0x40, out p3);
                                            Marshal.Copy(jm3, 0, (IntPtr)en3, 12);
                                            VirtualProtect((IntPtr)en3, (IntPtr)12, p3, out _);
                                            nI++; installed++;
                                        }
                                        else
                                        {
                                            var d3 = (DBoolP)Marshal.GetDelegateForFunctionPointer((IntPtr)tp3, typeof(DBoolP));
                                            _origB[tok] = d3;
                                            int cc = tokC;
                                            DBoolP rec = (s) => RecB(cc, s);
                                            _keepAlive.Add(rec);
                                            long fp3 = Marshal.GetFunctionPointerForDelegate(rec).ToInt64();
                                            byte[] jm3 = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
                                            for (int bi = 0; bi < 8; bi++) jm3[2 + bi] = (byte)(((ulong)fp3 >> (8 * bi)) & 0xFF);
                                            uint p3; VirtualProtect((IntPtr)en3, (IntPtr)12, 0x40, out p3);
                                            Marshal.Copy(jm3, 0, (IntPtr)en3, 12);
                                            VirtualProtect((IntPtr)en3, (IntPtr)12, p3, out _);
                                            nB++; installed++;
                                        }
                                    }
                                    catch { }
                                }
                                _traceInstalled = true;
                                lock (log2) { log2.WriteLine($"[v41] trace trampolines: bool={nB} int={nI}"); log2.Flush(); }
                            }
                        }
                        catch (Exception e41) { lock (log2) { log2.WriteLine("[v41] fail: " + e41.Message); log2.Flush(); } }
                        // ===== v43: 纯 asm 计数器跳板（无 GC 切换，安全）=====
                        try
                        {
                            if (false && !_asmInstalled && _sw.ElapsedMilliseconds > 25000)
                            {
                                int nA = 0;
                                foreach (var kv3 in prioBytes)
                                {
                                    int tok = kv3.Key;
                                    if (tok == 0x0600794C) continue;
                                    try
                                    {
                                        var mi4 = asm2.ManifestModule.ResolveMethod(0x06000000 | tok) as System.Reflection.MethodInfo;
                                        if (mi4 == null) continue;
                                        RuntimeHelpers.PrepareMethod(mi4.MethodHandle);
                                        long en4 = mi4.MethodHandle.GetFunctionPointer().ToInt64();
                                        if (en4 <= 0x10000) continue;
                                        byte[] o4 = Rd(en4, 12);
                                        if (o4.Length != 12) continue;
                                        // 就近分配（±2GB 内）：8 字节计数器 + stub
                                        long cnt = 0, st = 0;
                                        for (long base2 = (en4 & ~0xFFFFL); base2 < en4 + 0x10000000L; base2 += 0x10000)
                                        {
                                            var pa = VirtualAlloc((IntPtr)base2, (IntPtr)256, 0x3000, 0x40);
                                            if (pa != IntPtr.Zero) { cnt = pa.ToInt64(); st = cnt + 16; break; }
                                        }
                                        Marshal.WriteInt64((IntPtr)cnt, 0);
                                        _cntMap[tok] = cnt;
                                        byte[] code = new byte[15 + 12 + 12];
                                        int p = 0;
                                        code[p++] = 0x50;                       // push rax
                                        code[p++] = 0x48; code[p++] = 0xB8;     // mov rax, imm64
                                        for (int bi = 0; bi < 8; bi++) code[p++] = (byte)(((ulong)cnt >> (8 * bi)) & 0xFF);
                                        code[p++] = 0x48; code[p++] = 0xFF; code[p++] = 0x00;   // inc qword [rax]
                                        code[p++] = 0x58;                       // pop rax
                                        Array.Copy(o4, 0, code, p, 12); p += 12;
                                        code[p++] = 0x48; code[p++] = 0xB8;
                                        for (int bi = 0; bi < 8; bi++) code[p++] = (byte)(((ulong)(en4 + 12) >> (8 * bi)) & 0xFF);
                                        code[p++] = 0xFF; code[p++] = 0xE0;      // jmp rax
                                        Marshal.Copy(code, 0, (IntPtr)st, code.Length);
                                        // 入口: jmp rel32 -> stub
                                        long rel = st - (en4 + 5);
                                        if (rel > int.MaxValue || rel < int.MinValue) continue;
                                        byte[] j5 = new byte[5];
                                        j5[0] = 0xE9;
                                        Array.Copy(BitConverter.GetBytes((int)rel), 0, j5, 1, 4);
                                        uint p4; VirtualProtect((IntPtr)en4, (IntPtr)5, 0x40, out p4);
                                        Marshal.Copy(j5, 0, (IntPtr)en4, 5);
                                        VirtualProtect((IntPtr)en4, (IntPtr)5, p4, out _);
                                        nA++;
                                    }
                                    catch { }
                                }
                                _asmInstalled = true;
                                // 写映射：tok -> 计数器地址
                                foreach (var kvm in _cntMap)
                                    log2.WriteLine($"[v43] tok={kvm.Key:X6} cnt=0x{kvm.Value:X}");
                                log2.WriteLine($"[v43] asm counter stubs: {nA}");
                                log2.Flush();
                            }
                        }
                        catch (Exception e43) { lock (log2) { log2.WriteLine("[v43] fail: " + e43.Message); log2.Flush(); } }
                            // 全部补丁完成后停止轮询（消除异常洪水）
                            if (prioBytes.Count > 0 && prioBytes.Keys.All(k => cands.ContainsKey(k) && lastCand.ContainsKey(k) && stableCount.TryGetValue(k, out var sc2) && sc2 >= 3))
                            {
                                lock (log2) { log2.WriteLine("[fastpatch] all targets patched - thread sleeping"); log2.Flush(); }
                                Thread.Sleep(Timeout.Infinite);
                            }
                        }
                        catch { }
                        Thread.Sleep(1000);
                    }
                }) { IsBackground = true }.Start();
                log2.WriteLine($"[hook] priority tokens: {prioToks.Count}");
                // First-chance 异常追踪：被 catch 的异常也留痕（定位静默退出原因）
                try
                {
                    AppDomain.CurrentDomain.FirstChanceException += (s, fcea) =>
                    {
                        try
                        {
                            var ex = fcea.Exception;
                            string tn = ex.GetType().FullName ?? "?";
                            // 过滤已知噪音
                            if (tn == "System.Security.Cryptography.CryptographicException") return;
                            if (tn == "System.Configuration.ConfigurationErrorsException") return;
                            var top = "";
                            string stack = "";
                            try
                            {
                                var st = new System.Diagnostics.StackTrace(ex, true);
                                var lines = new List<string>();
                                for (int fi = 0; fi < st.FrameCount && fi < 20; fi++)
                                {
                                    var fr = st.GetFrame(fi);
                                    var mth = fr?.GetMethod();
                                    string ln = (mth?.DeclaringType?.FullName ?? "?") + "::" + (mth?.Name ?? "?");
                                    if (fi == 0) top = ln;
                                    lines.Add("    [" + fi + "] " + ln);
                                }
                                stack = string.Join("\r\n", lines);
                            }
                            catch { }
                            if (top == "" && ex.StackTrace != null)
                            {
                                var sl = ex.StackTrace.Split('\n');
                                if (sl.Length > 0) top = sl[0].Trim();
                            }
                            string msg = (ex.Message ?? "").Replace('\n', ' ').Replace('\r', ' ');
                            if (msg.Length > 400) msg = msg.Substring(0, 400);
                            string full = "";
                            // TimeoutException / TaskCanceled / 跨线程UI访问 时抓当前线程完整托管栈
                            if (tn.Contains("TimeoutException") || tn.Contains("TaskCanceledException") || tn.Contains("OperationCanceled")
                                || tn.Contains("InvalidOperationException"))
                            {
                                try { full = "\r\n[THREAD-STACK]\r\n" + Environment.StackTrace + "\r\n"; } catch { }
                            }
                            File.AppendAllText(@"C://s//hookout//firstchance.txt", $"{DateTime.Now:HH:mm:ss.fff}\t{tn}\t{msg}\t{top}\r\n{stack}{full}\r\n");
                        }
                        catch { }
                    };
                    log2.WriteLine("[hook] FirstChanceException tracer installed");
                }
                catch (Exception fce) { log2.WriteLine("[hook] fce fail: " + fce.Message); }
                // ===== 退出溯源：ProcessExit 事件里打印托管调用栈 =====
                try
                {
                    AppDomain.CurrentDomain.ProcessExit += (s, e) =>
                    {
                        try
                        {
                            var st = Environment.StackTrace;
                            File.AppendAllText(HO + "/exit_trace.log",
                                $"==== ProcessExit {DateTime.Now:HH:mm:ss.fff} tid={Environment.CurrentManagedThreadId} ====\r\n{st}\r\n\r\n");
                        }
                        catch { }
                    };
                    log2.WriteLine("[hook] ProcessExit tracer installed");
                    log2.Flush();
                }
                catch (Exception pex) { log2.WriteLine("[hook] ProcessExit fail: " + pex.Message); }
                // ===== 安装崩溃现场捕获 VEH =====
                try
                {
                    if (Flag("veh2", "0") == "1")
                    {
                        _vcKeep = VEH2;
                        var fp2 = Marshal.GetFunctionPointerForDelegate(_vcKeep);
                        IntPtr r2 = AddVectoredExceptionHandler(1, fp2);
                        new Thread(VehCrashDrain) { IsBackground = true }.Start();
                        log2.WriteLine($"[hook] crash-VEH installed first={r2.ToInt64():X} vehskip={Flag("vehskip", "0")}");
                        log2.Flush();
                    }
                }
                catch (Exception ve) { log2.WriteLine("[hook] crash-VEH fail: " + ve.Message); }
                // ===== 抢先 precode 补丁：抢先于启动验证的第一次调用 =====
                try
                {
                    foreach (var ptok in prioToks)
                    {
                        if (!entryPatchToks.Contains(ptok)) continue;
                        try
                        {
                            long pe = asm2.ManifestModule.ResolveMethod(0x06000000 | ptok).MethodHandle.GetFunctionPointer().ToInt64();
                            if (pe == 0) { log2.WriteLine($"[prepatch] tok {ptok:X}: null entry"); continue; }
                            uint oldPr;
                            VirtualProtect((IntPtr)pe, (IntPtr)16, 0x40, out oldPr);
                            Marshal.WriteByte((IntPtr)pe, 0xB8);
                            Marshal.WriteInt32((IntPtr)(pe + 1), 1);
                            Marshal.WriteByte((IntPtr)(pe + 5), 0xC3);
                            VirtualProtect((IntPtr)pe, (IntPtr)16, oldPr, out _);
                            log2.WriteLine($"[prepatch] tok {ptok:X} entry=0x{pe:X} -> mov eax,1; ret");
                        }
                        catch (Exception pex) { log2.WriteLine($"[prepatch] tok {ptok:X} fail: {pex.Message}"); }
                    }
                }
                catch { }
                // 注册 MessageBox.Show 全部重载地址 → cgraph 揭示弹框调用者
                try
                {
                    var pw = AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(a => a.GetName().Name == "PresentationFramework" || a.GetName().Name == "WindowsBase");
                    if (pw != null)
                    {
                        var mbT = pw.GetType("System.Windows.MessageBox");
                        if (mbT != null)
                        {
                            int mbn = 0;
                            foreach (var shm in mbT.GetMethods(BindingFlags.Public | BindingFlags.Static).Where(mm => mm.Name == "Show"))
                            {
                                try
                                {
                                    long me = shm.MethodHandle.GetFunctionPointer().ToInt64();
                                    capNames[me] = "MessageBox.Show(" + string.Join(",", shm.GetParameters().Select(pp => pp.ParameterType.Name)) + ")";
                                    mbn++;
                                }
                                catch { }
                            }
                            log2.WriteLine($"[hook] MessageBox.Show overloads registered: {mbn}");
                        // 注册 Window 关闭路径 → 揪出失败处理器
                        try
                        {
                            var winT = pw.GetType("System.Windows.Window");
                            int wn = 0;
                            foreach (var wm in winT.GetMethods(BindingFlags.Public | BindingFlags.Instance).Where(mm => mm.Name == "Close"))
                            {
                                try { capNames[wm.MethodHandle.GetFunctionPointer().ToInt64()] = "Window.Close()"; wn++; } catch { }
                            }
                            foreach (var wp in winT.GetProperties(BindingFlags.Public | BindingFlags.Instance).Where(pp => pp.Name == "DialogResult"))
                            {
                                try { capNames[wp.GetSetMethod().MethodHandle.GetFunctionPointer().ToInt64()] = "Window.set_DialogResult()"; wn++; } catch { }
                            }
                            foreach (var wm in winT.GetMethods(BindingFlags.Public | BindingFlags.Instance).Where(mm => mm.Name == "Hide"))
                            {
                                try { capNames[wm.MethodHandle.GetFunctionPointer().ToInt64()] = "Window.Hide()"; wn++; } catch { }
                            }
                            log2.WriteLine($"[hook] Window close-path methods registered: {wn}");
                        }
                        catch (Exception wxe) { log2.WriteLine("[hook] win reg fail: " + wxe.Message); }
                        }
                    }
                }
                catch (Exception mbe) { log2.WriteLine("[hook] mb register fail: " + mbe.Message); }
                while (true)
                {
                    try
                    {
                        if (File.Exists(HO + "/passive_off")) break;
                        // ===== v34: managed replacement for 06007411 (response decryptor) =====
                        try
                        {
                            if (false && !_replaced7411)
                            {
                                var mi = asm2.ManifestModule.ResolveMethod(0x06007411) as System.Reflection.MethodInfo;
                                if (mi != null)
                                {
                                    RuntimeHelpers.PrepareMethod(mi.MethodHandle);
                                    long tgt = mi.MethodHandle.GetFunctionPointer().ToInt64();
                                    if (tgt > 0x10000)
                                    {
                                        _repl7411Del = Repl7411;
                                        long fp = Marshal.GetFunctionPointerForDelegate(_repl7411Del).ToInt64();
                                        byte[] jmp = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
                                        ulong fpl = (ulong)fp;
                                        for (int bi = 0; bi < 8; bi++) jmp[2 + bi] = (byte)(fpl >> (8 * bi) & 0xFF);
                                        uint pop2; VirtualProtect((IntPtr)tgt, (IntPtr)jmp.Length, 0x40, out pop2);
                                        Marshal.Copy(jmp, 0, (IntPtr)tgt, jmp.Length);
                                        VirtualProtect((IntPtr)tgt, (IntPtr)jmp.Length, pop2, out _);
                                        _replaced7411 = true;
                                        log2.WriteLine($"[v34] 06007411 detoured to managed repl @0x{fp:X} (entry 0x{tgt:X})");
                                        log2.Flush();
                                    }
                                }
                            }
                        }
                        catch (Exception e34) { }
                        try
                        {
                            if (false && !_replShutdown && _sw.ElapsedMilliseconds > 15000)
                            {
                                Type appType = null;
                                foreach (var asmM in System.AppDomain.CurrentDomain.GetAssemblies())
                                {
                                    try { var tt = asmM.GetType("System.Windows.Application"); if (tt != null) { appType = tt; break; } } catch { }
                                }
                                if (appType == null) { try { appType = typeof(System.Windows.Window).Assembly.GetType("System.Windows.Application"); } catch { } }
                                if (appType != null)
                                {
                                    foreach (var m in appType.GetMethods(System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Instance).Where(x => x.Name == "Shutdown"))
                                    {
                                        var ps = m.GetParameters();
                                        RuntimeHelpers.PrepareMethod(m.MethodHandle);
                                        long entry = m.MethodHandle.GetFunctionPointer().ToInt64();
                                        long fp;
                                        if (ps.Length == 0) { _dShutdown = ReplShutdown; fp = Marshal.GetFunctionPointerForDelegate(_dShutdown).ToInt64(); }
                                        else if (ps.Length == 1 && ps[0].ParameterType == typeof(int)) { _dShutdownI = ReplShutdownI; fp = Marshal.GetFunctionPointerForDelegate(_dShutdownI).ToInt64(); }
                                        else continue;
                                        byte[] jm = { 0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0 };
                                        for (int bi = 0; bi < 8; bi++) jm[2 + bi] = (byte)(((ulong)fp >> (8 * bi)) & 0xFF);
                                        uint pp; VirtualProtect((IntPtr)entry, (IntPtr)jm.Length, 0x40, out pp);
                                        Marshal.Copy(jm, 0, (IntPtr)entry, jm.Length);
                                        VirtualProtect((IntPtr)entry, (IntPtr)jm.Length, pp, out _);
                                        lock (log2) { log2.WriteLine($"[v36] Application.Shutdown({ps.Length}) @0x{entry:X} -> repl"); log2.Flush(); }
                                    }
                                    _replShutdown = true;
                                }
                            }
                        }
                        catch (Exception e36) { lock (log2) { log2.WriteLine("[v36] fail: " + e36.Message); log2.Flush(); } }
                        lock (log2) { log2.WriteLine($"[beat] t={_sw.ElapsedMilliseconds}ms alive"); log2.Flush(); }
                        log2.Flush();
                    }
                    catch { }
                    Thread.Sleep(5000);
                }
            }
            var log = new StreamWriter(Path.Combine(outDir, "hook.log")) { AutoFlush = true };
            if (Flag("console", "1") == "1") Console.SetOut(log);
            _h = GetCurrentProcess();
            _hThreadSelf = new IntPtr(-2);

            string dll = @"C:/Program Files/Volumetrica Trading/Deepchart/Deepchart.dll";

            static List<(long addr, byte[] data)> ReadSpanLocal(long lo, long hi)
        {
            var chunks = new List<(long, byte[])>();
            long cur = lo;
            while (cur < hi)
            {
                if (VirtualQueryEx(_h, (IntPtr)cur, out MBI mbi, (IntPtr)Marshal.SizeOf<MBI>()) == IntPtr.Zero) break;
                long regEnd = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                if (mbi.State == 0x1000 && cur < regEnd)
                {
                    long take = Math.Min(regEnd, hi) - cur;
                    var buf = new byte[take];
                    ReadProcessMemory(_h, (IntPtr)cur, buf, (IntPtr)take, out _);
                    chunks.Add((cur, buf));
                }
                cur = regEnd;
                if (regEnd <= mbi.BaseAddress.ToInt64()) break;
            }
            return chunks;
        }

        // PEB 隐藏（防应用自身反调试）
            if (Flag("peb", "1") == "1") try { new Thread(PebHideLoop) { IsBackground = true }.Start(); } catch { }

            var stubs = new List<(int tok, string name)>();
            using (var mod = ModuleDefMD.Load(dll))
                foreach (var t in mod.GetTypes())
                    foreach (var m in t.Methods)
                    {
                        if (m.Body == null || m.Body.Instructions.Count == 0) continue;
                        var il = m.Body.Instructions;
                        bool refs = il.Any(i2 => i2.Operand is IMethod || i2.Operand is IField);
                        if (il.Count(i2 => i2.OpCode != OpCodes.Nop) <= 2 && !refs)
                            stubs.Add(((int)m.MDToken.Raw, m.FullName));
                    }
            Stage($"stubs enumerated: {stubs.Count}");

            Stage("LoadFile begin");
            var asm = Assembly.LoadFile(dll);
            Stage("LoadFile done");
            Type[] ts; try { ts = asm.GetTypes(); } catch (ReflectionTypeLoadException e2) { ts = e2.Types.Where(x => x != null).ToArray(); }
            if (Flag("modulector", "1") == "1")
                foreach (var t in ts) if (t.Name.StartsWith("<Module>{"))
                    try { RuntimeHelpers.RunClassConstructor(t.TypeHandle); } catch { }

            // 定位调度器
            var mb = asm.ManifestModule.ResolveMethod(0x06000005);
            long E = mb.MethodHandle.GetFunctionPointer().ToInt64();
            long disp = Q(E + 0x4010);
            _bpAddr = disp + 0x9D;
            { var dcode = Rd(disp, 0x60); int rel = BitConverter.ToInt32(dcode, 0x51); _resolverLo = disp + 0x55 + rel; _resolverHi = _resolverLo + 0x2000; }
            Console.WriteLine($"[hook] dispatcher=0x{disp:X}");

            // 真实机器码（旧版算法：Up + 非Loopback + 按速率降序取首）
            try
            {
                var nics = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                             && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    .OrderByDescending(n => n.Speed).ToList();
                var n0 = nics.FirstOrDefault();
                if (n0 != null)
                {
                    var mac = string.Join("", n0.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2")));
                    if (!string.IsNullOrEmpty(mac)) _macId = mac;
                }
            }
            catch { }
            Console.WriteLine($"[hook] machineId={_macId}");

            _retStubG = VirtualAlloc(IntPtr.Zero, (IntPtr)0x1000, 0x3000, 0x40).ToInt64();
            Marshal.WriteByte((IntPtr)_retStubG, 0xC3);
            scratch = _retStubG + 0x100;

            // VEH v6（仅 DR0 捕获，其他异常放行）
            if (Flag("veh", "1") == "1")
            {
            var vehBytes = File.ReadAllBytes(@"C:/Users/Admin/Desktop/DPDP/runtime/veh9.bin");
            var sents = new Dictionary<ulong, long>
            {
                { 0xDEADBEEFDEAD0001UL, _bpAddr },
                { 0xDEADBEEFDEAD0002UL, scratch },
                { 0xDEADBEEFDEAD0003UL, _retStubG },
                { 0xDEADBEEFDEAD0004UL, _resolverLo },
                { 0xDEADBEEFDEAD0005UL, _resolverHi },
                { 0xDEADBEEFDEAD0006UL, _bpAddr - 0x48 },
                { 0xDEADBEEFDEAD0007UL, _retStubG + 0x180 },
            };
            foreach (var kv in sents)
            {
                var pat = BitConverter.GetBytes(kv.Key);
                var rep = BitConverter.GetBytes(kv.Value);
                for (int i = 0; i <= vehBytes.Length - 8; i++)
                    if (vehBytes[i] == pat[0] && vehBytes[i+1] == pat[1] && vehBytes[i+2] == pat[2] && vehBytes[i+3] == pat[3]
                        && vehBytes[i+4] == pat[4] && vehBytes[i+5] == pat[5] && vehBytes[i+6] == pat[6] && vehBytes[i+7] == pat[7])
                    { Array.Copy(rep, 0, vehBytes, i, 8); break; }
            }
            long vehPage = VirtualAlloc(IntPtr.Zero, (IntPtr)0x1000, 0x3000, 0x40).ToInt64();
            Marshal.Copy(vehBytes, 0, (IntPtr)vehPage, vehBytes.Length);
            AddVectoredExceptionHandler(1, (IntPtr)vehPage);
            Stage("VEH installed");
            if (Flag("vehlog", "0") == "1") { StartVehLogDrain(); Console.WriteLine("[hook] VEH log drain started"); }

            // DR0 装配（本线程，伪句柄 -2）
            IntPtr raw = Marshal.AllocHGlobal(4096 + 16);
            IntPtr ctx = new IntPtr((raw.ToInt64() + 15) & ~15L);
            for (int i = 0; i < 4096; i += 8) Marshal.WriteInt64(ctx, i, 0);
            Marshal.WriteInt32(ctx, (int)CTX_FLAGS, unchecked((int)0x10001B));
            GetThreadContext(_hThreadSelf, ctx);
            Marshal.WriteInt64(ctx, (int)CTX_Dr0, _bpAddr);
            Marshal.WriteInt64(ctx, 0x50, _resolverLo + 0x700);
            Marshal.WriteInt64(ctx, 0x58, _resolverLo + 0x9A8);
            Marshal.WriteInt64(ctx, (int)CTX_Dr7, 0x407);
            SetThreadContext(_hThreadSelf, ctx);
            Marshal.FreeHGlobal(raw);
            Stage("DR0 armed");
            }

            // ===== Precode Fixup Bypass: 让所有平凡 stub 方法直接返回桩 IL 的值 =====
            // 绕过 Eazfuscator dispatcher → 不触发反调试/许可检查 → 应用正常运行
            if (Flag("bypass", "1") == "1")
            {
                // 创建原生 return-true 桩和 return 桩
                long rtStubPage = VirtualAlloc(IntPtr.Zero, (IntPtr)0x1000, 0x3000, 0x40).ToInt64();
                // mov eax,1; ret = B8 01 00 00 00 C3 (6 bytes)
                Marshal.WriteByte((IntPtr)rtStubPage, 0xB8);
                Marshal.WriteInt32((IntPtr)(rtStubPage+1), 1);
                Marshal.WriteByte((IntPtr)(rtStubPage+5), 0xC3);
                // ret = C3 (1 byte) at +8
                Marshal.WriteByte((IntPtr)(rtStubPage+8), 0xC3);
                long retTrueStub = rtStubPage;
                long retVoidStub = rtStubPage + 8;

                int bypassed = 0;
                foreach (var (tokB, nameB) in stubs)
                {
                    long eB = 0;
                    try { eB = asm.ManifestModule.ResolveMethod(0x06000000 | tokB).MethodHandle.GetFunctionPointer().ToInt64(); } catch { continue; }

                    // 读方法 IL
                    byte[] methodIl;
                    try {
                        var mi = (MethodInfo)asm.ManifestModule.ResolveMethod(0x06000000 | tokB);
                        methodIl = mi.GetMethodBody()?.GetILAsByteArray();
                    } catch { continue; }
                    if (methodIl == null || methodIl.Length == 0) continue;

                    // 只 patch return true 的方法（许可/认证检查）
                    // void/其他类型方法可能是 Main 或关键业务逻辑，不 patch
                    if (!(methodIl.Length == 2 && methodIl[0] == 0x17 && methodIl[1] == 0x2A)) continue;
                    if (nameB.Contains("Permit") || nameB.Contains("Main") || nameB.Contains("Gateway")) continue;

                    // patch precode fixup [E+0x4000] = retTrueStub
                    long fixAddr = eB + 0x4000;
                    Marshal.WriteInt64((IntPtr)fixAddr, retTrueStub);
                    bypassed++;
                    Console.WriteLine($"[bypass] {nameB}");
                }
                Stage($"precode bypass: {bypassed}");
            }

            // ===== 预解析地址表（被动监控与 sweep 共用）=====
            var stubList = new List<(int tok, string name, long e)>();
            foreach (var (tok, name) in stubs)
            {
                long e0 = 0;
                try { e0 = asm.ManifestModule.ResolveMethod(0x06000000 | tok).MethodHandle.GetFunctionPointer().ToInt64(); } catch { }
                if (e0 != 0) stubList.Add((tok, name, e0));
            }
            Console.WriteLine($"[hook] stubList={stubList.Count}");

            // ===== License.Status 定向补丁：precode 重定向 + 委托伪造 =====
            if (Flag("lic", "1") == "1")
            {
                Stage("lic patch begin");
                Type licT = ts.FirstOrDefault(t => t.Namespace == "License" && t.Name == "Status");
                if (licT == null)
                    licT = ts.FirstOrDefault(t => t.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic).Any(m2 => m2.Name == "PlanProc"));
                if (licT != null)
                {
                    Console.WriteLine($"[lic] type={licT.FullName}");
                    long licPage = VirtualAlloc(IntPtr.Zero, (IntPtr)0x1000, 0x3000, 0x40).ToInt64();
                    // retTrue: mov eax,1; ret
                    Marshal.WriteByte((IntPtr)licPage, 0xB8); Marshal.WriteInt32((IntPtr)(licPage + 1), 1); Marshal.WriteByte((IntPtr)(licPage + 5), 0xC3);
                    // ret100: mov eax,100; ret（许可级别）
                    Marshal.WriteByte((IntPtr)(licPage + 8), 0xB8); Marshal.WriteInt32((IntPtr)(licPage + 9), 100); Marshal.WriteByte((IntPtr)(licPage + 13), 0xC3);
                    // retVoid: ret
                    Marshal.WriteByte((IntPtr)(licPage + 16), 0xC3);
                    long retTrue2 = licPage, ret100 = licPage + 8, retVoid2 = licPage + 16;

                    var delTypes = new HashSet<Type>();
                    foreach (var f0 in licT.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
                        if (f0.FieldType.IsSubclassOf(typeof(MulticastDelegate))) delTypes.Add(f0.FieldType);

                    int nb = 0, ni = 0, ns = 0;
                    foreach (var m0 in licT.GetMethods(BindingFlags.Static | BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic))
                    {
                        if (m0.IsConstructor || m0.Name == ".cctor" || m0.Name == "Equals" || m0.Name == "GetHashCode" || m0.Name == "ToString") continue;
                        long eb0 = 0; try { eb0 = m0.MethodHandle.GetFunctionPointer().ToInt64(); } catch { continue; }
                        if (eb0 == 0) continue;
                        long tgt = 0;
                        var ps0 = m0.GetParameters();
                        string mn = m0.Name;
                        bool isStringVerifier = ps0.Length >= 1 && ps0.All(p => p.ParameterType == typeof(string));
                        if (m0.ReturnType == typeof(bool) && Flag("bools", "1") == "1" && !(isStringVerifier && Flag("machinepatch", "1") == "0")) tgt = retTrue2;
                        else if (m0.ReturnType == typeof(int) && ps0.Length == 0 && Flag("ints", "1") == "1") tgt = ret100;
                        else if (m0.ReturnType == typeof(void) && ps0.Length == 1 && delTypes.Contains(ps0[0].ParameterType) && Flag("setnops", "1") == "1") tgt = retVoid2;
                        if (tgt == 0) continue;
                        try
                        {
                            Marshal.WriteInt64((IntPtr)(eb0 + 0x4000), tgt);
                            Console.WriteLine($"[lic] patched {m0.Name} ({m0.ReturnType.Name},{ps0.Length}p)->0x{tgt:X}");
                            if (tgt == retTrue2) nb++; else if (tgt == ret100) ni++; else ns++;
                        }
                        catch (Exception pe) { Console.WriteLine($"[lic] patch FAIL {m0.Name}: {pe.Message}"); }
                    }
                    Console.WriteLine($"[lic] bool={nb} int={ni} setterNop={ns}");

                    // 委托字段伪造：机器码+确认码 / 激活码 验证回调全部替换为恒真
                    foreach (var f1 in licT.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
                    {
                        if (!f1.FieldType.IsSubclassOf(typeof(MulticastDelegate))) continue;
                        if (Flag("fakes", "1") != "1") break;
                        try
                        {
                            var inv = f1.FieldType.GetMethod("Invoke");
                            var ptypes = inv.GetParameters().Select(p => p.ParameterType).ToArray();
                            var dm = new System.Reflection.Emit.DynamicMethod("fake_" + f1.Name, inv.ReturnType, ptypes, typeof(StartupHook).Module, true);
                            var ig = dm.GetILGenerator();
                            var rt = inv.ReturnType;
                            if (rt == typeof(bool)) ig.Emit(System.Reflection.Emit.OpCodes.Ldc_I4_1);
                            else if (rt == typeof(int)) ig.Emit(System.Reflection.Emit.OpCodes.Ldc_I4_S, (byte)100);
                            else if (rt == typeof(string))
                            {
                                string mode = Flag("mac", "0");
                                if (mode == "1")
                                {
                                    var fi = typeof(StartupHook).GetField("_macId", BindingFlags.Static | BindingFlags.NonPublic);
                                    ig.Emit(System.Reflection.Emit.OpCodes.Ldsfld, fi);
                                }
                                else if (mode == "2" && licT != null)
                                {
                                    // 回显应用自己算好的机器码（保持正确格式 ####-####-####-####-####）
                                    var fTag = licT.GetField("m_PassiveCalculatorProxyTag", BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.Public);
                                    if (fTag != null) ig.Emit(System.Reflection.Emit.OpCodes.Ldsfld, fTag);
                                    else ig.Emit(System.Reflection.Emit.OpCodes.Ldnull);
                                }
                                else ig.Emit(System.Reflection.Emit.OpCodes.Ldnull);
                            }
                            else if (rt != typeof(void))
                            {
                                if (rt.IsValueType)
                                {
                                    var lb = ig.DeclareLocal(rt);
                                    ig.Emit(System.Reflection.Emit.OpCodes.Ldloca_S, lb);
                                    ig.Emit(System.Reflection.Emit.OpCodes.Initobj, rt);
                                    ig.Emit(System.Reflection.Emit.OpCodes.Ldloc, lb);
                                }
                                else ig.Emit(System.Reflection.Emit.OpCodes.Ldnull);
                            }
                            ig.Emit(System.Reflection.Emit.OpCodes.Ret);
                            f1.SetValue(null, dm.CreateDelegate(f1.FieldType));
                            Console.WriteLine($"[lic] delegate faked: {f1.Name} ({f1.FieldType.Name})");
                        }
                        catch (Exception de) { Console.WriteLine($"[lic] delegate FAIL {f1.Name}: {de.Message}"); }
                    }
                }
                else Console.WriteLine("[lic] License.Status NOT FOUND");
            }

            // ===== 参数捕获：ScheduledHandler 全部 ctor + 静态入口 =====
            var _acBufs = new List<(long buf, string label)>();
            if (Flag("argcap", "1") != "0")
            {
                try
                {
                    var ct = ts.FirstOrDefault(t2 => t2.FullName == "VolAnalysis.Handling.ScheduledHandler");
                    if (ct != null)
                    {
                        int idx = 0;
                        foreach (var cm in ct.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance))
                        {
                            long ea = cm.MethodHandle.GetFunctionPointer().ToInt64();
                            long t18 = Q(ea + 0x4018), f4000 = Q(ea + 0x4000);
                            Console.WriteLine($"[argcap] ctor#{idx} 9p?{cm.GetParameters().Length == 9} e=0x{ea:X} [4018]=0x{t18:X} [4000]=0x{f4000:X}");
                            long trampPage = VirtualAlloc(IntPtr.Zero, (IntPtr)0x2000, 0x3000, 0x40).ToInt64();
                            long argBuf = trampPage + 0x100;
                            long origTgt = f4000;
                            var code = new List<byte>();
                            void Qw(long v) { code.AddRange(BitConverter.GetBytes(v)); }
                            code.Add(0x50);
                            code.Add(0x48); code.Add(0xB8); Qw(argBuf);
                            code.Add(0x48); code.Add(0x89); code.Add(0x08);
                            code.Add(0x48); code.Add(0x89); code.Add(0x50); code.Add(0x08);
                            code.Add(0x4C); code.Add(0x89); code.Add(0x40); code.Add(0x10);
                            code.Add(0x4C); code.Add(0x89); code.Add(0x48); code.Add(0x18);
                            code.Add(0x58);
                            code.Add(0x48); code.Add(0xB8); Qw(origTgt);
                            code.Add(0xFF); code.Add(0xE0);
                            Marshal.Copy(code.ToArray(), 0, (IntPtr)trampPage, code.Count);
                            Marshal.WriteInt64((IntPtr)(ea + 0x4000), trampPage);
                            _acBufs.Add((argBuf, $"ctor#{idx}({string.Join(",", cm.GetParameters().Select(p => p.ParameterType.Name))})"));
                            idx++;
                        }
                        foreach (var mn in new[] { "HandleControllableAnalyzer", "ManagePassivePublisher" })
                        {
                            foreach (var sm in ct.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic).Where(m2 => m2.Name == mn))
                            {
                                long ea = sm.MethodHandle.GetFunctionPointer().ToInt64();
                                long f4000 = Q(ea + 0x4000);
                                long trampPage = VirtualAlloc(IntPtr.Zero, (IntPtr)0x2000, 0x3000, 0x40).ToInt64();
                                long argBuf = trampPage + 0x100;
                                var code = new List<byte>();
                                void Qw(long v) { code.AddRange(BitConverter.GetBytes(v)); }
                                code.Add(0x50);
                                code.Add(0x48); code.Add(0xB8); Qw(argBuf);
                                code.Add(0x48); code.Add(0x89); code.Add(0x08);
                                code.Add(0x48); code.Add(0x89); code.Add(0x50); code.Add(0x08);
                                code.Add(0x4C); code.Add(0x89); code.Add(0x40); code.Add(0x10);
                                code.Add(0x4C); code.Add(0x89); code.Add(0x48); code.Add(0x18);
                                code.Add(0x58);
                                code.Add(0x48); code.Add(0xB8); Qw(f4000);
                                code.Add(0xFF); code.Add(0xE0);
                                Marshal.Copy(code.ToArray(), 0, (IntPtr)trampPage, code.Count);
                                Marshal.WriteInt64((IntPtr)(ea + 0x4000), trampPage);
                                _acBufs.Add((argBuf, mn));
                                Console.WriteLine($"[argcap] {mn} trampoline e=0x{ea:X} orig=0x{f4000:X}");
                            }
                        }
                        var acThread = new Thread(() =>
                        {
                            var done = new HashSet<string>();
                            for (int i = 0; i < 600; i++)
                            {
                                Thread.Sleep(500);
                                try
                                {
                                    foreach (var (buf, label) in _acBufs)
                                    {
                                        if (done.Contains(label)) continue;
                                        long rcx = Marshal.ReadInt64((IntPtr)buf);
                                        if (rcx == 0) continue;
                                        long rdx = Marshal.ReadInt64((IntPtr)(buf + 8));
                                        long r8v = Marshal.ReadInt64((IntPtr)(buf + 16));
                            long r9v = Marshal.ReadInt64((IntPtr)(buf + 24));
                                        long r9 = Marshal.ReadInt64((IntPtr)(buf + 24));
                                        var line = $"[argcap] {label}: this=0x{rcx:X} a2={ReadManagedStr(rdx)} a3={ReadManagedStr(r8v)} a4=0x{r9:X}";
                                        Console.WriteLine(line);
                                        File.AppendAllText(HO + "/crash.txt", line + "\r\n");
                                        done.Add(label);
                                    }
                                }
                                catch { }
                            }
                        }) { IsBackground = true };
                        acThread.Start();
                    }
                    else Console.WriteLine("[argcap] ScheduledHandler NOT FOUND");
                }
                catch (Exception ae) { Console.WriteLine($"[argcap] FAIL {ae}"); }
            }

            // ===== 类型 cctor（触发懒加载解析）=====
            int cok = 0;
            bool doCctors = Flag("cctors", "1") == "1";
            foreach (var t in (doCctors ? ts.Where(t => !t.Name.StartsWith("<Module>{")) : Enumerable.Empty<Type>()))
            {
                try { RuntimeHelpers.RunClassConstructor(t.TypeHandle); cok++; }
                catch (Exception ce)
                {
                    Console.WriteLine($"[cctor] FAIL {t.FullName}: {ce.GetType().Name} {ce.Message}");
                    try { File.AppendAllText(HO + "/crash.txt", $"[cctor] FAIL {t.FullName} @ {DateTime.Now:HH:mm:ss}\r\n{ce}\r\n"); } catch { }
                }
            }
            Stage($"cctors ok={cok}");

            // ===== 周期性转储 License.Status 静态状态 =====
            if (Flag("statdump", "1") == "1")
            {
                var sdThread = new Thread(() =>
                {
                    for (int round = 0; round < 8; round++)
                    {
                        Thread.Sleep(10000);
                        try
                        {
                            var st2 = ts.FirstOrDefault(t2 => t2.Namespace == "License" && t2.Name == "Status");
                            if (st2 == null) return;
                            var sb2 = new System.Text.StringBuilder();
                            sb2.AppendLine($"==== Status statics t=+{(round + 1) * 10}s {DateTime.Now:HH:mm:ss} ====");
                            foreach (var f in st2.GetFields(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
                            {
                                object v = null;
                                try { v = f.GetValue(null); } catch { }
                                string vs;
                                if (v == null) vs = "<null>";
                                else if (v is byte[] ba) vs = "byte[" + ba.Length + "]";
                                else if (v is MulticastDelegate md) vs = "<delegate " + md.GetType().Name + ">";
                                else vs = v.ToString();
                                if (vs.Length > 120) vs = vs.Substring(0, 120);
                                sb2.AppendLine($"  {f.Name} : {f.FieldType.Name} = {vs}");
                            }
                            File.AppendAllText(HO + "/crash.txt", sb2.ToString());
                        }
                        catch { }
                    }
                });
                sdThread.IsBackground = true;
                sdThread.Start();
            }

            // skip 列表
            var skip = new HashSet<string>();
            string skipFile = Path.Combine(outDir, "skip.txt");
            if (File.Exists(skipFile)) foreach (var l in File.ReadAllLines(skipFile)) skip.Add(l);
            var curFile = Path.Combine(outDir, "current.txt");

            // ===== 被动监控线程：登录/UI 流程真实解析的方法体自动落盘 =====
            var seenPassive = new HashSet<long>();
            var pmThread = new Thread(() =>
            {
                while (true)
                {
                    try
                    {
                        foreach (var (tokP, nameP, eP) in stubList)
                        {
                            long t18 = Q(eP + 0x4018);
                            if (t18 != 0 && !IsTramp(t18) && seenPassive.Add(t18))
                            {
                                File.AppendAllText(Path.Combine(outDir, "passive.tsv"), $"0x{tokP:X8}\t0x{t18:X}\t{nameP}\r\n");
                                var bufP = new byte[4096];
                                if (ReadProcessMemory(_h, (IntPtr)t18, bufP, (IntPtr)4096, out _))
                                    try { File.WriteAllBytes(Path.Combine(outDir, $"p{tokP:X8}.bin"), bufP); } catch { }
                            }
                        }
                    }
                    catch { }
                    Thread.Sleep(5000);
                }
            });
            pmThread.IsBackground = true;
            pmThread.Start();
            Stage("passive monitor started");

            if (File.Exists(Path.Combine(outDir, "nosweep.txt")))
            {
                Console.WriteLine("[sweep] skipped (nosweep.txt)");
                return;
            }

            _sweeping = true;
            int ok = 0, fail = 0, batch = 0, shortcut = 0;
            var sb = new System.Text.StringBuilder();
            foreach (var (tok, name) in stubs)
            {
                File.WriteAllText(curFile, tok.ToString());
                if (skip.Contains(tok.ToString())) { fail++; continue; }
                MethodBase m = null;
                try { m = asm.ManifestModule.ResolveMethod(0x06000000 | tok); } catch { }
                if (m == null) { fail++; continue; }
                long e = 0;
                try { e = m.MethodHandle.GetFunctionPointer().ToInt64(); } catch { }
                if (e == 0) { fail++; continue; }

                long codeAddr = 0;
                long t18 = Q(e + 0x4018);
                if (t18 != 0 && !IsTramp(t18)) codeAddr = t18;
                if (codeAddr == 0)
                {
                    long fix = Q(e + 0x4000);
                    if (fix != 0 && fix != e + 6 && !IsTramp(fix)) codeAddr = fix;
                }
                if (codeAddr != 0) shortcut++;
                else
                {
                    Marshal.WriteInt64((IntPtr)scratch, 0);
                    try
                    {
                        object target = null;
                        if (!m.IsStatic)
                            target = System.Runtime.Serialization.FormatterServices.GetUninitializedObject(m.DeclaringType);
                        var iargs = new object[m.GetParameters().Length];
                        m.Invoke(target, iargs);
                    }
                    catch { }
                    codeAddr = Marshal.ReadInt64((IntPtr)scratch);
                }


                if (codeAddr != 0)
                {
                    ok++;
                    sb.AppendLine($"0x{tok:X8}\t0x{codeAddr:X}\tok\t{name}");
                    var buf = new byte[4096];
                    if (ReadProcessMemory(_h, (IntPtr)codeAddr, buf, (IntPtr)4096, out _))
                        File.WriteAllBytes(Path.Combine(outDir, $"{tok:X8}.bin"), buf);
                }
                else fail++;

                if (++batch % 100 == 0)
                {
                    Console.WriteLine($"[sweep] {batch} ok={ok} fail={fail}");
                    File.AppendAllText(Path.Combine(outDir, "sweep.tsv"), sb.ToString()); sb.Clear();
                }
            }
            File.AppendAllText(Path.Combine(outDir, "sweep.tsv"), sb.ToString());
            Console.WriteLine($"[sweep] LOOP-DONE ok={ok} fail={fail}");
        }

        static long _retStubG;
        static long lastProgress;
        static volatile bool _sweepFlagUnused;
        static string _macId = "00155D018B22";
        static Dictionary<string, string> _flags = new Dictionary<string, string>();
        static string Flag(string k, string def) => _flags.TryGetValue(k, out var v) ? v : def;
        static void LoadFlags()
        {
            try
            {
                foreach (var l in File.ReadAllLines(HO + "/flags.txt"))
                {
                    int i = l.IndexOf('=');
                    if (i > 0) _flags[l.Substring(0, i).Trim()] = l.Substring(i + 1).Trim();
                }
            }
            catch { }
            Console.WriteLine($"[hook] flags: vehlog={Flag("vehlog", "0")} mac={Flag("mac", "0")} bools={Flag("bools", "1")} ints={Flag("ints", "1")} setnops={Flag("setnops", "1")} fakes={Flag("fakes", "1")} machinepatch={Flag("machinepatch", "1")}");
        }

        // ===== 托管 VEH：记录原生 AV/非法访问（排除单步断点）=====
        [StructLayout(LayoutKind.Sequential)]
        struct EXCEPTION_POINTERS { public IntPtr ExceptionRecord, ContextRecord; }
        [StructLayout(LayoutKind.Sequential)]
        struct EXREC { public uint Code, Flags; public IntPtr InnerRecord, Address; public uint NumParams; public IntPtr _info; }
        delegate int VEHDel(IntPtr ep);
        static VEHDel _vehKeep;
        static int VEHLog(IntPtr ep)
        {
            try
            {
                if (ep != IntPtr.Zero)
                {
                    var er = Marshal.ReadIntPtr(ep);
                    var ctx = Marshal.ReadIntPtr(ep, 8);
                    if (er != IntPtr.Zero)
                    {
                        uint code = (uint)Marshal.ReadInt32(er, 0);
                        if (code == 0x80000004 && ctx != IntPtr.Zero && Flag("argcap", "1") == "1")
                        {
                            long dr6 = Marshal.ReadInt64(ctx, 0x68);
                            if ((dr6 & 0x8) != 0) // B3：我们的 ScheduledHandler ctor 断点
                            {
                                long rcx = Marshal.ReadInt64(ctx, 0x80);
                                long rdx = Marshal.ReadInt64(ctx, 0x88);
                                long r8v = Marshal.ReadInt64(ctx, 0xB8);
                                long r9 = Marshal.ReadInt64(ctx, 0xC0);
                                var line = $"[argcap {DateTime.Now:HH:mm:ss.fff}] ScheduledHandler..ctor this=0x{rcx:X} spec={ReadManagedStr(rdx)} ivk={ReadManagedStr(r8v)} p4=0x{r9:X}";
                                lock (_vehLock) _vehLog.Add(line);
                                long dr7 = Marshal.ReadInt64(ctx, 0x70);
                                dr7 &= ~0xC0L; // 清 L3/G3（一次性）
                                Marshal.WriteInt64(ctx, 0x70, dr7);
                                Marshal.WriteInt64(ctx, 0x68, 0);
                            }
                        }
                        if (code != 0x80000004 && code != 0x4000001F && code != 0x40000006)
                        {
                            long addr = Marshal.ReadIntPtr(er, 16).ToInt64();
                            lock (_vehLock)
                            {
                                if (_vehLog.Count < 500) _vehLog.Add($"{DateTime.Now:HH:mm:ss.fff} code=0x{code:X8} addr=0x{addr:X}");
                            }
                        }
                    }
                }
            }
            catch { }
            return 0; // EXCEPTION_CONTINUE_SEARCH
        }
        static string ReadManagedStr(long obj)
        {
            try
            {
                if (obj == 0) return "<null>";
                if ((obj >> 48) != 0) return "<bad ptr>";
                int len = Marshal.ReadInt32((IntPtr)(obj + 8));
                if (len < 0 || len > 4096) return "<len" + len + ">";
                var buf = new byte[len * 2];
                ReadProcessMemory(_h, (IntPtr)(obj + 12), buf, (IntPtr)buf.Length, out _);
                return "\"" + System.Text.Encoding.Unicode.GetString(buf) + "\"";
            }
            catch { return "<err>"; }
        }
        static long _ctorAddr;
        static readonly HashSet<int> _armedTids = new HashSet<int>();
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
        [DllImport("kernel32.dll")] static extern bool VirtualProtect(IntPtr addr, IntPtr size, uint newProt, out uint oldProt);
        [DllImport("kernel32.dll")] static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr mod, string name);
        static void ArmDr3Loop()
        {
            new Thread(() =>
            {
                int pid = System.Diagnostics.Process.GetCurrentProcess().Id;
                for (int i = 0; i < 60; i++)
                {
                    try
                    {
                        var proc = System.Diagnostics.Process.GetProcessById(pid);
                        foreach (System.Diagnostics.ProcessThread th in proc.Threads)
                        {
                            int tid = th.Id;
                            bool isNew;
                            lock (_armedTids) isNew = _armedTids.Add(tid);
                            if (!isNew) continue;
                            IntPtr h = OpenThread(THREAD_ALL_ACCESS, false, (uint)tid);
                            if (h == IntPtr.Zero) continue;
                            IntPtr raw = Marshal.AllocHGlobal(4096 + 16);
                            IntPtr ctx = new IntPtr((raw.ToInt64() + 15) & ~15L);
                            for (int z = 0; z < 1232; z += 8) Marshal.WriteInt64(ctx, z, 0);
                            Marshal.WriteInt32(ctx, 0x30, unchecked((int)0x00100010)); // CONTEXT_DEBUG_REGISTERS
                            if (GetThreadContext(h, ctx))
                            {
                                Marshal.WriteInt64(ctx, 0x60, _ctorAddr); // DR3
                                long dr7 = Marshal.ReadInt64(ctx, 0x70);
                                dr7 |= 0x40; // L3
                                Marshal.WriteInt64(ctx, 0x70, dr7);
                                SetThreadContext(h, ctx);
                            }
                            Marshal.FreeHGlobal(raw);
                            CloseHandle(h);
                        }
                    }
                    catch { }
                    Thread.Sleep(2000);
                }
            }) { IsBackground = true }.Start();
        }
        static readonly HashSet<long> _prestubBlacklist = new HashSet<long>();   // 学习到的共享 prestub 地址
        static byte[] _thunkSig;                                                  // PrecodeFixupThunk 字节签名
        static readonly Dictionary<long, int> _candOwner = new Dictionary<long, int>();  // 全局 cand 归属（跨迭代）
        static readonly object _vehLock = new object();
        static readonly List<string> _vehLog = new List<string>();
        static void TryCapture(int tok, string name, long e, IntPtr hProc, string outDir, StreamWriter logW,
            HashSet<long> seen2, Dictionary<long, string> capNames, List<(int tok, string name, long cand, byte[] buf)> capBodies,
            Dictionary<int, string> prioB)
        {
            try
            {
            long t18 = BitConverter.ToInt64(Rd(e + 0x4018, 8), 0);
            long f40 = BitConverter.ToInt64(Rd(e + 0x4000, 8), 0);
            long cand = 0;
            if (t18 != 0 && (t18 >> 48) == 0 && !(t18 >= e && t18 < e + 0x40)) cand = t18;
            if (cand == 0 && f40 != 0 && (f40 >> 48) == 0 && f40 != e + 6 && !(f40 >= e && f40 < e + 0x40))
            {
                long b2 = BitConverter.ToInt64(Rd(f40 + 0x4008, 8), 0);
                if (b2 != 0 && (b2 >> 48) == 0 && !(b2 >= f40 && b2 < f40 + 0x40)) cand = b2;
                else cand = f40;
            }
            if (cand == 0 || !seen2.Add(cand)) return;
            var fb = Rd(cand, 2);
            if (fb.Length == 2 && fb[0] == 0xFF && fb[1] == 0x25) return;
            logW.WriteLine($"passive\t0x{tok:X8}\t0x{cand:X}\t{name}");
            logW.Flush();
            var buf = new byte[8192];
            if (ReadProcessMemory(hProc, (IntPtr)cand, buf, (IntPtr)8192, out _))
            {
                try { File.WriteAllBytes(Path.Combine(outDir, $"p{tok:X8}.bin"), buf); } catch { }
                capNames[cand] = name;
                if (f40 != 0) capNames[f40] = name;
                lock (capBodies) capBodies.Add((tok, name, cand, buf));
                // 就地 body 补丁（优先 token 带字节码时）
                string pbytes2 = null;
                if (prioB != null) prioB.TryGetValue(tok, out pbytes2);
                if (pbytes2 != null && !_prestubBlacklist.Contains(cand))
                {
                    try
                    {
                        if (_thunkSig != null)
                        {
                            var head = Rd(cand, Math.Min(12, _thunkSig.Length));
                            if (head.Length == _thunkSig.Length && head.SequenceEqual(_thunkSig)) return;
                        }
                        var clean = new string(pbytes2.Where(ch => Uri.IsHexDigit(ch)).ToArray());
                        byte[] pb = new byte[clean.Length / 2];
                        for (int bi = 0; bi < pb.Length; bi++) pb[bi] = Convert.ToByte(clean.Substring(bi * 2, 2), 16);
                        uint pop; VirtualProtect((IntPtr)cand, (IntPtr)pb.Length, 0x40, out pop);
                        Marshal.Copy(pb, 0, (IntPtr)cand, pb.Length);
                        VirtualProtect((IntPtr)cand, (IntPtr)pb.Length, pop, out _);
                        lock (logW) { logW.WriteLine($"[bodypatch] tok={tok} cand=0x{cand:X} bytes={pbytes2} OK"); logW.Flush(); }
                    }
                    catch (Exception bpx) { lock (logW) { logW.WriteLine($"[bodypatch] tok={tok} fail: {bpx.GetType().Name}: {bpx.Message} raw=[{pbytes2}]"); logW.Flush(); } }
                }
            }
            }
            catch { }   // 防弹：TryCapture 任何异常都不得带崩应用
        }

        static void StartVehLogDrain()
        {
            _vehKeep = VEHLog;
            var fp = Marshal.GetFunctionPointerForDelegate(_vehKeep);
            AddVectoredExceptionHandler(0, fp); // 加到链尾，在 veh9 之后跑
            new Thread(() =>
            {
                while (true)
                {
                    Thread.Sleep(3000);
                    try
                    {
                        string[] snap;
                        lock (_vehLock) { snap = _vehLog.ToArray(); _vehLog.Clear(); }
                        if (snap.Length > 0)
                            File.AppendAllText(HO + "/crash.txt", string.Join("\r\n", snap) + "\r\n");
                    }
                    catch { }
                }
            }) { IsBackground = true }.Start();
        }

        static List<(long addr, byte[] data)> ReadSpanLocal(long lo, long hi)
        {
            var chunks = new List<(long, byte[])>();
            long cur = lo;
            while (cur < hi)
            {
                if (VirtualQueryEx(_h, (IntPtr)cur, out MBI mbi, (IntPtr)Marshal.SizeOf<MBI>()) == IntPtr.Zero) break;
                long regEnd = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                if (mbi.State == 0x1000 && cur < regEnd)
                {
                    long take = Math.Min(regEnd, hi) - cur;
                    var buf = new byte[take];
                    ReadProcessMemory(_h, (IntPtr)cur, buf, (IntPtr)take, out _);
                    chunks.Add((cur, buf));
                }
                cur = regEnd;
                if (regEnd <= mbi.BaseAddress.ToInt64()) break;
            }
            return chunks;
        }

        // PEB 隐藏
        [DllImport("ntdll.dll")] static extern uint NtQueryInformationProcess(IntPtr proc, uint cls, ref PBI pbi, uint len, out uint ret);
        [StructLayout(LayoutKind.Sequential)]
        struct PBI { public uint ExitStatus, _pad; public IntPtr PebBaseAddress, AffinityMask, BasePriority, Pid, ParentPid; }
        static void PebHideLoop()
        {
            try
            {
                var pbi = new PBI();
                NtQueryInformationProcess(GetCurrentProcess(), 0, ref pbi, (uint)Marshal.SizeOf<PBI>(), out _);
                IntPtr peb = pbi.PebBaseAddress;
                if (peb == IntPtr.Zero) return;
                while (true)
                {
                    Marshal.WriteByte(peb, 0x02, 0);      // PEB.BeingDebugged = 0
                    Marshal.WriteInt32(peb, 0x3BC, 0);    // PEB.NtGlobalFlag = 0
                    // ★ 清 DR 寄存器（x64dbg attach 会设 DR0-7，最常被反调试检测）
                    try {
                        IntPtr rawC = Marshal.AllocHGlobal(4096 + 16);
                        IntPtr ctxC = new IntPtr((rawC.ToInt64() + 15) & ~15L);
                        Marshal.WriteInt32(ctxC, (int)CTX_FLAGS, unchecked((int)0x10001B));
                        if (GetThreadContext(_hThreadSelf, ctxC)) {
                            Marshal.WriteInt64(ctxC, 0x48, 0);  // Dr0
                            Marshal.WriteInt64(ctxC, 0x50, 0);  // Dr1
                            Marshal.WriteInt64(ctxC, 0x58, 0);  // Dr2
                            Marshal.WriteInt64(ctxC, 0x60, 0);  // Dr3
                            Marshal.WriteInt64(ctxC, 0x68, 0);  // Dr6
                            Marshal.WriteInt64(ctxC, 0x70, 0);  // Dr7
                            SetThreadContext(_hThreadSelf, ctxC);
                        }
                        Marshal.FreeHGlobal(rawC);
                    } catch { }
                    Thread.Sleep(30);
                }
            } catch { }
        }
    }
