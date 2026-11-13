using System;
using System.IO;
using System.Runtime.ExceptionServices;

internal static class Repro
{
    // 复现原 Hook.cs 2754 行的行为：对“不存在的目录”写文件
    static readonly string BAD = @"C:\s\__definitely_missing_dir__\firstchance.txt";

    [ThreadStatic] static bool _inFce;   // 本次修复新增的重入守卫
    static bool _dead;
    static long _writes;

    static void Main(string[] args)
    {
        bool fix = args.Length > 0 && args[0] == "fix";

        AppDomain.CurrentDomain.FirstChanceException += (s, e) =>
        {
            if (fix) { if (_inFce) return; _inFce = true; }
            try
            {
                if (_dead) return;
                File.AppendAllText(BAD, "x" + _writes++ + "\r\n");
            }
            catch
            {
                if (fix) _dead = true;   // 写不进去就停手，绝不再抛
            }
            finally
            {
                if (fix) _inFce = false;
            }
        };

        Console.WriteLine($"[fcetest] fix={fix} -> 抛出一个被 catch 的异常");
        try { throw new InvalidOperationException("boom"); } catch { }
        Console.WriteLine($"[fcetest] 存活，file-write 尝试次数={_writes}");
    }
}
