using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    /// <summary>A running process the debugger could attach to.</summary>
    internal sealed class ProcEntry
    {
        public uint Pid;
        public string Name;
        public string Path;
        public bool Tswd;
        /// <summary>Creation time, FILETIME (UTC, 100 ns ticks). Written as a decimal STRING ("started"), since a
        /// JSON number loses precision above 2^53 in most readers.</summary>
        public ulong Started;
    }

    /// <summary>A process the enumerator passed over, and why (one of the ProcsCommand.Skip* reasons).</summary>
    internal sealed class ProcSkip
    {
        public uint Pid;
        public string Name;
        public string Reason;
    }

    /// <summary>
    /// <c>ClarionDbg procs [--json] [--verbose] [--all] [--exclude &lt;pid&gt;]...</c> - the attach picker's
    /// process list (ticket 3f2d747f part B). A one-shot, spawned by the host the way GetGlobalsJson spawns
    /// <c>globals</c>.
    /// <para>
    /// A process is listed when it is x86 (the engine debugs CONTEXT_X86 only), its image's first PE debug
    /// directory entry is TSWD (PeProbe - by the debug directory, never by a file or section name), it is
    /// not this process nor an excluded pid (the host passes the IDE's own), and no debugger is attached to
    /// it. <c>--all</c> also lists x86 images WITHOUT TSWD, with <c>"tswd":false</c>. Every other process is
    /// counted in <c>skipped</c>; <c>--verbose</c> lists each with its reason. A process that cannot be opened
    /// is skipped as access-denied, never an error.
    /// </para>
    /// </summary>
    internal static class ProcsCommand
    {
        public const string SkipSelf = "self";
        public const string SkipExcluded = "excluded";
        public const string SkipAccessDenied = "access-denied";
        public const string SkipNotX86 = "not-x86";
        public const string SkipNoPath = "no-path";
        public const string SkipUnreadableImage = "unreadable-image";
        public const string SkipNoTswd = "no-tswd";
        public const string SkipDebugged = "debugged";

        public static int Run(string[] args)
        {
            bool json = HasFlag(args, "--json");
            bool verbose = HasFlag(args, "--verbose");
            bool all = HasFlag(args, "--all");
            var exclude = new HashSet<uint>();
            for (int i = 1; i < args.Length; i++)
            {
                if (!string.Equals(args[i], "--exclude", StringComparison.OrdinalIgnoreCase)) continue;
                uint pid;
                if (i + 1 >= args.Length || !uint.TryParse(args[i + 1], NumberStyles.None, CultureInfo.InvariantCulture, out pid))
                {
                    Console.Error.WriteLine("procs: --exclude needs a process id");
                    return 1;
                }
                exclude.Add(pid);
                i++;
            }

            var procs = new List<ProcEntry>();
            var skips = new List<ProcSkip>();
            Enumerate(exclude, all, procs, skips);
            procs.Sort((a, b) => a.Pid.CompareTo(b.Pid));
            skips.Sort((a, b) => a.Pid.CompareTo(b.Pid));

            if (json)
            {
                Console.WriteLine(Json.Procs(procs, skips, verbose));
                return 0;
            }
            Console.WriteLine($"{procs.Count} attachable process(es), {skips.Count} skipped:");
            foreach (var p in procs)
                Console.WriteLine($"  {p.Pid,7}  {(p.Tswd ? "TSWD" : "    ")}  {p.Name}  {p.Path}");
            if (verbose)
                foreach (var s in skips)
                    Console.WriteLine($"  {s.Pid,7}  skip  {s.Name}  ({s.Reason})");
            return 0;
        }

        private static void Enumerate(HashSet<uint> exclude, bool all, List<ProcEntry> procs, List<ProcSkip> skips)
        {
            uint self = (uint)System.Diagnostics.Process.GetCurrentProcess().Id;
            bool everyProcessIsX86 = OsIsX86Only();

            IntPtr snap = Native.CreateToolhelp32Snapshot(Native.TH32CS_SNAPPROCESS, 0);
            if (snap == Native.INVALID_HANDLE_VALUE || snap == IntPtr.Zero)
                throw new InvalidOperationException("CreateToolhelp32Snapshot failed, error " + System.Runtime.InteropServices.Marshal.GetLastWin32Error());
            try
            {
                var pe = new Native.PROCESSENTRY32W();
                pe.dwSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf(typeof(Native.PROCESSENTRY32W));
                for (bool ok = Native.Process32FirstW(snap, ref pe); ok; ok = Native.Process32NextW(snap, ref pe))
                {
                    uint pid = pe.th32ProcessID;
                    string name = pe.szExeFile;
                    string reason;
                    ProcEntry entry = Classify(pid, name, self, exclude, all, everyProcessIsX86, out reason);
                    if (entry != null) procs.Add(entry);
                    else skips.Add(new ProcSkip { Pid = pid, Name = name, Reason = reason });
                }
            }
            finally { Native.CloseHandle(snap); }
        }

        /// <summary>The listed entry, or null with the skip reason. Never throws for a single process.</summary>
        private static ProcEntry Classify(uint pid, string name, uint self, HashSet<uint> exclude, bool all,
                                          bool everyProcessIsX86, out string reason)
        {
            reason = null;
            if (pid == self) { reason = SkipSelf; return null; }
            if (exclude.Contains(pid)) { reason = SkipExcluded; return null; }

            string path;
            IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) { reason = SkipAccessDenied; return null; }
            try
            {
                // WOW64 first: most processes on 64-bit Windows are x64, and this rules them out without
                // opening their image file. The PE Machine check below is still the authority.
                bool wow64;
                if (!everyProcessIsX86 && (!Native.IsWow64Process(h, out wow64) || !wow64)) { reason = SkipNotX86; return null; }

                var sb = new StringBuilder(1024);
                uint len = (uint)sb.Capacity;
                if (!Native.QueryFullProcessImageNameW(h, 0, sb, ref len) || len == 0) { reason = SkipNoPath; return null; }
                path = sb.ToString(0, (int)len);
            }
            finally { Native.CloseHandle(h); }

            ushort machine;
            bool tswd;
            if (!PeProbe.TryProbe(path, out machine, out tswd)) { reason = SkipUnreadableImage; return null; }
            if (machine != PeProbe.MachineI386) { reason = SkipNotX86; return null; }
            if (!tswd && !all) { reason = SkipNoTswd; return null; }

            // ProcessDebugPort needs PROCESS_QUERY_INFORMATION, not the limited right. A process that will not
            // give us that will not give an attach the far wider rights it needs either.
            IntPtr hq = Native.OpenProcess(Native.PROCESS_QUERY_INFORMATION, false, pid);
            if (hq == IntPtr.Zero) { reason = SkipAccessDenied; return null; }
            ulong started;
            try
            {
                bool present;
                if (!Native.CheckRemoteDebuggerPresent(hq, out present)) { reason = SkipAccessDenied; return null; }
                if (present) { reason = SkipDebugged; return null; }
                // The identity the host hands back as `attach --expect-start`. A process whose creation time cannot
                // be read cannot be proven to be the one listed, so it is not listed.
                if (!TryGetProcessStart(hq, out started)) { reason = SkipAccessDenied; return null; }
            }
            finally { Native.CloseHandle(hq); }

            return new ProcEntry { Pid = pid, Name = name, Path = path, Tswd = tswd, Started = started };
        }

        /// <summary>For `attach`: the image path of <paramref name="pid"/> and whether it is x86. False with a
        /// Win32 error when the process cannot be opened or named. x86 is decided by WOW64 FIRST, as in the
        /// listing: this engine is x86, so opening an x64 process's C:\Windows\System32 path would be silently
        /// redirected to the x86 copy in SysWOW64 and a PE probe of it would answer "x86". The probe then
        /// confirms the machine of the file actually named.</summary>
        internal static bool TryDescribeProcess(uint pid, out string path, out ImageArch arch, out int error)
        {
            path = null; arch = ImageArch.Unreadable; error = 0;
            IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) { error = System.Runtime.InteropServices.Marshal.GetLastWin32Error(); return false; }
            try
            {
                bool wow64;
                bool x86ByWow = OsIsX86Only() || (Native.IsWow64Process(h, out wow64) && wow64);
                var sb = new StringBuilder(1024);
                uint len = (uint)sb.Capacity;
                if (!Native.QueryFullProcessImageNameW(h, 0, sb, ref len) || len == 0)
                {
                    error = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                    return false;
                }
                path = sb.ToString(0, (int)len);
                ushort machine = 0; bool tswd;
                bool probed = x86ByWow && PeProbe.TryProbe(path, out machine, out tswd);
                arch = ClassifyProcessImage(x86ByWow, probed, machine);
                return true;
            }
            finally { Native.CloseHandle(h); }
        }

        /// <summary>What `attach` knows about a process's image (4b run 2): only a CONFIRMED non-x86 is "not x86";
        /// an image that could not be read is its own case, not folded into that one.</summary>
        internal enum ImageArch { X86, NotX86, Unreadable }

        /// <summary>Pure. A process WOW64 does not run is not x86, whatever its file says; for one it does run, the
        /// PE Machine field decides, and a probe that failed leaves it unreadable.</summary>
        internal static ImageArch ClassifyProcessImage(bool x86ByWow, bool probeOk, ushort machine)
        {
            if (!x86ByWow) return ImageArch.NotX86;
            if (!probeOk) return ImageArch.Unreadable;
            return machine == PeProbe.MachineI386 ? ImageArch.X86 : ImageArch.NotX86;
        }

        /// <summary>The `code` of an attach refusal for an image that is not attachable: 50 (ERROR_NOT_SUPPORTED)
        /// for a confirmed non-x86 machine, 0 for an image that could not be read (not a Win32 failure).</summary>
        internal static int AttachRefusalCode(ImageArch arch)
        {
            return arch == ImageArch.NotX86 ? 50 : 0;
        }

        /// <summary>A process's creation time as a FILETIME (UTC, 100 ns ticks), the identity `procs` lists as
        /// "started" and `attach --expect-start` checks. False when the process cannot be opened or asked.</summary>
        internal static bool TryGetProcessStart(uint pid, out ulong filetime)
        {
            filetime = 0;
            IntPtr h = Native.OpenProcess(Native.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero) return false;
            try { return TryGetProcessStart(h, out filetime); }
            finally { Native.CloseHandle(h); }
        }

        private static bool TryGetProcessStart(IntPtr h, out ulong filetime)
        {
            long c, e, k, u;
            bool ok = Native.GetProcessTimes(h, out c, out e, out k, out u);
            filetime = ok ? unchecked((ulong)c) : 0;
            return ok;
        }

        /// <summary>True on 32-bit Windows, where IsWow64Process is false for every process and every process
        /// is x86. This engine is built x86, so it runs either natively there or under WOW64 on 64-bit Windows.</summary>
        private static bool OsIsX86Only()
        {
            bool selfWow64;
            return IntPtr.Size == 4
                && Native.IsWow64Process(Native.GetCurrentProcess(), out selfWow64)
                && !selfWow64;
        }

        private static bool HasFlag(string[] args, string name)
        {
            foreach (var a in args) if (string.Equals(a, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }
    }
}
