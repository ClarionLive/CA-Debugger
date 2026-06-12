using System;
using System.Runtime.InteropServices;

namespace ClarionDbg.Cli
{
    /// <summary>Win32 debugging API surface for the x86 debug loop.</summary>
    internal static class Native
    {
        // --- process creation / debug flags ---
        public const uint DEBUG_ONLY_THIS_PROCESS = 0x00000002;
        public const uint CREATE_NEW_CONSOLE = 0x00000010;

        // --- debug event codes ---
        public const uint EXCEPTION_DEBUG_EVENT = 1;
        public const uint CREATE_THREAD_DEBUG_EVENT = 2;
        public const uint CREATE_PROCESS_DEBUG_EVENT = 3;
        public const uint EXIT_THREAD_DEBUG_EVENT = 4;
        public const uint EXIT_PROCESS_DEBUG_EVENT = 5;
        public const uint LOAD_DLL_DEBUG_EVENT = 6;
        public const uint UNLOAD_DLL_DEBUG_EVENT = 7;
        public const uint OUTPUT_DEBUG_STRING_EVENT = 8;
        public const uint RIP_EVENT = 9;

        // --- exception codes ---
        public const uint EXCEPTION_BREAKPOINT = 0x80000003;
        public const uint EXCEPTION_SINGLE_STEP = 0x80000004;

        // --- continue codes ---
        public const uint DBG_CONTINUE = 0x00010002;
        public const uint DBG_EXCEPTION_NOT_HANDLED = 0x80010001;

        // --- CONTEXT flags (x86) ---
        public const uint CONTEXT_i386 = 0x00010000;
        public const uint CONTEXT_CONTROL = CONTEXT_i386 | 0x1;   // SS:ESP, CS:EIP, FLAGS, EBP
        public const uint CONTEXT_INTEGER = CONTEXT_i386 | 0x2;   // EDI..EAX
        public const uint CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | (CONTEXT_i386 | 0x4);

        public const uint INFINITE = 0xFFFFFFFF;

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public uint cb;
            public IntPtr lpReserved, lpDesktop, lpTitle;
            public uint dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
            public ushort wShowWindow, cbReserved2;
            public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess, hThread;
            public uint dwProcessId, dwThreadId;
        }

        // x86 CONTEXT (716 bytes). FLOATING_SAVE_AREA is inlined as fields.
        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        public struct CONTEXT_X86
        {
            public uint ContextFlags;
            public uint Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            // FLOATING_SAVE_AREA (112 bytes)
            public uint FltControlWord, FltStatusWord, FltTagWord, FltErrorOffset, FltErrorSelector, FltDataOffset, FltDataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)] public byte[] FltRegisterArea;
            public uint FltCr0NpxState;
            // segment + integer + control registers
            public uint SegGs, SegFs, SegEs, SegDs;
            public uint Edi, Esi, Ebx, Edx, Ecx, Eax;
            public uint Ebp, Eip, SegCs, EFlags, Esp, SegSs;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)] public byte[] ExtendedRegisters;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcess(
            string lpApplicationName, string lpCommandLine,
            IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
            bool bInheritHandles, uint dwCreationFlags,
            IntPtr lpEnvironment, string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        // DEBUG_EVENT is read as a raw buffer and parsed by offset (the union is awkward to marshal).
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WaitForDebugEvent(byte[] lpDebugEvent, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr dwSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT_X86 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetThreadContext(IntPtr hThread, ref CONTEXT_X86 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        // Inject a breakpoint into the debuggee on a transient OS thread, so a running target can be
        // paused from the debugger. Raises EXCEPTION_BREAKPOINT in the debug loop.
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool DebugBreakProcess(IntPtr Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
}
