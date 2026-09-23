using System;
using System.Runtime.InteropServices;

namespace ClarionDbg.Cli
{
    /// <summary>Chooses where the Library State emulator's modeled stack lives in the debuggee's address
    /// space. Separate from DebugEngine because it needs nothing from the debug session but a process
    /// handle — which also makes it drivable on its own against any process.</summary>
    internal static class EmulatorStackWindow
    {
        /// <summary>Find a base for the emulator's modeled stack inside a region the debuggee has genuinely
        /// FREE, so the window can't overlap a real module or heap block.
        ///
        /// This matters because the window is authoritative: any access inside it is answered from the
        /// emulator's private buffer instead of the target. Pick a base that collides with something real
        /// and the getters read our zeroed buffer while believing they read the RTL — the panel then shows
        /// a number that looks fine and isn't, which is exactly what the emulator's refuse-don't-guess rule
        /// exists to prevent. (The guard bands make it louder, not safer: a collision there refuses a
        /// legitimate value instead of silently faking one.)
        ///
        /// Walks the target's regions and takes the first free one big enough for the stack plus both
        /// guards. Returns 0 when there's no such region — the caller turns that into an error rather than
        /// falling back to a fixed address.</summary>
        public static uint Pick(IntPtr hProcess)
        {
            int mbiSize = Marshal.SizeOf(typeof(Native.MEMORY_BASIC_INFORMATION));
            ulong addr = 0x10000;                                   // skip the reserved low 64 KB
            while (addr < UserSpaceEnd)
            {
                if (Native.VirtualQueryEx(hProcess, Ptr(addr), out var mbi, (IntPtr)mbiSize) == IntPtr.Zero)
                    break;                                          // walked off the end (or the query failed)
                ulong regionBase = (ulong)mbi.BaseAddress.ToInt64();
                ulong regionSize = (ulong)mbi.RegionSize.ToInt64();
                if (regionSize == 0) break;                         // no forward progress — don't spin

                // 64 KB-align inside the region: that's the allocation granularity, and it keeps the
                // window off the ragged front edge of a free block.
                ulong start = (regionBase + 0xFFFF) & ~0xFFFFUL;
                if (WindowFitsFree(mbi, start)) return (uint)start + RtlEmulator.StackGuard;

                ulong next = regionBase + regionSize;
                if (next <= addr) break;                            // defensive: never walk backwards
                addr = next;
            }
            return 0;
        }

        /// <summary>Is a window <see cref="Pick"/> returned earlier STILL inside one free region? One
        /// VirtualQueryEx instead of Pick's walk from the bottom of the address space (9b073cf9). Measured
        /// 2026-09-22 against a live 32-bit clbrws.exe: Pick ~340-380 us per call, about 85% of what building
        /// an emulator cost on every breakpoint hit that reads a THREADed name.
        ///
        /// The window cannot simply be cached across a resume: the target runs in between and may allocate
        /// into it, and then every emulated read there is answered from the emulator's zeroed buffer. So a
        /// caller re-asks this each time and falls back to Pick when it says no. The test is the SAME one
        /// Pick applies (<see cref="WindowFitsFree"/>), so a reused window meets exactly the bar a fresh one
        /// does.</summary>
        public static bool StillFree(IntPtr hProcess, uint stackBase)
        {
            if (stackBase < RtlEmulator.StackGuard) return false;
            ulong start = (ulong)stackBase - RtlEmulator.StackGuard;
            int mbiSize = Marshal.SizeOf(typeof(Native.MEMORY_BASIC_INFORMATION));
            if (Native.VirtualQueryEx(hProcess, Ptr(start), out var mbi, (IntPtr)mbiSize) == IntPtr.Zero)
                return false;
            return WindowFitsFree(mbi, start);
        }

        private const uint UserSpaceEnd = 0x7FFF0000;

        /// <summary>Does a whole window starting at <paramref name="start"/> (guards included) lie inside
        /// this FREE region, below the end of user space? The one rule both Pick and StillFree apply.</summary>
        private static bool WindowFitsFree(Native.MEMORY_BASIC_INFORMATION mbi, ulong start)
        {
            if (mbi.State != Native.MEM_FREE) return false;
            ulong regionBase = (ulong)mbi.BaseAddress.ToInt64();
            ulong regionSize = (ulong)mbi.RegionSize.ToInt64();
            return start >= regionBase && start + RtlEmulator.WindowBytes <= regionBase + regionSize
                   && start + RtlEmulator.WindowBytes <= UserSpaceEnd;
        }

        /// <summary>Address -> IntPtr by raw bit pattern. Same trap as DebugEngine.Ptr: on x86 the
        /// (IntPtr)(long) route is a CHECKED narrowing that throws for anything >= 0x80000000. The walk
        /// below stops at UserSpaceEnd so it can't reach that today, but the cast is the footgun from
        /// issue #20 and shouldn't be left lying around waiting for the bound to move.</summary>
        private static IntPtr Ptr(ulong addr) => (IntPtr)unchecked((int)(uint)addr);
    }
}
