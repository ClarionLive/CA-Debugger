using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------------ call stack

        private const int STACK_SCAN_BYTES = 0x4000;   // how far up from ESP to scan for return addrs
        private const uint FRAME_GAP_MAX = 0x800;      // max distance past a line record for a code addr
        private const int STACK_FRAMES_DEFAULT = 32;
        private const int STACK_FRAMES_MAX = 256;

        /// <summary>stack [maxFrames] [reqid=N] — resolved call stack while paused (frame 0 = current EIP). Walks
        /// the SELECTED thread's registers, which is usually but not always the stopped thread's; the reply is
        /// stamped with that tid so the host can drop it if it has since switched threads. A reqid is echoed on
        /// the reply as "reqId", so the host can tell WHICH request a reply answers (49538b78 wave 5 run 3): a
        /// stale reply for the same thread carries the same tid, and only its id tells it apart.</summary>
        private void HandleStackCommand(string[] parts, ref Native.CONTEXT_X86 ctx, bool haveCtx, uint tid,
                                        IntPtr hThread)
        {
            if (!haveCtx) { EmitError("stack: no context for thread " + TidText(tid)); return; }
            int max; string reqId, error;
            if (!TryParseStackArgs(parts, out max, out reqId, out error)) { EmitError(error); return; }
            var frames = BuildStack(ctx.Eip, ctx.Esp, ctx.Ebp, max, hThread);
            EmitThreadEvent(tid, Json.Stack(frames, reqId));
            Console.WriteLine($"  stack of thread {TidText(tid)} ({frames.Count} frame(s)):");
            for (int i = 0; i < frames.Count; i++)
            {
                var f = frames[i];
                string name = f.Proc ?? "(unknown)";
                string loc = f.Module != null ? $"  {f.Module}:{f.Line}" : "";
                string unc = f.Uncertain ? "  (uncertain — possibly a stale return address)" : "";
                Console.WriteLine($"    #{i,-2} {name}{loc}  RVA 0x{f.Rva:X}{(f.Kind != null ? "  [" + f.Kind + "]" : "")}{unc}");
            }
        }

        private const string REQID_TOKEN = "reqid=";   // a token no frame count, watch name or other argument can be
        private const int REQID_MAX_DIGITS = 10;

        /// <summary>
        /// Take the optional trailing <c>reqid=N</c> off a command's tokens (C1, wave 7): the ONE parser for it, used
        /// by `stack`, `watch` and `moduledata`. It is always the LAST token, N is 1 to 10 digits, and
        /// <paramref name="reqId"/> is null when there is none. A malformed id, or a <c>reqid=</c> token anywhere
        /// but last, is refused with <paramref name="error"/> naming <paramref name="grammar"/> (the command's
        /// "verb: expected ..."), never skipped: a request whose id was silently dropped would be answered with
        /// no id, and the host cannot tell that reply from an older engine's.
        /// <paramref name="rest"/> is <paramref name="parts"/> without the id.
        /// </summary>
        internal static bool TryTakeReqId(string[] parts, string grammar, out string[] rest, out string reqId, out string error)
        {
            rest = parts; reqId = null; error = null;
            int last = parts.Length - 1;
            for (int i = 1; i < last; i++)
                if (parts[i].StartsWith(REQID_TOKEN, StringComparison.Ordinal))
                {
                    error = grammar + ", reqid=N last";
                    return false;
                }
            if (last < 1 || !parts[last].StartsWith(REQID_TOKEN, StringComparison.Ordinal)) return true;
            string id = parts[last].Substring(REQID_TOKEN.Length);
            if (id.Length == 0 || id.Length > REQID_MAX_DIGITS || !IsAllDigits(id))
            {
                error = grammar + ", N 1.." + REQID_MAX_DIGITS + " digits";
                return false;
            }
            reqId = id;
            rest = new string[last];
            Array.Copy(parts, rest, last);
            return true;
        }

        /// <summary>The arguments of `stack` (and `bt`/`where`): an optional frame count, then an optional
        /// <c>reqid=N</c> (<see cref="TryTakeReqId"/>), in that order. Anything else is refused with the reason in
        /// <paramref name="error"/>. <paramref name="reqId"/> is null when none was given.</summary>
        internal static bool TryParseStackArgs(string[] parts, out int max, out string reqId, out string error)
        {
            max = STACK_FRAMES_DEFAULT;
            if (!TryTakeReqId(parts, "stack: expected [maxFrames] [reqid=N]", out parts, out reqId, out error)) return false;
            if (parts.Length > 1 && (!int.TryParse(parts[1], out max) || max < 1 || max > STACK_FRAMES_MAX))
            {
                max = 0; reqId = null;
                error = $"stack: max frames must be 1..{STACK_FRAMES_MAX}";
                return false;
            }
            if (parts.Length > 2) { reqId = null; error = "stack: expected [maxFrames] [reqid=N]"; return false; }
            return true;
        }

        private static bool IsAllDigits(string s)
        {
            foreach (char c in s) if (c < '0' || c > '9') return false;
            return true;
        }

        /// <summary>Test seam: the REAL HandleStackCommand for <paramref name="line"/>, with an invented context
        /// and no target (every walk is frame 0 alone), so `protocolcheck` can read the reply it emits.</summary>
        internal void HandleStackCommandForTest(string line, uint tid)
        {
            RefuseSeamIfAttached("HandleStackCommandForTest");
            var c = NewContext();
            c.Eip = 0x401000; c.Esp = 0x19F000; c.Ebp = 0x19F100;
            HandleStackCommand(line.Split(' '), ref c, true, tid, IntPtr.Zero);
        }

        /// <summary>
        /// Build the call stack. Frame 0 is the current EIP. Primary walk follows the EBP frame chain:
        /// Clarion's generated procedures and ABC methods set up standard {push ebp; mov ebp,esp}
        /// frames, so [ebp] = caller EBP and [ebp+4] = return address. This yields the TRUE caller
        /// links across all images (EXE/DLL/runtime) and terminates naturally when a return address
        /// leaves debuggable code (into the C runtime / OS) — so it does NOT manufacture the stale
        /// frames an unconstrained stack scan pulls from dead stack memory (which also made the stack
        /// differ run-to-run). Each link is still validated (mapped code within FRAME_GAP_MAX + a CALL
        /// precedes the return) so a corrupt/FPO frame breaks the chain cleanly rather than lying.
        ///
        /// Fallback: if the chain yields no caller (e.g. paused before the current frame's prologue
        /// ran, or an FPO leaf at the top), scan the stack for plausible return addresses — the legacy
        /// behaviour, which over-includes but never returns an empty stack.
        /// </summary>
        private List<StackFrame> BuildStack(uint eip, uint esp, uint ebp, int maxFrames)
        {
            return BuildStack(eip, esp, ebp, maxFrames, IntPtr.Zero);
        }

        /// <param name="hThread">the walked thread, for its TEB stack bounds. Without it a foreign top
        /// cannot be chain-walked safely and falls back to the stack scan, as it always did.</param>
        private List<StackFrame> BuildStack(uint eip, uint esp, uint ebp, int maxFrames, IntPtr hThread)
        {
            var m0 = ModuleAt(eip);
            var frames = new List<StackFrame> { FrameAt(m0, eip, 0) };
            frames[0].Ebp = ebp;   // frame 0's locals are read at the current EBP

            // Foreign top frame: a Pause (the thread idles in win32u/user32 under ClaRUN's event loop), a
            // DebugBreak() int3, or any stop inside an OS/runtime call. Walk the EBP chain up through the
            // foreign links until one returns into Clarion code; that link's saved EBP is the Clarion
            // frame's base, so its locals and module data are readable (70b58a1a). A frameless callee
            // (DebugBreak) never pushed EBP, so ctx.Ebp is already the Clarion caller's own: that caller is
            // the return at ESP itself, and it reads its locals at ctx.Ebp. A Clarion return found higher in
            // [ESP, EBP) is ambiguous: it may be a stale slot inside a FRAMED foreign function called directly
            // from Clarion, whose EBP is not the Clarion frame's, so it is shown Uncertain with no EBP.
            // Only when the chain proves nothing (FPO in the runtime, no stack bounds) do we scan, and a
            // scanned frame is Uncertain with no EBP: no locals rather than a guessed frame base.
            bool topIsClarion = m0 != null && m0.Dbg != null;
            if (!topIsClarion)
            {
                uint lo, hi, link, framelessSlot; bool framelessUncertain;
                if (TryStackBounds(hThread, esp, out lo, out hi)
                    && FindForeignTopLink(ebp, lo, hi, ReadStackU32, IsClarionReturnSlot,
                                          out link, out framelessSlot, out framelessUncertain))
                {
                    StackFrame fc;
                    if (framelessSlot != 0 && TryFrameForReturn(ReadU32(framelessSlot), framelessSlot, out fc))
                    {
                        fc.Ebp = framelessUncertain ? 0 : ebp;
                        fc.Uncertain = framelessUncertain;
                        frames.Add(fc);
                    }
                    WalkEbpChain(frames, link, esp, maxFrames);
                    if (frames.Count > 1) return frames;
                }
                ScanStack(frames, esp, maxFrames);
                return frames;
            }

            // Entry-prologue case: if EIP is exactly at the current procedure's entry, its
            // {push ebp; mov ebp,esp} has not run yet — EBP still belongs to the CALLER and the
            // caller's return address sits at [ESP]. Emit that direct caller first; the EBP chain
            // below (which begins at the caller's frame) then covers the rest without duplication.
            if (AtProcEntry(m0, eip))
            {
                StackFrame f0;
                if (TryFrameForReturn(ReadU32(esp), esp, out f0)) { f0.Ebp = ebp; frames.Add(f0); }
            }

            WalkEbpChain(frames, ebp, esp, maxFrames);

            if (frames.Count < 2) ScanStack(frames, esp, maxFrames);
            return frames;
        }

        /// <summary>Follow the EBP chain from <paramref name="cur"/>, adding one frame per link whose return
        /// address is validated Clarion code, and stop at the first link that is not.</summary>
        private void WalkEbpChain(List<StackFrame> frames, uint cur, uint floor, int maxFrames)
        {
            // frame bases sit at/above ESP and strictly increase up the stack
            bool first = true;
            while (frames.Count < maxFrames && cur != 0 && (first ? cur >= floor : cur > floor))
            {
                StackFrame f;
                if (!TryFrameForReturn(ReadU32(cur + 4), cur + 4, out f)) break; // chain end / corrupt
                uint callerEbp = ReadU32(cur);   // caller's saved EBP — that caller frame's base
                f.Ebp = callerEbp;               // so its locals are read at this base
                frames.Add(f);
                floor = cur;
                cur = callerEbp;
                first = false;
            }
        }

        private const int FOREIGN_LINKS_MAX = 256;   // EBP links walked through runtime/OS code before giving up
        private const uint FRAMELESS_SCAN_BYTES = 0x4000;   // how far above ESP to look for a frameless callee's return

        /// <summary>
        /// The EBP-chain walk above a foreign (non-Clarion) top frame. Starting at <paramref name="ebp"/>,
        /// follow saved-EBP links through code that is not Clarion until the return slot of a link
        /// (<c>cur + 4</c>) validates as a return into Clarion code; that link is <paramref name="link"/>, and
        /// the caller walks the ordinary chain from it. Every link must lie inside the live stack
        /// [<paramref name="lo"/>, <paramref name="hi"/>) — lo is ESP, hi the TEB's StackBase — be 4-aligned,
        /// and strictly increase: a link that breaks any of these is FPO code using EBP as a general register
        /// (or garbage), and the walk FAILS rather than guesses. Returns false when no link validates.
        ///
        /// <paramref name="framelessSlot"/> is set only when the first validated link is <paramref name="ebp"/>
        /// ITSELF: then EBP was never pushed below it, so a frameless callee (DebugBreak's int3) sits on top of a
        /// Clarion frame whose base IS <paramref name="ebp"/>, and its return is at ESP (<paramref name="lo"/>).
        /// A FRAMED foreign function called straight from Clarion has the same shape, with perhaps a stale
        /// Clarion return among its locals, so only a return AT lo is taken as the caller. Failing that, the
        /// lowest validated return in [lo, ebp), searched at most FRAMELESS_SCAN_BYTES up, is reported with
        /// <paramref name="framelessUncertain"/> set: an Uncertain frame with no base. In any other shape a
        /// return below the first link lies inside a foreign frame, and is not a caller.
        ///
        /// Static and fed through delegates so `protocolcheck` can drive it over synthetic stacks.
        /// </summary>
        internal static bool FindForeignTopLink(uint ebp, uint lo, uint hi,
                                                Func<uint, uint?> read32, Func<uint, bool> isClarionReturnSlot,
                                                out uint link, out uint framelessSlot, out bool framelessUncertain)
        {
            link = 0; framelessSlot = 0; framelessUncertain = false;
            if (hi < 8) return false;                 // hi - 8 below must not wrap
            uint cur = ebp, prev = 0;                 // prev = 0 also refuses a null EBP on the first link
            for (int n = 0; n < FOREIGN_LINKS_MAX; n++)
            {
                if ((cur & 3) != 0) return false;
                if (cur < lo || cur > hi - 8) return false;
                if (cur <= prev) return false;        // a link that does not climb is not a frame chain
                if (isClarionReturnSlot(cur + 4))
                {
                    link = cur;
                    if (n == 0)
                    {
                        uint first = (lo + 3) & ~3u;
                        uint end = cur - first > FRAMELESS_SCAN_BYTES ? first + FRAMELESS_SCAN_BYTES : cur;
                        for (uint s = first; s < end; s += 4)
                            if (isClarionReturnSlot(s))
                            {
                                framelessSlot = s;
                                framelessUncertain = s != lo;
                                break;
                            }
                    }
                    return true;
                }
                uint? next = read32(cur);
                if (next == null) return false;
                prev = cur;
                cur = next.Value;
            }
            return false;
        }

        /// <summary>The walked thread's stack as [lo, hi): the TEB's StackLimit (+8) and StackBase (+4), with
        /// lo raised to ESP. False without a thread handle or a readable TEB — the caller then scans.</summary>
        private bool TryStackBounds(IntPtr hThread, uint esp, out uint lo, out uint hi)
        {
            lo = 0; hi = 0;
            if (hThread == IntPtr.Zero) return false;
            uint teb = GetTebBase(hThread);
            if (teb == 0) return false;
            hi = ReadU32(teb + 4);
            lo = ReadU32(teb + 8);
            if (hi == 0 || lo >= hi || esp < lo || esp >= hi) return false;
            lo = esp;
            return true;
        }

        private uint? ReadStackU32(uint va)
        {
            var b = new byte[4];
            return ReadBlock(va, b) == 4 ? BitConverter.ToUInt32(b, 0) : (uint?)null;
        }

        private bool IsClarionReturnSlot(uint slot)
        {
            StackFrame f;
            uint? ret = ReadStackU32(slot);
            return ret != null && TryFrameForReturn(ret.Value, slot, out f);
        }

        /// <summary>The first frame whose locals can be read: a resolved procedure with a known frame base.
        /// Frame 0 after an ordinary stop; after a Pause, the Clarion frame under the runtime's event loop.
        /// Null when the stack has none (a scanned stack, or no context). Module data and local watches key
        /// on it, so after a Pause they describe the Clarion code, not the OS call it idles in.</summary>
        private StackFrame FirstClarionFrame(ref Native.CONTEXT_X86 ctx, IntPtr hThread)
        {
            var frames = FramesForStop(ref ctx, hThread);
            int i = FirstClarionFrameIndex(frames);
            return i < 0 ? null : frames[i];
        }

        /// <summary>Where <see cref="FirstClarionFrame"/> sits in <paramref name="frames"/>; -1 when none can
        /// read locals.</summary>
        internal static int FirstClarionFrameIndex(IList<StackFrame> frames)
        {
            for (int i = 0; i < frames.Count; i++)
                if (CanReadLocals(frames[i])) return i;
            return -1;
        }

        /// <summary>Can this frame's locals be read? It needs a procedure (a local set to look in) and a frame
        /// base (somewhere to read one); a scanned, Uncertain frame has no base.</summary>
        internal static bool CanReadLocals(StackFrame f)
        {
            return f.Proc != null && f.Ebp != 0;
        }

        // One stack walk per stop and register set, shared by every watch, module-data and local read at that
        // stop: a walk per watch per stop is dozens of reads each, times every watch the host re-sends. Cleared
        // on EVERY stop (PausedWait), which covers each resume. Keyed on EIP/ESP/EBP as well, so a setip or a
        // thread switch inside one stop re-walks rather than reads another register set's frames.
        private List<StackFrame> _stopFrames;
        private uint _stopFramesEip, _stopFramesEsp, _stopFramesEbp;

        private void ClearFrameCache() { _stopFrames = null; }

        /// <summary>The walked frames for these registers at this stop (see <see cref="_stopFrames"/>).</summary>
        private List<StackFrame> FramesForStop(ref Native.CONTEXT_X86 ctx, IntPtr hThread)
        {
            if (_stopFrames == null || _stopFramesEip != ctx.Eip || _stopFramesEsp != ctx.Esp || _stopFramesEbp != ctx.Ebp)
            {
                _stopFrames = BuildStack(ctx.Eip, ctx.Esp, ctx.Ebp, STACK_FRAMES_MAX, hThread);
                _stopFramesEip = ctx.Eip; _stopFramesEsp = ctx.Esp; _stopFramesEbp = ctx.Ebp;
            }
            return _stopFrames;
        }

        /// <summary>Test seams for `protocolcheck`: the per-stop frame cache through the REAL FramesForStop and
        /// ClearFrameCache. With no target every walk is frame 0 alone, which is enough: the check asserts
        /// WHICH list instance comes back, not what is in it. Changes nothing but the cache itself.</summary>
        internal List<StackFrame> FramesForStopForTest(uint eip, uint esp, uint ebp)
        {
            var c = NewContext();
            c.Eip = eip; c.Esp = esp; c.Ebp = ebp;
            return FramesForStop(ref c, IntPtr.Zero);
        }

        internal void ClearFrameCacheForTest() { ClearFrameCache(); }

        /// <summary>True when <paramref name="va"/> is exactly the entry of its containing procedure
        /// (prologue not yet run, so the frame's EBP is still the caller's).</summary>
        private bool AtProcEntry(LoadedModule m, uint va)
        {
            if (m == null || m.Dbg == null) return false;
            ProcSymbol sym;
            uint rva = va - m.LoadBase;
            return m.Dbg.ResolveSymbol(rva, out sym) && rva == sym.EntryRva;
        }

        /// <summary>Validate a candidate return address (mapped Clarion code within FRAME_GAP_MAX,
        /// preceded by a CALL) and build its frame. False when it isn't a real return address.</summary>
        private bool TryFrameForReturn(uint ret, uint stackAddr, out StackFrame frame)
        {
            frame = null;
            var rm = ModuleAt(ret);
            if (rm == null || rm.Dbg == null) return false;     // left debuggable code
            uint rrva = ret - rm.LoadBase;
            int line; int mi; uint recRva;
            if (!rm.Dbg.ResolveAddr(rrva, out line, out mi, out recRva)) return false;
            if (rrva - recRva > FRAME_GAP_MAX) return false;    // not Clarion-mapped code
            if (!CallPrecedes(ret)) return false;              // not a return address
            frame = FrameAt(rm, ret, stackAddr);
            return true;
        }

        /// <summary>Fallback stack reconstruction: scan upward from ESP for dwords that resolve into
        /// TSWD-mapped code (a +0x1C record within FRAME_GAP_MAX) preceded by a CALL. Over-includes
        /// stale frames from dead stack regions — used only when the EBP chain yields nothing.</summary>
        private void ScanStack(List<StackFrame> frames, uint esp, int maxFrames)
        {
            var stack = new byte[STACK_SCAN_BYTES];
            int got = ReadBlock(esp, stack);
            for (int off = 0; off + 4 <= got && frames.Count < maxFrames; off += 4)
            {
                uint cand = BitConverter.ToUInt32(stack, off);
                var cm = ModuleAt(cand);
                if (cm == null || cm.Dbg == null) continue;     // not in any debuggable image
                uint rva = cand - cm.LoadBase;

                int line; int mi; uint recRva;
                if (!cm.Dbg.ResolveAddr(rva, out line, out mi, out recRva)) continue;
                if (rva - recRva > FRAME_GAP_MAX) continue;     // not Clarion-mapped code
                if (!CallPrecedes(cand)) continue;              // not a return address

                var f = FrameAt(cm, cand, esp + (uint)off);
                f.Uncertain = true;   // a plausible-looking dword, not a chain-verified caller
                frames.Add(f);
            }
        }

        private StackFrame FrameAt(LoadedModule m, uint va, uint stackAddr)
        {
            uint rva = m != null ? va - m.LoadBase : va;
            int line = 0, mi = -1; uint recRva = 0;
            bool resolved = m != null && m.Dbg != null && m.Dbg.ResolveAddr(rva, out line, out mi, out recRva);
            ProcSymbol sym = null;
            // ResolveSymbolVerified (not the plain binary search): cold/init "glue" code with no symbol
            // of its own (e.g. a PROGRAM's compiler-generated global-object Construct() calls ahead of
            // its own CODE) would otherwise mislabel the frame with an unrelated PRECEDING symbol from a
            // different compiland — confirmed live (ML_ScanArc.exe line 99, _main's first statement,
            // resolved to ML_ProcessClass.Construct). Verified against the +0x1C line table instead of
            // the unreliable +0x28 backref moduleIdx (see TswdDebugInfo.ResolveSymbolVerified).
            bool hasSym = m != null && m.Dbg != null && m.Dbg.ResolveSymbolVerified(rva, out sym);
            return new StackFrame
            {
                Rva = rva,
                Va = va,
                StackAddr = stackAddr,
                Proc = hasSym ? sym.Name : null,
                Kind = hasSym ? sym.Kind.ToString().ToLowerInvariant() : null,
                Module = resolved ? m.Dbg.ModuleNameForIdx(mi) : null,
                Line = resolved ? line : 0
            };
        }

        /// <summary>
        /// Do the bytes immediately before a candidate return address form a CALL instruction?
        /// Checks the x86 encodings by length: E8 rel32 (5), FF /2 reg-or-[reg] (2), FF /2 disp8 or
        /// SIB (3), FF /2 disp32 or [mem] (6), FF /2 SIB+disp32 (7), 9A far (7). No decoder needed —
        /// combined with the TSWD-resolvability gate this filters nearly all stale stack noise.
        /// </summary>
        private bool CallPrecedes(uint va)
        {
            if (va < 8) return false;
            var b = new byte[8];                      // b[i] = byte at va-8+i, so byte at va-k is b[8-k]
            int read;
            if (!Native.ReadProcessMemory(_hProcess, Ptr(va - 8), b, 8, out read) || read != 8)
                return false;
            if (b[3] == 0xE8) return true;                                  // call rel32
            if (b[6] == 0xFF && (b[7] & 0x38) == 0x10) return true;         // call reg / [reg]
            if (b[5] == 0xFF && ((b[6] & 0xF8) == 0x50 || b[6] == 0x14)) return true;  // disp8 / SIB
            if (b[2] == 0xFF && ((b[3] & 0xF8) == 0x90 || b[3] == 0x15)) return true;  // disp32 / [mem]
            if (b[1] == 0xFF && b[2] == 0x94) return true;                  // SIB + disp32
            if (b[1] == 0x9A) return true;                                  // far call ptr16:32
            return false;
        }

        /// <summary>Read up to buf.Length bytes at va, page-by-page so a guard page or the stack top
        /// truncates the read instead of failing it entirely. Returns bytes actually read.</summary>
        private int ReadBlock(uint va, byte[] buf)
        {
            int total = 0;
            while (total < buf.Length)
            {
                int chunk = Math.Min(0x1000 - (int)((va + (uint)total) & 0xFFF), buf.Length - total);
                var page = new byte[chunk];
                int read;
                if (!Native.ReadProcessMemory(_hProcess, Ptr(va + (uint)total), page, chunk, out read) || read <= 0)
                    break;
                Array.Copy(page, 0, buf, total, read);
                total += read;
                if (read < chunk) break;
            }
            return total;
        }
    }
}
