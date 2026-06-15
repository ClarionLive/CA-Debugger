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

        /// <summary>stack [maxFrames] — resolved call stack while paused (frame 0 = current EIP).</summary>
        private void HandleStackCommand(string[] parts, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            if (!haveCtx) { EmitError("stack: no thread context"); return; }
            int max = STACK_FRAMES_DEFAULT;
            if (parts.Length > 1 && (!int.TryParse(parts[1], out max) || max < 1 || max > STACK_FRAMES_MAX))
            {
                EmitError($"stack: max frames must be 1..{STACK_FRAMES_MAX}");
                return;
            }
            var frames = BuildStack(ctx.Eip, ctx.Esp, ctx.Ebp, max);
            if (EmitJson) Console.WriteLine("@JSON " + Json.Stack(frames));
            Console.WriteLine($"  stack ({frames.Count} frame(s)):");
            for (int i = 0; i < frames.Count; i++)
            {
                var f = frames[i];
                string name = f.Proc ?? "(unknown)";
                string loc = f.Module != null ? $"  {f.Module}:{f.Line}" : "";
                Console.WriteLine($"    #{i,-2} {name}{loc}  RVA 0x{f.Rva:X}{(f.Kind != null ? "  [" + f.Kind + "]" : "")}");
            }
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
            var m0 = ModuleAt(eip);
            var frames = new List<StackFrame> { FrameAt(m0, eip, 0) };
            frames[0].Ebp = ebp;   // frame 0's locals are read at the current EBP

            // External / frameless top frame — a DebugBreak() int3 (which executes in ntdll), or a
            // thread paused inside an OS call. EBP here still belongs to the Clarion CALLER (the
            // frameless callee never pushed its own EBP), so the EBP walk below would read [ebp+4] =
            // the caller's return and jump a level too far, dropping the frame the user actually cares
            // about (the line that called DebugBreak / the line we paused at). Reconstruct the Clarion
            // frames by scanning the stack instead, which recovers that immediate caller.
            bool topIsClarion = m0 != null && m0.Dbg != null;
            if (!topIsClarion)
            {
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

            uint cur = ebp;
            uint floor = esp;        // frame bases sit at/above ESP and strictly increase up the stack
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

            if (frames.Count < 2) ScanStack(frames, esp, maxFrames);
            return frames;
        }

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

                frames.Add(FrameAt(cm, cand, esp + (uint)off));
            }
        }

        private StackFrame FrameAt(LoadedModule m, uint va, uint stackAddr)
        {
            uint rva = m != null ? va - m.LoadBase : va;
            int line = 0, mi = -1; uint recRva = 0;
            bool resolved = m != null && m.Dbg != null && m.Dbg.ResolveAddr(rva, out line, out mi, out recRva);
            ProcSymbol sym = null;
            bool hasSym = m != null && m.Dbg != null && m.Dbg.ResolveSymbol(rva, out sym);
            // same moduleIdx cross-check as ProcNameAt: don't name cold/init code with the
            // previous module's last symbol
            bool symOk = hasSym && (!resolved || sym.ModuleIdx == mi);
            return new StackFrame
            {
                Rva = rva,
                Va = va,
                StackAddr = stackAddr,
                Proc = symOk ? sym.Name : null,
                Kind = symOk ? sym.Kind.ToString().ToLowerInvariant() : null,
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
            if (!Native.ReadProcessMemory(_hProcess, (IntPtr)(va - 8), b, 8, out read) || read != 8)
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
                if (!Native.ReadProcessMemory(_hProcess, (IntPtr)(va + (uint)total), page, chunk, out read) || read <= 0)
                    break;
                Array.Copy(page, 0, buf, total, read);
                total += read;
                if (read < chunk) break;
            }
            return total;
        }
    }
}
