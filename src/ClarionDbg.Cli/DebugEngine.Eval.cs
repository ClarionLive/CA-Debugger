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
        // ------------------------------------------------------------------ watch (by name)

        /// <summary>
        /// watch NAME — resolve a data name and read its CURRENT value on the paused thread.
        /// Non-threaded data reads directly at template VA (returns false: stay paused).
        /// THREADed (.cwtls) data launches the THR$GetInstance func-eval (returns true: the
        /// caller must leave the pause loop so the target can run the call).
        /// </summary>
        private bool HandleWatchCommand(string[] parts, uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            if (parts.Length < 2) { EmitError("watch expects: watch NAME"); return false; }
            string name = parts[1];

            // A procedure-local shadows a same-named global while we are paused inside its frame, so resolve the
            // CURRENT frame's locals FIRST. Locals live on the stack (never .cwtls), so this is a direct read —
            // no THR$GetInstance func-eval — hence we always return false (stay paused).
            uint slotVa; LocalSym lsym; LoadedModule lowner;
            if (TryResolveLocalInCurrentFrame(ref ctx, haveCtx, name, out slotVa, out lsym, out lowner))
            {
                EmitWatchValue(name, slotVa, slotVa, false, lsym.TypeCode, lsym.Size, lsym.Target, lsym.Places);
                return false;
            }

            TswdDebugInfo.DataLocation loc; LoadedModule owner;
            if (!ResolveDataAcrossModules(name, out owner, out loc))
            {
                // Not a current-frame local and not a global. If it IS a local of some other procedure, it is
                // merely out of scope right now (we are paused elsewhere) — flag that so the Watch row reads
                // "(out of scope)" rather than the misleading "(not found)" used for genuinely unknown names.
                bool outOfScope = haveCtx && IsKnownLocalName(name);
                if (EmitJson) Console.WriteLine("@JSON " + Json.WatchMiss(name, outOfScope));
                Console.WriteLine($"  watch {name}: {(outOfScope ? "out of scope" : "not found")}");
                return false;
            }
            uint templateVa = owner.LoadBase + loc.Rva;
            bool threaded = loc.Rva >= owner.CwtlsLo && loc.Rva < owner.CwtlsHi && owner.CwtlsHi != 0;

            if (!threaded)
            {
                EmitWatchValue(name, templateVa, templateVa, false, loc.TypeCode, loc.Size);
                return false;
            }

            if (owner.ThrGetInstanceIatRva == 0)
            {
                EmitError($"watch {name}: THREADed data but THR$GetInstance import not found in {owner.Name}");
                return false;
            }
            if (!haveCtx)
            {
                EmitError($"watch {name}: no thread context for func-eval");
                return false;
            }
            uint helper = ReadU32(owner.LoadBase + owner.ThrGetInstanceIatRva);
            if (helper == 0)
            {
                EmitError($"watch {name}: could not read THR$GetInstance address from the IAT");
                return false;
            }

            // stash what the completion handler needs to finish the read
            _evalName = name; _evalSize = loc.Size; _evalTypeCode = loc.TypeCode;
            _evalTypeName = TswdDebugInfo.TypeCodeName(loc.TypeCode);
            _evalTemplateVa = templateVa;

            // save the real context (deep copy — the struct holds array references)
            _evalSavedCtx = CloneContext(ref ctx);

            // suspend any pending breakpoint re-plant for this thread: the BP byte is currently
            // the ORIGINAL instruction, and the eval resume must not consume the re-arm step
            _evalHadRearm = _rearm.TryGetValue(tid, out _evalSavedRearm);
            if (_evalHadRearm) _rearm.Remove(tid);

            // hijack: EAX = template VA, EBX = .cwtls base, return lands on the magic trap
            var e = CloneContext(ref ctx);
            e.Esp = ctx.Esp - 4;
            WriteU32(e.Esp, EVAL_TRAP_VA);
            e.Eax = templateVa;
            e.Ebx = owner.LoadBase + owner.CwtlsLo;
            e.Eip = helper;
            e.EFlags &= ~TRAP_FLAG;
            Native.SetThreadContext(hThread, ref e);

            _evalActive = true;
            _evalTid = tid;
            return true;   // leave PausedWait; the debug loop continues the event and the call runs
        }

        /// <summary>The func-eval returned (AV at the magic address): collect EAX = instance VA,
        /// restore the saved thread state, emit the watch value, and re-enter the pause loop.</summary>
        private uint OnEvalComplete(uint tid)
        {
            _evalActive = false;
            IntPtr hThread = OpenThreadForContext(tid);
            var c = NewContext();
            bool haveCtx = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref c);
            uint instanceVa = haveCtx ? c.Eax : 0;

            // restore the genuine pause state (EIP/ESP/regs exactly as before the eval)
            if (hThread != IntPtr.Zero) Native.SetThreadContext(hThread, ref _evalSavedCtx);
            if (_evalHadRearm) { _rearm[tid] = _evalSavedRearm; _evalHadRearm = false; }

            if (instanceVa != 0)
                EmitWatchValue(_evalName, _evalTemplateVa, instanceVa, true, _evalTypeCode, _evalSize);
            else
                EmitError($"watch {_evalName}: THR$GetInstance eval failed");

            // we are logically still paused at the original location — resume the command loop without
            // re-announcing a `paused` (the watch result already went out; a re-announce is spurious).
            PausedWait(tid, hThread, ref _evalSavedCtx, true, "watch", emitPaused: false);
            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return Native.DBG_CONTINUE;
        }

        /// <summary>Read and report a watch value (instanceVa = templateVa for non-threaded data). <paramref
        /// name="target"/>/<paramref name="places"/> carry a frame local's referent-type and DECIMAL scale so
        /// &amp;STRING locals deref correctly and DECIMAL locals render/edit at the right scale; both default to 0
        /// for global/static data (whose DataLocation does not carry them) — unchanged from before.</summary>
        private void EmitWatchValue(string name, uint templateVa, uint instanceVa, bool threaded, byte typeCode, uint size, byte target = 0, int places = 0)
        {
            int len = (int)Math.Min(Math.Max(size, 1), 4096);
            var buf = new byte[len];
            int read;
            Native.ReadProcessMemory(_hProcess, (IntPtr)instanceVa, buf, len, out read);
            if (read < 0) read = 0;
            // unified rendering: same engine-side type label + value formatter the Locals panel uses
            string tn = ClarionTypeLabel(typeCode, target, size, places);
            string value = FormatValueAt(typeCode, target, size, places, instanceVa);
            if (EmitJson)
                Console.WriteLine("@JSON " + Json.Watch(name, true, templateVa, instanceVa, threaded, typeCode, tn, size, places, value, buf, read, IsEditableCode(typeCode)));
            Console.WriteLine($"  watch {name}: {(tn ?? $"type 0x{typeCode:X2}")} size {size} at 0x{instanceVa:X}{(threaded ? $" (threaded; template 0x{templateVa:X})" : "")}");
            for (int row = 0; row < read; row += 16)
            {
                int n = Math.Min(16, read - row);
                var hex = new System.Text.StringBuilder(48);
                var asc = new System.Text.StringBuilder(16);
                for (int i = 0; i < n; i++)
                {
                    byte v = buf[row + i];
                    hex.Append(v.ToString("X2")).Append(' ');
                    asc.Append(v >= 0x20 && v < 0x7F ? (char)v : '.');
                }
                Console.WriteLine($"    0x{instanceVa + (uint)row:X8}: {hex.ToString().PadRight(48)} {asc}");
            }
        }
    }
}
