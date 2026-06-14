using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------------ disassembly view (Iced)

        /// <summary>Read process memory like <see cref="ReadBlock"/>, then restore the original bytes
        /// wherever we've planted an INT3 (user breakpoints + call-skip temps). Without this the
        /// disassembler decodes our 0xCC patches and mis-aligns the whole listing from that point.</summary>
        private int ReadCleanBlock(uint addr, byte[] buf)
        {
            int got = ReadBlock(addr, buf);
            if (got <= 0) return got;
            foreach (var kv in _armed) { uint va = kv.Key; if (va >= addr && va - addr < (uint)got) buf[va - addr] = kv.Value; }
            foreach (var kv in _temp)  { uint va = kv.Key; if (va >= addr && va - addr < (uint)got) buf[va - addr] = kv.Value; }
            return got;
        }

        /// <summary>Find the VA at which to start a window so it contains <paramref name="before"/>
        /// instructions immediately preceding <paramref name="addr"/>. x86 can't be decoded backwards, so
        /// probe successive start offsets until a forward decode lands exactly on addr (re-sync), then take
        /// the last `before` instruction boundaries before it. Returns 0 (with got=0) if no alignment is
        /// found. <paramref name="got"/> = how many instructions the returned start actually yields.</summary>
        private uint ResyncStart(uint addr, int before, out int got)
        {
            got = 0;
            int span = before * 15 + 16;
            if (span > addr) span = (int)addr;            // don't underflow the address space
            var buf = new byte[span + 16];
            for (int off = 0; off < 16; off++)
            {
                uint start = addr - (uint)span + (uint)off;
                int read = ReadCleanBlock(start, buf);
                if (read <= 0) continue;
                var reader = new Iced.Intel.ByteArrayCodeReader(buf, 0, read);
                var dec = Iced.Intel.Decoder.Create(32, reader);
                dec.IP = start;
                var ips = new List<uint>();
                bool aligned = false;
                while (reader.CanReadByte)
                {
                    Iced.Intel.Instruction ins;
                    dec.Decode(out ins);
                    if (ins.IsInvalid) break;
                    uint ip = (uint)ins.IP;
                    if (ip == addr) { aligned = true; break; }
                    if (ip > addr) break;                 // skipped past addr → misaligned, try next offset
                    ips.Add(ip);
                }
                if (aligned && ips.Count > 0)
                {
                    int take = Math.Min(before, ips.Count);
                    got = take;
                    return ips[ips.Count - take];
                }
            }
            return 0;
        }

        /// <summary>
        /// EXPERIMENT (disassembly view): disasm [0xADDR] [count] — decode x86 at an address
        /// (default: current EIP) via Iced and emit a listing. Each instruction carries its VA,
        /// raw bytes, text, whether it is the current EIP, and any module:line it maps to (for a
        /// mixed source/asm view). Especially useful when paused in external / no-source code
        /// (a DebugBreak int3, or an OS call) where the source pane is blank.
        /// </summary>
        private void HandleDisasmCommand(string[] parts, ref Native.CONTEXT_X86 ctx, bool haveCtx)
        {
            uint addr = haveCtx ? ctx.Eip : 0;
            int count = 16;
            if (parts.Length > 1 && parts[1].Length > 0)
            {
                string a = parts[1].Trim();
                try { addr = a.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? Convert.ToUInt32(a.Substring(2), 16) : Convert.ToUInt32(a); }
                catch { EmitError("disasm: bad address '" + a + "'"); return; }
            }
            if (parts.Length > 2 && (!int.TryParse(parts[2], out count) || count < 1 || count > 200)) count = 16;
            string tag = parts.Length > 3 ? parts[3] : "";   // caller's correlation tag, echoed back in the event
            if (addr == 0) { EmitError("disasm: no address"); return; }

            // Optional 5th arg: include this many instructions BEFORE addr (for scrolling the disassembly
            // view upward). x86 has no backward decode, so re-sync: find a start whose forward decode lands
            // exactly on addr, then anchor the window there. count grows to cover the extra instructions.
            int before = 0;
            if (parts.Length > 4 && int.TryParse(parts[4], out before) && before > 0)
            {
                int gotBefore;
                uint ws = ResyncStart(addr, Math.Min(before, 100), out gotBefore);
                if (ws != 0 && gotBefore > 0) { addr = ws; count += gotBefore; }
            }

            // read enough for `count` instructions (x86 max 15 bytes each), page-safe; mask our INT3 patches
            var buf = new byte[count * 15 + 16];
            int got = ReadCleanBlock(addr, buf);
            if (got <= 0) { EmitError($"disasm: read failed at 0x{addr:X}"); return; }

            var reader = new Iced.Intel.ByteArrayCodeReader(buf, 0, got);
            var decoder = Iced.Intel.Decoder.Create(32, reader);
            decoder.IP = addr;
            var formatter = new Iced.Intel.NasmFormatter();
            var output = new Iced.Intel.StringOutput();
            uint eip = haveCtx ? ctx.Eip : 0;

            var jsonRows = new List<string>();
            var textRows = new List<string>();
            int decoded = 0;
            while (reader.CanReadByte && decoded < count)
            {
                Iced.Intel.Instruction instr;
                decoder.Decode(out instr);
                if (instr.IsInvalid) break;
                uint ip = (uint)instr.IP;
                int ilen = instr.Length;
                formatter.Format(instr, output);
                string text = output.ToStringAndReset();

                var hex = new System.Text.StringBuilder(ilen * 2);
                int baseOff = (int)(ip - addr);
                for (int i = 0; i < ilen && baseOff + i < got; i++) hex.Append(buf[baseOff + i].ToString("X2"));

                bool cur = ip == eip;
                var m = ModuleAt(ip);
                int line = 0, mi = -1; uint rec;
                bool resolved = m != null && m.Dbg != null && m.Dbg.ResolveAddr(ip - m.LoadBase, out line, out mi, out rec);
                string mod = resolved ? m.Dbg.ModuleNameForIdx(mi) : null;

                string target = ResolveCallTargetName(ref instr);   // SPIKE: name what a `call` invokes
                // For code with no source line (runtime/RTL), name the containing function so the view can
                // show a header (e.g. "clarun.dll!Cla$PushLong") the way it interleaves .clw source lines.
                string func = resolved ? null : (NearestImportName(ip) ?? NameForCodeVa(ip, 0));

                jsonRows.Add("{\"va\":\"0x" + ip.ToString("X") + "\",\"len\":" + ilen
                    + ",\"bytes\":\"" + hex + "\",\"text\":" + Json.Str(text)
                    + ",\"current\":" + (cur ? "true" : "false")
                    + (target != null ? ",\"target\":" + Json.Str(target) : "")
                    + (func != null ? ",\"func\":" + Json.Str(func) : "")
                    + ",\"module\":" + Json.Str(mod) + ",\"line\":" + line + "}");
                textRows.Add($"  {(cur ? "=>" : "  ")} 0x{ip:X8}  {hex.ToString().PadRight(20)} {text}");
                decoded++;
            }

            if (EmitJson)
                Console.WriteLine("@JSON {\"event\":\"disasm\",\"addr\":\"0x" + addr.ToString("X") + "\",\"tag\":" + Json.Str(tag) + ",\"instrs\":[" + string.Join(",", jsonRows) + "]}");
            else
            {
                Console.WriteLine($"  disasm at 0x{addr:X} ({decoded} instr):");
                foreach (var l in textRows) Console.WriteLine(l);
            }
        }

        // ------------------------------------------------------------------ call-target naming

        /// <summary>SPIKE: name what a `call` instruction invokes, for the disassembly view. Two cases:
        /// a direct near call (target encoded in the instruction → TSWD symbol), or an indirect call
        /// through an absolute memory slot (`call dword [imm]`) — the slot is usually an IAT entry, so we
        /// name it from the owning image's import table (this is how Clarion reaches runtime routines like
        /// CLIP/FORMAT). Falls back to following the live pointer and resolving via TSWD. null when unknown
        /// (register-indirect calls, no-symbol targets).</summary>
        private string ResolveCallTargetName(ref Iced.Intel.Instruction instr)
        {
            try
            {
                var fc = instr.FlowControl;
                if (fc != Iced.Intel.FlowControl.Call && fc != Iced.Intel.FlowControl.IndirectCall) return null;

                if (instr.Op0Kind == Iced.Intel.OpKind.NearBranch32 || instr.Op0Kind == Iced.Intel.OpKind.NearBranch16)
                    return NameForCodeVa((uint)instr.NearBranch32, 2);

                if (instr.Op0Kind == Iced.Intel.OpKind.Memory
                    && instr.MemoryBase == Iced.Intel.Register.None
                    && instr.MemoryIndex == Iced.Intel.Register.None)
                    return NameForSlot((uint)instr.MemoryDisplacement64, 2);
            }
            catch { }
            return null;
        }

        /// <summary>SPIKE helper: TSWD symbol name for a code VA, qualified with the image name when it
        /// isn't the EXE (so cross-module calls read e.g. "schooldata.dll!SomeProc"). When there is no
        /// symbol and <paramref name="depth"/> allows, follow a one-instruction import/branch thunk
        /// (`jmp dword [slot]` or `jmp abs`) so calls reaching the runtime via a stub still name out.
        /// null if nothing resolves.</summary>
        private string NameForCodeVa(uint va, int depth)
        {
            var m = ModuleAt(va);
            if (m != null && m.Dbg != null)
            {
                uint rva = va - m.LoadBase;
                ProcSymbol sym;
                // Bound the distance: a sparse symbol table (e.g. the debug clarun.dll) would otherwise
                // collapse a large unsymbolised region onto whatever named symbol precedes it, so distant
                // addresses all mis-resolve to the same name. Beyond a plausible function span, treat as
                // unnamed rather than mislabel it.
                if (m.Dbg.ResolveSymbol(rva, out sym) && rva - sym.EntryRva <= 0x4000)
                    return (m != _exe && !string.IsNullOrEmpty(m.Name)) ? m.Name + "!" + sym.Name : sym.Name;
            }
            return depth > 0 ? FollowThunk(va, depth - 1) : null;
        }

        /// <summary>SPIKE helper: name an absolute memory slot targeted by an indirect call/jmp — an IAT
        /// name from the owning image's import table, else the live pointer it holds (resolved as code).</summary>
        private string NameForSlot(uint slotVa, int depth)
        {
            var ms = ModuleAt(slotVa);
            if (ms != null && ms.Pe != null)
            {
                string nm;
                if (ms.Pe.BuildIatNameMap().TryGetValue(slotVa - ms.LoadBase, out nm)) return nm;
            }
            uint funcVa = ReadU32(slotVa);              // pre-bound / already-resolved IAT: follow the pointer
            return funcVa != 0 ? NameForCodeVa(funcVa, depth) : null;
        }

        /// <summary>SPIKE helper: decode the single instruction at <paramref name="va"/>; if it's an import
        /// or branch thunk (`jmp dword [slot]` / `jmp abs`), resolve what it forwards to. Clarion reaches
        /// many runtime routines through these stubs, so following one hop names the otherwise-bare
        /// `call 0076xxxx` lines.</summary>
        private string FollowThunk(uint va, int depth)
        {
            try
            {
                var buf = new byte[16];
                int got = ReadBlock(va, buf);
                if (got < 2) return null;
                var reader = new Iced.Intel.ByteArrayCodeReader(buf, 0, got);
                var dec = Iced.Intel.Decoder.Create(32, reader);
                dec.IP = va;
                Iced.Intel.Instruction ins;
                dec.Decode(out ins);
                if (ins.IsInvalid) return null;
                if (ins.FlowControl == Iced.Intel.FlowControl.IndirectBranch
                    && ins.Op0Kind == Iced.Intel.OpKind.Memory
                    && ins.MemoryBase == Iced.Intel.Register.None
                    && ins.MemoryIndex == Iced.Intel.Register.None)
                    return NameForSlot((uint)ins.MemoryDisplacement64, depth);
                if (ins.FlowControl == Iced.Intel.FlowControl.UnconditionalBranch
                    && (ins.Op0Kind == Iced.Intel.OpKind.NearBranch32 || ins.Op0Kind == Iced.Intel.OpKind.NearBranch16))
                    return NameForCodeVa((uint)ins.NearBranch32, depth);
            }
            catch { }
            return null;
        }

        // SPIKE: a sparse symbol table for non-TSWD images (the Clarion runtime), built from the live
        // IAT — each import slot holds the resolved entry VA of a named runtime function. Lets us answer
        // "where am I" while stepping through ClaRUN.dll, which carries no TSWD of its own. Sorted by VA;
        // invalidated on module load/unload (see _modules churn). null until first built.
        private List<KeyValuePair<uint, string>> _liveSyms;

        private void BuildLiveImportSymbols()
        {
            var list = new List<KeyValuePair<uint, string>>();
            foreach (var m in _modules)
            {
                if (m == null || m.Pe == null || m.LoadBase == 0) continue;
                foreach (var kv in m.Pe.BuildIatNameMap())
                {
                    uint target = ReadU32(m.LoadBase + kv.Key);   // live entry VA the IAT slot points at
                    if (target != 0) list.Add(new KeyValuePair<uint, string>(target, kv.Value));
                }
            }
            list.Sort((a, b) => a.Key.CompareTo(b.Key));
            _liveSyms = list;
        }

        /// <summary>SPIKE: nearest named import entry at or below <paramref name="va"/> within the same
        /// (non-TSWD) image — e.g. "ClaRUN.dll!Cla$PushLong+0x7" — so a step into the runtime still tells
        /// the user where they are. null for TSWD images (use real symbols). Falls back to image+RVA when
        /// the nearest import is implausibly far (likely an internal, un-imported routine).</summary>
        private string NearestImportSymbol(uint va)
        {
            var m = ModuleAt(va);
            if (m == null || m.Dbg != null) return null;     // TSWD images resolve through ResolveAddr/ProcNameAt
            if (_liveSyms == null) BuildLiveImportSymbols();
            string fallback = m.Name + "+0x" + (va - m.LoadBase).ToString("X");
            if (_liveSyms.Count == 0) return fallback;
            int lo = 0, hi = _liveSyms.Count - 1, ans = -1;
            while (lo <= hi) { int mid = (lo + hi) / 2; if (_liveSyms[mid].Key <= va) { ans = mid; lo = mid + 1; } else hi = mid - 1; }
            if (ans >= 0 && ModuleAt(_liveSyms[ans].Key) == m)
            {
                uint off = va - _liveSyms[ans].Key;
                if (off <= 0x4000) return off == 0 ? _liveSyms[ans].Value : _liveSyms[ans].Value + "+0x" + off.ToString("X");
            }
            return fallback;
        }

        /// <summary>Name of the imported function whose live entry is nearest at-or-below <paramref name="va"/>
        /// (no offset), for labelling the containing function in the disassembly view. Unlike
        /// <see cref="NearestImportSymbol"/> this DOES look inside TSWD images (e.g. clarun.dll), because the
        /// IAT import names (Cla$PushLong) are more meaningful than the runtime's coarse internal symbols.
        /// null when nothing is close enough.</summary>
        private string NearestImportName(uint va)
        {
            var m = ModuleAt(va);
            if (m == null) return null;
            if (_liveSyms == null) BuildLiveImportSymbols();
            if (_liveSyms.Count == 0) return null;
            int lo = 0, hi = _liveSyms.Count - 1, ans = -1;
            while (lo <= hi) { int mid = (lo + hi) / 2; if (_liveSyms[mid].Key <= va) { ans = mid; lo = mid + 1; } else hi = mid - 1; }
            if (ans >= 0 && ModuleAt(_liveSyms[ans].Key) == m && va - _liveSyms[ans].Key <= 0x4000)
                return _liveSyms[ans].Value;
            return null;
        }
    }
}
