using System.Collections.Generic;
using System.Text;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    /// <summary>Tiny hand-rolled JSON for the engine's machine-readable event output.
    /// <para>
    /// NOT HERE: the thread-id writers (TidIsKnown, AppendTidMember, AppendTidValuedMember, WithTid). They
    /// live in DebugEngine.cs, in the block headed "THE RULE, stated once", and were left there on purpose
    /// (f367a04f item 3, 2026-09-22) rather than moved beside Str/BpSet/BpDel: the thread emitters in
    /// DebugEngine.Threads.cs and DebugEngine.ThreadScan.cs call them unqualified as DebugEngine members,
    /// and tools/test-engine-tid-members.ps1 and tools/test-addin-json.ps1 read the rule out of
    /// DebugEngine.cs's source by file name. Look there before adding a tid writer here.
    /// </para></summary>
    internal static class Json
    {
        public static string Str(string s)
        {
            if (s == null) return "null";
            // Escape control chars too: events are framed one-per-line on stdout, so a raw \n in a
            // debuggee-controlled string (e.g. a hostile TSWD module name) could otherwise forge a
            // second @JSON event line in the host addin.
            var sb = new System.Text.StringBuilder(s.Length + 2);
            sb.Append('"');
            foreach (char c in s)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        public static string Hit(string module, string proc, int line, uint rva, uint va, uint gap, bool resolved)
        {
            return "{\"event\":\"hit\""
                 + ",\"resolved\":" + (resolved ? "true" : "false")
                 + ",\"module\":" + Str(module)
                 + ",\"proc\":" + Str(proc)
                 + ",\"line\":" + line
                 + ",\"rva\":\"0x" + rva.ToString("X") + "\""
                 + ",\"va\":\"0x" + va.ToString("X") + "\""
                 + ",\"gap\":" + gap
                 + ",\"exact\":" + ((gap == 0 && resolved) ? "true" : "false")
                 + "}";
        }

        /// <summary>The set of breakable (record-carrying) source lines for a module — for gutter markers.</summary>
        public static string Lines(string module, List<int> lines)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"lines\",\"module\":").Append(Str(module)).Append(",\"lines\":[");
            for (int i = 0; i < lines.Count; i++) { if (i > 0) sb.Append(','); sb.Append(lines[i]); }
            sb.Append("]}");
            return sb.ToString();
        }

        /// <summary>Decoded symbol definitions (Phase 3): name + kind + entry RVA + owning module, and for a
        /// procedure or method with a known extent, its last source line (<c>endLine</c>, 6fa242ae). An
        /// unknown extent OMITS the member rather than writing 0, and a procedure or method says so with
        /// <c>"extent":"unknown"</c> instead (f1a98318); see <see cref="ProcExtents"/> for what unknown means
        /// and why routines carry neither.</summary>
        public static string Symbols(List<ProcSymbol> syms, TswdDebugInfo dbg)
        {
            var extents = new ProcExtents(dbg);   // indexed from dbg's WHOLE table, not the (maybe filtered) syms
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"symbols\",\"count\":").Append(syms.Count).Append(",\"symbols\":[");
            for (int i = 0; i < syms.Count; i++)
            {
                var s = syms[i];
                if (i > 0) sb.Append(',');
                // Definition line bounded to the symbol's OWN [entry, nextEntry) range (a plain ResolveAddr
                // can bind a proc to a neighbouring proc's / the previous module's record). 0 = not navigable.
                int line = dbg.DefinitionLine(s);
                sb.Append("{\"name\":").Append(Str(s.Name))
                  .Append(",\"raw\":").Append(Str(s.RawName))
                  .Append(",\"kind\":").Append(Str(s.Kind.ToString().ToLowerInvariant()))
                  .Append(",\"rva\":\"0x").Append(s.EntryRva.ToString("X")).Append('"')
                  .Append(",\"line\":").Append(line);
                int endLine = extents.EndLine(s);
                if (endLine > 0) sb.Append(",\"endLine\":").Append(endLine);
                // Said, not just omitted (f1a98318): the host must tell "this engine could not bound it" from an
                // engine too old to send extents at all. Only a procedure or method has an extent to be unknown.
                else if (ProcExtents.IsExtentKind(s)) sb.Append(",\"extent\":\"unknown\"");
                sb.Append(",\"moduleIdx\":").Append(s.ModuleIdx)
                  .Append(",\"module\":").Append(Str(dbg.ModuleNameForIdx(s.ModuleIdx)))
                  .Append('}');
            }
            sb.Append("]}");
            return sb.ToString();
        }

        // ------------------------------------------------------------------ Phase 2 events

        public static string Loaded(uint pid, uint loadBase)
        {
            return "{\"event\":\"loaded\",\"pid\":" + pid + ",\"loadBase\":\"0x" + loadBase.ToString("X") + "\"}";
        }

        /// <summary>An image (EXE or DLL) mapped into the target. hasDebug = TSWD present (the engine
        /// can resolve lines/symbols there); the host decides Tier 1 vs 2 from source resolvability.</summary>
        public static string ModuleLoaded(LoadedModule m)
        {
            return "{\"event\":\"module-loaded\""
                 + ",\"name\":" + Str(m.Name)
                 + ",\"path\":" + Str(m.Path)
                 + ",\"base\":\"0x" + m.LoadBase.ToString("X") + "\""
                 + ",\"size\":\"0x" + m.Size.ToString("X") + "\""
                 + ",\"hasDebug\":" + (m.HasDebug ? "true" : "false")
                 + "}";
        }

        public static string ModuleUnloaded(LoadedModule m)
        {
            return "{\"event\":\"module-unloaded\""
                 + ",\"name\":" + Str(m.Name)
                 + ",\"base\":\"0x" + m.LoadBase.ToString("X") + "\""
                 + "}";
        }

        public static string Exited(uint code)
        {
            return "{\"event\":\"exited\",\"code\":" + code + "}";
        }

        /// <summary>Register block — embedded inside paused/regs events (pass to Paused/RegsEvent).</summary>
        public static string Regs(uint eax, uint ebx, uint ecx, uint edx, uint esi, uint edi, uint ebp, uint esp, uint eip, uint eflags)
        {
            return "{\"eax\":\"0x" + eax.ToString("X8") + "\""
                 + ",\"ebx\":\"0x" + ebx.ToString("X8") + "\""
                 + ",\"ecx\":\"0x" + ecx.ToString("X8") + "\""
                 + ",\"edx\":\"0x" + edx.ToString("X8") + "\""
                 + ",\"esi\":\"0x" + esi.ToString("X8") + "\""
                 + ",\"edi\":\"0x" + edi.ToString("X8") + "\""
                 + ",\"ebp\":\"0x" + ebp.ToString("X8") + "\""
                 + ",\"esp\":\"0x" + esp.ToString("X8") + "\""
                 + ",\"eip\":\"0x" + eip.ToString("X8") + "\""
                 + ",\"eflags\":\"0x" + eflags.ToString("X8") + "\"}";
        }

        /// <summary>Target paused (breakpoint hit, step complete, or step-limit). regsJson may be null.
        /// proc = demangled symbol containing the pause address (null when unknown).</summary>
        public static string Paused(string reason, string module, string proc, int line, uint rva, uint va, uint gap, bool resolved, string sym, string regsJson)
        {
            return "{\"event\":\"paused\""
                 + ",\"reason\":" + Str(reason)
                 + ",\"resolved\":" + (resolved ? "true" : "false")
                 + ",\"module\":" + Str(module)
                 + ",\"proc\":" + Str(proc)
                 + ",\"line\":" + line
                 + ",\"rva\":\"0x" + rva.ToString("X") + "\""
                 + ",\"va\":\"0x" + va.ToString("X") + "\""
                 + ",\"gap\":" + gap
                 + ",\"exact\":" + ((gap == 0 && resolved) ? "true" : "false")
                 + ",\"sym\":" + Str(sym)               // SPIKE: runtime location for non-TSWD code (or null)
                 + ",\"regs\":" + (regsJson ?? "null")
                 + "}";
        }

        public static string Resumed(string mode)
        {
            return "{\"event\":\"resumed\",\"mode\":" + Str(mode) + "}";
        }

        public static string RegsEvent(string regsJson)
        {
            return "{\"event\":\"regs\",\"regs\":" + (regsJson ?? "null") + "}";
        }

        /// <summary>The OWNING IMAGE of a breakpoint, as a full disk path, or JSON null when the
        /// breakpoint is still pending (no image carries its compiland yet).
        /// <para>
        /// The .clw <c>module</c> alone is only a BASENAME, and two loaded images can each carry a
        /// compiland of that name. The host keys breakpoint identity on it, so without an owner two
        /// breakpoints in two DLLs collapse into one — which is the whole of task e80072f1. This is
        /// the IMAGE path (the EXE/DLL), NOT the .clw: it is an identity token to compare, never a
        /// file for anyone to open.
        /// </para>
        /// <para>
        /// Written by ONE function for all three breakpoint echoes (bp-set, bp-list, bp-del) so a
        /// future emitter cannot carry the owner on some of them and not others. That asymmetry is
        /// exactly how the <c>requestedLine</c> promise came to hold on one of three paths.
        /// </para></summary>
        private static string OwnerPath(UserBreakpoint bp)
        {
            return Str(bp.Owner == null ? null : bp.Owner.Path);
        }

        public static string BpSet(UserBreakpoint bp)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"bp-set\",\"module\":").Append(Str(bp.Module))
              .Append(",\"ownerPath\":").Append(OwnerPath(bp))
              .Append(",\"requestedLine\":").Append(bp.RequestedLine)
              .Append(",\"line\":").Append(bp.Line)
              .Append(",\"rvas\":[");
            for (int i = 0; i < bp.Rvas.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append("\"0x").Append(bp.Rvas[i].ToString("X")).Append('"');
            }
            sb.Append(']');
            AppendBpProps(sb, bp);
            sb.Append('}');
            return sb.ToString();
        }

        /// <summary>Serialize the advanced breakpoint properties (condition / hit count / tracepoint /
        /// live hit count) shared by bp-set and bp-list. Always emitted so the host can clear stale
        /// values when a property is removed.</summary>
        private static void AppendBpProps(StringBuilder sb, UserBreakpoint bp)
        {
            sb.Append(",\"condition\":").Append(Str(bp.Condition))
              .Append(",\"hitMode\":").Append(Str(bp.HitMode))
              .Append(",\"hitValue\":").Append(bp.HitValue)
              .Append(",\"trace\":").Append(Str(bp.Trace))
              .Append(",\"hitCount\":").Append(bp.HitCount);
        }

        /// <summary>The bp-del echo. Takes the breakpoint rather than a bare line so it cannot be written
        /// without BOTH identities: several logical breakpoints can share one planted <c>line</c> (distinct
        /// gutter lines that snapped to the same record), so <c>line</c> alone does not say WHICH one went,
        /// and a host keying on it drops the survivors too. Mirrors what BpSet already carries.</summary>
        public static string BpDel(UserBreakpoint bp)
        {
            return "{\"event\":\"bp-del\",\"module\":" + Str(bp.Module)
                 + ",\"ownerPath\":" + OwnerPath(bp)
                 + ",\"requestedLine\":" + bp.RequestedLine
                 + ",\"line\":" + bp.Line + "}";
        }

        /// <summary>Result of an edit-variable-value write: the address, whether it landed, the re-read
        /// canonical value (on success), and a user-facing error (on failure).</summary>
        public static string VarSet(uint va, bool ok, string value, string error)
        {
            return "{\"event\":\"varset\",\"va\":\"0x" + va.ToString("X") + "\""
                 + ",\"ok\":" + (ok ? "true" : "false")
                 + ",\"value\":" + Str(value)
                 + ",\"error\":" + Str(error) + "}";
        }

        /// <summary>A tracepoint fired: the interpolated message + the breakpoint's live hit count. The
        /// host surfaces this in the debugger console without the target ever pausing.</summary>
        public static string Trace(string module, int line, string message, int hitCount)
        {
            return "{\"event\":\"trace\",\"module\":" + Str(module) + ",\"line\":" + line
                 + ",\"message\":" + Str(message) + ",\"hitCount\":" + hitCount + "}";
        }

        public static string BpError(string module, int line, string error)
        {
            return "{\"event\":\"bp-error\",\"module\":" + Str(module) + ",\"line\":" + line
                 + ",\"error\":" + Str(error) + "}";
        }

        public static string BpList(List<UserBreakpoint> bps)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"bp-list\",\"bps\":[");
            for (int i = 0; i < bps.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append("{\"module\":").Append(Str(bps[i].Module))
                  .Append(",\"ownerPath\":").Append(OwnerPath(bps[i]))
                  .Append(",\"line\":").Append(bps[i].Line)
                  .Append(",\"requestedLine\":").Append(bps[i].RequestedLine);
                AppendBpProps(sb, bps[i]);
                sb.Append('}');
            }
            sb.Append("]}");
            return sb.ToString();
        }

        /// <summary>len = the REQUESTED read size (host correlates replies on it); read = bytes
        /// actually read, which is how many hex pairs follow in bytes. reqId, when the request carried one,
        /// is echoed as the LAST member so the host can match the reply to its request; null omits it.</summary>
        public static string Mem(uint addr, byte[] bytes, int read, int len, string reqId = null)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"mem\",\"addr\":\"0x").Append(addr.ToString("X"))
              .Append("\",\"len\":").Append(len)
              .Append(",\"read\":").Append(read).Append(",\"bytes\":\"");
            for (int i = 0; i < read; i++) sb.Append(bytes[i].ToString("X2"));
            sb.Append('"');
            if (reqId != null) sb.Append(",\"reqId\":").Append(Str(reqId));
            sb.Append('}');
            return sb.ToString();
        }

        /// <summary>A refused mem read that carried a reqId: the same event, no bytes, and the reason. A plain
        /// error event could not say WHICH request it answers, and the page would wait on it forever.</summary>
        public static string MemError(uint addr, int len, string reqId, string error)
        {
            return "{\"event\":\"mem\",\"addr\":\"0x" + addr.ToString("X") + "\",\"len\":" + len
                 + ",\"read\":0,\"bytes\":\"\",\"error\":" + Str(error) + ",\"reqId\":" + Str(reqId) + "}";
        }

        /// <summary>Resolved call stack (frame 0 = current EIP). proc/module are null when unknown.</summary>
        public static string Stack(List<StackFrame> frames)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"stack\",\"frames\":[");
            for (int i = 0; i < frames.Count; i++)
            {
                var f = frames[i];
                if (i > 0) sb.Append(',');
                sb.Append("{\"frame\":").Append(i)
                  .Append(",\"proc\":").Append(Str(f.Proc))
                  .Append(",\"kind\":").Append(Str(f.Kind))
                  .Append(",\"module\":").Append(Str(f.Module))
                  .Append(",\"line\":").Append(f.Line)
                  .Append(",\"rva\":\"0x").Append(f.Rva.ToString("X")).Append('"')
                  .Append(",\"va\":\"0x").Append(f.Va.ToString("X")).Append('"')
                  .Append(",\"ebp\":\"0x").Append(f.Ebp.ToString("X")).Append('"')
                  .Append(",\"stackAddr\":\"0x").Append(f.StackAddr.ToString("X")).Append('"')
                  .Append(",\"uncertain\":").Append(f.Uncertain ? "true" : "false")
                  .Append('}');
            }
            sb.Append("]}");
            return sb.ToString();
        }

        /// <summary>Static data symbols (globals + file record buffers with fields) for the Variables tree.</summary>
        public static string Globals(List<DataSymbol> syms, TswdDebugInfo dbg)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"globals\",\"count\":").Append(syms.Count).Append(",\"symbols\":[");
            for (int i = 0; i < syms.Count; i++)
            {
                var s = syms[i];
                if (i > 0) sb.Append(',');
                sb.Append("{\"name\":").Append(Str(s.Name))
                  .Append(",\"type\":\"0x").Append(s.TypeCode.ToString("X2")).Append('"')
                  .Append(",\"typeName\":").Append(Str(TswdDebugInfo.TypeCodeName(s.TypeCode)))
                  .Append(",\"size\":").Append(s.Size)
                  .Append(",\"rva\":\"0x").Append(s.Rva.ToString("X")).Append('"')
                  .Append(",\"module\":").Append(Str(dbg.ModuleNameForIdx(s.ModuleIdx)))
                  .Append(",\"fields\":[");
                // Prefer the byte-exact resolved type tree (recurses nested groups); fall back to the legacy
                // flat field list for symbols whose typeRef didn't resolve to a group.
                if (s.Type != null && s.Type.Kind == TypeKind.Group && s.Type.Members != null)
                    for (int f = 0; f < s.Type.Members.Count; f++)
                    {
                        if (f > 0) sb.Append(',');
                        AppendField(sb, s.Type.Members[f]);
                    }
                else if (s.Fields != null)
                    for (int f = 0; f < s.Fields.Count; f++)
                    {
                        var fl = s.Fields[f];
                        if (f > 0) sb.Append(',');
                        sb.Append("{\"name\":").Append(Str(fl.Name))
                          .Append(",\"offset\":").Append(fl.Offset)
                          .Append(",\"type\":\"0x").Append(fl.TypeCode.ToString("X2")).Append('"')
                          .Append(",\"typeName\":").Append(Str(TswdDebugInfo.TypeCodeName(fl.TypeCode)))
                          .Append(",\"size\":").Append(fl.Size).Append('}');
                    }
                sb.Append("]}");
            }
            sb.Append("]}");
            return sb.ToString();
        }

        /// <summary>Emit one resolved GROUP member as a field object, recursing nested groups into their own
        /// "fields" array. Leaf type labels go through the shared <see cref="DebugEngine.ClarionTypeLabel"/>
        /// so the globals tree labels types exactly like the locals panel.</summary>
        private static void AppendField(StringBuilder sb, TypeMember mb)
        {
            var t = mb.Type;
            bool group = t != null && t.Kind == TypeKind.Group;
            byte code = 0; uint size = t != null ? t.Size : 0; int places = 0;
            string typeName;
            if (group) typeName = "GROUP";
            else if (t != null && t.Kind == TypeKind.Array) typeName = "ARRAY(" + t.Length + ")";
            else if (t != null)
            {
                if (t.Tag == 0x16 || t.Tag == 0x26 || t.Tag == 0x29) { code = 0x16; size = 4; }
                else t.RenderHint(out code, out size, out places);
                typeName = DebugEngine.ClarionTypeLabel(code, 0, size, places);
            }
            else typeName = null;

            sb.Append("{\"name\":").Append(Str(mb.Name ?? "?"))
              .Append(",\"offset\":").Append(mb.Offset)
              .Append(",\"type\":\"0x").Append(code.ToString("X2")).Append('"')
              .Append(",\"typeName\":").Append(Str(typeName))
              .Append(",\"size\":").Append(size);
            if (group && t.Members != null)
            {
                sb.Append(",\"fields\":[");
                for (int i = 0; i < t.Members.Count; i++) { if (i > 0) sb.Append(','); AppendField(sb, t.Members[i]); }
                sb.Append(']');
            }
            sb.Append('}');
        }

        /// <summary>Resolved data symbol for watch-by-name. typeName null = unproven code (render hex).</summary>
        public static string Sym(string name, bool found, uint rva, uint va, byte typeCode, string typeName, uint size, string container)
        {
            if (!found)
                return "{\"event\":\"sym\",\"name\":" + Str(name) + ",\"found\":false}";
            return "{\"event\":\"sym\",\"name\":" + Str(name)
                 + ",\"found\":true"
                 + ",\"rva\":\"0x" + rva.ToString("X") + "\""
                 + ",\"va\":\"0x" + va.ToString("X") + "\""
                 + ",\"type\":\"0x" + typeCode.ToString("X2") + "\""
                 + ",\"typeName\":" + Str(typeName)
                 + ",\"size\":" + size
                 + ",\"container\":" + Str(container)
                 + "}";
        }

        /// <summary>A found watch value: instanceVa is the live (per-thread when threaded, frame slot for a
        /// local) address the bytes were read from; templateVa is the link-time template address. <paramref
        /// name="editable"/> gates the edit-variable-value metadata (va + places): the host keys "is this cell
        /// editable" purely on the presence of "va", so a non-writable type (ref / group / unknown) emits no va
        /// and therefore shows no edit pencil instead of erroring on commit. A miss goes through
        /// <see cref="WatchMiss"/>.</summary>
        public static string Watch(string name, bool found, uint templateVa, uint instanceVa, bool threaded,
                                   byte typeCode, string typeName, uint size, int places, string value, byte[] bytes, int read, bool editable,
                                   string note = null)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"watch\",\"name\":").Append(Str(name))
              .Append(",\"found\":true")
              .Append(",\"templateVa\":\"0x").Append(templateVa.ToString("X")).Append('"')
              .Append(",\"threaded\":").Append(threaded ? "true" : "false")
              .Append(",\"type\":\"0x").Append(typeCode.ToString("X2")).Append('"')
              .Append(",\"typeName\":").Append(Str(typeName))
              .Append(",\"size\":").Append(size)
              .Append(",\"value\":").Append(Str(value))   // engine-formatted (shared with the Locals panel)
              .Append(",\"read\":").Append(read);
            if (note != null) sb.Append(",\"note\":").Append(Str(note));
            if (editable)
                sb.Append(",\"va\":\"0x").Append(instanceVa.ToString("X")).Append('"')
                  .Append(",\"places\":").Append(places);
            sb.Append(",\"bytes\":\"");
            for (int i = 0; i < read; i++) sb.Append(bytes[i].ToString("X2"));
            sb.Append("\"}");
            return sb.ToString();
        }

        /// <summary>A watch that resolved to no value: either genuinely unknown, or (outOfScope) a known local of
        /// a procedure we are not currently paused inside. The host renders the latter as "(out of scope)".</summary>
        public static string WatchMiss(string name, bool outOfScope)
        {
            return "{\"event\":\"watch\",\"name\":" + Str(name) + ",\"found\":false"
                 + (outOfScope ? ",\"outOfScope\":true" : "") + "}";
        }

        /// <summary>A watch that RESOLVED to a name but could not be read (e.g. a THREADed instance the
        /// runtime wouldn't yield). Carried on the watch event against the name so the host resolves that
        /// row's pending state instead of leaving it on "…" forever.</summary>
        public static string WatchError(string name, string error)
        {
            return "{\"event\":\"watch\",\"name\":" + Str(name) + ",\"found\":false"
                 + ",\"error\":" + Str(error) + "}";
        }

        public static string Error(string message)
        {
            return "{\"event\":\"error\",\"message\":" + Str(message) + "}";
        }

        /// <summary>`procs --json` (ProcsCommand.cs): the attach picker's process list, one line. The host parses
        /// it, so the member names and order are a contract: event, procs[{pid,name,path,tswd,started}], skipped, and
        /// with verbose a trailing skips[{pid,name,reason}].</summary>
        public static string Procs(List<ProcEntry> procs, List<ProcSkip> skips, bool verbose)
        {
            var sb = new StringBuilder("{\"event\":\"procs\",\"procs\":[");
            for (int i = 0; i < procs.Count; i++)
            {
                var p = procs[i];
                if (i > 0) sb.Append(',');
                sb.Append("{\"pid\":").Append(p.Pid)
                  .Append(",\"name\":").Append(Str(p.Name))
                  .Append(",\"path\":").Append(Str(p.Path))
                  .Append(",\"tswd\":").Append(p.Tswd ? "true" : "false")
                  .Append(",\"started\":\"").Append(p.Started.ToString(System.Globalization.CultureInfo.InvariantCulture)).Append('"')
                  .Append('}');
            }
            sb.Append("],\"skipped\":").Append(skips.Count);
            if (verbose)
            {
                sb.Append(",\"skips\":[");
                for (int i = 0; i < skips.Count; i++)
                {
                    var s = skips[i];
                    if (i > 0) sb.Append(',');
                    sb.Append("{\"pid\":").Append(s.Pid)
                      .Append(",\"name\":").Append(Str(s.Name))
                      .Append(",\"reason\":").Append(Str(s.Reason))
                      .Append('}');
                }
                sb.Append(']');
            }
            return sb.Append('}').ToString();
        }

        /// <summary>`loaded` for an ATTACHED session (3f2d747f): the launch shape plus an additive
        /// "attached":true, so a host that does not read it is unaffected.</summary>
        public static string Loaded(uint pid, uint loadBase, bool attached)
        {
            string s = Loaded(pid, loadBase);
            return attached ? s.Substring(0, s.Length - 1) + ",\"attached\":true}" : s;
        }

        /// <summary>The engine let go of the target and it keeps running. drained = debug events that were
        /// already queued and were answered before the stop; restored = breakpoint bytes put back. "error" is
        /// present only when a restore or the stop itself failed - the app may then crash later, and the host
        /// must say so rather than report a clean detach.</summary>
        public static string Detached(uint pid, int drained, int restored, string error)
        {
            return "{\"event\":\"detached\",\"pid\":" + pid + ",\"drained\":" + drained + ",\"restored\":" + restored
                 + (error != null ? ",\"error\":" + Str(error) : "") + "}";
        }

        /// <summary>An `attach` that could not start: the ordinary error event plus the Win32 error code
        /// (0 when the failure is not a Win32 one, such as an image with no TSWD).</summary>
        public static string AttachError(string message, int code)
        {
            return "{\"event\":\"error\",\"message\":" + Str(message) + ",\"code\":" + code + "}";
        }
    }
}
