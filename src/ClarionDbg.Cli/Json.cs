using System.Collections.Generic;
using System.Text;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    /// <summary>Tiny hand-rolled JSON for the engine's machine-readable event output.</summary>
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

        /// <summary>Decoded symbol definitions (Phase 3): name + kind + entry RVA + owning module.</summary>
        public static string Symbols(List<ProcSymbol> syms, TswdDebugInfo dbg)
        {
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
                  .Append(",\"line\":").Append(line)
                  .Append(",\"moduleIdx\":").Append(s.ModuleIdx)
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

        public static string BpSet(string module, int requestedLine, int line, List<uint> rvas)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"bp-set\",\"module\":").Append(Str(module))
              .Append(",\"requestedLine\":").Append(requestedLine)
              .Append(",\"line\":").Append(line)
              .Append(",\"rvas\":[");
            for (int i = 0; i < rvas.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append("\"0x").Append(rvas[i].ToString("X")).Append('"');
            }
            sb.Append("]}");
            return sb.ToString();
        }

        public static string BpDel(string module, int line)
        {
            return "{\"event\":\"bp-del\",\"module\":" + Str(module) + ",\"line\":" + line + "}";
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
                  .Append(",\"line\":").Append(bps[i].Line)
                  .Append(",\"requestedLine\":").Append(bps[i].RequestedLine)
                  .Append('}');
            }
            sb.Append("]}");
            return sb.ToString();
        }

        /// <summary>len = the REQUESTED read size (host correlates replies on it); read = bytes
        /// actually read, which is how many hex pairs follow in bytes.</summary>
        public static string Mem(uint addr, byte[] bytes, int read, int len)
        {
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"mem\",\"addr\":\"0x").Append(addr.ToString("X"))
              .Append("\",\"len\":").Append(len)
              .Append(",\"read\":").Append(read).Append(",\"bytes\":\"");
            for (int i = 0; i < read; i++) sb.Append(bytes[i].ToString("X2"));
            sb.Append("\"}");
            return sb.ToString();
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

        /// <summary>Watch-by-name value: instanceVa is the live (per-thread when threaded) address
        /// the bytes were read from; va is the link-time template address.</summary>
        public static string Watch(string name, bool found, uint templateVa, uint instanceVa, bool threaded,
                                   byte typeCode, string typeName, uint size, string value, byte[] bytes, int read)
        {
            if (!found)
                return "{\"event\":\"watch\",\"name\":" + Str(name) + ",\"found\":false}";
            var sb = new StringBuilder();
            sb.Append("{\"event\":\"watch\",\"name\":").Append(Str(name))
              .Append(",\"found\":true")
              .Append(",\"templateVa\":\"0x").Append(templateVa.ToString("X")).Append('"')
              .Append(",\"va\":\"0x").Append(instanceVa.ToString("X")).Append('"')
              .Append(",\"threaded\":").Append(threaded ? "true" : "false")
              .Append(",\"type\":\"0x").Append(typeCode.ToString("X2")).Append('"')
              .Append(",\"typeName\":").Append(Str(typeName))
              .Append(",\"size\":").Append(size)
              .Append(",\"value\":").Append(Str(value))   // engine-formatted (shared with the Locals panel)
              .Append(",\"read\":").Append(read)
              .Append(",\"bytes\":\"");
            for (int i = 0; i < read; i++) sb.Append(bytes[i].ToString("X2"));
            sb.Append("\"}");
            return sb.ToString();
        }

        public static string Error(string message)
        {
            return "{\"event\":\"error\",\"message\":" + Str(message) + "}";
        }
    }
}
