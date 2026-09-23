using System;
using System.Collections.Generic;
using System.Globalization;

namespace ClarionDebugger.Terminal
{
    // Typed forms of what the debugger page sends the host (afbc68c7, bridge hardening stage 2).
    //
    // THE THREAT MODEL is JsonMessageReader's: the debuggee is untrusted, its names and values reach the page,
    // and the page's messages come back here. Each request is parsed ONCE, into a type, by the Parse method
    // beside it - and a Parse that returns null means "drop the message". A handler never sees a half-read
    // payload and never picks fields out of raw text, which is what the eighteen scattered JsonVal calls
    // used to do one field at a time.
    //
    // The wire formats are UNCHANGED except where a request stopped carrying something the host must not
    // trust (break-on-entry now names a host-issued procedure id). The delimiter-separated payloads - "a|b|c"
    // and "module:line" - are typed here too rather than converted to JSON, because converting them would
    // move risk into the page for no gain: every field in them is validated again by the service before it
    // reaches the engine.
    //
    // THERE IS NO RULE ABOUT FIELD ORDER. The reader these DTOs replaced searched for "key": with no idea where
    // strings began or ended, and payloads were ordered - untrusted content last - to work around it. That was
    // never a boundary, and ae5b678a stage 1 retired it: every field here is read by key through
    // JsonMessageReader, which matches only top-level members, so a sender may order its members however
    // reads best.

    /// <summary>The outer <c>{action, data}</c> envelope every page message arrives in.</summary>
    internal sealed class PageEnvelope
    {
        public string Action;
        /// <summary>The request's payload: a plain string, or JSON text for the requests that carry an object.
        /// Null when the page sent none.</summary>
        public string Data;

        /// <summary>Null when <paramref name="json"/> is not an object with a string <c>action</c>.</summary>
        public static PageEnvelope Parse(string json)
        {
            string action = JsonMessageReader.ReadField(json, "action");
            if (string.IsNullOrEmpty(action)) return null;
            return new PageEnvelope { Action = action, Data = JsonMessageReader.ReadField(json, "data") };
        }
    }

    /// <summary>A <c>module:line</c> reference (jump, bpremove, runtocursor). Split on the LAST colon, so the
    /// module part may itself contain one; the service validates the module name before it is used.</summary>
    internal sealed class ModuleLineRequest
    {
        public string Module;
        public int Line;

        public static ModuleLineRequest Parse(string spec)
        {
            if (string.IsNullOrEmpty(spec)) return null;
            int c = spec.LastIndexOf(':');
            if (c <= 0) return null;
            int line;
            if (!PageNumbers.TryInt(spec.Substring(c + 1), out line)) return null;
            return new ModuleLineRequest { Module = spec.Substring(0, c), Line = line };
        }
    }

    /// <summary>Lazy reference expansion: <c>reqId|module|typeRef|addr</c>.</summary>
    internal sealed class ExpandRequest
    {
        public int ReqId;
        public string Module;
        public uint TypeRef;
        public string Addr;

        public static ExpandRequest Parse(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var a = data.Split('|');
            int rq; uint tr;
            if (a.Length != 4 || !PageNumbers.TryInt(a[0], out rq) || !PageNumbers.TryUInt(a[2], out tr)) return null;
            return new ExpandRequest { ReqId = rq, Module = a[1], TypeRef = tr, Addr = a[3] };
        }
    }

    /// <summary>One call-stack frame's locals: <c>reqId|va|ebp</c>.</summary>
    internal sealed class FrameLocalsRequest
    {
        public int ReqId;
        public string Va;
        public string Ebp;

        public static FrameLocalsRequest Parse(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var a = data.Split('|');
            int rq;
            if (a.Length != 3 || !PageNumbers.TryInt(a[0], out rq)) return null;
            return new FrameLocalsRequest { ReqId = rq, Va = a[1], Ebp = a[2] };
        }
    }

    /// <summary>Open a breakpoint's source by the exact path the gutter gave: <c>line\tfullPath</c>.</summary>
    internal sealed class OpenBpRequest
    {
        public int Line;
        public string Path;

        public static OpenBpRequest Parse(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            int t = data.IndexOf('\t');
            int line;
            if (t <= 0 || !PageNumbers.TryInt(data.Substring(0, t), out line)) return null;
            return new OpenBpRequest { Line = line, Path = data.Substring(t + 1) };
        }
    }

    /// <summary>Break on a procedure's entry: <c>{"id": "..."}</c>, where the id is one the HOST issued with
    /// the Procedures list it last sent (see <see cref="ProcedureIds"/>).
    /// <para>
    /// The page used to send the row's module and line, and the host armed whatever it was told. Those came
    /// from the row, but nothing made the host check that they still did: any module:line the page named
    /// became a persistent breakpoint. The page now names a row, and the host looks up what that row means.
    /// </para></summary>
    internal sealed class BreakOnProcEntryRequest
    {
        public string ProcId;

        public static BreakOnProcEntryRequest Parse(string data)
        {
            string id = JsonMessageReader.ReadField(data, "id");
            if (string.IsNullOrEmpty(id)) return null;
            return new BreakOnProcEntryRequest { ProcId = id };
        }
    }

    /// <summary>Advanced breakpoint properties from the Breakpoints pane:
    /// <c>{module, line, condition, hitMode, hitValue, trace}</c>. Module and line are required; the rest
    /// are passed on as sent, and the handler normalises them.</summary>
    internal sealed class BpPropsRequest
    {
        public string Module;
        public int Line;
        public string Condition;
        public string HitMode;
        public int HitValue;
        public string Trace;

        public static BpPropsRequest Parse(string data)
        {
            string module = JsonMessageReader.ReadField(data, "module");
            if (string.IsNullOrEmpty(module)) return null;
            int line;
            if (!PageNumbers.TryInt(JsonMessageReader.ReadField(data, "line"), out line)) return null;
            int hitValue;
            if (!PageNumbers.TryInt(JsonMessageReader.ReadField(data, "hitValue"), out hitValue)) hitValue = 0;
            return new BpPropsRequest
            {
                Module = module,
                Line = line,
                Condition = JsonMessageReader.ReadField(data, "condition"),
                HitMode = JsonMessageReader.ReadField(data, "hitMode"),
                HitValue = hitValue,
                Trace = JsonMessageReader.ReadField(data, "trace")
            };
        }
    }

    /// <summary>Write a value into a live variable: <c>{va, typeCode, size, places, tid, value}</c>. The
    /// first five are the row's own edit metadata, which the host checks against what it ISSUED (see
    /// <see cref="EditGrants"/>); only <c>value</c> is the user's.</summary>
    internal sealed class EditVarRequest
    {
        public string Va;
        public string TypeCode;
        public int Size;
        public int Places;
        /// <summary>The thread the row was read on, or null when the page had no selection to name.</summary>
        public uint? Tid;
        public string Value;

        public static EditVarRequest Parse(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            int size, places;
            PageNumbers.TryInt(JsonMessageReader.ReadField(data, "size"), out size);
            if (!PageNumbers.TryInt(JsonMessageReader.ReadField(data, "places"), out places)) places = 0;
            uint tid;
            bool haveTid = PageNumbers.TryUInt(JsonMessageReader.ReadField(data, "tid"), out tid);
            return new EditVarRequest
            {
                Va = JsonMessageReader.ReadField(data, "va"),
                TypeCode = JsonMessageReader.ReadField(data, "typeCode"),
                Size = size,
                Places = places,
                Tid = haveTid ? (uint?)tid : null,
                Value = JsonMessageReader.ReadField(data, "value") ?? string.Empty
            };
        }
    }

    /// <summary>The one number parser for page payloads: invariant culture, integer syntax only, null reads
    /// as "not a number".</summary>
    internal static class PageNumbers
    {
        public static bool TryInt(string s, out int v)
        {
            v = 0;
            return s != null && int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out v);
        }

        public static bool TryUInt(string s, out uint v)
        {
            v = 0;
            return s != null && uint.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out v);
        }
    }

    /// <summary>The procedures the host last LISTED, by the opaque id each row was sent with.
    /// <para>
    /// An id is issued per push and means nothing outside it: a new list replaces the whole table, so an id
    /// from a list the page no longer shows resolves to nothing rather than to whatever now sits at that
    /// index. What a row MEANS - its module and line - stays on this side of the bridge; the page only ever
    /// hands back a name for a row it was given.
    /// </para></summary>
    internal sealed class ProcedureIds
    {
        private Dictionary<string, ProcRef> _byId =
            new Dictionary<string, ProcRef>(StringComparer.Ordinal);

        /// <summary>A fresh, empty table. Fill it off the UI thread with <see cref="IdFor"/> keys, then hand it
        /// to <see cref="Replace"/> in the same step that posts the list.</summary>
        public static Dictionary<string, ProcRef> NewTable()
        {
            return new Dictionary<string, ProcRef>(StringComparer.Ordinal);
        }

        /// <summary>The id row <paramref name="index"/> of push <paramref name="generation"/> is sent with.
        /// Unique across pushes, so a stale id can never collide with a current one.</summary>
        public static string IdFor(int generation, int index)
        {
            return "p" + generation.ToString(CultureInfo.InvariantCulture) + "." + index.ToString(CultureInfo.InvariantCulture);
        }

        // THE GENERATION the table belongs to (afbc68c7, codex adversary gate). A push parses off the UI
        // thread, and the table used to be swapped only when that parse finished - so for the whole parse, the
        // PREVIOUS exe's ids still resolved, and a right-click on the old list armed an old row in the new
        // session. Now a push BEGINS its generation synchronously, which empties the table at once; only that
        // generation's table can be installed; and an id resolves only if it carries the current generation.
        private int _generation;

        /// <summary>Start push <paramref name="generation"/>: every id issued before it stops resolving NOW,
        /// not when the new list arrives.</summary>
        public void Begin(int generation)
        {
            _generation = generation;
            _byId = NewTable();
        }

        /// <summary>Install the table for <paramref name="generation"/>. Refused (false) unless that is still
        /// the current generation - a slower, older parse can never overwrite a newer one.</summary>
        public bool Replace(int generation, Dictionary<string, ProcRef> table)
        {
            if (generation != _generation) return false;
            _byId = table ?? NewTable();
            return true;
        }

        /// <summary>Empty the table without starting a push (the solution closed).</summary>
        public void Clear() { _byId = NewTable(); }

        /// <summary>The procedure behind <paramref name="id"/>, or null when it was not issued for the CURRENT
        /// generation's list - including an id the host did issue, for a list it has since begun replacing.</summary>
        public ProcRef Resolve(string id)
        {
            if (id == null || GenerationOf(id) != _generation) return null;
            ProcRef v;
            return _byId.TryGetValue(id, out v) ? v : null;
        }

        /// <summary>The generation an id was issued for (see <see cref="IdFor"/>), or -1 when it is not one of
        /// ours.</summary>
        internal static int GenerationOf(string id)
        {
            if (string.IsNullOrEmpty(id) || id[0] != 'p') return -1;
            int dot = id.IndexOf('.');
            int gen;
            if (dot <= 1 || !int.TryParse(id.Substring(1, dot - 1), NumberStyles.None, CultureInfo.InvariantCulture, out gen)) return -1;
            return gen;
        }

        /// <summary>The procedure or method in the current list that truly CONTAINS <paramref name="line"/> of
        /// <paramref name="module"/>, or null with the reason in <paramref name="why"/>.
        /// <para>
        /// CONTAINMENT, NEVER "NEAREST PRECEDING" (PM ruling, codex adversary gate). This used to return the last
        /// procedure starting at or above the line, with no upper bound - so module data, generated trailer code
        /// or a cursor below the last procedure armed the PREVIOUS procedure's entry. A procedure's range is
        /// [its start, <see cref="ProcRef.EndLine"/>], the extent the engine reports. A procedure with NO known
        /// extent is REFUSED as an engine/host version mismatch, never bounded by a guess (pipeline run 2).
        /// </para>
        /// <para>
        /// ROUTINEs are skipped as candidates and as bounds: they sit INSIDE their procedure, so a routine is
        /// neither what "procedure entry" means nor where the procedure ends. Module is compared ignoring case:
        /// it is a Windows file name. A position is only a lookup key into what the host listed (e61e4f92).
        /// </para>
        /// </summary>
        public ProcRef Containing(string module, int line, out string why)
        {
            why = null;
            if (string.IsNullOrEmpty(module) || line <= 0) { why = "no usable file or line"; return null; }
            ProcRef at = null, next = null;
            foreach (var p in _byId.Values)
            {
                if (p == null || p.Line <= 0) continue;
                if (string.Equals(p.Kind, "routine", StringComparison.OrdinalIgnoreCase)) continue;
                if (!string.Equals(p.Module, module, StringComparison.OrdinalIgnoreCase)) continue;
                if (p.Line <= line) { if (at == null || p.Line > at.Line) at = p; }
                else if (next == null || p.Line < next.Line) next = p;
            }
            if (at == null)
            {
                why = next == null ? "no listed procedure is in " + module
                                   : module + ":" + line + " is above the first listed procedure";
                return null;
            }
            // FAIL CLOSED on an unknown end (PM ruling, codex adversary, pipeline run 2). The bundled engine sends
            // endLine for every procedure since e049e07, and it ships in this addin with the host, so a
            // procedure WITHOUT one means the two have come apart. Bounding it by the next procedure's start
            // instead - the fallback this replaced - attributed module data between A's end and B's start to A.
            if (at.EndLine <= 0)
            {
                why = "the debugger does not know where " + at.Name + " ends (the engine sent no endLine: an engine/host"
                    + " version mismatch - reinstall the CA Debugger so both come from one build)";
                return null;
            }
            if (line <= at.EndLine) return at;
            why = module + ":" + line + " is past the end of " + at.Name + " (line " + at.EndLine + "), outside every listed procedure";
            return null;
        }    }

    /// <summary>What one listed procedure row means: the definition its id stands for.</summary>
    internal sealed class ProcRef
    {
        public string Name;
        public string Module;
        public int Line;
        public string Kind;   // procedure | method | routine
        public int EndLine;   // last source line when the engine reported one, else 0 = unknown
    }

    /// <summary>The edit tuples the host has ISSUED for the rows currently on screen.
    /// <para>
    /// A value cell carries its row's address, type code, size and scale, and the page sends them back when
    /// the user edits it. They used to go straight to SetVariable, so the page - and anything that could put
    /// a message on the bridge - could write to any address in the debuggee under any type it named. Only
    /// the value is the user's; the rest must be something the host itself sent for a row that is still
    /// current. So every editable row is recorded on the way OUT, and an edit whose tuple is not in here is
    /// refused.
    /// </para>
    /// <para>
    /// CURRENT means "since the last stop, resume, or thread switch": the owner clears this at each, and the
    /// replies that follow refill it. A grant is scoped to the thread the row was read on; a row the engine
    /// did not stamp (an expanded reference) is granted UNSCOPED and accepts any thread, which is safe
    /// because the engine refuses a write whose thread is not the selected one on its own.
    /// </para>
    /// <para>
    /// BOUNDED: past <see cref="MaxGrants"/> further rows are simply not granted, which fails closed - an
    /// edit on one of them is refused and says why - rather than growing without limit on a huge tree.
    /// </para></summary>
    internal sealed class EditGrants
    {
        public const int MaxGrants = 50000;
        private readonly HashSet<string> _keys = new HashSet<string>(StringComparer.Ordinal);
        // EXPAND is issued the same way as EDIT (afbc68c7, codex security gate). An expand names a module, a
        // type and an ADDRESS, and the engine renders that type's members at that address - edit metadata
        // included. Forwarded unchecked, a forged expand at any address minted grants for every member it
        // rendered: an arbitrary-address write by two requests instead of one. So the expandable tuples
        // the host issued are recorded like edit tuples, an expand is forwarded only for one of them, and
        // an expand reply grants its rows only when the host forwarded that request (_expandsInFlight).
        private readonly HashSet<string> _expandable = new HashSet<string>(StringComparer.Ordinal);
        private readonly HashSet<string> _expandsInFlight = new HashSet<string>(StringComparer.Ordinal);

        /// <summary>The number of EDIT tuples granted.</summary>
        public int Count { get { return _keys.Count; } }

        /// <summary>The number of EXPANDABLE tuples issued.</summary>
        public int ExpandableCount { get { return _expandable.Count; } }

        /// <summary>Retire everything: edit grants, expandable rows and forwarded expands. One clear, so no
        /// clear site can retire one family and leave the other live.</summary>
        public void Clear() { _keys.Clear(); _expandable.Clear(); _expandsInFlight.Clear(); _writesInFlight.Clear(); }

        // A grant is CONSUMED by the write it authorises (afbc68c7, codex security gate): otherwise one grant
        // let the same write be replayed for the rest of the pause. The consumed key waits here, by address,
        // for the engine's reply to that write - the reply is what re-issues it, so the row the user just
        // edited can be edited again. A clear drops these too: a reply after a stop must not resurrect a
        // grant for a row that is no longer on screen.
        //
        // ONE WRITE PER ADDRESS AT A TIME (codex security, pipeline run 2). The engine's varset reply names only
        // the address, so with two writes in flight to one va - two issued tuples, e.g. two type or thread views
        // of it - the first reply could not tell which spent grant was its own, and re-issued BOTH before the
        // second write was answered. A second write to an address whose write is pending is refused instead
        // (IsWritePending), so each reply re-issues exactly the one grant its own write spent.
        private readonly Dictionary<string, string> _writesInFlight =
            new Dictionary<string, string>(StringComparer.Ordinal);

        /// <summary>True while a write to <paramref name="va"/> has been sent and not yet answered.</summary>
        public bool IsWritePending(string va)
        {
            return !string.IsNullOrEmpty(va) && _writesInFlight.ContainsKey(va.ToUpperInvariant());
        }

        /// <summary>Check AND spend the grant for this tuple: true when it was granted and no other write to its
        /// address is pending, in which case it is no longer granted until <see cref="Regrant"/> is called for
        /// that address.</summary>
        public bool TryConsume(string va, string typeCode, int size, int places, uint? tid)
        {
            if (string.IsNullOrEmpty(va) || string.IsNullOrEmpty(typeCode)) return false;
            if (IsWritePending(va)) return false;
            string scoped = tid.HasValue ? Key(va, typeCode, size, places, TidKey(tid)) : null;
            string key = (scoped != null && _keys.Contains(scoped)) ? scoped
                       : _keys.Contains(Key(va, typeCode, size, places, Unscoped)) ? Key(va, typeCode, size, places, Unscoped)
                       : null;
            if (key == null) return false;
            _keys.Remove(key);
            _writesInFlight[va.ToUpperInvariant()] = key;
            return true;
        }

        /// <summary>The write to <paramref name="va"/> has been answered (or never left): re-issue the one grant
        /// it spent, so the refreshed row is editable again.</summary>
        public void Regrant(string va)
        {
            if (string.IsNullOrEmpty(va)) return;
            string vaKey = va.ToUpperInvariant();
            string spent;
            if (!_writesInFlight.TryGetValue(vaKey, out spent)) return;
            _writesInFlight.Remove(vaKey);
            if (_keys.Count + _expandable.Count < MaxGrants) _keys.Add(spent);
        }

        /// <summary>Record an expandable row (a lazy reference / array-element group node) the host issued.</summary>
        public void GrantExpandable(string module, uint typeRef, string addr)
        {
            if (string.IsNullOrEmpty(module) || string.IsNullOrEmpty(addr)) return;
            if (_keys.Count + _expandable.Count >= MaxGrants) return;
            _expandable.Add(ExpandKey(module, typeRef, addr));
        }

        /// <summary>True when this exact (module, typeRef, addr) is a row the host issued for the rows now
        /// current. Anything else is a forged or stale expand and is not forwarded.</summary>
        public bool IsExpandIssued(string module, uint typeRef, string addr)
        {
            if (string.IsNullOrEmpty(module) || string.IsNullOrEmpty(addr)) return false;
            return _expandable.Contains(ExpandKey(module, typeRef, addr));
        }

        /// <summary>The host forwarded expand <paramref name="reqId"/> to the engine after verifying it.</summary>
        public void ExpandForwarded(int reqId) { _expandsInFlight.Add(reqId.ToString(CultureInfo.InvariantCulture)); }

        /// <summary>Consume the record that <paramref name="reqId"/> was a verified, forwarded expand. False
        /// for a reply the host never asked for, or one from before the last clear; its rows grant nothing.</summary>
        public bool ExpandVerified(string reqId) { return reqId != null && _expandsInFlight.Remove(reqId); }

        private static string ExpandKey(string module, uint typeRef, string addr)
        {
            return module.ToUpperInvariant() + "|" + typeRef.ToString(CultureInfo.InvariantCulture) + "|" + addr.ToUpperInvariant();
        }

        /// <summary>Record one editable tuple. Rows with no address or type code are not editable and are
        /// ignored.</summary>
        public void Grant(string va, string typeCode, int size, int places, uint? tid)
        {
            if (string.IsNullOrEmpty(va) || string.IsNullOrEmpty(typeCode)) return;
            if (_keys.Count + _expandable.Count >= MaxGrants) return;
            _keys.Add(Key(va, typeCode, size, places, TidKey(tid)));
        }

        /// <summary>Record every editable row, and every EXPANDABLE row, inside an engine row array body (the
        /// text between the brackets, exactly as it is forwarded to the page), children included.</summary>
        public void GrantRows(string itemsJson, uint? tid)
        {
            if (string.IsNullOrEmpty(itemsJson)) return;
            JsonMessageReader.ForEachObject("[" + itemsJson + "]", o =>
            {
                if (JsonMessageReader.ReadField(o, "ref") == "true")
                {
                    uint typeRef;
                    if (PageNumbers.TryUInt(JsonMessageReader.ReadField(o, "typeRef"), out typeRef))
                        GrantExpandable(JsonMessageReader.ReadField(o, "module"), typeRef, JsonMessageReader.ReadField(o, "addr"));
                }
                string va = JsonMessageReader.ReadField(o, "va");
                string tc = JsonMessageReader.ReadField(o, "typeCode");
                if (va == null || tc == null) return;
                int size, places;
                PageNumbers.TryInt(JsonMessageReader.ReadField(o, "size"), out size);
                if (!PageNumbers.TryInt(JsonMessageReader.ReadField(o, "places"), out places)) places = 0;
                Grant(va, tc, size, places, tid);
            });
        }

        /// <summary>True when this exact tuple was issued for the thread the page names, or issued unscoped.
        /// A page with no thread selection (null) matches only an unscoped grant.</summary>
        public bool IsGranted(string va, string typeCode, int size, int places, uint? tid)
        {
            if (string.IsNullOrEmpty(va) || string.IsNullOrEmpty(typeCode)) return false;
            return (tid.HasValue && _keys.Contains(Key(va, typeCode, size, places, TidKey(tid))))
                || _keys.Contains(Key(va, typeCode, size, places, Unscoped));
        }

        private const string Unscoped = "*";

        // 0 is not a thread (the absent-tid rule), so it scopes nothing.
        private static string TidKey(uint? tid)
        {
            return tid.HasValue && tid.Value != 0 ? tid.Value.ToString(CultureInfo.InvariantCulture) : Unscoped;
        }

        // Hex is compared without regard to case: both come from the engine's own formatting, but the page
        // round-trips them through the DOM and nothing about a hex digit's case is meaningful.
        private static string Key(string va, string typeCode, int size, int places, string tid)
        {
            return va.ToUpperInvariant() + "|" + typeCode.ToUpperInvariant() + "|"
                 + size.ToString(CultureInfo.InvariantCulture) + "|"
                 + places.ToString(CultureInfo.InvariantCulture) + "|" + tid;
        }
    }
}
