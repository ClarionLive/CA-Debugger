using System;
using System.Collections.Generic;
using System.Globalization;
using ClarionDebugger.Services;
using ClarionDebugger.Wire;

namespace ClarionDebugger.Terminal
{
    // The host's STATEFUL authorization: what it issued to the page, and so what it will honour coming back.
    // Split out of PageMessages.cs (6ac29815 #4) and moved unchanged; ListedProcesses, added there later, stays there.

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
            // FAIL CLOSED on an unknown end (PM ruling, codex adversary, pipeline run 2). Bounding it by the next
            // procedure's start instead - the fallback this replaced - attributed module data between A's end and
            // B's start to A. The CAUSE is worded by what the engine sent (f1a98318): "extent":"unknown" is a
            // same-build engine that could not bound this procedure from the debug info, while neither member is
            // an engine too old to send extents, the only case a reinstall fixes.
            if (at.EndLine <= 0)
            {
                why = at.ExtentUnknown
                    ? "the debug info does not say where " + at.Name + " ends, so the debugger cannot tell whether line "
                      + line + " is inside it - break on its entry from the Procedures list instead"
                    : "the debugger does not know where " + at.Name + " ends (the engine sent no extent at all: an"
                      + " engine/host version mismatch - reinstall the CA Debugger so both come from one build)";
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
        public bool ExtentUnknown;   // the engine sent "extent":"unknown": it could not bound this one (f1a98318)
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
    /// CURRENT means "since the last stop, resume, or thread switch": a stop or a switch moves the service's
    /// selection epoch, which this table checks on every call and retires itself on; the owner clears it at a
    /// resume, which moves none. The replies that follow refill it. A grant is scoped to the thread the row
    /// was read on; a row the engine did not stamp (an expanded reference) is granted UNSCOPED and accepts any
    /// thread, which is safe because the engine refuses a write whose thread is not the selected one on its own.
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
        // FRAME LOCALS are issued the same way (49538b78 wave 5, codex adversary). A framelocals request names
        // a procedure VA and an EBP, and the engine renders that procedure's locals at EBP + each local's
        // offset - edit metadata included. Forwarded unchecked, a real VA with a made-up EBP minted grants at
        // addresses the page chose. So the (va, ebp) of every frame a stack reply offered is recorded, and a
        // framelocals reply grants only when the host forwarded that request for one of them.
        //
        // BOUND TO THE SELECTED THREAD AND THE EPOCH (49538b78 wave 5 run 2, codex security + adversary). The
        // request names no thread, and every stack reply used to offer its frames whatever thread it was for:
        // a late reply for thread A, landing after a switch to B, re-offered A's (va, ebp); the page's request
        // for it was forwarded, and the engine rendered A's locals at A's EBP in a reply stamped and granted
        // for B. Now a stack reply offers only when it answers a stack request made in the CURRENT epoch (a
        // clear - stop, resume, thread switch - starts a new one) and is for the thread the host has
        // selected. WHICH request it answers is proven by the id the engine echoes (run 3, codex security +
        // adversary): a count of requests could be spent by a stale reply for the same thread - A's stack,
        // a switch to B and back to A, a new request, and the OLD reply arriving first - which carries the
        // same tid, and only its id tells it apart. A forwarded request remembers the thread of the offer it was checked against, and its
        // reply grants only when stamped for that thread; the clear that ends an epoch retires every
        // forwarded request, so a reply after it grants nothing (the epoch is not stored with the request as
        // well: with the clear in front of it, that comparison could never fail).
        //
        // THE SELECTED THREAD IS THE SERVICE'S (49538b78 8b). This table kept its own copy, set by the pad at
        // a stop and a switch and by nothing else, so an inventory that moved the selection left it behind.
        // It now reads the service's selection when a reply arrives. The read is on the UI thread and may be
        // AHEAD of the event being handled there; ahead can only mean a newer epoch or another thread, so it
        // refuses an offer and never makes one.
        //
        // THE WHOLE TABLE BELONGS TO ONE SELECTION EPOCH (3517fd15). Everything in it - grants, offers, and the
        // ids of the requests whose replies may grant - was issued under _epoch, and every public member first
        // compares that with the service's epoch NOW (Sync): a selection that has moved retires the lot, before
        // anything is checked or recorded. That is what binds an outstanding id to the epoch it was sent in (a
        // per-id epoch beside it could never fail), and it is the ONLY way a selection move clears this table.
        // The pad used to clear it from each move's handler, marshalled to the UI thread, so a request bound on
        // that thread in between was wiped by the clear queued before it (debugger L2, wave 6). There is no
        // marshalled clear for a move any more, so there is nothing to arrive out of order: whatever runs first
        // after the move observes it and clears, and everything it records is the new epoch's.
        private readonly HashSet<string> _framesOffered = new HashSet<string>(StringComparer.Ordinal);
        private uint? _framesTid;          // the thread the current offer came from
        private readonly Func<ThreadSelection> _selection;   // the service's selected thread, read, never kept
        private int _epoch;                // the selection epoch everything in this table was issued under
        private readonly HashSet<string> _stackIds = new HashSet<string>(StringComparer.Ordinal);  // stack requests sent this epoch, unanswered
        // WATCH and MODULEDATA requests sent this epoch, unanswered (3517fd15, codex adversary wave 6). Their
        // replies grant edit tuples, and used to grant whatever request they answered - a reply delayed past a
        // resume and a new stop re-granted a row from the old pause. Now only a reply echoing one of these ids
        // grants; a reply with no id (an older engine) is shown and grants nothing.
        private readonly HashSet<string> _readIds = new HashSet<string>(StringComparer.Ordinal);
        private uint _nextRequestId;       // never reset: an id is unique for the session
        private readonly Dictionary<string, uint?> _frameLocalsInFlight =
            new Dictionary<string, uint?>(StringComparer.Ordinal);

        /// <param name="selection">The service's current selected thread (ClarionDebuggerService.Selection).</param>
        public EditGrants(Func<ThreadSelection> selection)
        {
            _selection = selection ?? (() => ThreadSelection.None);
        }

        /// <summary>The number of EDIT tuples granted.</summary>
        public int Count { get { Sync(); return _keys.Count; } }

        /// <summary>The number of EXPANDABLE tuples issued.</summary>
        public int ExpandableCount { get { Sync(); return _expandable.Count; } }

        /// <summary>Retire everything: edit grants, expandable rows, offered frames and every forwarded or
        /// outstanding request, so a reply to a request sent before now grants and offers nothing. One clear,
        /// so no clear site can retire one family and leave another live. Unconditional: for a session's end.</summary>
        public void Clear()
        {
            _keys.Clear(); _expandable.Clear(); _expandsInFlight.Clear(); _writesInFlight.Clear();
            _framesOffered.Clear(); _framesTid = null; _frameLocalsInFlight.Clear();
            _stackIds.Clear(); _readIds.Clear();
        }

        /// <summary>The target resumed while <paramref name="epoch"/> was the selection, as read on the thread that
        /// raised the resume. A resume moves no selection, so Sync cannot see it: this retires what was issued in that
        /// epoch - every row on screen is now stale - and spares only a table that has already moved on to a newer one
        /// (a stop after the resume, observed before this marshalled call ran).</summary>
        public void Resumed(int epoch)
        {
            if (epoch < _epoch) return;
            Clear();
            _epoch = epoch;
        }

        /// <summary>Bring the table to the service's epoch NOW, retiring everything first when it has moved: a stop,
        /// an accepted switch, or an inventory that disagreed with the host. Every member that reads, checks or
        /// records calls it before anything else.</summary>
        private void Sync()
        {
            int now = _selection().Epoch;
            if (now == _epoch) return;
            Clear();
            _epoch = now;
        }

        /// <summary>A fresh request id, never issued before in this session: the ONE source for every request
        /// whose reply the table will match by id (stack, watch, moduledata).</summary>
        public string NewRequestId()
        {
            _nextRequestId++;
            return _nextRequestId.ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>The host sent stack request <paramref name="id"/> under the service's current selection.</summary>
        public void StackRequested(string id) { Sync(); if (!string.IsNullOrEmpty(id)) _stackIds.Add(id); }

        /// <summary>The host sent a watch or moduledata request <paramref name="id"/> under the service's current
        /// selection: its reply may grant (<see cref="ReadAnswered"/>).</summary>
        public void ReadRequested(string id) { Sync(); if (!string.IsNullOrEmpty(id)) _readIds.Add(id); }

        /// <summary>A watch or moduledata reply echoing <paramref name="reqId"/> arrived: true when it may GRANT its
        /// rows, i.e. it answers a request sent in the current epoch and not yet answered (it is answered now).
        /// False for no id at all (an engine that predates the echo: the reply is shown, read-only), one from
        /// before the selection moved or the target resumed, one never sent, or one already answered.</summary>
        public bool ReadAnswered(string reqId)
        {
            Sync();
            return reqId != null && _readIds.Remove(reqId);
        }

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
            Sync();
            return !string.IsNullOrEmpty(va) && _writesInFlight.ContainsKey(va.ToUpperInvariant());
        }

        /// <summary>Check AND spend the grant for this tuple: true when it was granted and no other write to its
        /// address is pending, in which case it is no longer granted until <see cref="Regrant"/> is called for
        /// that address.</summary>
        public bool TryConsume(string va, string typeCode, int size, int places, uint? tid)
        {
            Sync();
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
            Sync();
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
            Sync();
            if (string.IsNullOrEmpty(module) || string.IsNullOrEmpty(addr)) return;
            if (_keys.Count + _expandable.Count >= MaxGrants) return;
            _expandable.Add(ExpandKey(module, typeRef, addr));
        }

        /// <summary>True when this exact (module, typeRef, addr) is a row the host issued for the rows now
        /// current. Anything else is a forged or stale expand and is not forwarded.</summary>
        public bool IsExpandIssued(string module, uint typeRef, string addr)
        {
            Sync();
            if (string.IsNullOrEmpty(module) || string.IsNullOrEmpty(addr)) return false;
            return _expandable.Contains(ExpandKey(module, typeRef, addr));
        }

        /// <summary>The host forwarded expand <paramref name="reqId"/> to the engine after verifying it.</summary>
        public void ExpandForwarded(int reqId) { Sync(); _expandsInFlight.Add(reqId.ToString(CultureInfo.InvariantCulture)); }

        /// <summary>Consume the record that <paramref name="reqId"/> was a verified, forwarded expand. False
        /// for a reply the host never asked for, or one from before the last clear; its rows grant nothing.</summary>
        public bool ExpandVerified(string reqId) { Sync(); return reqId != null && _expandsInFlight.Remove(reqId); }

        /// <summary>A stack reply for <paramref name="tid"/>, echoing request <paramref name="reqId"/>, carried
        /// exactly these frames, each a (va, ebp) pair. They are OFFERED, replacing the previous offer, only when
        /// <paramref name="reqId"/> is a request sent since the last clear and not yet answered (it is answered
        /// now, and cannot offer again), the service's selection is still the one it was sent under (same
        /// epoch), and <paramref name="tid"/> is that selection's thread; otherwise nothing is
        /// offered and false is returned. A frame with no VA, or with the engine's "unknown" EBP (0x0), offers
        /// nothing: the page never asks about one.</summary>
        public bool OfferFrames(uint? tid, string reqId, IEnumerable<KeyValuePair<string, string>> vaEbp)
        {
            // Sent under a selection that has since moved (a stop, a switch, an inventory that disagreed): Sync
            // retires it here, with everything else from that epoch.
            Sync();
            // An id from before the last clear, one never sent, one already answered, or none at all. It is
            // answered either way: a live id stamped for another thread spends it too.
            if (reqId == null || !_stackIds.Remove(reqId)) return false;
            var sel = _selection();
            // A live id is the selected thread's request, so a reply stamped otherwise comes from an engine
            // that does not agree about the selection: its frames are not the ones asked for.
            if (!WireRules.TidIsKnown(tid) || tid != sel.Tid) return false;
            _framesOffered.Clear();
            _framesTid = tid;
            if (vaEbp != null)
                foreach (var f in vaEbp)
                    if (!string.IsNullOrEmpty(f.Key) && !string.IsNullOrEmpty(f.Value) && f.Value != "0x0")
                        _framesOffered.Add(FrameKey(f.Key, f.Value));
            return true;
        }

        /// <summary>True when this exact (va, ebp) is a frame the current offer holds. The offer is the selected
        /// thread's: only its replies offer, and the clear in front of every selection change empties it.</summary>
        public bool IsFrameOffered(string va, string ebp)
        {
            Sync();
            if (string.IsNullOrEmpty(va) || string.IsNullOrEmpty(ebp)) return false;
            return _framesOffered.Contains(FrameKey(va, ebp));
        }

        /// <summary>The host forwarded framelocals <paramref name="reqId"/> to the engine after checking it
        /// against the current offer: the offer's thread goes with it.</summary>
        public void FrameLocalsForwarded(int reqId)
        {
            Sync();
            _frameLocalsInFlight[reqId.ToString(CultureInfo.InvariantCulture)] = _framesTid;
        }

        /// <summary>Consume the record that <paramref name="reqId"/> was a verified, forwarded framelocals, and
        /// say whether its reply may grant: only when it is stamped with the thread whose offer the request was
        /// checked against. False for a reply the host never asked for, one from before the last clear, or one
        /// for another thread; its rows grant nothing.</summary>
        public bool FrameLocalsVerified(string reqId, uint? replyTid)
        {
            Sync();
            uint? sentTid;
            if (reqId == null || !_frameLocalsInFlight.TryGetValue(reqId, out sentTid)) return false;
            _frameLocalsInFlight.Remove(reqId);
            return WireRules.TidIsKnown(replyTid) && replyTid == sentTid;
        }

        private static string FrameKey(string va, string ebp)
        {
            return va.ToUpperInvariant() + "|" + ebp.ToUpperInvariant();
        }

        private static string ExpandKey(string module, uint typeRef, string addr)
        {
            return module.ToUpperInvariant() + "|" + typeRef.ToString(CultureInfo.InvariantCulture) + "|" + addr.ToUpperInvariant();
        }

        /// <summary>Record one editable tuple. Rows with no address or type code are not editable and are
        /// ignored.</summary>
        public void Grant(string va, string typeCode, int size, int places, uint? tid)
        {
            Sync();
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
                PageNumbers.ReadEditTuple(o, out size, out places);
                Grant(va, tc, size, places, tid);
            });
        }

        /// <summary>True when this exact tuple was issued for the thread the page names, or issued unscoped.
        /// A page with no thread selection (null) matches only an unscoped grant.</summary>
        public bool IsGranted(string va, string typeCode, int size, int places, uint? tid)
        {
            Sync();
            if (string.IsNullOrEmpty(va) || string.IsNullOrEmpty(typeCode)) return false;
            return (tid.HasValue && _keys.Contains(Key(va, typeCode, size, places, TidKey(tid))))
                || _keys.Contains(Key(va, typeCode, size, places, Unscoped));
        }

        private const string Unscoped = "*";

        // 0 is not a thread (the absent-tid rule), so it scopes nothing.
        private static string TidKey(uint? tid)
        {
            return WireRules.TidIsKnown(tid) ? tid.Value.ToString(CultureInfo.InvariantCulture) : Unscoped;
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
