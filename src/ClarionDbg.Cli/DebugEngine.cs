using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    /// <summary>A requested breakpoint location (module:line) plus optional advanced properties
    /// (conditional / hit count / tracepoint), resolved and planted by the engine.</summary>
    internal sealed class BpSpec
    {
        public readonly string Module;
        public readonly int Line;
        public string Condition;   // null = unconditional
        public string HitMode;     // null | "eq" (=N) | "gte" (>=N) | "mod" (every Nth)
        public int HitValue;       // N for the hit-count rule
        public string Trace;       // non-null = tracepoint message

        /// <summary>The OWNING IMAGE the caller means, or null when it did not say.
        /// <para>
        /// <see cref="Module"/> is a bare .clw BASENAME, and in a multi-DLL app two loaded images can each
        /// carry a compiland of that name. Without this, `bp add clbrws011.clw:50` can only ever mean "the
        /// first image that happens to carry it" - so the second DLL's breakpoint was never armed and the
        /// user's gutter dot silently never fired (task af81c054).
        /// </para>
        /// <para>
        /// NULL MEANS UNQUALIFIED, not "no image": the caller did not name one, and the engine arms the
        /// breakpoint in every loaded image carrying the compiland (one image, for |one=1). An older host,
        /// which sends nothing but a bare basename, gets exactly that.
        /// </para></summary>
        public string Image;

        /// <summary>The caller wants this breakpoint in exactly ONE image, even if several carry the
        /// compiland and it named none (<c>|one=1</c>).
        /// <para>
        /// It was added for run-to-cursor, which is composed host-side as <c>bp add</c> + <c>continue</c>.
        /// From wave 7 (2026-09-25) the host sends that transient WITHOUT it, as a plain unqualified add
        /// armed in every image carrying the compiland, and removes every copy with one <c>bp del</c> at the
        /// stop (contract C3). Nothing sends it now; it is still parsed and honoured - see
        /// <see cref="DebugEngine.AddBreakpoint"/>.
        /// </para>
        /// <para>
        /// DEFAULT FALSE IS DELIBERATE. An older host sends neither <c>img=</c> nor <c>one=</c>, and it
        /// must get the fixed behaviour rather than opt into it - a host that cannot be updated is exactly
        /// the one whose second-DLL breakpoints silently never fired before this change.
        /// </para></summary>
        public bool One;

        public BpSpec(string module, int line) { Module = module; Line = line; }

        /// <summary>Parse one space-free breakpoint spec token: <c>module:line</c> optionally followed by
        /// <c>|img=&lt;base64&gt;|c=&lt;base64&gt;|hm=eq|hv=5|t=&lt;base64&gt;</c>. Free-text fields
        /// (image, condition, trace) are base64(UTF-8) so they survive the line/space-split CLI + stdin
        /// protocol without quoting or injection risk. Returns false if the head isn't a valid module:line.
        /// <para>
        /// AN UNRECOGNISED SEGMENT IS IGNORED, AND THAT IS LOAD-BEARING, not laziness. The switch below has
        /// no <c>default:</c>, so a segment this build does not know about is skipped and the segments
        /// AFTER it are still read. That is what makes the spec extensible in BOTH directions with no
        /// version negotiation: an engine older than <c>img=</c> ignores it and arms the way it always did,
        /// and this engine given no <c>img=</c> arms unqualified. Verified against the real
        /// pre-change parser in tools/test-engine-bpowner.ps1 rather than assumed - it is the entire
        /// compatibility argument for the grammar, so it is checked instead of being reasoned about.
        /// </para></summary>
        public static bool TryParse(string spec, out BpSpec result)
        {
            result = null;
            if (string.IsNullOrEmpty(spec)) return false;
            var segs = spec.Split('|');
            string head = segs[0];
            int colon = head.LastIndexOf(':');
            if (colon <= 0) return false;
            int line;
            if (!int.TryParse(head.Substring(colon + 1), out line)) return false;
            var bp = new BpSpec(head.Substring(0, colon), line);
            for (int i = 1; i < segs.Length; i++)
            {
                string s = segs[i];
                int eq = s.IndexOf('=');
                if (eq <= 0) continue;
                string key = s.Substring(0, eq);
                string val = s.Substring(eq + 1);
                switch (key)
                {
                    case "c":  bp.Condition = DecodeB64(val); break;
                    case "hm": bp.HitMode = (val == "eq" || val == "gte" || val == "mod") ? val : null; break;
                    case "hv": int hv; bp.HitValue = int.TryParse(val, out hv) ? hv : 0; break;
                    case "t":  bp.Trace = DecodeB64(val); break;
                    // Base64 for the same reason c= and t= are, and it is not optional here: an image path
                    // carries backslashes, spaces and a drive colon, and the protocol is line- and
                    // space-split. It cannot travel in the module field either - the host's
                    // IsValidModuleName allows only [A-Za-z0-9_.-], which is the guard against argument
                    // smuggling and stays.
                    // FAILS CLOSED (af81c054, pipeline run 1): a PRESENT img= that is empty, oversized, not
                    // base64 or carries a control character rejects the whole spec. Decoding it to null made
                    // it "unqualified", so a del meant for one image removed every copy.
                    case "img":
                    {
                        string img;
                        if (!TryDecodeImage(val, out img)) return false;
                        bp.Image = img;
                        break;
                    }
                    case "one": bp.One = (val == "1" || val == "true"); break;
                }
            }
            result = bp;
            return true;
        }

        /// <summary>Longest encoded img= accepted: 4096 base64 chars, about 3 KB of path, well above
        /// MAX_PATH and bounded so a pending entry cannot pin an arbitrarily large string.</summary>
        public const int MaxImageB64 = 4096;

        public static bool TryDecodeImage(string b64, out string image)
        {
            image = null;
            if (string.IsNullOrEmpty(b64) || b64.Length > MaxImageB64) return false;
            string s = DecodeB64(b64);
            if (string.IsNullOrEmpty(s)) return false;
            foreach (char c in s) if (c < 0x20 || c == 0x7F) return false;
            image = s;
            return true;
        }

        private static string DecodeB64(string b64)
        {
            if (string.IsNullOrEmpty(b64)) return null;
            try { return System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(b64)); }
            catch { return null; }
        }
    }

    /// <summary>One resolved call-stack frame (frame 0 = current EIP, rest = return addresses).</summary>
    internal sealed class StackFrame
    {
        public uint Rva;
        public uint Va;
        public uint StackAddr;     // stack slot holding the return address (0 for frame 0)
        public uint Ebp;           // this frame's base pointer (for reading its locals); 0 = unknown (scan/FPO frame)
        public string Proc;        // demangled symbol, null when unknown
        public string Kind;        // procedure | method | routine | other, null when unknown
        public string Module;      // .clw name, null when unresolved
        public int Line;
        public bool Uncertain;     // recovered by ScanStack's raw-memory heuristic, not the EBP chain —
                                    // may be a stale leftover return address rather than a real caller
    }

    /// <summary>One logical user breakpoint: a module:line bound to its code RVAs in the owning image.</summary>
    internal sealed class UserBreakpoint
    {
        public string Module;          // canonical compiland name (e.g. clbrws011.clw)
        public int ModuleIdx;          // index within Owner.Dbg (valid once Owner is set)
        public LoadedModule Owner;     // the mapped/known image whose TSWD carries this compiland; null = pending

        /// <summary>The owning image the CALLER named (<c>bp add m:l|img=...</c>), or null when it named
        /// none. Distinct from <see cref="Owner"/>, which is the image actually bound: this is the REQUEST
        /// and it is kept because a breakpoint set before launch is pending until its image maps, and
        /// <c>ResolvePendingFor</c> must then bind it to the image that was ASKED FOR rather than to the
        /// first one that happens to carry the compiland.
        /// <para>
        /// Null = unqualified = armed in every carrying image. See <see cref="BpSpec.Image"/>.
        /// </para></summary>
        public string OwnerSpec;

        /// <summary>The CALLER ASKED for a single target (<see cref="BpSpec.One"/>), so a later image
        /// carrying the same compiland must NOT get a copy of this breakpoint.
        /// <para>
        /// Named for what it is: a demand from whoever created the breakpoint, not a property of the
        /// breakpoint itself. Nothing about a breakpoint makes it single-target - a run-to-cursor and a
        /// gutter dot at the same module:line are identical down here, which is exactly why the request
        /// has to travel with it. Carried on the record because the images that would trigger a copy map
        /// long after the add was handled.
        /// </para></summary>
        public bool SingleTargetRequested;
        public int RequestedLine;      // the line the user asked for
        public int Line;               // the line actually planted (snapped to nearest record line)
        public readonly List<uint> Rvas = new List<uint>();   // code RVAs within Owner
        public bool Pending { get { return Owner == null; } } // owning image not yet loaded/resolved

        // ---- advanced breakpoint properties (conditional / hit count / tracepoint) ----
        public string Condition;       // expression evaluated on hit; false ⇒ resume silently (null = unconditional)
        public string HitMode;         // null | "eq" (=N) | "gte" (>=N) | "mod" (every Nth); applied AFTER condition passes
        public int HitValue;           // N for the hit-count rule
        public string Trace;           // non-null ⇒ tracepoint: interpolate {var} tokens, log to Console, resume (never pause)
        public int HitCount;           // runtime: times this breakpoint's condition has been satisfied (drives HitMode)
    }

    /// <summary>
    /// x86 debug engine: launches a target under the Windows debug API, plants INT3 breakpoints,
    /// pumps the debug-event loop, and resolves hits to module + source line via TSWD info.
    ///
    /// Phase 2 adds:
    ///  - persistent breakpoints (re-armed after each hit via a TF single-step over the original byte)
    ///  - multiple module:line breakpoints, with runtime add/remove
    ///  - an interactive stdin command loop while paused: continue / step / stepover / stepout /
    ///    bp add|del|list / mem / regs / quit  (while running: bp add|del|list / quit)
    ///  - source-level stepping driven by the TF single-step flag + the +0x1C line table, with a
    ///    call-skip optimization (temp INT3 at the return address) so callees run at full speed —
    ///    no x86 instruction decoder needed.
    /// </summary>
    internal sealed partial class DebugEngine
    {
        private enum StepMode { None, Into, Over, Out, OverInstr }

        private const uint TRAP_FLAG = 0x100;        // EFLAGS TF bit
        private const int MAX_STEPS = 2000000;       // hard cap of single-steps per step command
        private const uint CALL_WINDOW = 8;          // max CALL instr length for return-addr detection
        // ONE meaning, and it is the declared one: a callee with a line record this close to entry is
        // Clarion code (StepMachine's `follow` test). It was ALSO being used as "am I still inside the
        // prologue" in BeginStep, where 0x100 let a start point 256 bytes into the procedure BODY count as
        // "at entry" and disable the ESP gate. That test now measures against the procedure's own first line
        // record instead (FirstRecordRvaInProc) and needs no constant, so this one is not reused.
        private const uint PROLOGUE_WINDOW = 0x100;  // callee with a line record this close to entry is Clarion code
        private const uint ESP_SLACK = 0x10;         // frame-depth slack for step-over stop checks
        private const uint OUT_GAP_MAX = 0x200;      // step-out: max gap for "this looks like the call statement"

        private readonly string _exePath;
        private readonly bool _once;
        private readonly int _waitMs;
        private readonly bool _interactive;
        private readonly List<uint> _rawRvas;
        private readonly List<BpSpec> _initialSpecs;

        /// <summary>When true, emit one machine-readable JSON object per event (for the IDE addin).</summary>
        public bool EmitJson;

        // The module table: the EXE (module 0) plus every loaded DLL. Pre-launch, the EXE and any
        // solution DLLs are present with LoadBase==0 (not yet mapped) so breakpoints resolve against
        // their TSWD before launch; the live base is filled in at CREATE_PROCESS / LOAD_DLL.
        private readonly List<LoadedModule> _modules = new List<LoadedModule>();
        private LoadedModule _exe;           // module 0 — the launched image

        private IntPtr _hProcess = IntPtr.Zero;
        // The debuggee's pid, from CREATE_PROCESS. INVARIANT: valid exactly when _hProcess is non-zero —
        // the two are assigned together from the same CREATE_PROCESS event (header pid, hProcess at +16), in
        // launch and attach alike, and cleared together when a detach lets go.
        // ProcessId() enforces that rather than trusting it, because a pid left behind for a process we no
        // longer hold reads as a live process, which is the same defect class as a sentinel thread id.
        private uint _pid;
        private bool _seenInitialBreak;
        public int Hits { get; private set; }

        // ---- pause (break into a running target) ----
        // DebugBreakProcess injects a breakpoint on a throwaway OS thread; when that break arrives we
        // pick the app thread actually in Clarion code and pause there. Live thread ids are tracked so
        // we can scan them at pause time (the injected thread is not the one the user cares about).
        private bool _pauseRequested;
        private readonly HashSet<uint> _threads = new HashSet<uint>();
        private uint _mainTid;               // first thread (from CREATE_PROCESS) — pause fallback

        // Creation order per live tid (0 = the CREATE_PROCESS main thread, then 1,2,… as CREATE_THREAD
        // events arrive). A HashSet has no order, and "which thread is newest" is exactly the question a
        // pause has to answer — an MDI child's thread is newer than the frame's. Dropped on EXIT_THREAD so
        // a reused tid never inherits a dead thread's position; the counter itself never rewinds.
        private readonly Dictionary<uint, int> _threadSeq = new Dictionary<uint, int>();
        private int _nextThreadSeq;

        private void NoteThreadCreated(uint tid)
        {
            _threads.Add(tid);
            if (!_threadSeq.ContainsKey(tid)) _threadSeq[tid] = _nextThreadSeq++;
        }

        private void NoteThreadExited(uint tid)
        {
            _threads.Remove(tid);
            _threadSeq.Remove(tid);
        }

        /// <summary>Creation order of a live tid; int.MaxValue for one we never saw created (sorts last).</summary>
        private int SeqOf(uint tid)
        {
            int s;
            return _threadSeq.TryGetValue(tid, out s) ? s : int.MaxValue;
        }

        // ---- per-stop thread selection (`thread <tid>`) ----
        // Which thread the READ commands answer about, for THIS STOP ONLY. PausedWait resets it to the
        // stopped thread at every new stop, so a selection is never carried across one and the host can
        // never be shown a stale thread's data as if it were the new stop's. Resume-type commands always
        // act on the stopped thread and reset this first — see the command loop.
        private uint _selectedTid;

        // The throwaway ntdll thread DebugBreakProcess injected to cause THIS stop, or 0 when the stop was
        // not pause-initiated. It is a real live thread, so `threads` would list it and `thread <tid>` would
        // happily select it — a thread that exits the moment the target resumes and has nothing to do with
        // the program. PickPauseThread already skipped it; the picker has to skip it too, and only
        // OnPauseBreak knows which tid it was. Cleared when the stop ends.
        private uint _breakTid;

        /// <summary>The thread a read command should answer about: the selected one, which is usually (but
        /// not always) the stopped one. Holds the registers to read the stack/locals/disassembly at and the
        /// handle the threaded-data and Library State emulators need.</summary>
        private sealed class ThreadView
        {
            public uint Tid;
            public IntPtr HThread;
            public Native.CONTEXT_X86 Ctx;
            public bool HaveCtx;
            public bool Owned;      // true when WE opened HThread and must close it

            public void Release()
            {
                if (Owned && HThread != IntPtr.Zero) Native.CloseHandle(HThread);
                HThread = IntPtr.Zero; Owned = false;
            }
        }

        /// <summary>Build the view for the current selection. When nothing is selected, or the selection IS
        /// the stopped thread, this reuses the stopped thread's already-open handle and context and opens
        /// nothing. The whole process is frozen at a stop, so another thread's context is stable to read.</summary>
        private ThreadView AcquireView(uint stoppedTid, IntPtr stoppedH, ref Native.CONTEXT_X86 stoppedCtx, bool stoppedHave)
        {
            if (_selectedTid == 0 || _selectedTid == stoppedTid)
                return new ThreadView { Tid = stoppedTid, HThread = stoppedH, Ctx = stoppedCtx,
                                        HaveCtx = stoppedHave, Owned = false };

            var v = new ThreadView { Tid = _selectedTid };
            v.HThread = OpenThreadForContext(_selectedTid);
            v.Owned = v.HThread != IntPtr.Zero;
            // Once the handle is open, this method owns it until it returns. A throw from GetThreadContext
            // between those two points would otherwise strand it: the caller's finally releases the view it
            // was RETURNED, and on a throw it is never returned one. Not reachable in practice — which is
            // exactly why it would have leaked quietly if it ever became reachable.
            try
            {
                var c = NewContext();
                v.HaveCtx = v.HThread != IntPtr.Zero && Native.GetThreadContext(v.HThread, ref c);
                v.Ctx = c;
            }
            catch { v.Release(); throw; }
            return v;
        }

        /// <summary>Resume-type verbs the PAUSE LOOP implements. These always act on the stopped thread,
        /// never the selected one, and reset the selection before they run so the next stop is never
        /// reported against a stale view.
        ///
        /// This list must contain only verbs the pause loop's switch actually handles. It once also named
        /// pause/break/runtocursor — which the switch does NOT implement — so those reset the selection and
        /// then fell through to "unknown command": a verb that did nothing silently discarded the user's
        /// `thread &lt;tid&gt;` for the rest of the stop. They are rejected explicitly instead, below.
        ///
        /// THIS IS THE ONE OWNER of the resume-verb set. There were three hand-maintained copies: this, the
        /// pause-loop switch, and the running-state switch (the pad held a fourth until a9f3407). The
        /// running-state switch now asks this method instead of listing them again, leaving TWO sites — this
        /// one, and the pause-loop switch, whose labels dispatch to different handlers and so cannot be a
        /// list. `ClarionDbg protocolcheck` asserts the set both ways: every verb the pause loop dispatches
        /// is accepted, and the verbs the running-state switch implements itself (pause/break in particular)
        /// are rejected, because this is consulted BEFORE that switch and a wrong accept diverts them.</summary>
        private static bool IsResumeVerb(string verb)
        {
            switch (verb)
            {
                case "continue": case "c": case "g":
                case "step": case "stepinto": case "s": case "i":
                case "stepover": case "next": case "n":
                case "stepout": case "out": case "finish": case "o":
                case "stepi": case "si": case "nexti": case "ni":
                    return true;
                default:
                    return false;
            }
        }

        /// <summary>Test seam for <see cref="IsResumeVerb"/>.</summary>
        internal static bool IsResumeVerbForTest(string verb) { return IsResumeVerb(verb); }

        // ---------------------------------------------------------------- the absent-tid rule, in ONE place
        //
        // THE RULE: a thread id is either a real Win32 tid or the field is ABSENT. Never 0, never -1.
        //
        // The host treats an unstamped reply as UNSCOPED and accepts it, but reads a literal 0 (or -1) as a
        // real thread id: it then matches nothing, and the pad starts dropping replies it should have shown
        // — a silently blank panel rather than an error.
        //
        // The rule was broken THREE times in one day by two different agents (ticket a39d9477), every time on
        // a path that BYPASSED the helper the rule lived in. It lived in WithTid, which splices whole events;
        // the four hand-built emitters in DebugEngine.Threads.cs never went through it, so each either
        // re-implemented the rule or simply omitted it. So the rule now lives in ONE predicate below, and
        // BOTH writers derive from it — nothing else in the engine decides whether a tid is written.
        //
        // AND THE RULE IS NOT ABOUT THE NAME (ticket 3b043dfc). a39d9477 closed it for members literally
        // called "tid" and left three carrying a thread id under another name: the `threads` event's
        // top-level "stopped" and "selected", and `threadscan`'s top-level "stopped". Those were safe by
        // ORDERING — PausedWait sets _selectedTid before the pause loop can dispatch — while AcquireView in
        // this very file already treats _selectedTid == 0 as a state that happens. The engine did not agree
        // with itself, and that disagreement was the defect; no failure had been observed out of luck.
        // So the writer below takes the member NAME, and the names it will write are declared here, once.
        //
        // IF YOU ARE ADDING AN EMITTER: do not type the member. Call AppendTidValuedMember with one of the
        // TidMember* constants (or WithTid), and add your builder to ProtocolCheck.CheckHandBuiltTidEmitters,
        // which runs the REAL builders rather than copies of their shapes. A hand-typed `,"tid":` is the
        // exact defect this rule holder exists to stop, and no compiler can stop you typing it — but
        // tools/test-engine-tid-members.ps1 reads THIS SOURCE and fails when one is typed outside the
        // writer, which is the part protocolcheck cannot do (it has no source tree at runtime).
        //
        // WHY THIS IS NOT IN Json.cs with the other emitter helpers (f367a04f item 3, 2026-09-22): that suite and
        // tools/test-addin-json.ps1 locate the rule in THIS file by name, and the thread emitters call these
        // as DebugEngine members. Json.cs's class comment points back here.

        /// <summary>THE RULE, stated once: is this a thread id worth writing to the wire?
        ///
        /// 0 is the engine's own "no thread here" value. uint.MaxValue is the `(uint)-1` an int cast can
        /// produce — the protocol names -1 as a forbidden sentinel, and 0xFFFFFFFF is what -1 actually looks
        /// like once it reaches a uint tid, so it is rejected here rather than printed as 4294967295.</summary>
        private static bool TidIsKnown(uint tid) { return tid != 0 && tid != uint.MaxValue; }

        /// <summary>The same rule for the CONSOLE, which has no way to omit a field: an unknown id reads as
        /// "(unknown)" rather than as the number 0, so a human is not sent looking for thread 0 either.</summary>
        private static string TidText(uint tid) { return TidIsKnown(tid) ? tid.ToString() : "(unknown)"; }

        // The member names a thread id is written under. THREE of them, and the count is checkable against
        // the wire: "tid" (every stamped event, the `threads` rows and the `threadscan` rows), "stopped"
        // (the `threads` and `threadscan` events) and "selected" (the `threads` event). Emit sites pass the
        // constant, never a literal, so tools/test-engine-tid-members.ps1 can say flatly that a thread-id
        // member name typed as JSON text anywhere but the writer below is a bypass.
        //
        // NOT in this set, deliberately: "clarionThread" is the RTL's own thread NUMBER, not a Win32 tid,
        // and it already has its own absent representation (JSON null, via ClarionThreadJson). "pid" is a
        // process id. And the PER-ROW "stopped"/"selected" members of the `threads` and `threadscan` rows
        // are JSON BOOLEANS that merely share these names — the source scanner classifies those by the
        // value appended after them, not by the name, which is the distinction this note is making.
        private const string TidMemberTid = "tid";
        private const string TidMemberStopped = "stopped";
        private const string TidMemberSelected = "selected";

        /// <summary>The declared names, as one array the source scanner extracts, so the test cannot hold a
        /// second copy of the set that drifts from this one.</summary>
        private static readonly string[] TidValuedMemberNames =
            { TidMemberTid, TidMemberStopped, TidMemberSelected };

        /// <summary>Append a thread-id-valued member to an object that ALREADY has at least one member, or
        /// append nothing at all when the id is unknown. The one writer for every hand-built emitter; the
        /// leading comma is inside the guard on purpose, so an absent id cannot leave a dangling separator.
        ///
        /// The name is checked against the declared set rather than taken on trust. Every call site passes a
        /// compile-time constant, so this either throws on the first call the engine ever makes or never —
        /// it cannot begin throwing mid-session — and protocolcheck makes that first call for all three.</summary>
        private static void AppendTidValuedMember(StringBuilder sb, string name, uint tid)
        {
            if (Array.IndexOf(TidValuedMemberNames, name) < 0)
                throw new ArgumentException("not a declared thread-id member name: " + name, "name");
            if (TidIsKnown(tid)) sb.Append(",\"").Append(name).Append("\":").Append(tid);
        }

        /// <summary>The "tid" case, which is most of them.</summary>
        private static void AppendTidMember(StringBuilder sb, uint tid)
        {
            AppendTidValuedMember(sb, TidMemberTid, tid);
        }

        /// <summary>Test seams for the two writers. The rule they assert is documented above, so that
        /// deleting a seam cannot delete the rationale.</summary>
        internal static string WithTidForTest(string json, uint tid) { return WithTid(json, tid); }

        internal static string AppendTidMemberForTest(string json, uint tid)
        {
            var sb = new StringBuilder(json.Substring(0, json.Length - 1));
            AppendTidMember(sb, tid);
            return sb.Append('}').ToString();
        }

        /// <summary>The name-taking writer, and the declared set it validates against. protocolcheck drives
        /// BOTH — the set so the count in its summary is read off the code rather than retyped, and the
        /// writer with a name outside the set so the ArgumentException is a falsifiable claim rather than a
        /// line nobody has ever executed.</summary>
        internal static string[] TidValuedMemberNamesForTest()
        {
            return (string[])TidValuedMemberNames.Clone();
        }

        internal static string AppendTidValuedMemberForTest(string json, string name, uint tid)
        {
            var sb = new StringBuilder(json.Substring(0, json.Length - 1));
            AppendTidValuedMember(sb, name, tid);
            return sb.Append('}').ToString();
        }

        /// <summary>Stamp a thread-scoped event with the tid it describes, so the host can drop a reply that
        /// arrived for a thread it is no longer showing. Splicing the member in here rather than threading a
        /// tid parameter through seven JSON builders keeps one rule in one place: if it is emitted from the
        /// pause loop about a thread, it carries that thread's id. Member order is not significant in JSON,
        /// but the tid is written FIRST here because that is the shape already on the wire, and this change
        /// was meant to be structural rather than observable.
        ///
        /// An unknown tid emits NO "tid" member at all — see <see cref="TidIsKnown"/> for why absence is the
        /// only safe representation. Every stamped event today is emitted from inside the pause loop, where
        /// the tid is always known; the guard is here so that stays true if some future caller emits one from
        /// a path that has no thread. `ClarionDbg protocolcheck` asserts both halves, because the unknown-tid
        /// case cannot be produced against a live debuggee.</summary>
        private static string WithTid(string json, uint tid)
        {
            if (string.IsNullOrEmpty(json) || json[0] != '{' || !TidIsKnown(tid)) return json;
            // The name comes from the constant, not from a literal typed here. That is what lets
            // tools/test-engine-tid-members.ps1 state its rule as an absolute with nothing to except: a
            // declared thread-id member name appearing as JSON text in the engine is a bypass, full stop.
            string head = "{\"" + TidMemberTid + "\":" + tid;
            return json.Length == 2 ? head + "}" : head + "," + json.Substring(1);
        }

        /// <summary>Emit a thread-scoped @JSON event for <paramref name="tid"/>.</summary>
        private void EmitThreadEvent(uint tid, string json)
        {
            if (EmitJson) Console.WriteLine("@JSON " + WithTid(json, tid));
        }

        // logical user breakpoints + armed-byte map (VA -> original byte)
        private readonly List<UserBreakpoint> _bps = new List<UserBreakpoint>();
        private readonly Dictionary<uint, byte> _armed = new Dictionary<uint, byte>();
        // internal temp breakpoints (call-skip return addresses): VA -> original byte
        private readonly Dictionary<uint, byte> _temp = new Dictionary<uint, byte>();

        // re-arm: a VA whose original byte was restored so the real instruction can execute; re-plant
        // 0xCC after one single-step. Keyed by the thread that restored the byte and consumed by THAT
        // thread's next single-step — a scalar here loses re-plants when a second thread hits a
        // breakpoint (or a recursive temp BP fires) between the restore and its single-step.
        private struct Rearm { public uint Va; public bool IsTemp; }
        private readonly Dictionary<uint, Rearm> _rearm = new Dictionary<uint, Rearm>();

        // ---- threaded data (watch NAME on THREADed .cwtls data) ----
        // Resolved by emulating ClaRUN!THR$GetInstance READ-ONLY on the paused thread's TLS — no hijack, no
        // func-eval, no resume. See DebugEngine.Watch.cs (TryResolveThreadedInstance) for why the old
        // thread-hijack had to go.

        // source-level stepping state
        private StepMode _mode = StepMode.None;
        private uint _stepTid;
        private uint _startEsp;       // ESP at step start (stack grows down: larger = shallower)
        private int _startLine;
        private int _startModIdx;
        private LoadedModule _startModule;   // owning image at step start (moduleIdx is only comparable within it)
        private uint _prevVa;         // EIP at the previous single-step trap (for call-entry detection)
        private uint _stepStartVa;    // EIP when the step began (OverInstr stops once EIP leaves it)
        private int _stepCount;
        // The prologue ESP-gate bypass. The step began BELOW its procedure's own first line record — i.e.
        // in the prologue, before any statement of that procedure has run — so Over must not gate on ESP
        // there: the prologue's own `sub esp,N` legitimately drops ESP before any nested call happens.
        // These three are ONE piece of state and are set and cleared together (BeginStep / CancelStep):
        // the bypass is armed only inside the procedure the step started in, which is what the module +
        // entry RVA identify. Arming it without that bound skipped the ESP gate for the whole step session
        // and let Over stop inside a callee — see PrologueBypassApplies in DebugEngine.Stepping.cs.
        private bool _startAtProcEntry;
        private LoadedModule _startSymModule;  // owning image of the procedure the step began in
        private uint _startSymEntryRva;        // ... and that procedure's EntryRva
        private bool _skipRunning;    // running full-speed to a call-skip temp BP; TF off
        private uint _skipEntryEsp;   // ESP at the callee's entry instruction (return depth = this + 4)

        // instruction-level step (stepi): one Trap-Flag step, then pause — independent of the
        // source-level step machine above (used by the disassembly view).
        private bool _instrStep;
        private uint _instrStepTid;

        private readonly ConcurrentQueue<string> _cmds = new ConcurrentQueue<string>();

        public DebugEngine(string exe, PeImage exePe, TswdDebugInfo exeDbg, List<uint> rawRvas,
                           List<BpSpec> specs, bool once, int waitMs, bool interactive,
                           IEnumerable<string> solutionDlls = null, uint attachPid = 0)
        {
            _exePath = exe;
            _attachPid = attachPid;   // 0 = launch; otherwise DebugActiveProcess (DebugEngine.Attach.cs)
            _rawRvas = rawRvas ?? new List<uint>();
            _initialSpecs = specs ?? new List<BpSpec>();
            _once = once; _waitMs = waitMs; _interactive = interactive;

            // Seed the module table with the EXE (module 0) and any solution DLLs the host named, so
            // breakpoints resolve against their TSWD before launch. LoadBase stays 0 until mapped.
            _exe = RegisterImageFromPe(exe, exePe, exeDbg);
            if (solutionDlls != null)
                foreach (var dll in solutionDlls)
                    TryPreloadSolutionDll(dll);
        }

        public int Run()
        {
            if (_interactive) StartStdinReader();

            // resolve module:line specs up front so bp-set/bp-error report before launch
            foreach (var s in _initialSpecs) AddBreakpoint(s);
            // raw RVAs (legacy --rva/--entry/--all-entries) become anonymous breakpoints
            foreach (var rva in _rawRvas) AddRawBreakpoint(rva);

            if (_bps.Count == 0 && !_interactive)
            {
                Console.Error.WriteLine("nothing to break on — no breakpoint resolved");
                return -1;
            }

            if (IsAttach)
            {
                if (!StartAttach()) return 0;
                CheckAttachedIsTheListedProcess();   // --expect-start: a reused pid detaches before anything is planted
            }
            else
            {
                var si = new Native.STARTUPINFO();
                si.cb = (uint)System.Runtime.InteropServices.Marshal.SizeOf(si);
                Native.PROCESS_INFORMATION pi;

                string workDir = Path.GetDirectoryName(Path.GetFullPath(_exePath));
                bool ok = Native.CreateProcess(_exePath, null, IntPtr.Zero, IntPtr.Zero, false,
                    Native.DEBUG_ONLY_THIS_PROCESS, IntPtr.Zero, workDir, ref si, out pi);
                if (!ok)
                    throw new InvalidOperationException("CreateProcess failed, win32 error " + System.Runtime.InteropServices.Marshal.GetLastWin32Error());

                Console.WriteLine($"launched {Path.GetFileName(_exePath)} (pid {pi.dwProcessId}); {_bps.Count} breakpoint(s)");
                // Ours, and needed for nothing: _hProcess and _pid come from the CREATE_PROCESS event in both
                // modes (see the invariant on _pid), so these two are closed at once rather than held to the end.
                Native.CloseHandle(pi.hThread);
                Native.CloseHandle(pi.hProcess);
            }

            DebugLoop();
            return Hits;
        }

        // The loop's wait and continue, as delegates so protocolcheck can run the REAL loop against an event
        // source that never goes quiet (CheckCommandsNeverStarved). In a session they are the Win32 functions.
        private Func<byte[], uint, bool> _loopWait = Native.WaitForDebugEvent;
        private Func<uint, uint, uint, bool> _loopContinue = Native.ContinueDebugEvent;

        /// <summary>The debug loop, from the first event to the target's exit or a detach.</summary>
        private void DebugLoop()
        {
            var buf = new byte[1024];
            bool running = true;
            uint pollMs = _interactive ? 200u : (uint)_waitMs;
            while (running)
            {
                // Every pass, not only the timeout branch: a stream of debug events never reaches that branch,
                // and its 200 ms is coarser than the hover's 150. PollHover throttles itself by timestamp.
                //
                // The COMMANDS too, for the same reason and with more at stake (3f2d747f, 4b run 1): an app that
                // raises events with no 200 ms gap - OutputDebugString spam, a thread storm, the attach burst -
                // left `detach` and `quit` unread, the host gave up after 8 s and killed the app with our bytes
                // still planted. Here no event is held (the previous one was continued at the bottom of the last
                // pass), so this is the same state the timeout branch ran in; a detach it accepts takes effect at
                // the next event's arrival check. Unthrottled: with nothing queued it is one TryDequeue.
                if (_interactive) { PollHover(false); DrainCommandsWhileRunning(); }
                if (!_loopWait(buf, pollMs))
                {
                    if (_interactive) continue;   // no event: the commands were serviced at the top of the pass
                    Console.WriteLine("(timeout waiting for debug event — terminating target)");
                    ReleaseRearmHold();   // resume what the re-arm hold suspended before the kill (ca29e2da)
                    Native.TerminateProcess(_hProcess, 0);
                    // drain until exit
                    while (Native.WaitForDebugEvent(buf, 2000))
                    {
                        if (Code(buf) == Native.EXIT_PROCESS_DEBUG_EVENT) break;
                        Native.ContinueDebugEvent(Pid(buf), Tid(buf), Native.DBG_CONTINUE);
                    }
                    break;
                }

                uint code = Code(buf);
                uint pid = Pid(buf);
                uint tid = Tid(buf);
                uint status = Native.DBG_CONTINUE;

                // A detach asked for while RUNNING: this event, whatever it is, freezes the process, so detach on
                // it before any handler can pause on it (DebugEngine.Attach.cs).
                if (_detachPending) { DetachAt(buf, null); break; }

                switch (code)
                {
                    case Native.CREATE_PROCESS_DEBUG_EVENT:
                        // union @+12: hFile(+12) hProcess(+16) hThread(+20) lpBaseOfImage(+24)
                        // hProcess and hThread belong to kernel32, which closes them when EXIT_PROCESS is
                        // continued or the debugger detaches; hFile is ours to close.
                        _hProcess = Ptr(U32(buf, 16));
                        _pid = pid;
                        CloseHandleValue(U32(buf, 12));
                        _exe.LoadBase = U32(buf, 24);
                        _mainTid = tid; NoteThreadCreated(tid);
                        PlantAll();
                        uint preferred = _exe.Pe != null ? _exe.Pe.ImageBase : 0;
                        Console.WriteLine($"process created: loadBase=0x{_exe.LoadBase:X} (preferred 0x{preferred:X}){(_exe.LoadBase != preferred ? "  [relocated]" : "")}");
                        if (EmitJson)
                        {
                            Console.WriteLine("@JSON " + Json.Loaded(pid, _exe.LoadBase, IsAttach));
                            Console.WriteLine("@JSON " + Json.ModuleLoaded(_exe));
                        }
                        break;

                    case Native.LOAD_DLL_DEBUG_EVENT:
                        // union @+12: hFile(+12) lpBaseOfDll(+16) ...
                        OnDllLoaded(U32(buf, 12), U32(buf, 16));
                        break;

                    case Native.UNLOAD_DLL_DEBUG_EVENT:
                        // union @+12: lpBaseOfDll(+12)
                        OnDllUnloaded(U32(buf, 12));
                        break;

                    case Native.CREATE_THREAD_DEBUG_EVENT:
                        NoteThreadCreated(tid);
                        break;

                    case Native.EXIT_THREAD_DEBUG_EVENT:
                        NoteThreadExited(tid);
                        ForgetRearmThread(tid);   // its owed re-plant, and any hold on it (DebugEngine.Stepping.cs)
                        // DEFENCE IN DEPTH, NOT LOAD-BEARING — and saying so is the point. It does run with a
                        // non-empty cache: the previous episode's entries outlive that episode and sit there
                        // while the target runs, which is exactly when EXIT_THREAD arrives, so this really
                        // does drop the dead tid's block. What it cannot do is change an answer, because
                        // every episode that READS the cache clears all of it on the way in (PausedWait and
                        // ShouldPauseAtBp), so a dead tid's entry is already gone before anyone looks.
                        // It stops being ornamental the moment a reader resolves a threaded name without
                        // opening an episode — then a reused tid inheriting a dead thread's block is a live
                        // bug and this is the line that prevents it. Cheap; kept.
                        ClearThreadedBlockCache(tid);
                        ForgetSetIpThread(tid);   // setip observations: a reused tid starts with none
                        break;

                    case Native.EXCEPTION_DEBUG_EVENT:
                        // union @+12: EXCEPTION_RECORD: code(+12) flags(+16) recPtr(+20) addr(+24)
                        uint exCode = U32(buf, 12);
                        uint exAddr = U32(buf, 24);
                        if (exCode == Native.EXCEPTION_BREAKPOINT)
                        {
                            if (_armed.ContainsKey(exAddr))
                                status = OnUserBp(tid, exAddr);
                            else if (_temp.ContainsKey(exAddr))
                                status = OnTempBp(tid, exAddr);
                            else if (IsStaleHitOfOurs(exAddr))
                                // Ours, removed while this hit was queued (bp del while paused, a cleared temp):
                                // rewind and run on. Ahead of OnProgrammaticBreak, which would pause at va+1.
                                status = OnStaleHit(tid, exAddr);
                            else if (!_seenInitialBreak)
                            {
                                _seenInitialBreak = true; // OS loader breakpoint (or the attach break) — swallow it
                                if (IsAttach) ReseedThreadOrderAfterAttach(tid);   // tid = the injected break thread
                                status = Native.DBG_CONTINUE;
                            }
                            else if (_pauseRequested)
                            {
                                // Our injected DebugBreakProcess landed → pause here. MUST be checked
                                // before OnProgrammaticBreak, or a user-requested pause would be
                                // misreported as a hardcoded breakpoint the debuggee executed itself.
                                _pauseRequested = false;
                                status = OnPauseBreak(tid);
                            }
                            else status = OnProgrammaticBreak(tid); // an int3 the debuggee executed itself
                        }
                        else if (exCode == Native.EXCEPTION_SINGLE_STEP)
                        {
                            status = OnSingleStep(tid);
                        }
                        else
                        {
                            // pass first-chance non-breakpoint exceptions back to the app
                            status = Native.DBG_EXCEPTION_NOT_HANDLED;
                            SetIpOnExceptionPassed(tid);   // the app's handler may unwind a watched step: see DebugEngine.SetIp.cs
                        }
                        break;

                    case Native.EXIT_PROCESS_DEBUG_EVENT:
                        uint exitCode = U32(buf, 12);
                        Console.WriteLine($"process exited (code {exitCode})");
                        if (EmitJson) Console.WriteLine("@JSON " + Json.Exited(exitCode));
                        ReleaseRearmHold();   // this event is never continued, so the reconcile below never runs
                        running = false;
                        break;

                    // OUTPUT_DEBUG_STRING / RIP: just continue
                    default:
                        status = Native.DBG_CONTINUE;
                        break;
                }

                // A detach asked for while PAUSED: PausedWait returned without resuming, and the handler's status
                // is the one this held event gets (DebugEngine.Attach.cs).
                if (running && _detachPending) { DetachAt(buf, status); break; }

                if (running)
                {
                    // The re-arm hold (DebugEngine.Stepping.cs): suspend or resume the other threads for what this
                    // continue releases, while the process is still frozen on the event.
                    ReconcileRearmHold(tid, status);
                    _loopContinue(pid, tid, status);
                }
            }
        }

        // ------------------------------------------------------------------ programmatic breakpoint

        /// <summary>
        /// An unexpected breakpoint after startup that we did NOT plant — the debuggee executed an
        /// int3 itself: a hardcoded breakpoint via DebugBreak() / __debugbreak() (e.g. a Clarion
        /// program calling kernel32 DebugBreak under IsDebuggerPresent()). This is the program asking
        /// the debugger to stop here, so honour it and enter the pause loop.
        ///
        /// Unlike our planted 0xCC — where we restore the original byte and rewind EIP so the real
        /// instruction re-executes — a hardcoded int3 IS the instruction. EIP already points past it
        /// and must NOT be rewound (rewinding would re-run the int3 forever). We just report and, on
        /// resume, DBG_CONTINUE so the thread proceeds. Non-interactive sessions ignore it (the legacy
        /// behaviour) so batch runs never block.
        /// </summary>
        private uint OnProgrammaticBreak(uint tid)
        {
            if (!_interactive) return Native.DBG_CONTINUE;
            Hits++;
            IntPtr hThread = OpenThreadForContext(tid);
            var ctx = NewContext();
            bool haveCtx = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref ctx);
            CancelStep(); // a programmatic break supersedes any in-flight step
            PausedWait(tid, hThread, ref ctx, haveCtx, "debugbreak");
            if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            return Native.DBG_CONTINUE;
        }

        // ------------------------------------------------------------------ pause (break into running)

        /// <summary>Inject a breakpoint into the target so a running session can pause. The break is
        /// caught by the debug loop and routed to <see cref="OnPauseBreak"/>.</summary>
        private void RequestPause()
        {
            if (_hProcess == IntPtr.Zero) { EmitError("pause: no target running"); return; }
            _pauseRequested = true;
            if (!Native.DebugBreakProcess(_hProcess))
            {
                _pauseRequested = false;
                EmitError("pause: DebugBreakProcess failed (" + System.Runtime.InteropServices.Marshal.GetLastWin32Error() + ")");
            }
        }

        /// <summary>The injected break arrived. It runs on a throwaway ntdll thread, so pick the app
        /// thread actually in Clarion code (or the main thread) and pause there. The whole process is
        /// frozen while we hold this event, so every thread's context is stable to read.</summary>
        private uint OnPauseBreak(uint breakTid)
        {
            uint tid = PickPauseThread(breakTid);
            IntPtr hThread = OpenThreadForContext(tid);
            var ctx = NewContext();
            bool haveCtx = hThread != IntPtr.Zero && Native.GetThreadContext(hThread, ref ctx);
            CancelStep();
            _breakTid = breakTid;   // hide the injected thread from the picker for this stop
            try
            {
                if (_interactive)
                    PausedWait(tid, hThread, ref ctx, haveCtx, "pause");
            }
            finally
            {
                _breakTid = 0;      // it dies on resume; never carry it into the next stop
                if (hThread != IntPtr.Zero) Native.CloseHandle(hThread);
            }
            return Native.DBG_CONTINUE;  // release the injected break thread (it then exits)
        }

        // ------------------------------------------------------------------ pause + command loop

        /// <summary>
        /// Resolve where the stopped thread is and announce it: the thread-stamped `paused` event and the
        /// console line. Lifted out of <see cref="PausedWait"/> so it can run AGAIN within one stop: after
        /// `setip` moves EIP, the pause loop re-runs this with reason "setip", so the host refreshes every
        /// panel through its ordinary `paused` path and the step verbs get locals for the NEW line.
        /// </summary>
        private void AnnounceStop(uint tid, ref Native.CONTEXT_X86 ctx, bool haveCtx, string reason,
                                  out LoadedModule m, out bool resolved, out int line, out int mi)
        {
            uint va = haveCtx ? ctx.Eip : 0;
            m = haveCtx ? ModuleAt(va) : null;
            uint rva = m != null ? va - m.LoadBase : va;
            line = 0; mi = -1; uint recRva = 0;
            resolved = haveCtx && m != null && m.Dbg != null && m.Dbg.ResolveAddr(rva, out line, out mi, out recRva);
            if (!resolved) { line = 0; mi = -1; recRva = 0; }
            string mod = resolved ? m.Dbg.ModuleNameForIdx(mi) : null;
            string proc = haveCtx ? ProcNameAt(m, rva) : null;
            uint gap = resolved ? rva - recRva : 0;
            // SPIKE: when stopped in non-TSWD code (the runtime), name the location from the live IAT
            // so the host can show "in ClaRUN.dll!Cla$PushLong+0x7" instead of "(unresolved)".
            string sym = (haveCtx && !resolved) ? NearestImportSymbol(va) : null;

            // Remember where this thread stood, for setip's observed-ESP path (DebugEngine.SetIp.cs).
            ObserveStop(tid, ref ctx, haveCtx, m, rva, resolved, gap, reason);

            // `paused` carries the STOPPED thread's tid. It describes one thread's location and registers,
            // so it is thread-scoped like the rest; carrying the tid means the host knows which thread it
            // stopped on even if its follow-up `threads` request fails or races. Additive: a host that does
            // not read the field is unaffected.
            EmitThreadEvent(tid, Json.Paused(reason, mod, proc, resolved ? line : 0, rva, va, gap, resolved, sym,
                haveCtx ? Json.Regs(ctx.Eax, ctx.Ebx, ctx.Ecx, ctx.Edx, ctx.Esi, ctx.Edi, ctx.Ebp, ctx.Esp, ctx.Eip, ctx.EFlags) : null));
            Console.WriteLine($"  [paused: {reason}]{(resolved ? " " + mod + " line " + line : "")}{(proc != null ? " in " + proc : sym != null ? " in " + sym : "")} — commands: continue step stepover stepout bp mem regs stack disasm sym watch setip quit");
        }

        /// <summary>
        /// Blocks the debug loop (target fully suspended — the debug event is not continued) and
        /// services stdin commands until a resume-type command arrives.
        /// </summary>
        private void PausedWait(uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx, string reason)
        {
            _pauseRequested = false;  // any pause we reach consumes a pending pause request
            _instrStep = false;       // and consumes a pending instruction-step
            _selectedTid = tid;       // a new stop always starts on the stopped thread — a selection is
                                      // per-stop and is never carried across one
            HoverNewStop();             // one fresh hover answer per stop, however long the step took
            ClearThreadedBlockCache();  // a fresh stop is a fresh episode: re-resolve .cwtls instance blocks
                                        // rather than trust bases cached while the target was last frozen
            ClearFrameCache();          // and re-walk the stack: frames cached at the last stop are history

            // The stop's location. These four are what the step verbs hand BeginStep, so they must describe
            // where EIP IS: `setip` moves it and re-runs AnnounceStop to recompute them (a77abd94 risk 6).
            LoadedModule m; bool resolved; int line; int mi;
            AnnounceStop(tid, ref ctx, haveCtx, reason, out m, out resolved, out line, out mi);

            while (true)
            {
                string cmd;
                if (!_cmds.TryDequeue(out cmd)) { PollHover(true); Thread.Sleep(20); continue; }
                cmd = cmd.Trim();
                if (cmd.Length == 0) continue;
                var parts = cmd.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                string verb = parts[0].ToLowerInvariant();

                // Resume-type commands act on the STOPPED thread and reset the selection FIRST, so the stop
                // they produce is never reported against the thread the user was merely looking at. This is
                // deliberately ahead of the dispatch: it must hold even if a handler throws.
                if (IsResumeVerb(verb)) _selectedTid = tid;

                // Everything below reads the SELECTED thread. Ordinarily that IS the stopped thread and this
                // opens nothing; after `thread <tid>` it is another thread's frozen context.
                //
                // AcquireView is INSIDE the try that owns Release(). It used to sit above it, where a throw
                // would have escaped the command loop entirely and taken the pause with it, instead of being
                // reported by the catch below. Note this alone does NOT close the handle-leak window the
                // review found: a throw part-way through AcquireView never returns a view for the finally to
                // release, so AcquireView is made exception-safe on its own side too.
                ThreadView view = null;
                try
                {
                    view = AcquireView(tid, hThread, ref ctx, haveCtx);
                switch (verb)
                {
                    case "continue": case "c": case "g":
                        EmitResumed("continue");
                        ArmResume(tid, hThread, ref ctx, haveCtx, false);
                        return;

                    case "step": case "stepinto": case "s": case "i":
                        BeginStep(StepMode.Into, tid, ref ctx, haveCtx, resolved, line, mi, m);
                        EmitResumed("step");
                        ArmResume(tid, hThread, ref ctx, haveCtx, true);
                        return;

                    case "stepi": case "si":   // one instruction, into calls (disassembly view)
                        _instrStep = true; _instrStepTid = tid;
                        EmitResumed("stepi");
                        ArmResume(tid, hThread, ref ctx, haveCtx, true);
                        return;

                    case "nexti": case "ni":   // one instruction, over calls (disassembly view)
                        BeginStep(StepMode.OverInstr, tid, ref ctx, haveCtx, resolved, line, mi, m);
                        EmitResumed("stepi");
                        ArmResume(tid, hThread, ref ctx, haveCtx, true);
                        return;

                    case "stepover": case "next": case "n":
                        BeginStep(StepMode.Over, tid, ref ctx, haveCtx, resolved, line, mi, m);
                        EmitResumed("stepover");
                        ArmResume(tid, hThread, ref ctx, haveCtx, true);
                        return;

                    case "stepout": case "out": case "finish": case "o":
                        BeginStep(StepMode.Out, tid, ref ctx, haveCtx, resolved, line, mi, m);
                        EmitResumed("stepout");
                        ArmResume(tid, hThread, ref ctx, haveCtx, true);
                        return;

                    case "bp":
                        HandleBpCommand(parts);
                        break;

                    case "regs":
                        if (view.HaveCtx && EmitJson)
                            EmitThreadEvent(view.Tid, Json.RegsEvent(Json.Regs(view.Ctx.Eax, view.Ctx.Ebx, view.Ctx.Ecx, view.Ctx.Edx, view.Ctx.Esi, view.Ctx.Edi, view.Ctx.Ebp, view.Ctx.Esp, view.Ctx.Eip, view.Ctx.EFlags)));
                        else if (view.HaveCtx)
                            Console.WriteLine($"  EAX={view.Ctx.Eax:X8} EBX={view.Ctx.Ebx:X8} ECX={view.Ctx.Ecx:X8} EDX={view.Ctx.Edx:X8} ESI={view.Ctx.Esi:X8} EDI={view.Ctx.Edi:X8} EBP={view.Ctx.Ebp:X8} ESP={view.Ctx.Esp:X8} EIP={view.Ctx.Eip:X8}");
                        else
                            EmitError("regs: no context for thread " + TidText(view.Tid));
                        break;

                    case "mem":
                        HandleMemCommand(parts);
                        break;

                    case "setval":   // write a new value into a live variable (edit-variable-value)
                        HandleSetValCommand(parts, view.Tid);
                        break;

                    case "stack": case "bt": case "where":
                        HandleStackCommand(parts, ref view.Ctx, view.HaveCtx, view.Tid, view.HThread);
                        break;

                    case "moduledata": case "moddata":
                        HandleModuleDataCommand(parts, ref view.Ctx, view.HaveCtx, view.Tid, view.HThread);
                        break;

                    case "pause": case "break": case "runtocursor":
                        // Resume-shaped in intent, but the pause loop implements none of them: `pause` only
                        // means anything while the target RUNS (DrainCommandsWhileRunning has it), and
                        // run-to-cursor is composed host-side from `bp add` + `continue`. Rejecting them
                        // here keeps them out of IsResumeVerb, so they can no longer discard the user's
                        // thread selection on their way to "unknown command".
                        EmitError(verb + ": the target is already paused");
                        break;

                    case "setip":   // set next statement: move the STOPPED thread's EIP (DebugEngine.SetIp.cs)
                        if (HandleSetIpCommand(parts, tid, hThread, ref ctx, haveCtx))
                        {
                            AnnounceStop(tid, ref ctx, haveCtx, "setip", out m, out resolved, out line, out mi);
                            HoverNewStop();   // a setip stop is a new stop for the hover tracker too (the page re-baselines on it)
                        }
                        break;

                    case "threads":
                        HandleThreadsCommand(tid);
                        break;

                    case "thread":
                        HandleThreadSelectCommand(parts, tid);
                        break;

                    case "hover":   // identify-thread-by-window mode (DebugEngine.Hover.cs)
                        HandleHoverCommand(parts, true);
                        break;

                    case "expand":   // lazy expansion of a reference node (read-only; no target code runs)
                        HandleExpandCommand(parts, view.Tid);
                        break;

                    case "framelocals":   // locals of one call-stack frame (Call-Stack-driven Variables)
                        HandleFrameLocalsCommand(parts, view.Tid, ref view.Ctx, view.HaveCtx);
                        break;

                    case "disasm": case "u":
                        // The SELECTED thread, like every read below it. 0128a37e pinned this to the
                        // stopped thread for one reason only: the disassembly window could not say whose
                        // code it was showing, so honouring a selection would have put one thread's code on
                        // screen while the pad said you were viewing another — the mismatch relocated, not
                        // fixed. The window names the thread now (381aabd7) and gates replies on the
                        // stamped tid, so the reason is gone and the restriction with it.
                        //
                        // The view goes in WHOLE. The failure this path invites is a context from one
                        // thread stamped with another's id, and passing `ref view.Ctx, view.HaveCtx,
                        // view.Tid` separately is three chances to get that pairing wrong at the one call
                        // site that matters.
                        HandleDisasmCommand(parts, view);
                        break;

                    case "sym":
                        HandleSymCommand(parts);
                        break;

                    case "watch":
                        // resolve + read a data symbol's CURRENT-THREAD value. THREADed (.cwtls) names
                        // resolve by emulating THR$GetInstance read-only, so this answers inline like every
                        // other read — no resume, no leaving the pause loop.
                        HandleWatchCommand(parts, view.Tid, view.HThread, ref view.Ctx, view.HaveCtx);
                        break;

                    case "threadscan":
                        // MEASUREMENT PROBE (task 0128a37e item 0): per-thread evidence at this stop —
                        // read-only, no target code runs. See DebugEngine.Threads.cs.
                        HandleThreadScanCommand(tid, parts);
                        break;

                    case "libstate":
                        // per-thread RTL "Library State" (ERROR/EVENT/FIELD/…). Read by EMULATING each
                        // ClaRUN getter read-only — synchronous and safe at any stop, so it answers inline
                        // (no thread hijack, no leaving the pause loop).
                        HandleLibStateCommand(parts, view.Tid, view.HThread);
                        break;

                    case "detach":
                        _detachPending = true;   // the debug loop detaches on THIS held event (DebugEngine.Attach.cs)
                        return;

                    case "quit": case "q": case "kill":
                        if (QuitDetaches(verb)) { _detachPending = true; return; }
                        TerminateTarget();
                        return; // the EXIT_PROCESS event ends the loop

                    default:
                        EmitError("unknown command: " + verb);
                        break;
                }
                }
                catch (Exception ex)
                {
                    // A command-handler bug must never crash the engine — that would terminate the
                    // debuggee. Report it and keep the pause loop alive.
                    EmitError("command '" + verb + "' failed: " + ex.Message);
                }
                finally
                {
                    // Closes only a handle WE opened for a non-stopped selection; the stopped thread's
                    // handle belongs to the caller. Runs on the resume paths too, which return out of the
                    // switch above. Null only if AcquireView threw, and it releases its own handle then.
                    if (view != null) view.Release();
                }
            }
        }

        /// <summary>Set TF on the paused thread when the resume needs a single-step (BP re-arm or stepping).</summary>
        private void ArmResume(uint tid, IntPtr hThread, ref Native.CONTEXT_X86 ctx, bool haveCtx, bool stepping)
        {
            // FIRST, before anything can return: every resume verb comes through here, so this is where setip's
            // observations are cut back for the run that follows (DebugEngine.SetIp.cs). Position pinned by
            // tools/test-engine-setip-sites.ps1.
            SetIpOnResume(tid, stepping, haveCtx, haveCtx ? ctx.Esp : 0);
            if (!haveCtx) return;
            bool needTf = stepping || _rearm.ContainsKey(tid);
            if (!needTf) return;
            Native.GetThreadContext(hThread, ref ctx); // refresh — EIP was rewritten at hit time
            ctx.EFlags |= TRAP_FLAG;
            Native.SetThreadContext(hThread, ref ctx);
        }

        /// <summary>Commands accepted while the target is running (between debug events).</summary>
        private void DrainCommandsWhileRunning()
        {
            string cmd;
            while (_cmds.TryDequeue(out cmd))
            {
                cmd = cmd.Trim();
                if (cmd.Length == 0) continue;
                var parts = cmd.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                string verb = parts[0].ToLowerInvariant();
                // A resume verb while the target is already running. Decided HERE rather than by a third
                // copy of the verb list in the switch below, so the set has one owner (IsResumeVerb).
                //
                // This is ahead of the switch, so it changes control flow, not just shape: a verb diverted
                // here never reaches its case. That is safe only because IsResumeVerb accepts EXACTLY the
                // verbs that fell to the "only valid while paused" case and nothing else — in particular it
                // rejects pause/break, which this switch DOES implement and which must still reach it.
                // `ClarionDbg protocolcheck` asserts both halves of that, including the non-resume verbs
                // this switch handles, because getting it wrong looks identical on the happy path.
                if (IsResumeVerb(verb))
                {
                    EmitError("target is running — " + verb + " is only valid while paused");
                    continue;
                }

                switch (verb)
                {
                    case "bp":
                        HandleBpCommand(parts);
                        break;
                    case "sym":
                        HandleSymCommand(parts);   // static lookup — safe while running
                        break;
                    case "pause": case "break":
                        RequestPause();            // inject a break → pause at the app's current location
                        break;
                    case "thread":
                    {
                        // A selectthread that raced a resume. Answer in the command's OWN vocabulary: the
                        // host is waiting for a threadselected reply, and a generic error would leave its
                        // picker stuck on "switching…". Echo the tid it asked for so it can match the reply
                        // to its request; there is no stop, so there is no selection to name instead.
                        uint wantTid;
                        EmitThreadSelected(parts.Length > 1 && uint.TryParse(parts[1], out wantTid) ? wantTid : 0,
                                           false, "no thread selection while the target is running");
                        break;
                    }
                    case "hover":   // identify-thread-by-window mode: report-only while running
                        HandleHoverCommand(parts, false);
                        break;
                    case "detach":
                        RequestDetach();
                        break;
                    case "quit": case "q": case "kill":
                        if (QuitDetaches(verb)) { RequestDetach(); break; }
                        TerminateTarget();
                        break;
                    case "setip":   // its own refusal event, so the pad can toast it like any other setip refusal
                        EmitSetIpNotPaused(parts);
                        break;
                    // The resume verbs USED TO BE LISTED HERE, as a third hand-maintained copy of the set.
                    // They are now recognised by IsResumeVerb ahead of this switch — one owner, so adding a
                    // verb in one place cannot leave another place stale. They still produce exactly this
                    // error; only who decides they are resume verbs has changed. The read verbs below are
                    // NOT a duplicated set and stay where they are.
                    case "mem": case "regs": case "stack": case "bt": case "where": case "watch":
                    case "locals": case "vars":
                    case "moduledata": case "moddata":
                    case "disasm": case "u":
                    case "setval":
                    case "threads": case "threadscan":
                    case "framelocals": case "libstate": case "expand":
                        EmitError("target is running — " + verb + " is only valid while paused");
                        break;
                    default:
                        EmitError("unknown command: " + verb);
                        break;
                }
            }
        }

        /// <summary>bp add module:line | bp del module:line | bp list</summary>
        private void HandleBpCommand(string[] parts)
        {
            string sub = parts.Length > 1 ? parts[1].ToLowerInvariant() : "list";
            if (sub == "list")
            {
                if (EmitJson) Console.WriteLine("@JSON " + Json.BpList(_bps));
                else foreach (var b in _bps) Console.WriteLine($"  bp {b.Module}:{b.Line} ({b.Rvas.Count} addr)");
                return;
            }
            if (parts.Length < 3) { EmitError("bp " + sub + " expects module:line"); return; }
            // spec = "module:line" optionally followed by "|c=<b64>|hm=eq|hv=5|t=<b64>" (one space-free token)
            BpSpec spec;
            if (!BpSpec.TryParse(parts[2], out spec))
            {
                EmitError("bp " + sub + " expects module:line, got '" + parts[2] + "'");
                return;
            }
            // The whole spec goes through, never a field list: a breakpoint's identity now includes the
            // image the caller named, and an argument list is exactly where a new identity field gets
            // dropped on one of the two paths. This is the same lesson as requestedLine reaching bp-del
            // and not bp-set.
            if (sub == "add") AddBreakpoint(spec);
            else if (sub == "del" || sub == "remove" || sub == "rm") RemoveBreakpoint(spec);
            else EmitError("unknown bp subcommand: " + sub);
        }

        /// <summary>
        /// sym NAME — resolve a data name (global, record buffer, or record field like JOB:JOBID)
        /// to its live VA + type/size so the host can follow up with a mem read. Resolution is
        /// static (TSWD tables), so it is valid while paused OR running. The VA is the link-time
        /// template instance — for THREADed (.cwtls) data the active thread's copy may differ.
        /// </summary>
        private void HandleSymCommand(string[] parts)
        {
            if (parts.Length < 2) { EmitError("sym expects: sym NAME"); return; }
            string name = parts[1];
            TswdDebugInfo.DataLocation loc; LoadedModule owner; string ambiguity;
            var found = ResolveDataAcrossModules(name, out owner, out loc, out ambiguity);
            if (found != DataResolve.Found)
            {
                // Ambiguous (04d7b4c8) goes out as not found: no address for a name that has two.
                if (EmitJson) Console.WriteLine("@JSON " + Json.Sym(name, false, 0, 0, 0, null, 0, null));
                Console.WriteLine($"  sym {name}: {(found == DataResolve.Ambiguous ? ambiguity : "not found")}");
                return;
            }
            uint va = owner.LoadBase + loc.Rva;
            string tn = TswdDebugInfo.TypeCodeName(loc.TypeCode);
            if (EmitJson) Console.WriteLine("@JSON " + Json.Sym(name, true, loc.Rva, va, loc.TypeCode, tn, loc.Size, loc.Container));
            Console.WriteLine($"  sym {name}: VA 0x{va:X} (RVA 0x{loc.Rva:X}) {(tn ?? $"type 0x{loc.TypeCode:X2}")} size {loc.Size}{(loc.Container != null ? " in " + loc.Container : "")}");
        }

        /// <summary>uint -> IntPtr without .NET's checked long->int narrowing. On x86 builds, the
        /// compiler-inserted uint->long widen followed by IntPtr's explicit operator(long) does a CHECKED
        /// (int) cast internally — any value >= 0x80000000 (large-address-aware targets routinely hand out
        /// stack/heap addresses up there) throws OverflowException. The Win32 callee only wants the raw bit
        /// pattern, so reinterpreting unchecked is correct here.
        ///
        /// Use this for EVERY uint->IntPtr conversion, not just addresses: the trap is in the conversion,
        /// not in what the number means. Debug-event HANDLE values go through it too — Windows keeps handles
        /// small in practice, so the overflow is latent there rather than observed, but a bare (IntPtr)uint
        /// anywhere in this file is the bug from issue #20 waiting to be reintroduced. There should be no
        /// remaining uint-sourced (IntPtr) casts, so the pattern can be grepped for as a rule.</summary>
        private static IntPtr Ptr(uint va) => (IntPtr)unchecked((int)va);

        private void WriteU32(uint va, uint value)
        {
            int wrote;
            Native.WriteProcessMemory(_hProcess, Ptr(va), BitConverter.GetBytes(value), 4, out wrote);
        }

        /// <summary>mem 0xADDR LEN [reqId] — read target memory while paused (the Memory panel). READ-ONLY and
        /// capped at <see cref="MemMaxLen"/> bytes; only the pause loop dispatches it, so it never runs
        /// against a running target. The optional trailing reqId is echoed on the reply, and on a refusal as a
        /// mem event with an "error" member, so the host can match a reply to the request that asked for it.
        /// Without one a refusal is a plain error event, as before.</summary>
        private void HandleMemCommand(string[] parts)
        {
            uint addr; int len; string reqId; byte[] buf; int read;
            string err = MemRead(parts, out addr, out len, out reqId, out buf, out read);
            if (err != null)
            {
                if (reqId != null && EmitJson) Console.WriteLine("@JSON " + Json.MemError(addr, len, reqId, err));
                else EmitError(err);
                return;
            }
            // echo the REQUESTED len so the host can correlate the reply to its request even when
            // the read came back short; bytes carries only what was actually read
            if (EmitJson) Console.WriteLine("@JSON " + Json.Mem(addr, buf, read, len, reqId));
            else
            {
                // hex + ASCII sidebar, 16 bytes per row (a flat hex blob hides readable strings)
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
                    Console.WriteLine($"  mem 0x{addr + (uint)row:X8}: {hex.ToString().PadRight(48)} {asc}");
                }
            }
        }

        /// <summary>The largest mem read, in bytes. The Memory panel pages within it.</summary>
        internal const int MemMaxLen = 4096;

        /// <summary>Parse and perform one mem read. Returns null on success, else the refusal text. addr, len
        /// and reqId are filled as far as parsing got, so a refusal can still be correlated.
        /// <para>
        /// The read goes through <see cref="ReadCleanBlock"/>, not a raw ReadProcessMemory. The raw call is
        /// all-or-nothing, so a span running into an unreadable page failed outright instead of returning the
        /// bytes before it, and it showed our own planted 0xCC wherever a breakpoint or call-skip temp sits.
        /// ReadBlock reads page by page, and ReadCleanBlock puts the original bytes back.
        /// </para></summary>
        private string MemRead(string[] parts, out uint addr, out int len, out string reqId, out byte[] buf, out int read)
        {
            addr = 0; len = 0; buf = null; read = 0;
            reqId = parts.Length > 3 ? parts[3] : null;
            if (parts.Length < 3) return "mem expects: mem 0xADDR LEN [reqId]";
            string a = parts[1].Trim();
            try
            {
                addr = a.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                    ? Convert.ToUInt32(a.Substring(2), 16)
                    : Convert.ToUInt32(a);
            }
            catch { return "mem: bad address '" + a + "'"; }
            if (!int.TryParse(parts[2], out len) || len <= 0 || len > MemMaxLen)
            {
                len = 0;
                return "mem: length must be 1.." + MemMaxLen;
            }
            // ReadBlock steps va + total in uint arithmetic, so a span past 0xFFFFFFFF would wrap to page 0.
            if ((ulong)addr + (ulong)len > 0x100000000UL)
                return $"mem: 0x{addr:X} + {len} runs past the end of the address space";
            buf = new byte[len];
            read = ReadCleanBlock(addr, buf);
            if (read <= 0) { read = 0; return $"mem: read failed at 0x{addr:X}"; }
            return null;
        }

        /// <summary>Test seam for `protocolcheck`: the REAL mem parse and read, against whatever process
        /// handle the engine holds (see <see cref="SetProcessHandleForTest"/>).</summary>
        internal string MemReadForTest(string[] parts, out uint addr, out int len, out string reqId, out byte[] buf, out int read)
        {
            return MemRead(parts, out addr, out len, out reqId, out buf, out read);
        }

        /// <summary>Test seam: point the engine's reads at <paramref name="h"/>. protocolcheck hands it its OWN
        /// process, so a read meets real pages, a real unreadable page, and bytes the harness planted.</summary>
        internal void SetProcessHandleForTest(IntPtr h) { _hProcess = h; }

        /// <summary>Test seam: record a planted INT3 at <paramref name="va"/> whose original byte was
        /// <paramref name="original"/>, as a user breakpoint or (temp) a call-skip temp would.</summary>
        internal void PlantForTest(uint va, byte original, bool temp)
        {
            if (temp) _temp[va] = original; else _armed[va] = original;
        }

        private void EmitResumed(string mode)
        {
            if (EmitJson) Console.WriteLine("@JSON " + Json.Resumed(mode));
            Console.WriteLine($"  [resumed: {mode}]");
        }

        private void EmitError(string message)
        {
            if (EmitJson) Console.WriteLine("@JSON " + Json.Error(message));
            Console.WriteLine("  ERROR: " + message);
        }

        // ------------------------------------------------------------------ helpers

        private void StartStdinReader()
        {
            var t = new Thread(() =>
            {
                try
                {
                    string line;
                    while ((line = Console.In.ReadLine()) != null)
                        _cmds.Enqueue(line);
                }
                catch { /* stdin torn down */ }
                // stdin closed → the host (IDE addin) went away. A LAUNCHED target is killed rather than
                // orphaned; an ATTACHED one is detached from, since `quit` means detach in attach mode.
                _cmds.Enqueue("quit");
            });
            t.IsBackground = true;
            t.Name = "stdin-commands";
            t.Start();
        }

        /// <summary>
        /// Demangled symbol (proc/method/routine) containing a code RVA, or null when unknown. Uses
        /// ResolveSymbolVerified — the plain binary search can mislabel cold/init "glue" code (no
        /// symbol of its own) with an unrelated preceding symbol from a different compiland; verifying
        /// against the +0x1C line table catches that without the unreliable +0x28 backref moduleIdx.
        /// </summary>
        private string ProcNameAt(LoadedModule m, uint rva)
        {
            if (m == null || m.Dbg == null) return null;
            ProcSymbol sym;
            if (!m.Dbg.ResolveSymbolVerified(rva, out sym)) return null;
            return sym.Name;
        }

        /// <summary>Is there a line record in [rva, rva+window] in this image? (Spots Clarion callees.)</summary>
        private bool HasRecordInRange(LoadedModule m, uint rva, uint window)
        {
            if (m == null || m.Dbg == null) return false;
            var t = m.Dbg.AddrTable;
            if (t == null || t.Count == 0) return false;
            int lo = 0, hi = t.Count - 1, ans = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                if (t[mid].Rva >= rva) { ans = mid; hi = mid - 1; }
                else lo = mid + 1;
            }
            return ans >= 0 && t[ans].Rva <= rva + window;
        }

        private bool ReadByte(uint va, out byte value)
        {
            var b = new byte[1];
            int read;
            bool ok = Native.ReadProcessMemory(_hProcess, Ptr(va), b, 1, out read) && read == 1;
            value = ok ? b[0] : (byte)0;
            return ok;
        }

        private void WriteByte(uint va, byte value)
        {
            int wrote;
            Native.WriteProcessMemory(_hProcess, Ptr(va), new[] { value }, 1, out wrote);
            Native.FlushInstructionCache(_hProcess, Ptr(va), (IntPtr)1);
            if (value == 0xCC && _int3Trace != null) _int3Trace.Add(va);   // protocolcheck only (Stepping.cs)
        }

        /// <summary>Write a block of bytes to target memory (data writes — edit-variable-value). Returns
        /// true only when every byte was written. No instruction-cache flush: this is data, not code.</summary>
        private bool WriteBlock(uint va, byte[] buf)
        {
            int wrote;
            return Native.WriteProcessMemory(_hProcess, Ptr(va), buf, buf.Length, out wrote) && wrote == buf.Length;
        }

        private uint ReadU32(uint va)
        {
            var b = new byte[4];
            int read;
            if (!Native.ReadProcessMemory(_hProcess, Ptr(va), b, 4, out read) || read != 4) return 0;
            return BitConverter.ToUInt32(b, 0);
        }

        private static Native.CONTEXT_X86 NewContext()
        {
            var c = new Native.CONTEXT_X86();
            c.ContextFlags = Native.CONTEXT_FULL;
            c.FltRegisterArea = new byte[80];
            c.ExtendedRegisters = new byte[512];
            return c;
        }

        // EXCEPTION debug events don't carry a thread handle, so open one for the thread id.
        private static IntPtr OpenThreadForContext(uint tid)
        {
            const uint THREAD_GET_CONTEXT = 0x0008;
            const uint THREAD_SET_CONTEXT = 0x0010;
            const uint THREAD_QUERY_INFORMATION = 0x0040;
            return OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, false, tid);
        }

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
        private static extern uint GetFinalPathNameByHandle(IntPtr hFile, System.Text.StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

        /// <summary>Resolve a LOAD_DLL file handle to its on-disk path, stripping the \\?\ device
        /// prefix. Returns null when the handle is invalid or the path can't be resolved.</summary>
        private static string GetPathFromHandle(uint hFile)
        {
            if (hFile == 0) return null;
            var sb = new System.Text.StringBuilder(520);
            uint n = GetFinalPathNameByHandle(Ptr(hFile), sb, (uint)sb.Capacity, 0);
            if (n == 0) return null;
            string p = sb.ToString();
            if (p.StartsWith(@"\\?\UNC\")) p = @"\\" + p.Substring(8);
            else if (p.StartsWith(@"\\?\")) p = p.Substring(4);
            return p;
        }

        /// <summary>Close a raw debug-event handle (the LOAD_DLL hFile) so we don't leak it.</summary>
        private static void CloseHandleValue(uint handle)
        {
            if (handle != 0) Native.CloseHandle(Ptr(handle));
        }

        // --- DEBUG_EVENT header accessors (first 12 bytes) ---
        private static uint Code(byte[] b) { return U32(b, 0); }
        private static uint Pid(byte[] b) { return U32(b, 4); }
        private static uint Tid(byte[] b) { return U32(b, 8); }
        private static uint U32(byte[] b, int off) { return BitConverter.ToUInt32(b, off); }

    }
}
