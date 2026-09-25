using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows.Forms;
using ClarionDebugger.Services;
using ClarionDebugger.Wire;
using ICSharpCode.SharpDevelop.Project;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace ClarionDebugger.Terminal
{
    /// <summary>
    /// WebView2 front-end for the CA Debugger (Phase 3). Hosts Terminal/debugger.html and bridges it
    /// to the standalone ClarionDbg engine via ClarionDebuggerService: forwards paused / call-stack /
    /// watch-by-name / breakpoint / register / console events to the page, and routes the page's
    /// toolbar + watch actions back to the engine. Breakpoints are still set in the Clarion editor
    /// gutter (Phase 2 EditorBreakpointService) and merged on session start.
    /// </summary>
    public sealed class ClarionDebuggerWebView : UserControl, IDebugSessionTarget
    {
        private WebView2 _webView;
        // _ready/_startQueued are written from the WebView2 NavigationCompleted callback and read from
        // command-surface methods; both run on the UI thread, but mark volatile to make the
        // publish/consume explicit and tolerate any reordering. UI-thread-only access otherwise.
        private volatile bool _ready;
        private bool _initializing;
        private volatile bool _startQueued; // a toolbar Start arrived before the WebView was ready; fire it on NavigationCompleted

        // Messages posted before the WebView is ready, held until NavigationCompleted rather than
        // discarded. The page's inline script calls send('ready') while the document is still
        // parsing, but WebView2 raises NavigationCompleted only after the load event — so the whole
        // "ready" handler runs in a window where _ready is false. Without this buffer every message
        // it produces is thrown away, silently: the initial runstate, the About payload, and the
        // "auto-detected target" console line. (PushProcedures escaped it only by accident, because
        // it posts via UI(), i.e. a later message-loop turn.)
        //
        // Bounded: if navigation never completes, this must not grow without limit. On overflow the
        // OLDEST is dropped — for state pushes the newest message is the truthful one.
        //
        // _postLock guards both the queue and the enqueue-vs-flush decision. It is not enough for
        // _ready to be volatile: without the lock, Post() can observe _ready == false, be preempted
        // by the flush, and then enqueue into a queue nobody will drain again.
        private const int MaxPendingPosts = 64;
        private readonly object _postLock = new object();
        private readonly Queue<string> _pendingPosts = new Queue<string>();
        private bool _pendingOverflowed;

        private readonly ClarionDebuggerService _svc = new ClarionDebuggerService();
        private readonly EditorBreakpointService _gutter = new EditorBreakpointService();
        private readonly List<DebugBreakpoint> _pending = new List<DebugBreakpoint>(); // breakpoints while idle
        // Transient "run to cursor" breakpoints — planted in the engine then auto-removed on the next pause
        // (whether the cursor line or another breakpoint is hit first). Kept OUT of _pending and the gutter so
        // they never persist or show in the Breakpoints pane. Keyed "module:line" (module compared case-insensitively).
        private readonly HashSet<string> _transientBps = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // The one run-to-cursor transient awaiting engine bp-set confirmation before we resume (two-phase, so a
        // transient the engine rejects via async bp-error never leaves the target running with no stop). Null
        // when no run-to-cursor is in flight. Its key is also in _transientBps, so cleanup happens regardless of
        // whether confirmation ever arrives. UI-thread only.
        private string _pendingRtcKey;
        private int _pendingRtcLine;   // requested line of the pending run-to-cursor — matches the engine's bp echo by line
        private readonly HashSet<string> _watched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        // What the page may hand back, as the HOST issued it (afbc68c7). The page names a Procedures row by
        // the id it was sent with, and an edit by the row's own tuple; both are checked here rather than
        // trusted. UI-thread only, like every other piece of pad state.
        private readonly ProcedureIds _procIds = new ProcedureIds();
        // It reads the thread selection from the service, the one owner of it (49538b78 8b); set in the constructor.
        private readonly EditGrants _editGrants;
        // The attach picker's pids, as the HOST listed them (3f2d747f): `attach` is honoured only for one of these.
        private readonly ListedProcesses _listedProcs = new ListedProcesses();
        private int _procsGen;   // generation of the newest process listing; an older one arriving late is dropped
        // The ATTACH session in progress, or null for a launch / no session. UI-thread only.
        private AttachContext _attach;
        // The app last attached to, for the "Detached; <name>" line only. The engine's `detached` event names just the
        // pid, and when the engine's exit is handled before that buffered line, both the service's target and _attach
        // are already gone. Display only: nothing decides anything on it.
        private string _lastAttachName;
        private string _exe = "";
        private bool _exeAuto;          // _exe came from auto-resolve (re-resolvable)
        private string _exeManualKey;   // when _exe is a manual Browse pick, the solution/project context it was chosen for (one-shot)

        // The exact local file URI the WebView is expected to navigate to. Used to (a) gate _ready on the
        // navigation actually being our packaged page and (b) reject web messages from any other origin.
        private string _expectedUri;
        // Event handlers retained so Dispose can detach them from _svc BEFORE teardown.
        private CoreWebView2 _coreForEvents;

        public ClarionDebuggerWebView()
        {
            BackColor = Color.FromArgb(30, 30, 30);
            Dock = DockStyle.Fill;
            _editGrants = new EditGrants(() => _svc.Selection);
            _webView = new WebView2 { Dock = DockStyle.Fill };
            Controls.Add(_webView);

            // Wire engine + gutter events via named handlers (stored implicitly by method group) so Dispose
            // can detach them BEFORE _svc.Stop()/teardown — no late callback can touch a half-disposed pad.
            _svc.StateChanged          += OnSvcStateChanged;
            _svc.Paused                += OnPaused;
            _svc.Resumed               += OnSvcResumed;
            _svc.HitReceived           += OnSvcHit;
            _svc.StackReceived         += OnSvcStack;
            _svc.ModuleDataReceived    += OnSvcModuleData;
            _svc.ExpandedReceived      += OnSvcExpanded;
            _svc.FrameLocalsReceived   += OnSvcFrameLocals;
            _svc.LibStateReceived      += OnSvcLibState;
            _svc.MemReceived           += OnSvcMem;
            _svc.WatchReceived         += OnSvcWatch;
            _svc.RegsReceived          += OnSvcRegs;
            _svc.ThreadsReceived       += OnSvcThreads;
            _svc.ThreadSelected        += OnSvcThreadSelected;
            _svc.SelectionChanged      += OnSvcSelectionChanged;
            _svc.HoverChanged          += OnSvcHover;
            _svc.VariableSet           += OnSvcVariableSet;
            _svc.BreakpointSet         += OnSvcBreakpointSet;
            _svc.BreakpointRemoved     += OnSvcBreakpointRemoved;
            _svc.BreakpointListReceived += OnSvcBreakpointList;
            _svc.BreakpointError       += OnSvcBreakpointError;
            _svc.Traced                += OnSvcTraced;
            _svc.EngineError           += OnSvcEngineError;
            _svc.SetIpResult           += OnSvcSetIpResult;
            _svc.ModuleLoaded          += OnSvcModuleLoaded;
            _svc.ModuleUnloaded        += OnSvcModuleUnloaded;
            _svc.LogReceived           += OnSvcLog;
            _svc.Exited                += OnSvcExited;
            _svc.Detached              += OnSvcDetached;
            _svc.DetachAbandoned       += OnSvcDetachAbandoned;

            _gutter.GutterBreakpointAdded   += OnGutterAdded;
            _gutter.GutterBreakpointRemoved += OnGutterRemoved;

            HandleCreated += OnHandleCreated;

            AttachProjectEvents();

            // Become the live target for the IDE debug toolbar. The latest pad instance wins.
            DebugSessionController.Register(this);
        }

        /// <summary>
        /// Track the IDE's solution/project so the pad reflects what is open without being told to.
        /// Previously the target and Procedures were resolved only on the page's "ready" message —
        /// once, when the WebView first navigates — or when the user pressed the refresh button.
        /// Opening a solution afterwards left the pad showing "No procedures yet" indefinitely, and
        /// there was no user action that plausibly fixed it: closing the pad only HIDES it, so
        /// reopening does not re-run initialization.
        /// </summary>
        /// <remarks>
        /// Subscribed directly rather than through reflection: ProjectService exposes these three
        /// events with identical signatures on Clarion 10, 11 and 12 (verified against each install's
        /// ICSharpCode.SharpDevelop.dll), and the addin is compiled once per version anyway.
        /// ProjectTargetService reflects for a different reason — it walks solution/project shapes
        /// that do differ.
        /// </remarks>
        private void AttachProjectEvents()
        {
            try
            {
                ProjectService.SolutionLoaded        += OnIdeSolutionLoaded;
                ProjectService.SolutionClosed        += OnIdeSolutionClosed;
                ProjectService.CurrentProjectChanged += OnIdeCurrentProjectChanged;
            }
            catch (Exception ex)
            {
                // Never let a host-API difference stop the pad from loading — the refresh button and
                // Start both still re-resolve, so this degrades to the old behaviour rather than failing.
                System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] could not subscribe to ProjectService events: " + ex.Message);
            }
        }

        private void DetachProjectEvents()
        {
            try
            {
                ProjectService.SolutionLoaded        -= OnIdeSolutionLoaded;
                ProjectService.SolutionClosed        -= OnIdeSolutionClosed;
                ProjectService.CurrentProjectChanged -= OnIdeCurrentProjectChanged;
            }
            catch { }
        }

        private void OnIdeSolutionLoaded(object sender, SolutionEventArgs e) => RefreshForIdeContext("solution opened");
        private void OnIdeSolutionClosed(object sender, EventArgs e) => ClearForClosedSolution();
        private void OnIdeCurrentProjectChanged(object sender, ProjectEventArgs e) => RefreshForIdeContext("project changed");

        /// <summary>
        /// Re-resolve the target and re-list procedures for whatever the IDE now has open — the same
        /// work the refresh button does, just triggered by the IDE instead of by the user.
        /// </summary>
        /// <remarks>
        /// Idle-guarded, and that guard is load-bearing rather than defensive: PushProcedures calls
        /// _svc.PrimeTarget(), which re-anchors the .red resolver at a new EXE. Doing that while a
        /// session is live repoints the resolver away from the binary actually being debugged — the
        /// "live-session resolver poisoning" failure already fixed once on the sibling
        /// ClarionAssistant work. A solution opened mid-session is ignored here on purpose; the next
        /// Start re-resolves from scratch via ResolveTargetForStart().
        /// </remarks>
        /// <param name="sessionEnded">
        /// True when called from the state-change handler because the session just ended. The caller
        /// already knows the session is over, so the idle check is skipped: _svc.State is not
        /// guaranteed to read Idle yet at the moment the StateChanged callback runs, and re-deriving
        /// it here would make this depend on an ordering assumption. Getting exactly that wrong is
        /// what caused the two preceding bugs in this file.
        /// </param>
        private void RefreshForIdeContext(string why, bool sessionEnded = false)
        {
            UI(() =>
            {
                try
                {
                    if (!sessionEnded && CurrentState != DebugSessionState.Idle) return;
                    // TryAutoResolveExe already announces a changed target and pushes it to the
                    // target bar; a second line here just said the same thing twice.
                    TryAutoResolveExe();
                    if (!string.IsNullOrEmpty(_exe)) PushProcedures(_exe);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] IDE context refresh failed: " + ex.Message);
                }
            });
        }

        /// <summary>Drop target/procedure state when the solution closes, so the pad never shows a list
        /// belonging to a solution that is no longer open. Idle-guarded for the same reason as above.</summary>
        private void ClearForClosedSolution()
        {
            UI(() =>
            {
                try
                {
                    if (CurrentState != DebugSessionState.Idle) return;
                    _exe = null; _exeAuto = false; _exeManualKey = null;
                    _procGen++;                       // invalidate any in-flight procedure parse
                    _procIds.Clear();                 // and every id the old list was sent with
                    Post("{\"type\":\"procedures\",\"procs\":[]}");
                    PushTarget();                     // blanks the target bar
                    Console("info", "solution closed — target cleared");
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] solution-closed cleanup failed: " + ex.Message);
                }
            });
        }

        /// <summary>Detach every engine/gutter event handler. Called from Dispose BEFORE _svc.Stop() so a
        /// late off-thread callback (Exited/StateChanged fire off-thread) can't run against a disposing pad.</summary>
        private void DetachServiceEvents()
        {
            _svc.StateChanged           -= OnSvcStateChanged;
            _svc.Paused                 -= OnPaused;
            _svc.Resumed                -= OnSvcResumed;
            _svc.HitReceived            -= OnSvcHit;
            _svc.StackReceived          -= OnSvcStack;
            _svc.ModuleDataReceived     -= OnSvcModuleData;
            _svc.ExpandedReceived       -= OnSvcExpanded;
            _svc.FrameLocalsReceived    -= OnSvcFrameLocals;
            _svc.LibStateReceived       -= OnSvcLibState;
            _svc.MemReceived            -= OnSvcMem;
            _svc.WatchReceived          -= OnSvcWatch;
            _svc.RegsReceived           -= OnSvcRegs;
            _svc.ThreadsReceived        -= OnSvcThreads;
            _svc.ThreadSelected         -= OnSvcThreadSelected;
            _svc.SelectionChanged       -= OnSvcSelectionChanged;
            _svc.HoverChanged           -= OnSvcHover;
            _svc.VariableSet            -= OnSvcVariableSet;
            _svc.BreakpointSet          -= OnSvcBreakpointSet;
            _svc.BreakpointRemoved      -= OnSvcBreakpointRemoved;
            _svc.BreakpointListReceived -= OnSvcBreakpointList;
            _svc.BreakpointError        -= OnSvcBreakpointError;
            _svc.Traced                 -= OnSvcTraced;
            _svc.EngineError            -= OnSvcEngineError;
            _svc.SetIpResult            -= OnSvcSetIpResult;
            _svc.ModuleLoaded           -= OnSvcModuleLoaded;
            _svc.ModuleUnloaded         -= OnSvcModuleUnloaded;
            _svc.LogReceived            -= OnSvcLog;
            _svc.Exited                 -= OnSvcExited;
            _svc.Detached               -= OnSvcDetached;
            _svc.DetachAbandoned        -= OnSvcDetachAbandoned;

            _gutter.GutterBreakpointAdded   -= OnGutterAdded;
            _gutter.GutterBreakpointRemoved -= OnGutterRemoved;
        }

        // ------------------------------------------------------------------ engine event handlers (named, detachable)

        private void OnSvcStateChanged(DebugSessionState s)
        {
            // Mirror engine state into the IDE-toolbar controller. Instance-aware: the controller ignores
            // this if we are no longer the registered target (a stale/disposed pad can't stomp toolbar state).
            // Fires off-thread (OutputDataReceived/Exited); the Post is marshalled to the UI thread.
            DebugSessionController.SetState(this, ToControllerState(s));
            UI(() => Post("{\"type\":\"runstate\",\"state\":\"" + StateName(s) + "\"}"));

            // Catch up with the IDE now the session is over. RefreshForIdeContext deliberately
            // ignores solution/project events while a session is live, because re-priming the .red
            // resolver mid-session would repoint it away from the binary being debugged. But
            // suppressing those events left nothing to reconcile afterwards: open a different
            // solution while paused, Stop, and the pad went on showing the OLD target indefinitely —
            // it only corrected itself on the next IDE event, which might be the solution closing
            // minutes later. Observed exactly that way during the v1.2.0 session test.
            if (s == DebugSessionState.Idle) RefreshForIdeContext("session ended", sessionEnded: true);

            // Session over by any route (exit, terminate, detach, engine crash): drop the execution-line
            // marker. Exited/CmdStop/Dispose clear too; this also catches an engine that dies without them.
            if (s == DebugSessionState.Idle) UI(ClearExecutionLineIfHooked);
        }

        // Every resume (continue, step in/over/out, stepi, run-to-cursor's deferred Continue) arrives here:
        // the target is running again, so the paused-line marker no longer applies. Watch func-evals don't
        // emit 'resumed', so they leave the marker alone.
        private void OnSvcResumed(string mode) => UI(() => { _editGrants.Clear(); _stopSource = null; ClearExecutionLineIfHooked(); Post("{\"type\":\"resumed\",\"mode\":" + Str(mode) + "}"); Console("info", "resumed (" + mode + ")"); });
        private void OnSvcHit(DebugHit hit) => UI(() => Console("hit", "*** HIT  " + (hit.Resolved ? hit.Module + " line " + hit.Line : hit.Va)));
        private void OnSvcStack(List<DebugStackFrame> frames, uint? tid, string reqId) => UI(() => OnStack(frames, tid, reqId));
        // The engine already produces display-ready, escaped JSON rows (with nested children + lazy ref
        // fields); forward its array bodies verbatim so the structure survives intact.

        // Each of the three row replies GRANTS its editable rows before it posts them (afbc68c7): these are the
        // rows whose address/type tuple the page may later send back in an edit, and EditVar honours only a
        // tuple issued here. An expanded reference carries no tid, so its rows are granted unscoped.
        private void OnSvcModuleData(string module, string itemsJson, uint? tid) => UI(() =>
        {
            _editGrants.GrantRows(itemsJson, tid);
            Post("{\"type\":\"moduledata\",\"module\":" + Str(module) + ",\"items\":[" + (itemsJson ?? "") + "]" + TidJson(tid) + "}");
        });

        private void OnSvcExpanded(string reqId, string itemsJson) => UI(() =>
        {
            // Only a reply to an expand the host VERIFIED and forwarded may grant (afbc68c7): its rows are
            // members of a group the host itself offered. Any other reply is posted for display, and grants
            // nothing - its rows cannot be edited or expanded further.
            if (_editGrants.ExpandVerified(reqId)) _editGrants.GrantRows(itemsJson, null);
            Post("{\"type\":\"expanded\",\"reqId\":" + Str(reqId) + ",\"items\":[" + (itemsJson ?? "") + "]}");
        });

        private void OnSvcFrameLocals(string reqId, string itemsJson, uint? tid) => UI(() =>
        {
            // Only a reply to a framelocals the host VERIFIED and forwarded may grant (49538b78 wave 5): its rows
            // are the locals of a frame the host itself offered, at that frame's own EBP. Any other reply is
            // posted for display, and grants nothing.
            if (_editGrants.FrameLocalsVerified(reqId, tid)) _editGrants.GrantRows(itemsJson, tid);
            Post("{\"type\":\"framelocals\",\"reqId\":" + Str(reqId) + ",\"items\":[" + (itemsJson ?? "") + "]" + TidJson(tid) + "}");
        });
        private void OnSvcLibState(string reqId, string error, string itemsJson, uint? tid) => UI(() =>
            Post("{\"type\":\"libstate\",\"reqId\":" + Str(reqId) + ",\"error\":" + Str(error) + ",\"items\":[" + (itemsJson ?? "") + "]" + TidJson(tid) + "}"));
        // Memory panel. Grants nothing: a dump is display only (see RequestMem's security note).
        private void OnSvcMem(string reqId, string addr, int len, int read, string bytes, string error) => UI(() =>
            Post("{\"type\":\"mem\",\"reqId\":" + Str(reqId) + ",\"addr\":" + Str(addr)
                 + ",\"len\":" + len.ToString(CultureInfo.InvariantCulture) + ",\"read\":" + read.ToString(CultureInfo.InvariantCulture)
                 + ",\"bytes\":" + Str(bytes) + ",\"error\":" + Str(error) + "}"));
        private void OnSvcRegs(Dictionary<string, string> regs, uint? tid) => UI(() =>
            Post("{\"type\":\"regs\",\"regs\":" + RegsJson(regs) + TidJson(tid) + "}"));
        private void OnSvcThreads(DebugThreadList list) => UI(() => OnThreads(list));
        // A stop and a switch clear the grants in their own handlers. An inventory that MOVED the selection (the
        // engine's selection was not the one the host held) has no handler of its own that clears, and every row
        // on screen is then the old thread's.
        private void OnSvcSelectionChanged(ThreadSelection s) => UI(() =>
        {
            if (s.Cause == ThreadSelectionCause.Inventory) _editGrants.Clear();
        });
        // The tid here is the thread that was ASKED FOR, and a malformed request carries none — so it is
        // forwarded through TidJson, which OMITS the member rather than writing a 0 the page would read as
        // a real thread id. On a refusal the engine's selection is unchanged; the page keeps the selection
        // it had and re-asks 'threads' for the authoritative one.
        private void OnSvcThreadSelected(uint? tid, bool ok, string error) => UI(() =>
        {
            // A switch makes every row on screen another thread's; the page re-reads, and the replies re-grant.
            // Only the new thread's stack replies may offer frames from here on (the service moved the selection).
            if (ok) _editGrants.Clear();
            Post("{\"type\":\"threadselected\"" + TidJson(tid) + ",\"ok\":" + (ok ? "true" : "false")
                + ",\"error\":" + Str(error) + "}");
            if (!ok) Console("err", "thread " + (tid.HasValue ? tid.Value.ToString(CultureInfo.InvariantCulture) : "?")
                                  + ": " + (error ?? "could not select"));
        });
        // Hover mode (f6e547ce). Not thread-SCOPED: the tid names the thread under the cursor, so the page
        // must not run it through tidAccepted. None is an absent tid, through TidJson like every tid.
        private void OnSvcHover(uint? tid, bool on, bool paused) => UI(() =>
        {
            Post("{\"type\":\"hover\",\"on\":" + (on ? "true" : "false") + ",\"paused\":" + (paused ? "true" : "false")
                + TidJson(tid) + "}");
        });
        private void OnSvcWatch(DebugWatch w) => UI(() => OnWatch(w));
        // The ENGINE's answer to a write the host sent: it re-issues the grant that write spent, so the row can
        // be edited again (afbc68c7). A refusal the host makes itself goes through PostVarSet and re-issues
        // nothing - it spent nothing.
        private void OnSvcVariableSet(string va, bool ok, string value, string error) => UI(() =>
        {
            _editGrants.Regrant(va);
            PostVarSet(va, ok, value, error);
        });

        private void PostVarSet(string va, bool ok, string value, string error)
        {
            Post("{\"type\":\"varset\",\"va\":" + Str(va) + ",\"ok\":" + (ok ? "true" : "false")
                + ",\"value\":" + Str(value) + ",\"error\":" + Str(error) + "}");
            if (!ok) Console("err", "edit value failed: " + (error ?? "unknown"));
        }

        private void OnSvcBreakpointSet(DebugBreakpoint bp) => UI(() =>
        {
            // Phase 2 of run-to-cursor: the transient is now confirmed armed, so it's safe to resume. There is
            // at most one pending run-to-cursor, just planted while paused on a line that had NO breakpoint
            // before, so the bp-set at that requested/planted line is unambiguously ours — match by LINE, not
            // module. Then ADOPT the engine's CANONICAL module+line as the transient's tracking key, so the
            // later RemoveBreakpoint (OnPaused) matches engine truth even if the engine canonicalizes the module
            // name differently from the UI's curFile — no stranded, untracked one-shot.
            if (_pendingRtcKey != null && bp != null && bp.Module != null
                && (bp.DisplayLine == _pendingRtcLine || bp.Line == _pendingRtcLine))
            {
                _transientBps.Remove(_pendingRtcKey);
                _pendingRtcKey = null;
                _transientBps.Add(TransientKey(bp.Module, bp.DisplayLine));   // engine-confirmed identity
                SendBps();
                if (CurrentState == DebugSessionState.Paused) _svc.Continue();
                return;
            }
            SendBps();
        });
        private void OnSvcBreakpointRemoved(string m, int l) => UI(() => SendBps());
        private void OnSvcBreakpointList(List<DebugBreakpoint> list) => UI(() => SendBps());
        private void OnSvcBreakpointError(string m, int l, string err) => UI(() =>
        {
            // A pending run-to-cursor transient the engine rejected (e.g. no resolvable code record): it never
            // armed, so drop it and stay paused rather than running free with no stop. Match by line for the
            // same reason as bp-set (one pending RTC; module spelling may be the engine's canonical form).
            if (_pendingRtcKey != null && l == _pendingRtcLine)
            {
                _transientBps.Remove(_pendingRtcKey);
                _pendingRtcKey = null;
                Console("err", "run to cursor: " + m + ":" + l + " — " + err + " (could not arm; staying paused).");
                SendBps();
                return;
            }
            Console("err", "breakpoint " + m + ":" + l + " — " + err);
        });
        private void OnSvcTraced(string m, int l, string msg, int hits) => UI(() => Console("trace", m + ":" + l + "  " + msg + "  (#" + hits + ")"));
        // Also pushed to the page as a typed message, not only to the console: the page can have a request
        // in flight (a thread switch) that this error is the answer to, and a console line is text it
        // cannot act on. Nothing else in the page reads it today.
        private void OnSvcEngineError(string msg) => UI(() =>
        {
            // An attach that failed says why in this error, and the engine exits right after it. The exit clears the
            // page's console, so the reason is kept to be said again after that clear (see OnSvcExited).
            if (_attach != null && msg != null && msg.StartsWith("attach ", StringComparison.Ordinal)) _attach.LastError = msg;
            Console("err", "engine: " + msg);
            Post("{\"type\":\"engineerror\",\"message\":" + Str(msg) + "}");
        });
        private void OnSvcModuleLoaded(DebugModule m) => UI(() => OnModuleLoaded(m));
        private void OnSvcModuleUnloaded(DebugModule m) => UI(() => Post("{\"type\":\"module-unloaded\",\"name\":" + Str(m.Name) + "}"));
        private void OnSvcLog(string s) => UI(() => Console("info", s));
        private void OnSvcExited(int code) => UI(() =>
        {
            _editGrants.Clear(); _transientBps.Clear(); _pendingRtcKey = null; ClearExecutionLine();
            var attach = _attach;
            _attach = null;
            if (attach == null) { Console("info", "— session ended (exit " + code + ") —"); Post("{\"type\":\"clear\"}"); return; }
            // An ATTACH session (3f2d747f). After a detach, OnSvcDetached has already cleared the page and said the
            // app is still running; clearing again here would wipe that line.
            if (attach.Detached) return;
            // Otherwise clear FIRST, since `clear` empties the console, and then say why: an attach that failed
            // reported its reason just before the engine exited, and that line is gone with the clear.
            Post("{\"type\":\"clear\"}");
            if (attach.LastError != null) Console("err", "engine: " + attach.LastError);
            Console("info", "— session ended (exit " + code + ") —");
        });

        /// <summary>The engine let the attached process go, and it keeps running (3f2d747f). The same reset as a
        /// session end (OnSvcExited), then the one line the user needs - and a warning when a planted breakpoint
        /// byte could not be restored, because the app will then hit an INT3 with no debugger and most likely crash.
        /// The engine's exit follows; OnSvcExited sees <see cref="AttachContext.Detached"/> and leaves this alone.</summary>
        private void OnSvcDetached(DebugDetach d) => UI(() =>
        {
            if (_attach != null) _attach.Detached = true;
            _editGrants.Clear(); _transientBps.Clear(); _pendingRtcKey = null; ClearExecutionLine();
            Post("{\"type\":\"clear\"}");   // first: `clear` empties the console, and the lines below must survive it
            string name = d != null && !string.IsNullOrEmpty(d.Name) ? d.Name
                        : !string.IsNullOrEmpty(_lastAttachName) ? _lastAttachName : "the app";
            // `restored` is a COUNT and informational; -1 = the engine did not say. The crash warning is driven
            // ONLY by `error`, which the engine sets whenever any restore failed.
            string count = d != null && d.Restored >= 0
                ? " (" + d.Restored.ToString(CultureInfo.InvariantCulture) + " breakpoint" + (d.Restored == 1 ? "" : "s") + " restored)"
                : "";
            Console("info", "Detached; " + name + " is still running" + count + ".");
            if (d != null && !string.IsNullOrEmpty(d.Error))
                Console("err", "detach could not restore every breakpoint (" + d.Error + "): "
                    + name + " will probably crash when it reaches one. Save your work in it and restart it.");
        });

        // Stop had to kill an attached engine (the page is live here; a closing pad is covered by TeardownObserver).
        private void OnSvcDetachAbandoned(AttachableProcess t) => UI(() =>
            Console("err", DetachWarningText(t != null ? t.Name : _lastAttachName, t != null ? (uint?)t.Pid : null,
                "the engine did not detach in time and had to be killed, so breakpoints may still be planted")));

        /// <summary>The one wording of an unsafe detach, for the console, the dialog and the log alike.</summary>
        internal static string DetachWarningText(string name, uint? pid, string error)
        {
            string app = string.IsNullOrEmpty(name) ? "the app" : name;
            return "CA Debugger could not detach cleanly from " + app
                + (pid.HasValue ? " (pid " + pid.Value.ToString(CultureInfo.InvariantCulture) + ")" : "")
                + ": " + (string.IsNullOrEmpty(error) ? "unknown error" : error)
                + ". Save your work in " + app + " and restart it.";
        }

        private void OnGutterAdded(string m, int l, string f) => UI(() => OnGutterBpAdded(m, l));
        private void OnGutterRemoved(string m, int l, string f) => UI(() => OnGutterBpRemoved(m, l));

        private async void OnHandleCreated(object sender, EventArgs e)
        {
            if (_initializing || _ready) return;
            _initializing = true;
            try
            {
                var env = await WebView2EnvironmentCache.GetEnvironmentAsync();
                await _webView.EnsureCoreWebView2Async(env);
                var core = _webView.CoreWebView2;
                _coreForEvents = core;
                var st = core.Settings;
                st.IsScriptEnabled = true;
                st.AreDefaultContextMenusEnabled = false;
                st.IsStatusBarEnabled = false;

                string html = GetHtmlPath();
                if (!File.Exists(html))
                {
                    _initializing = false;
                    _startQueued = false; // nothing to navigate to — don't strand a queued Start
                    System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] init: debugger.html not found at " + html);
                    return;
                }
                // The exact origin we trust: our packaged debugger.html. Used to gate readiness and to reject
                // web messages from any other navigation.
                _expectedUri = new Uri(html).AbsoluteUri;

                core.WebMessageReceived += OnWebMessage;
                core.NavigationCompleted += OnNavigationCompleted;

                core.Navigate(_expectedUri + "?theme=dark");
            }
            catch (Exception ex)
            {
                // Initialization failed. Reset the init flags (don't leave _initializing latched) and clear any
                // queued Start so it isn't silently stranded. NOTE: OnHandleCreated is wired to the one-shot
                // HandleCreated event and won't re-run, so we deliberately do NOT promise a Start-retry here —
                // recovery is reopening the pad.
                _initializing = false;
                _ready = false;
                _startQueued = false;
                System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] init: " + ex.Message);
                UI(() => Console("err", "debugger view failed to initialize: " + ex.Message + " — reopen the CA Debugger pad to retry."));
            }
        }

        /// <summary>
        /// Gate readiness on the navigation having (a) succeeded and (b) landed on OUR packaged debugger.html
        /// — not just "any completed navigation". On failure: stay not-ready, surface a console error, and
        /// CLEAR any queued Start so a toolbar Start isn't silently stranded against a dead view.
        /// </summary>
        private void OnNavigationCompleted(object s, CoreWebView2NavigationCompletedEventArgs ev)
        {
            bool ok = false;
            string reason = null;
            try
            {
                if (ev != null && !ev.IsSuccess) reason = "web error " + ev.WebErrorStatus;
                else if (!IsExpectedSource(SafeSource())) reason = "unexpected navigation target";
                else ok = true;
            }
            catch (Exception ex) { reason = ex.Message; }

            if (ok)
            {
                _ready = true; _initializing = false;
                // Deliver anything the page missed while it was still loading — in particular
                // everything the "ready" handler produced, which runs strictly before this event.
                // Flush FIRST so the page receives startup state in generation order, and before any
                // queued Start starts producing newer messages on top of it.
                FlushPendingPosts();
                // Run a queued Start now that the page is live — but re-check idempotency (StartSession only
                // when still Idle) so the queued path is guarded identically to CmdStart.
                if (_startQueued)
                {
                    _startQueued = false;
                    // Re-check both gates (pad-local + global controller Idle) before firing the queued Start —
                    // identical to CmdStart, in case state changed while we were navigating.
                    UI(() => { try { if (CurrentState == DebugSessionState.Idle && DebugSessionController.State == DebugControllerState.Idle) StartSession(); } catch (Exception ex) { Console("err", "start failed: " + ex.Message); } });
                }
            }
            else
            {
                _ready = false; _initializing = false;
                _startQueued = false; // don't strand a queued Start on a failed navigation
                // Same reasoning for buffered messages: the page never came up, so there is nothing
                // to replay them into. Holding them would also keep them alive across the reopen
                // that is the documented recovery, delivering stale startup state to a fresh page.
                DiscardPendingPosts("navigation failed: " + (reason ?? "unknown"));
                // Don't promise a Start-retry: OnHandleCreated is one-shot and won't re-run.
                //
                // This used to tell the user to reopen the pad, which cannot work: the IDE only HIDES
                // a closed pad, it does not dispose it, so reopening reuses this same instance and
                // re-runs nothing. Restarting the IDE is the honest recovery.
                UI(() => Console("err", "debugger view failed to initialize: " + (reason ?? "unknown") + " — restart the Clarion IDE to retry (closing the pad only hides it)."));
            }
        }

        /// <summary>The WebView's current document URI, or null if unavailable.</summary>
        private string SafeSource()
        {
            try { return _coreForEvents != null ? _coreForEvents.Source : null; }
            catch { return null; }
        }

        /// <summary>The origin URI a web message was posted from (falls back to the WebView's current Source).</summary>
        private string SafeMessageSource(CoreWebView2WebMessageReceivedEventArgs e)
        {
            try { if (e != null && !string.IsNullOrEmpty(e.Source)) return e.Source; }
            catch { }
            return SafeSource();
        }

        /// <summary>True when <paramref name="uri"/> is our packaged debugger.html (ignoring the ?theme query).</summary>
        private bool IsExpectedSource(string uri)
        {
            if (string.IsNullOrEmpty(_expectedUri) || string.IsNullOrEmpty(uri)) return false;
            try
            {
                int q = uri.IndexOf('?');
                string bare = q >= 0 ? uri.Substring(0, q) : uri;
                return string.Equals(bare, _expectedUri, StringComparison.OrdinalIgnoreCase);
            }
            catch { return false; }
        }

        private static string GetHtmlPath()
        {
            string dir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string p = Path.Combine(dir, "Terminal", "debugger.html");
            return File.Exists(p) ? p : Path.Combine(dir, "debugger.html");
        }

        // ------------------------------------------------------------------ page → host

        private void OnWebMessage(object sender, CoreWebView2WebMessageReceivedEventArgs e)
        {
            try
            {
                // Defense-in-depth: only honour messages from our trusted packaged debugger.html. A message
                // whose origin we can't confirm is dropped (an injected/redirected page can't drive the engine).
                if (!IsExpectedSource(SafeMessageSource(e)))
                {
                    System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] dropped web message from untrusted source");
                    return;
                }

                // Typed once, here: a message that is not a well-formed envelope is dropped whole. Each case
                // below parses its own payload through the DTO in PageMessages.cs and drops a malformed one.
                var msg = PageEnvelope.Parse(e.TryGetWebMessageAsString());
                if (msg == null) return;
                string data = msg.Data;
                switch (msg.Action)
                {
                    // The page also asks for About data whenever the panel is opened, so it reflects
                    // live state rather than a value captured once at startup. The push on "ready"
                    // below now survives too (Post buffers until NavigationCompleted), but this
                    // request path is kept deliberately: it is the one that cannot be broken by a
                    // future change to initialization ordering.
                    case "about": PushAbout(); break;
                    case "revealexe": RevealExe(); break;
                    case "opendocs": OpenDocs(); break;
                    case "ready":
                        Post("{\"type\":\"runstate\",\"state\":\"idle\"}");
                        PushAbout();
                        PushTarget();
                        if (string.IsNullOrEmpty(_exe)) TryAutoResolveExe();
                        if (!string.IsNullOrEmpty(_exe)) PushProcedures(_exe);   // list procedures before running
                        break;
                    case "start": CmdStart(); break;
                    case "continue": CmdContinue(); break;
                    case "pause": CmdPause(); break;
                    case "stepover": CmdStepOver(); break;
                    case "stepinto": CmdStepInto(); break;
                    case "stepout": CmdStepOut(); break;
                    case "stop": CmdStop(); break;
                    case "procs": CmdListProcs(); break;           // attach picker: list attachable processes
                    case "attach": CmdAttach(data); break;         // data = a pid from the host's own last listing
                    case "watch":
                        if (!string.IsNullOrEmpty(data)) { _watched.Add(data); if (_svc.State == DebugSessionState.Paused) WatchOrExplain(data); }
                        break;
                    case "unwatch": if (!string.IsNullOrEmpty(data)) _watched.Remove(data); break;
                    case "expand": Expand(data); break;   // lazy ref-node expansion: data = "reqId|module|typeRef|addr"
                    case "framelocals": FrameLocals(data); break;   // call-stack frame locals: data = "reqId|va|ebp"
                    case "mem":   // Memory panel read: data = "reqId|0xADDR|len". Trust model (page trusted for reads, 2026-09-23): see RequestMem.
                        if (_svc.State == DebugSessionState.Paused)
                        {
                            var mr = MemRequest.Parse(data);
                            if (mr != null) _svc.RequestMem(mr.ReqId, mr.Addr, mr.Len);
                        }
                        break;
                    case "libstate":   // per-thread Library State refresh: data = reqId
                        if (_svc.State == DebugSessionState.Paused && PageNumbers.TryInt(data, out int lrq))
                            _svc.RequestLibState(lrq);
                        break;

                    // ---- thread selection (Call Stack thread picker) ----
                    // The page drives the re-read after a switch, because it is the side that knows what is
                    // on screen. Each of these is paused-only; the engine refuses them otherwise anyway.
                    case "threads": if (_svc.State == DebugSessionState.Paused) _svc.RequestThreads(); break;
                    case "selectthread":
                        if (_svc.State == DebugSessionState.Paused && PageNumbers.TryUInt(data, out uint seltid))
                            _svc.SelectThread(seltid);
                        break;
                    // Hover mode: NOT paused-gated. The engine polls while running too, and reports only.
                    case "hover": if (data == "on" || data == "off") _svc.SetHover(data == "on"); break;
                    case "stack": if (_svc.State == DebugSessionState.Paused) RequestStack(); break;
                    case "moduledata": if (_svc.State == DebugSessionState.Paused) _svc.RequestModuleData(); break;
                    case "regs": if (_svc.State == DebugSessionState.Paused) _svc.RequestRegs(); break;
                    case "rewatch":
                        // Re-resolve EVERY watched name against the newly selected thread. Host-side rather
                        // than name-by-name from the page: _watched also holds the Variables-tree rows that
                        // are watched purely because they are visible, which the page's own Watch list
                        // doesn't know about — and those rows are on screen showing the old thread's values.
                        if (_svc.State == DebugSessionState.Paused)
                            foreach (var name in _watched) WatchOrExplain(name);
                        break;
                    case "editvar": EditVar(data); break;
                    case "jump": Jump(data); break;
                    case "openbp": OpenBp(data); break;
                    case "bpremove": RemoveBp(data); break;
                    case "bpprops": SetBpProps(data); break;
                    case "runtocursor": CmdRunToCursor(data); break;   // transient one-shot bp at module:line, then resume
                    case "setip": CmdSetNextStatement(data); break;    // move the stopped thread's IP to module:line
                    case "breakonprocentry": CmdBreakOnProcEntry(data); break;   // persistent bp at a procedure's entry line
                    case "proclist":   // user pressed ↻ — re-resolve FRESH so the list tracks a project/solution switch
                        TryAutoResolveExe();   // (re-resolves against the active project even if _exe was already set)
                        if (!string.IsNullOrEmpty(_exe)) PushProcedures(_exe);
                        else Console("info", "(no target EXE resolved yet — build the app, or open its solution)");
                        break;
                }
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] msg: " + ex.Message); }
        }

        // ------------------------------------------------------------------ command surface (IDebugSessionTarget)
        // One execution path shared by the in-pad buttons' web messages (above) and the IDE toolbar
        // (via DebugSessionController). All run on the UI thread (web messages arrive on it; the
        // controller is invoked from AbstractMenuCommand.Run, also on the UI thread).

        /// <summary>True once the WebView has navigated and can accept Post()/commands.</summary>
        public bool IsReady { get { return _ready && _webView != null; } }

        /// <summary>True when this pad's engine has no live session. Read by the controller (post-dispose-safe:
        /// _svc outlives the WebView teardown) to decide whether the current target is genuinely idle.</summary>
        public bool IsSessionIdle { get { try { return _svc.State == DebugSessionState.Idle; } catch { return true; } } }

        // The Cmd* methods are the SINGLE execution point for every command source — the IDE toolbar
        // (DebugSessionController forwarder -> Cmd*) AND the pad's web-message / keyboard-shortcut path
        // (OnWebMessage -> Cmd*). They are therefore SELF-GUARDING: each checks whether its command is valid
        // in the current engine state (the same matrix the toolbar condition evaluator uses) and is a safe
        // no-op otherwise. This guarantees a pad shortcut for an out-of-state command never reaches _svc and a
        // 2nd Start while a session is live can never fall through to _svc.StartSession() ("already running").
        // The controller forwarders keep their own guard as defense-in-depth; this is the authoritative one.

        /// <summary>The engine's current run-state — the source of truth both the toolbar (via the controller
        /// mirror) and these guards read, so toolbar-enabled == Cmd*-executes.</summary>
        private DebugSessionState CurrentState { get { return _svc.State; } }

        public void CmdStart()
        {
            // Idempotent: only Idle starts a session. A 2nd Start while Launching/Running/Paused is a no-op.
            if (CurrentState != DebugSessionState.Idle) return;
            // ALSO require the GLOBAL controller state to be Idle. A reopened pad's own _svc is Idle, so the
            // pad-local guard alone would let an in-pad shortcut / web-message Start launch a SECOND session
            // while a PRIOR engine is still tearing down (controller non-idle until Stop() confirms dead — see
            // ClarionDebuggerService.Stop, now authoritative). This shares the same pre-start gate the IDE
            // toolbar already gets via the condition evaluator, closing the page/shortcut bypass.
            if (DebugSessionController.State != DebugControllerState.Idle) return;
            // The toolbar can fire Start before the pad's WebView has finished navigating (the pad was just
            // opened). Queue it; NavigationCompleted will run StartSession once the page is live.
            if (!_ready) { _startQueued = true; return; }
            StartSession();
        }

        /// <summary>The attach picker asked for the processes it may offer (3f2d747f). Listed off the UI thread by the
        /// engine's one-shot <c>procs</c>, with this IDE's own pid excluded, and posted to the page as a
        /// <c>procs</c> message. The listing is also what <see cref="CmdAttach"/> checks a pid against, so a
        /// refresh retires the previous listing's pids AT ONCE, not when the new one arrives.</summary>
        private void CmdListProcs()
        {
            int gen = ++_procsGen;
            _listedProcs.Begin(gen);
            int self;
            try { self = System.Diagnostics.Process.GetCurrentProcess().Id; } catch { self = 0; }
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                string error;
                var procs = ClarionDebuggerService.ListProcesses(self, out error);
                UI(() =>
                {
                    if (!_listedProcs.Replace(gen, procs)) return;   // a newer listing was asked for meanwhile
                    Post(ProcsJson(procs, error));
                });
            });
        }

        /// <summary>The page's <c>procs</c> message. Names and paths are the processes' own, so they are written as
        /// JSON strings here and rendered as TEXT by the page, never as markup.</summary>
        private static string ProcsJson(List<AttachableProcess> procs, string error)
        {
            var sb = new StringBuilder("{\"type\":\"procs\",\"procs\":[");
            if (procs != null)
                for (int i = 0; i < procs.Count; i++)
                {
                    var p = procs[i];
                    if (i > 0) sb.Append(',');
                    sb.Append("{\"pid\":").Append(p.Pid.ToString(CultureInfo.InvariantCulture))
                      .Append(",\"name\":").Append(Str(p.Name))
                      .Append(",\"path\":").Append(Str(p.Path)).Append('}');
                }
            sb.Append("],\"error\":").Append(Str(error)).Append('}');
            return sb.ToString();
        }

        /// <summary>Attach to the process the picker named (3f2d747f). <paramref name="data"/> is a pid, and it is
        /// honoured ONLY when it is in the listing this host last sent (<see cref="ListedProcesses"/>): anything else
        /// is dropped with a console line, so nothing on the bridge can point the debugger at an arbitrary process.
        /// Gated like <see cref="CmdStart"/>: this pad idle AND the global controller idle.</summary>
        public void CmdAttach(string data)
        {
            if (CurrentState != DebugSessionState.Idle) return;
            if (DebugSessionController.State != DebugControllerState.Idle) return;
            var req = AttachRequest.Parse(data);
            if (req == null) { Console("err", "attach: dropped a request that did not name a process id"); return; }
            var target = _listedProcs.Take(req.Pid);
            if (target == null)
            {
                Console("err", "attach: pid " + req.Pid.ToString(CultureInfo.InvariantCulture)
                    + " was not in the process list this pad last showed, so it was refused. Refresh the list and pick again.");
                return;
            }
            // A pid is not an identity: without the listed start time the engine cannot check that pid still names
            // the process the user picked, so the attach is refused rather than made blind (an older engine).
            if (!AttachableProcess.IsStartTime(target.Started))
            {
                Console("err", "attach: the process list gave no start time for " + (target.Name ?? "the process") + " (pid "
                    + req.Pid.ToString(CultureInfo.InvariantCulture) + "), so the debugger cannot prove that pid is still the process"
                    + " you picked. It was not attached. The CA Debugger engine may be older than the add-in: reinstall it.");
                return;
            }
            AttachSession(target);
        }

        /// <summary>Start an ATTACH session on <paramref name="target"/>: StartSession's steps, with the listed process
        /// in place of a launched EXE.</summary>
        private void AttachSession(AttachableProcess target)
        {
            try
            {
                RearmAndReportMonacoHooks();
                if (_svc.IsEngineStillClosing) { Console("err", ClarionDebuggerService.EngineClosingMessage); return; }

                MergeGutterIntoPending();
                Post("{\"type\":\"clear\"}");
                var solutionDlls = ProjectTargetService.ResolveSolutionDlls();
                string label = (target.Name ?? "process") + " (pid " + target.Pid.ToString(CultureInfo.InvariantCulture) + ")";
                Console("info", "attaching to " + label + SessionCounts(solutionDlls));
                _attach = new AttachContext { Name = target.Name };
                _lastAttachName = target.Name;
                try { _svc.AttachSession(target, _pending.ToArray(), solutionDlls); }
                catch { _attach = null; throw; }
                // Stop now DETACHES; the page says so on its Stop control.
                Post("{\"type\":\"attachmode\",\"on\":true}");

                // Symbols come from the image on disk, as for a launch, when the listed path still resolves.
                string exe = target.Path;
                if (!string.IsNullOrEmpty(exe) && File.Exists(exe)) LoadStaticSymbols(exe);
            }
            catch (Exception ex) { Console("err", "attach failed: " + ex.Message); }
        }

        /// <summary>What the pad knows about the attach session in progress (UI-thread only).</summary>
        private sealed class AttachContext
        {
            public string Name;
            /// <summary>The engine reported <c>detached</c>: the page has been told the app is still running.</summary>
            public bool Detached;
            /// <summary>The engine's "attach ..." error, said again after the exit clears the console.</summary>
            public string LastError;
        }

        public void CmdContinue() { if (CurrentState == DebugSessionState.Paused) _svc.Continue(); }
        public void CmdStepOver() { if (CurrentState == DebugSessionState.Paused) _svc.StepOver(); }
        public void CmdStepInto() { if (CurrentState == DebugSessionState.Paused) _svc.StepInto(); }
        public void CmdStepOut()  { if (CurrentState == DebugSessionState.Paused) _svc.StepOut(); }

        /// <summary>Run to cursor: plant a transient one-shot breakpoint at module:line and resume. The bp is
        /// tracked in <see cref="_transientBps"/> (NOT _pending / the gutter), filtered out of the Breakpoints
        /// pane by <see cref="SendBps"/>, and removed on the next pause (<see cref="OnPaused"/>) — so it fires
        /// once and is cancelled whether the cursor line or another breakpoint is hit first. Only valid while
        /// paused (the Source view, and hence a cursor, exists only then). Data is "module:line", or EMPTY to mean
        /// "wherever my caret actually is" — resolved from the active Monaco editor's live cursor. Behaviour when
        /// a breakpoint already sits on the SAME REQUESTED line: an unconditional one will stop anyway (just
        /// continue); a conditional/hit-count/tracepoint one may NOT stop, so we defer to it with a warning
        /// rather than planting a clobbering duplicate. We only resume if the transient actually armed.</summary>
        public void CmdRunToCursor(string spec)
        {
            if (CurrentState != DebugSessionState.Paused) return;
            // No explicit spec = "wherever my caret actually is": resolve the ACTIVE Monaco editor's live
            // cursor. The pad's own mini-source-view right-click still passes an explicit module:line, and
            // pointing at a specific line is the more specific intent, so it wins whenever it's present.
            if (string.IsNullOrEmpty(spec))
            {
                spec = ResolveMonacoCursorSpec();
                if (spec == null) return;   // ResolveMonacoCursorSpec already reported why to the console
            }
            var at = ModuleLineRequest.Parse(spec);
            if (at == null) return;
            string module = at.Module;
            int line = at.Line;

            // A persistent breakpoint on the SAME REQUESTED line is the only conflict: the engine collapses a
            // re-add at an identical requested line into a props-update (and removal is by requested line), so
            // planting a transient there would clobber — then delete — the user's breakpoint. (A transient that
            // merely SNAPS onto another bp's planted address is safe: it gets its own logical bp and the shared
            // INT3 is ref-counted.) So branch only on an exact requested-line match:
            //   • unconditional bp already there → it will stop anyway; just continue, don't plant.
            //   • conditional / hit-count / tracepoint bp there → it may NOT stop, but we can't plant a separate
            //     transient without clobbering it. Defer to it and warn, rather than silently failing to stop.
            //   • nothing on this requested line → plant the transient one-shot and continue.
            DebugBreakpoint exact = null;
            foreach (var b in _svc.Breakpoints)
                if (string.Equals(b.Module, module, StringComparison.OrdinalIgnoreCase) && b.DisplayLine == line) { exact = b; break; }

            if (exact != null)
            {
                bool advanced = !string.IsNullOrEmpty(exact.Condition) || !string.IsNullOrEmpty(exact.HitMode) || !string.IsNullOrEmpty(exact.Trace);
                if (advanced)
                    Console("info", "run to cursor: a conditional/hit-count/tracepoint breakpoint already sits on "
                        + module + ":" + line + " — resuming; execution stops there only if that breakpoint's rule is met.");
                else
                    Console("info", "run to cursor: " + module + ":" + line + " (breakpoint already set here)");
                _svc.Continue();   // an existing bp already covers this line — nothing to arm, resume now
                return;
            }

            // No breakpoint on this requested line — plant a transient one-shot. TWO-PHASE: arm first, then
            // resume only once the engine CONFIRMS it armed (bp-set). A true AddBreakpoint return is just a
            // successful stdin write; the engine can still reject the line ASYNCHRONOUSLY via bp-error (e.g. no
            // resolvable code record), and resuming before confirmation would run the target free with no stop —
            // a "ran to cursor" that silently didn't. So: track the key now (filtered from the pane immediately,
            // and always cleaned up on pause/exit even if confirmation never comes), then defer Continue() to
            // OnSvcBreakpointSet; OnSvcBreakpointError aborts and stays paused.
            // singleTarget: this is a transient "run to cursor", not a user breakpoint. Several loaded
            // images can carry a same-named .clw, and an unqualified add now arms in ALL of them - which
            // would stop us somewhere on the way to where the user actually pointed.
            if (!_svc.AddBreakpoint(module, line, true))
            {
                Console("err", "run to cursor: could not set a breakpoint at " + module + ":" + line + " — staying paused.");
                return;
            }
            string rtcKey = TransientKey(module, line);
            _transientBps.Add(rtcKey);
            _pendingRtcKey = rtcKey;    // resume happens in OnSvcBreakpointSet once the engine confirms this bp
            _pendingRtcLine = line;     // match the engine echo by line (module spelling is re-adopted from it)
            Console("info", "run to cursor: " + module + ":" + line + " (pending engine confirmation)");
        }

        private static string TransientKey(string module, int line) { return (module ?? "") + ":" + line; }

        /// <summary>Set next statement: move the stopped thread's instruction pointer to module:line. Paused
        /// only, and an explicit module:line only (the pad's source-view menu); the engine decides whether the
        /// move is safe. A refusal comes back through <see cref="OnSvcSetIpResult"/>; a success is followed by
        /// an ordinary `paused` (reason "setip"), which <see cref="OnPaused"/> handles like any other stop.</summary>
        public void CmdSetNextStatement(string spec)
        {
            if (CurrentState != DebugSessionState.Paused) return;
            var at = ModuleLineRequest.Parse(spec);
            if (at == null) return;
            if (!_svc.SetNextStatement(at.Module, at.Line))
                Console("err", "set next statement: could not send the request for " + at.Module + ":" + at.Line + ".");
        }

        // The success line is logged here; the refresh itself rides on the `paused` that follows it. A refusal is
        // logged and handed to the page, which shows the engine's sentence as is.
        private void OnSvcSetIpResult(bool ok, string reason, string module, int line, string error) => UI(() =>
        {
            if (ok) Console("info", "set next statement: " + module + ":" + line);
            else Console("err", "set next statement refused (" + reason + "): " + error);
            Post("{\"type\":\"setip\",\"ok\":" + (ok ? "true" : "false") + ",\"reason\":" + Str(reason)
                 + ",\"error\":" + Str(error) + ",\"module\":" + Str(module) + ",\"line\":" + line + "}");
        });

        // ── Run to cursor sourced from the real Monaco editor ─────────────────────────────────────
        // "Wherever the developer's caret actually is right now", pulled from ClarionAssistant's live Monaco
        // cursor tracking (MonacoSourceNavigator.TryGetActiveCursor). This is the no-spec branch of
        // CmdRunToCursor, NOT a second command: one "run to cursor" concept, two ways to say where. The
        // eventual Monaco-side trigger (context menu / gutter click) needs no new plumbing here — it sends
        // the same "runtocursor" web message with no data.

        /// <summary>Resolve "module:line" from the ACTIVE Monaco editor's live cursor, or null if there is no
        /// usable cursor — reporting WHY to the Debug Console in that case, since every failure here is
        /// something the user can act on (install/enable ClarionAssistant, open a source file, click a line).
        /// Deliberately does NOT fall back to the pad's mini source view: silently running to a line the user
        /// wasn't looking at is worse than an error. Module comes from the file name (a generated-source file
        /// name IS the module name — the same assumption EditorBreakpointService makes).</summary>
        private string ResolveMonacoCursorSpec()
        {
            var mi = _hookCursor.Method;
            if (mi == null)
            {
                // Say WHICH failure this is. "Not loaded", "your ClarionAssistant predates the hook" and
                // "the hook is there but its signature has drifted" are three different problems with three
                // different fixes, and they are all invisible from the page. The third one in particular has
                // no other way of ever being reported: every other caller treats an unbound hook as
                // "ClarionAssistant isn't here" and quietly takes the native path.
                Console("err", "run to cursor: " + _hookCursor.Explain() + " — can't read the active editor's cursor.");
                return null;
            }

            object[] args = new object[] { null, 0, 0 };   // out filePath, out line, out column
            bool ok;
            try { ok = (bool)mi.Invoke(null, args); }
            catch (Exception ex)
            {
                Console("err", "run to cursor: couldn't read the Monaco cursor — " + ex.Message);
                return null;
            }

            string path = args[0] as string;
            int line = args[1] is int ? (int)args[1] : 0;
            if (!ok || string.IsNullOrEmpty(path) || line <= 0)
            {
                // Upstream returns false when the active workbench window isn't a Monaco-hosted Clarion source
                // editor, or the overlay just attached and hasn't reported a cursor yet. Both are actionable.
                Console("err", "run to cursor: no active Monaco editor cursor — open a source file and click a line first.");
                return null;
            }
            return Path.GetFileName(path) + ":" + line;
        }

        /// <summary>Break on procedure entry: plant a normal (persistent) breakpoint at a procedure's
        /// definition line, surfaced from a right-click on a Procedures-pane row. Data is a JSON object
        /// {id} naming the row by the id <see cref="PushProcedures"/> sent it with; the module and line are
        /// looked up HERE, in the table that push issued, never read from the page (afbc68c7). An id the
        /// current list did not issue - a stale list, or one nobody listed - arms nothing and says so.
        /// Running or paused → push straight to the engine; idle → stage in _pending (deduped), exactly like a
        /// gutter breakpoint. Deliberately does NOT touch the IDE gutter (no red dot), matching how _pending
        /// bps work.</summary>
        public void CmdBreakOnProcEntry(string data)
        {
            var req = BreakOnProcEntryRequest.Parse(data);
            if (req == null) return;
            var proc = _procIds.Resolve(req.ProcId);
            if (proc == null)
            {
                Console("err", "break on entry: that procedure is not in the current list — refresh the Procedures pane and try again.");
                return;
            }
            BreakOnEntry(proc);
        }

        /// <summary>Break on the entry of the procedure containing <paramref name="filePath"/>:<paramref
        /// name="line"/> - the editor cursor, reached from ClarionAssistant through
        /// <see cref="DebugSessionController.BreakOnProcEntry"/> (e61e4f92). The position is ONLY a lookup key
        /// into the list <see cref="PushProcedures"/> issued; which procedure it falls in, and where that one
        /// starts, are the list's answer, exactly as with an id. The module is the file's name, the same
        /// mapping every editor-to-engine path uses (a generated source file's name IS its module name).</summary>
        public void CmdBreakOnProcEntryAt(string filePath, int line)
        {
            string module = null;
            try { module = string.IsNullOrEmpty(filePath) ? null : Path.GetFileName(filePath); }
            catch (ArgumentException) { module = null; }
            string why;
            var proc = _procIds.Containing(module, line, out why);
            if (proc == null)
            {
                // A visible refusal, never a guess at the nearest procedure above (codex adversary gate).
                Console("err", "break on entry: " + why + " — nothing was set. (If the Procedures pane is empty, open the app's solution or refresh it.)");
                return;
            }
            BreakOnEntry(proc);
        }

        /// <summary>The one body both break-on-entry paths share: validate, announce, then arm (live) or stage
        /// (idle). Everything it knows about the procedure came from the host's own list.</summary>
        private void BreakOnEntry(ProcRef proc)
        {
            string module = proc.Module;
            int line = proc.Line;
            string name = proc.Name;
            if (line <= 0)
            {
                Console("err", "break on entry: " + (string.IsNullOrEmpty(name) ? "that procedure" : name)
                    + " has no definition line to break on.");
                return;
            }

            // Validated BEFORE either branch. The live branch always had this check, inside AddBreakpoint;
            // the idle branch staged whatever module it was handed, so a name the engine would refuse sat
            // in the pane as a breakpoint until the next Start silently dropped it (StartSession skips an
            // invalid module).
            if (!ClarionDebuggerService.IsValidModuleName(module))
            {
                Console("err", "break on entry: not a module name the debugger can use: " + module);
                return;
            }

            Console("info", "break on entry: " + (string.IsNullOrEmpty(name) ? "" : name + "  ") + module + ":" + line);

            if (_svc.IsRunning)
            {
                // The engine echoes bp-set and the pane refreshes from that. A false return means the
                // command never reached the engine, so no echo will ever come - and this used to be
                // ignored, leaving the info line above as the only word on a breakpoint that was never
                // armed. Say so instead.
                if (!_svc.AddBreakpoint(module, line))
                    Console("err", "break on entry: could not set a breakpoint at " + module + ":" + line
                        + " — the engine did not take the request.");
            }
            else
            {
                foreach (var b in _pending) if (SameBp(b, module, line)) return;   // already staged
                _pending.Add(new DebugBreakpoint { Module = module, RequestedLineOrNull = line, Line = line });
                SendBps();
            }
        }

        public void CmdPause()
        {
            var s = CurrentState;
            if (s == DebugSessionState.Running || s == DebugSessionState.Launching) _svc.Pause();
        }

        public void CmdStop()
        {
            if (CurrentState == DebugSessionState.Idle) return;   // nothing to stop
            // Clear the execution-line marker (Monaco + native) on the UI thread (it's a UI operation).
            ClearExecutionLine();
            // _svc.Stop() blocks (quit + WaitForExit + Kill; for an ATTACHED session detach + up to 8 s, so the app
            // keeps running); run it off the UI thread so the IDE doesn't freeze. Results come back via the existing
            // Exited/Detached/StateChanged -> UI() path.
            var svc = _svc;
            System.Threading.Tasks.Task.Run(() => { try { svc.Stop(); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] stop: " + ex.Message); } });
        }

        private void StartSession()
        {
            try
            {
                // Cross-addin hooks cache their MISSES for the whole session, so a ClarionAssistant that was
                // absent (or older, or a mismatched build) when the last session started would stay "absent"
                // for the life of the IDE process. A session start is the natural point to re-scan, and the
                // only one worth paying for it at.
                RearmAndReportMonacoHooks();

                // The run just reported itself over, but its engine has not exited yet (0449e5c9): say so and
                // stop here, before anything below announces a start that is not going to happen.
                if (_svc.IsEngineStillClosing) { Console("err", ClarionDebuggerService.EngineClosingMessage); return; }

                // The Target EXE field is intentionally gone — Start always sources the target from the app.
                // On EVERY Start we re-resolve from the active project and use the fresh result. A manual Browse
                // pick is honoured only as a ONE-SHOT tied to the solution/project context it was chosen for: if
                // that context has changed (or can't be confirmed the same), the stale pick is discarded and we
                // re-resolve / re-Browse rather than launching a hidden EXE against a different solution.
                if (!ResolveTargetForStart()) return;

                // Echo the resolved target so the console always confirms which process is about to launch.
                Console("info", "target: " + _exe);
                _attach = null;   // a launch: Stop quits (and ends the target) rather than detaching
                MergeGutterIntoPending();
                Post("{\"type\":\"clear\"}");
                // Pre-load the solution's output DLLs so breakpoints set in DLL source bind before
                // launch (multi-DLL apps); other DLLs are still picked up automatically as they load.
                var solutionDlls = ProjectTargetService.ResolveSolutionDlls();
                Console("info", "starting: " + Path.GetFileName(_exe) + SessionCounts(solutionDlls));
                _svc.StartSession(_exe, _pending.ToArray(), solutionDlls);

                LoadStaticSymbols(_exe);
            }
            catch (Exception ex) { Console("err", "start failed: " + ex.Message); }
        }

        /// <summary>A session's static symbols, read from the image on disk for a launch and an attach alike
        /// (70860d6b C7): the data symbols (file buffers) for the Variables tree, off the UI thread, and the
        /// Procedures list against this target.</summary>
        private void LoadStaticSymbols(string exe)
        {
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                string g = ClarionDebuggerService.GetGlobalsJson(exe);
                if (!string.IsNullOrEmpty(g))
                    UI(() => Post(g.Replace("\"event\":\"globals\"", "\"type\":\"globals\"")));
            });
            PushProcedures(exe);
        }

        /// <summary>The "  (N breakpoint(s), M solution DLL(s))" a session's start line ends with.</summary>
        private string SessionCounts(List<string> solutionDlls)
        {
            return "  (" + _pending.Count + " breakpoint(s)"
                + (solutionDlls.Count > 0 ? ", " + solutionDlls.Count + " solution DLL(s)" : "") + ")";
        }

        /// <summary>Merge the gutter's (red-dot) breakpoints, set before the session, into _pending.</summary>
        private void MergeGutterIntoPending()
        {
            foreach (var gb in _gutter.Snapshot())
            {
                bool known = false;
                foreach (var b in _pending) if (SameBp(b, gb.Module, gb.DisplayLine)) { known = true; break; }
                if (!known) _pending.Add(gb);
            }
        }

        /// <summary>Enumerate the target's procedures + methods (static parse, off the UI thread) and send
        /// them to the page for the Procedures list. Clicking a row reuses the existing 'jump' handler, so
        /// no new inbound action is needed. Silent on failure (the list just stays empty).</summary>
        private int _procGen;   // generation token — discard stale async procedure pushes (EXE switch / overlapping ready+start+refresh)
        private void PushProcedures(string exe)
        {
            if (string.IsNullOrEmpty(exe)) return;
            _svc.PrimeTarget(exe);          // anchor the .red resolver to this EXE so PRE-RUN clicks resolve (UI thread)
            int gen = ++_procGen;
            // The old list's ids stop resolving NOW, not when the parse below finishes, and the page is told to
            // drop them: a right-click in that window used to arm the PREVIOUS exe's row (codex adversary gate).
            _procIds.Begin(gen);
            Post("{\"type\":\"procedures\",\"procs\":[],\"loading\":true}");
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    var procs = ClarionDebuggerService.GetProcedures(exe);
                    // Each row goes out with an id, and the table behind the ids goes live in the SAME UI step
                    // that posts the list, so the page can never hold an id the host cannot resolve (short of
                    // a newer list replacing it, which is the point).
                    var ids = ProcedureIds.NewTable();
                    var sb = new StringBuilder();
                    sb.Append("{\"type\":\"procedures\",\"procs\":[");
                    for (int i = 0; i < procs.Count; i++)
                    {
                        var p = procs[i];
                        string id = ProcedureIds.IdFor(gen, i);
                        ids[id] = new ProcRef { Name = p.Name, Module = p.Module, Line = p.Line, Kind = p.Kind, EndLine = p.EndLine,
                                                 ExtentUnknown = p.ExtentUnknown };
                        if (i > 0) sb.Append(',');
                        sb.Append("{\"id\":").Append(Str(id))
                          .Append(",\"name\":").Append(Str(p.Name))
                          .Append(",\"module\":").Append(Str(p.Module))
                          .Append(",\"line\":").Append(p.Line)
                          .Append(",\"kind\":").Append(Str(p.Kind))
                          .Append('}');
                    }
                    sb.Append("]}");
                    string json = sb.ToString();
                    // ignore an out-of-date parse — a newer push won, and its table with it
                    UI(() => { if (gen == _procGen && _procIds.Replace(gen, ids)) Post(json); });
                }
                catch { }
            });
        }

        /// <summary>
        /// Decide the target EXE for a Start. Always prefers a FRESH ProjectTargetService.ResolveTargetExe()
        /// against the active project. A manual Browse pick is reused only if the IDE context (solution+project)
        /// is unchanged AND the file still exists; otherwise the stale manual pick is discarded. When nothing
        /// auto-resolves, falls back to a one-shot Browse tied to the current context. Returns true if _exe is a
        /// valid, launchable target; false (with a console message) to abort the Start. Never throws.
        /// </summary>
        private bool ResolveTargetForStart()
        {
            string ctx = null;
            try { ctx = ProjectTargetService.GetActiveContextKey(); } catch { }

            // 1) Always re-resolve from the active project first — this is the primary source of truth.
            string fresh = null;
            try { fresh = ProjectTargetService.ResolveTargetExe(); } catch { }
            if (!string.IsNullOrEmpty(fresh))
            {
                if (!string.Equals(fresh, _exe, StringComparison.OrdinalIgnoreCase) || _exeAuto == false)
                    Console("info", "resolved target: " + Path.GetFileName(fresh));
                _exe = fresh;
                _exeAuto = true;
                _exeManualKey = null;            // an auto-resolve supersedes any prior manual pick
                if (File.Exists(_exe)) return true;
                Console("err", "Resolved target does not exist on disk: " + _exe + " — build the app, or choose one to launch.");
                return BrowseForContext(ctx);
            }

            // 2) No auto-resolve. Honour a manual pick ONLY if it's still valid for the SAME context.
            if (!_exeAuto && !string.IsNullOrEmpty(_exe))
            {
                bool sameContext = ctx != null && string.Equals(ctx, _exeManualKey, StringComparison.OrdinalIgnoreCase);
                if (sameContext && File.Exists(_exe)) return true;

                // Context changed (or unconfirmable) — never launch a hidden EXE against a different solution.
                Console("err", "Previously chosen target no longer matches the active solution — choose a target to launch.");
                _exe = ""; _exeManualKey = null;
                return BrowseForContext(ctx);
            }

            // 3) Nothing to launch — offer a one-shot Browse.
            Console("err", "Could not auto-detect a Target EXE for the current solution — choose one to launch.");
            return BrowseForContext(ctx);
        }

        /// <summary>Browse for a target and bind the manual pick to <paramref name="ctx"/> (the context it was
        /// chosen for). Returns true only if a valid, existing EXE was selected.</summary>
        private bool BrowseForContext(string ctx)
        {
            if (!Browse()) return false;
            _exeManualKey = ctx;               // one-shot: only valid while the active context stays this
            if (!File.Exists(_exe)) { Console("err", "Chosen target does not exist: " + _exe); _exe = ""; _exeManualKey = null; return false; }
            return true;
        }

        /// <summary>
        /// Auto-fill _exe from the IDE's active project when the pad first becomes ready (purely so the console
        /// can confirm the auto-detected target early). Start always re-resolves regardless. Best-effort:
        /// ProjectTargetService never throws and returns null when it can't decide on a single EXE.
        /// </summary>
        private void TryAutoResolveExe()
        {
            try
            {
                string result = ProjectTargetService.ResolveTargetExe();
                if (!string.IsNullOrEmpty(result))
                {
                    // Log only on an actual change. This runs on every IDE context event, and
                    // re-announcing the same unchanged target each time was pure console noise.
                    bool changed = !string.Equals(_exe, result, StringComparison.OrdinalIgnoreCase);
                    _exe = result;
                    _exeAuto = true;
                    _exeManualKey = null;
                    if (changed) Console("info", "auto-detected target: " + Path.GetFileName(_exe));
                    PushTarget();
                }
            }
            catch { }
        }

        /// <summary>
        /// Sends the resolved target to the page's target bar. The target belongs on-screen, not in
        /// the Debug Console: the console is a hideable section, so anyone with it collapsed had no
        /// way to see what the debugger was about to launch.
        /// </summary>
        private void PushTarget()
        {
            string path = _exe ?? string.Empty;
            bool exists = false;
            try { exists = path.Length > 0 && File.Exists(path); } catch { }
            Post("{\"type\":\"target\",\"path\":" + Str(path) + ",\"exists\":" + (exists ? "true" : "false") + "}");
        }

        /// <summary>Shows the target EXE in File Explorer, with the file selected.</summary>
        private void RevealExe()
        {
            try
            {
                if (string.IsNullOrEmpty(_exe)) { Console("info", "no target resolved yet."); return; }
                if (!File.Exists(_exe)) { Console("err", "target does not exist on disk: " + _exe + " — build the app."); return; }
                // A Windows path cannot contain a double quote, so quoting is sufficient here and
                // there is no argument-injection surface. UseShellExecute so this works without a
                // console subsystem attached.
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                    "explorer.exe", "/select,\"" + _exe + "\"") { UseShellExecute = true });
            }
            catch (Exception ex) { Console("err", "could not open Explorer: " + ex.Message); }
        }

        /// <summary>
        /// Opens the user guide — the copy the installer laid down if present, otherwise the
        /// published one. The installer's docs component is OPTIONAL, so a local copy cannot be
        /// assumed, and the guide does not live beside the addin DLL (it goes to the app dir, while
        /// the addin goes under the Clarion install's accessory\addins).
        /// </summary>
        private void OpenDocs()
        {
            const string online = "https://htmlpreview.github.io/?https://github.com/ClarionLive/CA-Debugger/blob/main/docs/user-guide.html";
            string target = online;
            try
            {
                foreach (var root in new[]
                {
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)
                })
                {
                    if (string.IsNullOrEmpty(root)) continue;
                    string candidate = Path.Combine(root, "CA Debugger", "user-guide.html");
                    if (File.Exists(candidate)) { target = candidate; break; }
                }
            }
            catch { }

            try { System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(target) { UseShellExecute = true }); }
            catch (Exception ex) { Console("err", "could not open the user guide: " + ex.Message); }
        }

        /// <summary>Prompt for a Target EXE. Returns true if the user picked one. A manual choice clears
        /// _exeAuto; the caller (BrowseForContext) binds it to the current context as a one-shot.</summary>
        private bool Browse()
        {
            using (var dlg = new OpenFileDialog { Filter = "Clarion executables (*.exe)|*.exe|All files (*.*)|*.*" })
            {
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    _exe = dlg.FileName;
                    _exeAuto = false; // a manual pick — re-resolve will still take precedence on the next Start
                    return true;
                }
            }
            return false;
        }

        private void Jump(string spec)
        {
            var at = ModuleLineRequest.Parse(spec);
            if (at == null) return;
            string module = at.Module;
            int line = at.Line;
            string path = ResolvePath(module);
            if (path != null) NavigateTo(path, line);
            else Console("info", "(can't resolve " + module + " — open the app's solution so the .red is active)");
        }

        /// <summary>Open a breakpoint's source in the Clarion editor using the exact .clw path the IDE
        /// gutter gave us (no fragile re-resolution). Data is "line\tfullPath".</summary>
        private void OpenBp(string data)
        {
            var req = OpenBpRequest.Parse(data);
            if (req == null) return;
            int line = req.Line;
            string path = req.Path;
            if (!string.IsNullOrEmpty(path) && File.Exists(path)) NavigateTo(path, line);
            else Console("info", "(can't open " + path + " — file not found)");
        }

        /// <summary>Remove a breakpoint from the pane's "x". Removes the IDE gutter bookmark, which
        /// cascades through BreakPointRemoved → OnGutterBpRemoved (engine/pending + pane refresh) and
        /// clears the editor's red dot. Falls back to a direct removal if no bookmark is found (e.g. a
        /// pending bp whose editor was closed). Data is "module:line".
        /// <para>
        /// The page can only name the breakpoint the way the engine does, by bare .clw basename, so this
        /// resolves the row's FILE before touching the gutter - through the same path map SendBps built
        /// the row from, so the file removed is the file the row's link would have opened. Without it,
        /// two DLLs each holding a same-named .clw bookmarked at the same line meant the "x" cleared
        /// whichever bookmark the IDE enumerated first (task e80072f1). A null path here is not a
        /// failure: it is the map saying it cannot tell, and RemoveByModuleLine then removes a lone
        /// bookmark and declines an ambiguous one.
        /// </para></summary>
        private void RemoveBp(string data)
        {
            var at = ModuleLineRequest.Parse(data);
            if (at == null) return;
            string module = at.Module;
            int line = at.Line;
            if (!_gutter.RemoveByModuleLine(module, line, PaneBpPath(module, line)))
                OnGutterBpRemoved(module, line); // no gutter bookmark matched — keep the pane/engine consistent
        }

        /// <summary>The .clw path of the pane row the page is naming, or null when there is none to
        /// trust. Reads the same list SendBps rendered and resolves it through the same map, so the
        /// pane, its filename link and its "x" can never disagree about which file a row means.</summary>
        private string PaneBpPath(string module, int line)
        {
            try
            {
                var paths = GutterPathsByModuleLine();
                foreach (var b in (_svc.IsRunning ? _svc.Breakpoints : _pending.ToArray()))
                    if (SameBp(b, module, line))
                    {
                        // The STATE is deliberately discarded here: ambiguous and unknown both mean "I
                        // cannot name a file", and RemoveByModuleLine already treats a null path as
                        // "match on module:line, and decline if several bookmarks do". The distinction
                        // exists for the PAGE, which renders the two differently; the removal path has
                        // only one sensible behaviour for both.
                        BpPathState ignored;
                        return GutterPathFor(paths, b, out ignored);
                    }
            }
            catch { }
            return null;
        }

        /// <summary>Apply advanced breakpoint properties (condition / hit count / tracepoint) from the
        /// BREAKPOINTS pane's properties editor. Data is a JSON object
        /// {module,line,condition,hitMode,hitValue,trace}. The host-side pending list is the source of
        /// truth for properties (the gutter only stores module:line), so they persist across a restart and
        /// are re-applied via the launch spec; on a live session they are pushed to the engine immediately.</summary>
        private void SetBpProps(string data)
        {
            var req = BpPropsRequest.Parse(data);
            if (req == null) return;
            string module = req.Module;
            int line = req.Line;

            string condition = req.Condition;
            string hitMode = req.HitMode;
            int hitValue = req.HitValue;
            string trace = req.Trace;

            // normalize empties to null = "no such property"
            if (string.IsNullOrWhiteSpace(condition)) condition = null;
            if (hitMode != "eq" && hitMode != "gte" && hitMode != "mod") hitMode = null;
            if (string.IsNullOrWhiteSpace(trace)) trace = null;

            // update (or create) the pending entry — the persistent source of truth for properties
            DebugBreakpoint target = null;
            foreach (var b in _pending) if (SameBp(b, module, line)) { target = b; break; }
            if (target == null)
            {
                target = new DebugBreakpoint { Module = module, RequestedLineOrNull = line, Line = line };
                _pending.Add(target);
            }
            target.Condition = condition;
            target.HitMode = hitMode;
            target.HitValue = hitValue;
            target.Trace = trace;

            if (_svc.IsRunning) _svc.SetBreakpoint(target); // engine echoes bp-set → pane refresh
            SendBps();                                      // idle: reflect the pending entry immediately
        }

        // ------------------------------------------------------------------ host → page

        private void OnPaused(DebugPause p)
        {
            UI(() =>
            {
                // A new stop: nothing on screen is current any more, and the replies requested below re-grant
                // the rows that are. The engine drops any thread selection at a stop, so the stopped thread is
                // the selected one; the service has already moved its selection there.
                _editGrants.Clear();

                // Cancel any "run to cursor" transient breakpoints — execution has genuinely stopped (at the
                // cursor line, or at a real breakpoint reached first), so the one-shot has served its purpose.
                // Remove from the engine and clear the set; the bp-del echo refreshes the pane.
                // A `paused` with reason "setip" (set next statement) lands here too and cancels a run-to-cursor
                // still waiting for its bp-set. That is intended: the user moved the IP after asking to run, so
                // the pending run is moot, and it is not resumed behind their back.
                if (_transientBps.Count > 0)
                {
                    foreach (var key in new List<string>(_transientBps))
                    {
                        int ci = key.LastIndexOf(':');
                        if (ci <= 0) continue;
                        int tl;
                        if (!int.TryParse(key.Substring(ci + 1), out tl)) continue;
                        _svc.RemoveBreakpoint(key.Substring(0, ci), tl);
                    }
                    _transientBps.Clear();
                    _pendingRtcKey = null;   // defensive: any in-flight run-to-cursor is now moot (we've stopped)
                    // Resync the pane from engine truth. A transient can snap onto the SAME planted address as a
                    // real breakpoint at a different requested line; the engine ref-counts the INT3 and keeps the
                    // real bp armed, but its bp-del echo carries only the planted line, and the host bp mirror
                    // (keyed by planted line) would then drop the surviving real bp's row. A bp-list refresh
                    // rebuilds the mirror from the engine, so the real breakpoint stays visible.
                    _svc.RequestBreakpointList();
                }

                var sb = new StringBuilder();
                sb.Append("{\"type\":\"paused\",\"module\":").Append(Str(p.Module))
                  .Append(",\"proc\":").Append(Str(p.Proc))
                  .Append(",\"line\":").Append(p.Line)
                  .Append(",\"regs\":").Append(RegsJson(p.Regs)).Append(TidJson(p.Tid)).Append('}');
                Post(sb.ToString());
                Console("pause", "paused [" + p.Reason + "]  " + (p.Resolved ? p.Module + " line " + p.Line + (p.Proc != null ? " in " + p.Proc : "") : "(unresolved)"));

                // The module goes in as well as the path: when the path does not resolve there is still a
                // source message, carrying the module so the page can name the stop and clear the last one's
                // listing instead of leaving it on screen.
                NoteStopSource(p);
                SendSource(p.Module, p.ResolvedPath, p.Proc, p.Line);
                RequestStack();               // per-frame locals now load lazily from the Call Stack (frame 0 auto)
                _svc.RequestModuleData();
                // The thread inventory for THIS stop. The engine drops any previous selection at every stop,
                // so this also tells the page which thread the panels it is about to receive belong to.
                _svc.RequestThreads();
                foreach (var name in _watched) WatchOrExplain(name);

                // 'stepi' = a single machine-instruction step driven from the Disassembly view. Keep the
                // panel refresh above, but DON'T jump the editor to the .clw — that activates the source
                // tab and steals focus away from the disassembly view on every instruction step.
                bool instrStep = string.Equals(p.Reason, "stepi", StringComparison.OrdinalIgnoreCase);
                var execLine = _hookExecLine.Method;
                if (execLine != null)
                {
                    // ClarionAssistant can paint the execution line itself (issue #26).
                    MarkExecutionLine(execLine, p.ResolvedPath, p.Line, instrStep);
                }
                else if (!instrStep && !string.IsNullOrEmpty(p.ResolvedPath))
                {
                    // No SetExecutionLine hook (ClarionAssistant absent or an older build): unchanged path.
                    JumpToLine(p.ResolvedPath, p.Line);
                    // JumpToCurrentLine activates the Clarion editor and grabs keyboard focus, so the
                    // next configured debug shortcut would be handled by the editor instead of this
                    // pane. Return focus to our pad so stepping shortcuts keep working in a loop.
                    ReturnFocusToPad();
                }
            });
        }

        /// <summary>Pause-time execution-line marker when ClarionAssistant exposes SetExecutionLine.
        /// Navigation still goes through <see cref="JumpToLine"/> (skipped for a 'stepi' instruction step so
        /// the Disassembly view keeps focus); the marker itself is Monaco's when it reports it painted one.
        /// When it returns false (overlay OFF) or throws, the stock editor's native marker is painted
        /// instead, which also fixes the pre-#26 overlay-off case where no marker appeared at all. An
        /// unresolved pause (no source path) clears the marker.</summary>
        private void MarkExecutionLine(MethodInfo setter, string path, int line, bool instrStep)
        {
            if (string.IsNullOrEmpty(path)) { ClearExecutionLine(); return; }

            bool nativeMarkerPainted = false;
            if (!instrStep) nativeMarkerPainted = JumpToLine(path, line);

            bool painted = InvokeExecutionLine(setter, path, line);
            if (painted)
            {
                // Monaco owns the marker. If the navigator declined and JumpToLine fell back to the stock
                // editor, drop the native arrow it painted so there is only ever one marker.
                if (nativeMarkerPainted) ClearCurrentLineMarker();
            }
            else if (!instrStep && !nativeMarkerPainted)
            {
                PaintNativeMarker(path, line);
            }

            if (!instrStep) ReturnFocusToPad();
        }

        /// <summary>A thread-scoped reply's <c>"tid"</c> suffix, or nothing when the engine didn't stamp one.
        /// ABSENT IS NOT ZERO: the page treats a reply without a tid as unscoped and accepts it (so the pad
        /// still works against an engine that predates the stamp), while a tid that names another thread is
        /// dropped. Emitting 0 for "unknown" would make every such reply look like a different thread's.</summary>
        private static string TidJson(uint? tid)
        {
            return TidMember(TidMemberTid, tid);
        }

        // The host's thread-id-valued member names, declared once (c299aced). tools/test-host-tid-members.ps1
        // READS this array, so a name added here comes under its scan automatically, and it fails any host
        // source that writes one of these as JSON text instead of passing it to TidMember - the same
        // structure the engine side has had since 3b043dfc. `stopped` and `selected` are also the names of
        // two per-row BOOLEANS in OnThreads; the scanner tells them apart by the value, not the name.
        private const string TidMemberTid = "tid";
        private const string TidMemberStopped = "stopped";
        private const string TidMemberSelected = "selected";
        private static readonly string[] TidValuedMemberNames = { TidMemberTid, TidMemberStopped, TidMemberSelected };

        /// <summary>THE host's one writer of a thread-id-valued member, whatever the member is called.
        /// Writes <paramref name="name"/> only when the id is KNOWN, and nothing at all when it is not.
        /// <para>
        /// 0 is treated as "unknown" too, not written out: no Win32 thread has id 0, so a 0 reaching here
        /// is a caller that turned an absent tid into a sentinel — which the page would then read as a
        /// real thread and start dropping good replies against. Enforcing it here rather than trusting
        /// every caller is the point; the engine's own writer does the same on its side.
        /// </para>
        /// <para>
        /// It takes the NAME because a thread id does not stop being one when it is called something else.
        /// The <c>threads</c> message carries three of them — <c>tid</c> per row, plus a top-level
        /// <c>stopped</c> and <c>selected</c> — and the two that are not called "tid" were written
        /// unconditionally, so they said "thread 0" where they meant "I do not know" (task 3b043dfc).
        /// The page already reads a non-number or a 0 as no selection, so an omitted member is the shape
        /// it was waiting for.
        /// </para></summary>
        private static string TidMember(string name, uint? tid)
        {
            System.Diagnostics.Debug.Assert(Array.IndexOf(TidValuedMemberNames, name) >= 0,
                "TidMember was handed an undeclared name; add it to TidValuedMemberNames");
            if (!WireRules.TidIsKnown(tid)) return string.Empty;
            return ",\"" + name + "\":" + tid.Value.ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>Push the engine's thread inventory to the page (Call Stack thread picker). Names come from
        /// the debuggee's own symbols, so every string goes through <see cref="Str"/>.</summary>
        private void OnThreads(DebugThreadList list)
        {
            if (list == null) return;
            // Both go through the one writer, so an unknown stopped/selected is ABSENT rather than the
            // thread-0 it used to claim to be — the same rule the per-row tid has always had here.
            var sb = new StringBuilder("{\"type\":\"threads\"")
                .Append(TidMember(TidMemberStopped, list.StoppedTid))
                .Append(TidMember(TidMemberSelected, list.SelectedTid))
                .Append(",\"threads\":[");
            for (int i = 0; i < list.Threads.Count; i++)
            {
                var t = list.Threads[i];
                if (i > 0) sb.Append(',');
                // The row's own tid goes through the one writer too (c299aced). It used to be typed inline as
                // `{"tid":` + t.Tid, which is correct only while every row has a real id; the writer makes
                // that a rule rather than a fact about the parser (which, as of 2026-09-22, drops a row with no
                // tid). clarionThread opens the row because TidMember writes a leading comma - the page reads
                // members by key, so order is free.
                sb.Append("{\"clarionThread\":").Append(t.ClarionThread.HasValue
                        ? t.ClarionThread.Value.ToString(CultureInfo.InvariantCulture) : "null")
                  .Append(TidMember(TidMemberTid, t.Tid))
                  .Append(",\"proc\":").Append(Str(t.Proc))
                  .Append(",\"module\":").Append(Str(t.Module))
                  .Append(",\"line\":").Append(t.Line)
                  .Append(",\"state\":").Append(Str(t.State))
                  .Append(",\"clarionFrames\":").Append(t.ClarionFrames)
                  .Append(",\"stopped\":").Append(t.Stopped ? "true" : "false")
                  .Append(",\"selected\":").Append(t.Selected ? "true" : "false").Append('}');
            }
            sb.Append("]}");
            Post(sb.ToString());
        }

        /// <summary>Ask the engine for a name's value, and ANSWER THE PAGE when we cannot.
        /// <para>
        /// <see cref="ClarionDebuggerService.Watch"/> refuses a name it cannot put on the wire — the engine
        /// protocol is line- and space-split, so a name containing a space or a quote would arrive as a
        /// second command — and it refuses silently. Nothing is sent, so no reply can ever come, and the
        /// row that asked sits on "…" for the rest of the session looking like it is still loading. The
        /// engine emits an outcome for every watch it receives; this makes the ones it never receives
        /// behave the same way, as the miss they are.
        /// </para>
        /// No tid: this answer is not from any thread, and an unstamped reply is unscoped, which the page
        /// accepts whatever it is currently showing.</summary>
        private void WatchOrExplain(string name)
        {
            if (string.IsNullOrEmpty(name)) return;
            string why = null;
            if (!ClarionDebuggerService.IsValidWatchName(name))
                why = "not a data name the debugger can read — letters, digits and _ : $ . only, up to 128 characters";
            else if (!_svc.Watch(name))
                why = "the engine did not accept the request";
            if (why == null) return;
            Post("{\"type\":\"watch\",\"name\":" + Str(name) + ",\"found\":false,\"outOfScope\":false,\"error\":"
                + Str(why) + "}");
        }

        /// <summary>Ask the engine for the selected thread's stack under a fresh request id, recorded for the
        /// current epoch once sent: only a reply echoing a recorded id may offer frames (EditGrants.OfferFrames).</summary>
        private void RequestStack()
        {
            string id = _editGrants.NewStackRequestId();
            if (_svc.RequestStack(id)) _editGrants.StackRequested(id);
        }

        private void OnStack(List<DebugStackFrame> frames, uint? tid, string reqId)
        {
            var sb = new StringBuilder("{\"type\":\"stack\",\"frames\":[");
            for (int i = 0; i < frames.Count; i++)
            {
                var f = frames[i];
                if (i > 0) sb.Append(',');
                sb.Append("{\"frame\":").Append(f.Frame)
                  .Append(",\"proc\":").Append(Str(f.Proc))
                  .Append(",\"kind\":").Append(Str(f.Kind))
                  .Append(",\"module\":").Append(Str(f.Module))
                  .Append(",\"line\":").Append(f.Line)
                  .Append(",\"va\":").Append(Str(f.Va))
                  .Append(",\"ebp\":").Append(Str(f.Ebp))
                  .Append(",\"uncertain\":").Append(f.Uncertain ? "true" : "false").Append('}');
            }
            sb.Append(']').Append(TidJson(tid)).Append('}');
            // The frames just offered are the only ones whose locals the page may ask for (see FrameLocals), and
            // only when this reply is for the selected thread and echoes a request id of this epoch (OfferFrames).
            var offered = new List<KeyValuePair<string, string>>();
            foreach (var f in frames) offered.Add(new KeyValuePair<string, string>(f.Va, f.Ebp));
            _editGrants.OfferFrames(tid, reqId, offered);
            Post(sb.ToString());
            FollowSelectedThread(frames, tid);
        }

        private void OnWatch(DebugWatch w)
        {
            var sb = new StringBuilder("{\"type\":\"watch\",\"name\":").Append(Str(w.Name))
                .Append(",\"found\":").Append(w.Found ? "true" : "false");
            // The one row reply the host builds itself; it grants its tuple the way the engine-row replies do.
            if (w.Found) _editGrants.Grant(w.Va, w.TypeCode, w.Size, w.Places, w.Tid);
            if (w.Found)
                sb.Append(",\"value\":").Append(Str(w.Value))
                  .Append(",\"typeName\":").Append(Str(w.TypeName))
                  .Append(",\"threaded\":").Append(w.Threaded ? "true" : "false")
                  // edit-variable-value metadata so the Watch value cell can be written back
                  .Append(",\"va\":").Append(Str(w.Va))
                  .Append(",\"typeCode\":").Append(Str(w.TypeCode))
                  .Append(",\"size\":").Append(w.Size)
                  .Append(",\"places\":").Append(w.Places)
                  // a real value that carries a caveat (e.g. a THREADed variable this thread hasn't used yet)
                  .Append(",\"note\":").Append(Str(w.Note))
                  // "View memory" address (own storage only) and the caller frame a local resolved in
                  .Append(",\"addr\":").Append(Str(w.Addr))
                  .Append(",\"frameIdx\":").Append(w.FrameIdx.HasValue ? w.FrameIdx.Value.ToString(CultureInfo.InvariantCulture) : "null")
                  .Append(",\"frameProc\":").Append(Str(w.FrameProc));
            else
                // a miss: distinguish a frame local that is merely out of scope, a genuinely unknown name, and
                // a name that resolved but could not be read (error) — all three must clear the row's pending state
                sb.Append(",\"outOfScope\":").Append(w.OutOfScope ? "true" : "false")
                  .Append(",\"error\":").Append(Str(w.Error));
            // which thread this name resolved on — the page drops a value that isn't for the thread it shows
            sb.Append(TidJson(w.Tid)).Append('}');
            Post(sb.ToString());
        }

        /// <summary>Edit-variable-value: the page asked to write a new value into a live variable. Data is a
        /// JSON object {va, typeCode, size, places, tid, value} carried from the row's own metadata. Only valid
        /// while paused; the service validates va/typeCode as hex and base64-encodes the value. The result
        /// comes back via <see cref="OnSvcVariableSet"/>.
        /// <para>
        /// Only <c>value</c> is the user's. The other five decide WHERE and HOW the write lands, and they are
        /// honoured only when the host itself issued that exact tuple for a row that is still current
        /// (<see cref="_editGrants"/>, afbc68c7). They used to be forwarded as sent, so anything that could
        /// put a message on the bridge could write any address under any type it named. The tid is part of
        /// the tuple: it is also passed on so the engine can refuse a write whose thread is no longer the
        /// selected one; absent when the page has no thread selection to name.
        /// </para>
        /// <para>
        /// A refusal is ANSWERED with a failed varset, the same shape the engine's own refusal takes, so the
        /// page treats it as the failure it is - and so does a false from SetVariable, which means the
        /// request never reached the engine and no varset would ever have come.
        /// </para></summary>
        private void EditVar(string data)
        {
            if (_svc.State != DebugSessionState.Paused) return;
            var req = EditVarRequest.Parse(data);
            if (req == null) return;
            // The grant is SPENT by the write it authorises, so the same request cannot be replayed; the
            // engine's varset reply re-issues it (OnSvcVariableSet). A write that never left re-issues it now,
            // because no reply is coming.
            string why = null;
            if (_editGrants.IsWritePending(req.Va))
                why = "a write to this address is still pending — wait for its result, then edit again";
            else if (!_editGrants.TryConsume(req.Va, req.TypeCode, req.Size, req.Places, req.Tid))
                why = "that value is no longer current (or was never offered for editing) — let it refresh, then edit again";
            else if (!_svc.SetVariable(req.Va, req.TypeCode, req.Size, req.Places, req.Value, req.Tid))
            {
                _editGrants.Regrant(req.Va);
                why = "the engine did not take the request";
            }
            if (why != null) PostVarSet(req.Va, false, null, why);
        }

        /// <summary>Lazy expansion of a reference / group node: data is <c>reqId|module|typeRef|addr</c>, and it
        /// is forwarded ONLY when that exact tuple is an expandable row the host issued for the rows now current
        /// (afbc68c7, codex security gate). Otherwise the engine would render any type's members at any
        /// address the page named - edit metadata included - and a forged expand would mint the edit grants
        /// that EditVar checks. A refusal, or a request the service would not send, is ANSWERED with an empty
        /// expanded reply for that reqId, so the node the page is opening does not wait forever.</summary>
        private void Expand(string data)
        {
            if (_svc.State != DebugSessionState.Paused) return;
            var x = ExpandRequest.Parse(data);
            if (x == null) return;
            if (!_editGrants.IsExpandIssued(x.Module, x.TypeRef, x.Addr))
            {
                RefuseExpand(x.ReqId, "that node is no longer current (or was never offered) — let the view refresh, then open it again");
                return;
            }
            if (!_svc.RequestExpand(x.ReqId, x.Module, x.TypeRef, x.Addr))
            {
                RefuseExpand(x.ReqId, "the engine did not take the request");
                return;
            }
            _editGrants.ExpandForwarded(x.ReqId);
        }

        /// <summary>A call-stack frame's locals: data is <c>reqId|va|ebp</c>, and it is forwarded ONLY when that
        /// exact (va, ebp) is a frame the host's own stack reply offered since the last stop, resume or thread
        /// switch (49538b78 wave 5, codex adversary). The engine renders the locals of the procedure at va at
        /// EBP + each local's offset, edit metadata included, so a real va with a made-up EBP would mint edit
        /// grants at addresses the page chose - and the page is trusted to READ memory, never to write it.
        /// <para>
        /// A frame that was not offered is REFUSED, not forwarded for display only. The page asks only about
        /// frames it was shown, so a refusal costs a genuine page nothing but a lost race with the next stack
        /// reply, which re-offers the frames that are current; a display-only forward would keep a second,
        /// unverified path to the engine that no user needs. Like an expand refusal it is ANSWERED with an
        /// empty reply for that reqId, so the frame the page is opening does not wait forever - and so is a
        /// request the service would not send.
        /// </para></summary>
        private void FrameLocals(string data)
        {
            if (_svc.State != DebugSessionState.Paused) return;
            var fl = FrameLocalsRequest.Parse(data);
            if (fl == null) return;
            if (!_editGrants.IsFrameOffered(fl.Va, fl.Ebp))
            {
                RefuseFrameLocals(fl.ReqId, "that frame is no longer current (or was never offered) — let the call stack refresh, then open it again");
                return;
            }
            if (!_svc.RequestFrameLocals(fl.ReqId, fl.Va, fl.Ebp))
            {
                RefuseFrameLocals(fl.ReqId, "the engine did not take the request");
                return;
            }
            _editGrants.FrameLocalsForwarded(fl.ReqId);
        }

        // No tid: this answer is not from any thread, and an unstamped reply is one the page accepts whatever
        // thread it is showing.
        private void RefuseFrameLocals(int reqId, string why)
        {
            Post("{\"type\":\"framelocals\",\"reqId\":" + Str(reqId.ToString(CultureInfo.InvariantCulture))
                + ",\"items\":[],\"refused\":true}");
            Console("err", "frame locals refused: " + why);
        }

        private void RefuseExpand(int reqId, string why)
        {
            Post("{\"type\":\"expanded\",\"reqId\":" + Str(reqId.ToString(CultureInfo.InvariantCulture))
                + ",\"items\":[],\"refused\":true}");
            Console("err", "expand refused: " + why);
        }

        private void SendBps()
        {
            var sb = new StringBuilder("{\"type\":\"bplist\",\"bps\":[");
            // Transient "run to cursor" breakpoints live in the engine list while armed; never surface them in
            // the pane (they're one-shot and removed on the next pause).
            var list = new List<DebugBreakpoint>();
            foreach (var b in (_svc.IsRunning ? _svc.Breakpoints : _pending.ToArray()))
            {
                if (b.Module != null && (_transientBps.Contains(TransientKey(b.Module, b.Line))
                                      || _transientBps.Contains(TransientKey(b.Module, b.DisplayLine)))) continue;
                list.Add(b);
            }

            // The engine's bp list carries no source path; the IDE gutter is the source of truth for
            // the .clw file. Build a (module|line) -> path map from the gutter so each row can carry
            // the exact path for click-to-open, in both running and stopped states.
            var paths = GutterPathsByModuleLine();

            for (int i = 0; i < list.Count; i++)
            {
                if (i > 0) sb.Append(',');
                var b = list[i];
                // The state comes back from the SAME call that resolved the path, so the page can never be
                // handed a reason that does not describe the path beside it. ALWAYS emitted - a row with no
                // pathState would leave the page guessing again, which is the defect this closes.
                BpPathState pathState;
                string path = GutterPathFor(paths, b, out pathState);
                sb.Append("{\"module\":").Append(Str(b.Module))
                  .Append(",\"line\":").Append(b.Line)
                  .Append(",\"requested\":").Append(b.DisplayLine)
                  .Append(",\"path\":").Append(Str(path))
                  .Append(",\"pathState\":").Append(Str(PathStateName(pathState)))
                  .Append(",\"condition\":").Append(Str(b.Condition))
                  .Append(",\"hitMode\":").Append(Str(b.HitMode))
                  .Append(",\"hitValue\":").Append(b.HitValue)
                  .Append(",\"trace\":").Append(Str(b.Trace))
                  .Append(",\"hitCount\":").Append(b.HitCount).Append('}');
            }
            sb.Append("]}");
            Post(sb.ToString());
        }

        /// <summary>The IDE gutter's bookmarks as (module|line) -> the .clw path that claims it, with a
        /// NULL value meaning "more than one file claims this key, and we cannot tell which".
        /// <para>
        /// A module is a bare basename. In a multi-DLL app two DLLs can each hold a <c>clbrws011.clw</c>
        /// bookmarked at the same line, and this map used to be a plain assignment - so the second
        /// bookmark silently overwrote the first and a pane row could carry the OTHER file's path.
        /// Clicking the filename then opened the wrong source with no hint that it had (task e80072f1);
        /// <c>OpenBp</c> could not catch it either, because both paths exist on disk.
        /// </para>
        /// <para>
        /// Recording the collision instead of resolving it is the honest answer: the engine names the
        /// breakpoint by basename, so the host genuinely does not know which of the two files it armed.
        /// A row with no path falls back to the page's <c>jump</c> action and the .red resolution behind
        /// it - a best effort that is ADMITTEDLY one, rather than a confident wrong file.
        /// </para></summary>
        private Dictionary<string, string> GutterPathsByModuleLine()
        {
            var paths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var g in _gutter.Snapshot())
                {
                    if (string.IsNullOrEmpty(g.Path) || string.IsNullOrEmpty(g.Module)) continue;
                    ClaimGutterPath(paths, g.Module + "|" + g.Line, g.Path);
                    ClaimGutterPath(paths, g.Module + "|" + g.DisplayLine, g.Path);
                }
            }
            catch { }
            return paths;
        }

        /// <summary>Record that <paramref name="path"/> claims <paramref name="key"/>. The first claim
        /// wins; a second claim from a DIFFERENT file poisons the key to null, and no later claim can
        /// un-poison it. (The same file claiming the same key twice is ordinary - a bookmark whose
        /// requested and planted lines are equal claims it under both.)</summary>
        private static void ClaimGutterPath(Dictionary<string, string> paths, string key, string path)
        {
            string had;
            if (!paths.TryGetValue(key, out had)) { paths[key] = path; return; }
            if (had != null && !string.Equals(had, path, StringComparison.OrdinalIgnoreCase)) paths[key] = null;
        }

        /// <summary>Why a breakpoint row has the path it has - or has none. Sent to the page as
        /// <c>pathState</c> on every bplist row.
        /// <para>
        /// The page needs the REASON, not just the absence. The host withholding a path for an ambiguous
        /// row was only half a fix: the page still rendered <c>path:null</c> as an ordinary link and fell
        /// back to a basename lookup, so the user could still be taken to an arbitrary same-named file
        /// with nothing on screen saying the host had refused to choose. "No path" and "several paths and
        /// I will not guess" call for different UI, and only the host can tell them apart.
        /// </para></summary>
        /// <remarks>ORDER IS DELIBERATE: the ZERO value is the SAFEST state, not the most trusted one.
        /// <c>default(BpPathState)</c> is what a field, an array element, an uninitialised struct member or
        /// anything deserialised gets for free, and for an enum whose failure mode is taking the user to an
        /// arbitrary same-named file, that free value must not be <c>Ok</c>. Nothing reaches the default
        /// today - <see cref="GutterPathFor"/>'s out-param is assigned on its first line - so this is a
        /// fence, not a fix: it means a future caller who forgets gets "I cannot say", which is refusable,
        /// rather than "trust this path", which is not.
        /// <para>
        /// The wire is unaffected: the three tokens come from <see cref="PathStateName"/>, which compares
        /// by NAME, so the ordering is invisible to the page and the frozen contract is untouched.
        /// </para></remarks>
        private enum BpPathState
        {
            Unknown,    // no gutter bookmark claims it at all; there is simply nothing to offer
            Ambiguous,  // several DIFFERENT files claim it; the host refuses to choose, path is null
            Ok          // exactly one file claims this row; path is that file
        }

        /// <summary>The wire spelling of a <see cref="BpPathState"/>. One writer, so the three tokens the
        /// page switches on cannot drift from the three states the host can produce.</summary>
        private static string PathStateName(BpPathState state)
        {
            return state == BpPathState.Ok ? "ok"
                 : state == BpPathState.Ambiguous ? "ambiguous"
                 : "unknown";
        }

        /// <summary>The .clw path to show for one breakpoint row, with the REASON reported from the SAME
        /// lookup that resolved it.
        /// <para>
        /// ONE PASS, TWO ANSWERS, DELIBERATELY. Deriving the state in a second pass over the map would let
        /// the two disagree - a row could carry a path while being labelled ambiguous, or the reverse -
        /// and the page would then be acting on a reason that does not describe the path it was given.
        /// The contract the page relies on is <c>(pathState == "ok") == (path != null)</c>, and it holds
        /// here BY CONSTRUCTION: every return that yields a path sets Ok, and the only return that yields
        /// null sets Ambiguous or Unknown.
        /// </para>
        /// <para>
        /// The entry's OWN path wins when it has one (a gutter-built entry knows the file it came from);
        /// otherwise the planted line is tried before the requested one, and a contested key is SKIPPED
        /// rather than returned - a row whose planted line is contested may still have an uncontested
        /// requested line, and the other way round. Contested-anywhere is remembered, so a row that found
        /// no usable path but DID meet a contested key reports Ambiguous rather than Unknown: the
        /// difference is exactly "I will not guess" versus "there is nothing here".
        /// </para></summary>
        private static string GutterPathFor(Dictionary<string, string> paths, DebugBreakpoint b, out BpPathState state)
        {
            state = BpPathState.Unknown;
            if (!string.IsNullOrEmpty(b.Path)) { state = BpPathState.Ok; return b.Path; }
            if (b.Module == null) return null;

            bool contested = false;
            string p;
            if (paths.TryGetValue(b.Module + "|" + b.Line, out p))
            {
                if (p != null) { state = BpPathState.Ok; return p; }
                contested = true;                      // the key exists but two files claim it
            }
            if (paths.TryGetValue(b.Module + "|" + b.DisplayLine, out p))
            {
                if (p != null) { state = BpPathState.Ok; return p; }
                contested = true;
            }
            state = contested ? BpPathState.Ambiguous : BpPathState.Unknown;
            return null;
        }

        /// <summary>An image (EXE or DLL) mapped into the target. Surface debuggable images to the
        /// console and post a structured message a future "Modules" panel can render. Tier 1 vs 2
        /// (source available) is decided per-compiland when a hit/frame resolves via the .red, so at
        /// image-load time we only report symbol availability (hasDebug).</summary>
        private void OnModuleLoaded(DebugModule m)
        {
            Post("{\"type\":\"module\",\"name\":" + Str(m.Name)
                + ",\"path\":" + Str(m.Path)
                + ",\"base\":" + Str(m.Base)
                + ",\"hasDebug\":" + (m.HasDebug ? "true" : "false") + "}");
            // Only log images we can actually debug — don't bury the console under 30+ system DLLs.
            if (m.HasDebug) Console("info", "module loaded: " + m.Name + " (symbols)");
        }

        /// <summary>Read ~±12 lines around the current line from the resolved .clw and show them.
        /// <para>
        /// ALWAYS posts a <c>source</c> message, even when there is nothing to read. "This stop has no
        /// source" is a state the page has to be TOLD about: this used to return silently, so no source
        /// message followed the pause and the page's <c>$('src')</c>, <c>curFile</c> and <c>curLine</c> kept
        /// the PREVIOUS stop's file, listing and highlight under the new stop's header (87c66af6 made the
        /// 'paused' arm always write that header). <c>curFile</c> is load-bearing: the page sends
        /// run-to-cursor as <c>curFile + ':' + line</c>, so a stale one armed a breakpoint in a file the user
        /// was no longer stopped in.
        /// </para>
        /// <para>
        /// An empty <c>lines</c> array is that message, and it keeps buildSource the ONE writer of the
        /// listing — the same shape 87c66af6 gave the location caption. <paramref name="module"/> is what
        /// <c>file</c> carries when there is no path, so the header still names where the stop is.
        /// </para></summary>
        private void SendSource(string module, string path, string proc, int line)
        {
            string[] all = null;
            // Unreadable is the same as absent as far as the page is concerned — either way there is no
            // listing for this stop, and either way it must be told so.
            try { if (!string.IsNullOrEmpty(path) && File.Exists(path)) all = File.ReadAllLines(path); }
            catch { all = null; }

            bool have = all != null && all.Length > 0;
            int start = have ? Math.Max(1, line - 12) : 0;
            int end = have ? Math.Min(all.Length, line + 12) : -1;
            var sb = new StringBuilder("{\"type\":\"source\",\"file\":")
                .Append(Str(have ? Path.GetFileName(path) : module))
                .Append(",\"proc\":").Append(Str(proc))
                .Append(",\"startLine\":").Append(start)
                .Append(",\"current\":").Append(line)
                .Append(",\"lines\":[");
            for (int i = start; i <= end; i++)
            {
                if (i > start) sb.Append(',');
                sb.Append(Str(all[i - 1]));
            }
            sb.Append("]}");
            Post(sb.ToString());
        }

        // ------------------------------------------------------------------ the source pane follows the selected thread
        // (0955b29f, Owner decision 2026-09-24). SendSource used to run only at a stop, so after a thread switch
        // the pane and its header still showed the STOPPED thread's location. The page re-reads the stack on a
        // switch, and that reply is stamped with the thread it describes, so it is the switch's source.

        private DebugPause _stopSource;   // the stop's own location; null = not paused (cleared on resume)
        private uint? _stopTid;           // the stopped thread; null = unknown, and then the pane never follows
        private uint? _sourceTid;         // the thread whose location the source pane shows now

        private void NoteStopSource(DebugPause p)
        {
            _stopSource = p;
            _stopTid = p.Tid;
            _sourceTid = p.Tid;
        }

        /// <summary>Re-points the source pane when a stack reply is for a thread other than the one it shows.
        /// Back on the stopped thread it restores the stop's OWN source (its location may be a line no frame
        /// carries, e.g. a step inside runtime code). Repeated replies for the thread on screen send nothing,
        /// and neither does any reply when the stop named no thread: there is then no way to tell a switch from
        /// the stop's own stack.</summary>
        private void FollowSelectedThread(List<DebugStackFrame> frames, uint? tid)
        {
            if (_stopSource == null || !_stopTid.HasValue || !tid.HasValue || tid == _sourceTid) return;
            _sourceTid = tid;
            if (tid == _stopTid) { SendSource(_stopSource.Module, _stopSource.ResolvedPath, _stopSource.Proc, _stopSource.Line); return; }
            var f = SourceFrameOf(frames);
            // No frame with a line: still a source message, so the pane stops showing the other thread's code.
            if (f == null) SendSource(null, null, null, 0);
            else SendSource(f.Module, f.ResolvedPath, f.Proc, f.Line);
        }

        /// <summary>The frame whose line is a thread's location: frame 0 when it has a line, else the first frame
        /// that is a real Clarion frame (a proc, and an ebp other than "0x0") with a line. A thread stopped inside
        /// the runtime has no line in frame 0; the engine gives frames above a runtime frame a real ebp.</summary>
        internal static DebugStackFrame SourceFrameOf(List<DebugStackFrame> frames)
        {
            if (frames == null) return null;
            for (int i = 0; i < frames.Count; i++)
            {
                var f = frames[i];
                if (f == null || f.Line <= 0 || string.IsNullOrEmpty(f.Module)) continue;
                if (i == 0 || (f.Proc != null && f.Ebp != "0x0")) return f;
            }
            return null;
        }

        // ------------------------------------------------------------------ gutter breakpoints

        private void OnGutterBpAdded(string module, int line)
        {
            Console("info", "gutter breakpoint: " + module + ":" + line);
            if (_svc.IsRunning) _svc.AddBreakpoint(module, line);
            else
            {
                foreach (var b in _pending) if (SameBp(b, module, line)) return;
                _pending.Add(new DebugBreakpoint { Module = module, RequestedLineOrNull = line, Line = line });
                SendBps();
            }
        }

        private void OnGutterBpRemoved(string module, int line)
        {
            // Keep _pending in sync regardless of run state — it's what StartSession() resends wholesale
            // on the NEXT session, so a removal that only reached the live engine (running-session branch)
            // would otherwise resurrect the "removed" breakpoint on the next start.
            //
            // THE ORDERING BELOW IS DELIBERATE — do not "tidy" the trim back above the engine call.
            // While running, _pending is trimmed ONLY if the engine actually took the removal.
            // RemoveBreakpoint returns false when IsValidModuleName rejects the module or SendCommand
            // fails, and the breakpoint is then still ARMED in the live session. Trimming anyway would
            // forget an armed breakpoint: the user gets a stop they cannot account for and has nothing
            // left to retry from. A stale pending entry is the better failure — it is visible in the
            // pane and they can remove it again.
            if (_svc.IsRunning)
            {
                if (_svc.RemoveBreakpoint(module, line)) _pending.RemoveAll(b => SameBp(b, module, line));
            }
            else
            {
                _pending.RemoveAll(b => SameBp(b, module, line));
                SendBps();
            }
        }

        /// <summary>Does this staged entry name (module, line)? The line every caller passes is a
        /// REQUESTED line - the gutter's, the Procedures list's, the pane's <c>b.requested</c> - so this
        /// keys on the requested line, the same key <see cref="ClarionDebuggerService.SameBpIdentity"/>
        /// and <see cref="ClarionDebuggerService.BpDelMatches"/> use, by calling the same body they do.
        /// <para>
        /// It used to also match <c>b.Line == line</c>, a two-way OR that let ONE removal trim a
        /// DIFFERENT staged entry whose planted line happened to equal the removed one's requested line -
        /// silently losing it from the next session's launch spec (b1db9a76 item 2). That OR was
        /// unreachable in-tree, because every _pending entry is created with Line equal to its requested line and
        /// nothing writes the engine's snapped line back into _pending. It was held back from wave 1
        /// until 05959085 settled which line is the key; it has, so the OR is gone rather than left as a
        /// promise the rest of the identity code no longer makes.
        /// </para>
        /// <para>
        /// The absent case is not dropped with it: BpLineMatches still falls back to the planted line for
        /// an entry with no requested line at all, which is what an echo from an engine older than that
        /// protocol change leaves behind. Module is compared ignoring case here and not there because one
        /// side of THIS comparison is a gutter basename (Path.GetFileName keeps the file's own case)
        /// while both sides of those are engine-lowercased.
        /// </para></summary>
        private static bool SameBp(DebugBreakpoint b, string module, int line)
        {
            return string.Equals(b.Module, module, StringComparison.OrdinalIgnoreCase)
                && ClarionDebuggerService.BpLineMatches(b, line, line);
        }

        // ------------------------------------------------------------------ helpers

        private string ResolvePath(string module)
        {
            try
            {
                if (string.IsNullOrEmpty(module) || module != Path.GetFileName(module)) return null;
                // Primary: the service's .red-based resolver (the same one that resolves call-stack frame
                // paths). This is what lets clicks open project source that doesn't sit next to the EXE.
                string viaRed = _svc != null ? _svc.ResolveSourcePath(module) : null;
                if (!string.IsNullOrEmpty(viaRed) && File.Exists(viaRed)) return viaRed;
                // Fallback: next to the EXE (generated source often sits there).
                string dir = string.IsNullOrEmpty(_exe) ? null : Path.GetDirectoryName(_exe);
                if (dir != null)
                {
                    string p = Path.Combine(dir, module);
                    if (File.Exists(p)) return p;
                }
            }
            catch { }
            return null;
        }

        /// <summary>Pause-time jump to the current execution line. With ClarionAssistant's Monaco overlay
        /// on, the stock editor sits hidden behind Monaco, so JumpToCurrentLine moves an invisible caret and
        /// the visible Monaco editor never scrolls. Prefer the Monaco navigator (its frozen contract covers
        /// overlay ON and OFF and self-queues if the page isn't ready); only fall back to the stock editor's
        /// current-line jump — which also paints the execution-line marker — when ClarionAssistant is absent.
        ///
        /// RETURN VALUE IS <c>usedNativeMarker</c>, NOT SUCCESS. True means the jump went through the stock
        /// editor, which also paints the native current-line marker, so the caller knows a native marker is
        /// now on screen and may need clearing. This used to be named as a Try* method, which read like a
        /// success flag and inverted the usual meaning of that prefix: it returns true precisely on the
        /// FALLBACK path, and false when the preferred Monaco navigator handled the jump.</summary>
        private static bool JumpToLine(string path, int line)
        {
            if (string.IsNullOrEmpty(path)) return false;
            try
            {
                var nav = _hookNavigate.Method;
                if (nav != null)
                {
                    object handled = nav.Invoke(null, new object[] { path, line, 1 });
                    if (handled is bool && (bool)handled) return false;
                }
            }
            catch { }
            PaintNativeMarker(path, line);
            return true;
        }

        /// <summary>Paint the stock editor's current-execution-line marker (the yellow bar) at
        /// <paramref name="path"/>:<paramref name="line"/>, which is a side effect of its current-line jump.
        /// A throw is swallowed: failing to paint a marker must never break stepping.</summary>
        private static void PaintNativeMarker(string path, int line)
        {
            try { ICSharpCode.SharpDevelop.Debugging.DebuggerService.JumpToCurrentLine(path, line, 1, line, 1); }
            catch { }
        }

        /// <summary>Call SetExecutionLine; a throw counts as "not painted" so stepping never breaks.</summary>
        private static bool InvokeExecutionLine(MethodInfo setter, string path, int line)
        {
            try
            {
                object r = setter.Invoke(null, new object[] { path, line });
                return r is bool && (bool)r;
            }
            catch { return false; }
        }

        /// <summary>Clear the execution-line marker everywhere: Monaco's (when the hook is bound) and the
        /// stock editor's native arrow. Without the hook this is exactly <see cref="ClearCurrentLineMarker"/>.</summary>
        private static void ClearExecutionLine()
        {
            var setter = _hookExecLine.Method;
            if (setter != null) InvokeExecutionLine(setter, null, 0);
            ClearCurrentLineMarker();
        }

        /// <summary>The target left the paused state (resumed or session over). Only acts when the
        /// SetExecutionLine hook is bound; without it no clear happened here before #26, so none happens now.</summary>
        private static void ClearExecutionLineIfHooked()
        {
            if (_hookExecLine.Method != null) ClearExecutionLine();
        }

        // ─────────────────────────────────────────── cross-addin reflection: ONE resolver for every hook
        //
        // Every hook into ClarionAssistant lives on ONE type, and there is no compile-time reference between
        // the two addins, so they all bind by name at runtime. Three near-identical AppDomain scans used to
        // do that; this is the single copy of it.
        //
        // Reflection across an addin boundary fails SILENTLY by nature: rename a method or change a parameter
        // on the other side and the feature simply stops existing, with nothing anywhere saying so. The whole
        // shape of what follows is about making that failure legible — bind by FULL signature, tell "not
        // loaded" apart from "older build" and from "wrong shape", and notice a second loaded copy.

        private const string MonacoTypeName = "ClarionAssistant.Services.MonacoSourceNavigator";

        /// <summary>The assembly the hook type must come from. Verified against the shipped
        /// ClarionAssistant.dll, whose simple name is exactly this; it is unsigned, so the name is the only
        /// identity available. This is NOT an attack boundary — any in-process IDE addin is already fully
        /// trusted. It stops us binding to an unrelated assembly that happens to define the same type name,
        /// and it is what makes a STALE second copy reportable instead of silently chosen.</summary>
        private const string MonacoAssemblyName = "ClarionAssistant";

        /// <summary>Why a hook is not callable. Three different problems with three different fixes, and
        /// collapsing them all into "null" is what made this integration undiagnosable:
        /// <list type="bullet">
        /// <item>NotLoaded — ClarionAssistant isn't installed or enabled. Normal; the user fixes it.</item>
        /// <item>OlderBuild — it IS loaded but predates this hook. The user upgrades it.</item>
        /// <item>WrongShape — the method is there under a DIFFERENT signature, i.e. the two addins have
        /// drifted apart. A developer fixes it, and nothing else in either process would ever say so.</item>
        /// </list></summary>
        private enum HookStatus { Unresolved, Bound, NotLoaded, OlderBuild, WrongShape }

        /// <summary>One late-bound static method on MonacoSourceNavigator, bound by FULL signature and cached
        /// for the session — INCLUDING the misses. Before this, an unresolved hook re-scanned every loaded
        /// assembly on every call, so a single step ran three whole-AppDomain scans whenever ClarionAssistant
        /// was absent or older. <see cref="Rearm"/> drops the cache at session start, the one moment where the
        /// set of loaded addins can usefully have changed and re-paying for the scan is worth it.</summary>
        private sealed class MonacoHook
        {
            private readonly string _name;
            private readonly Type _returns;
            private readonly Type[] _takes;
            private MethodInfo _mi;
            private HookStatus _status;

            public MonacoHook(string name, Type returns, params Type[] takes)
            {
                _name = name; _returns = returns; _takes = takes;
            }

            /// <summary>The bound method, or null when it did not resolve. Resolves on first use.</summary>
            public MethodInfo Method { get { Resolve(); return _mi; } }

            public HookStatus Status { get { Resolve(); return _status; } }

            /// <summary>Forget the cached resolution, misses included, so the next use re-scans.</summary>
            public void Rearm() { _mi = null; _status = HookStatus.Unresolved; }

            /// <summary>One clause naming what is wrong and what fixes it, for the Debug Console. Null once
            /// the hook is bound.</summary>
            public string Explain()
            {
                switch (Status)
                {
                    case HookStatus.NotLoaded:
                        return "ClarionAssistant isn't loaded";
                    case HookStatus.OlderBuild:
                        return "this build of ClarionAssistant has no " + _name + " — upgrade it";
                    case HookStatus.WrongShape:
                        return "ClarionAssistant's " + _name + " has a different signature than this debugger "
                             + "expects — the two addins have drifted apart, so upgrade both to matching builds";
                    default:
                        return null;
                }
            }

            private void Resolve()
            {
                if (_status != HookStatus.Unresolved) return;
                // Pessimistic default: anything throwing below settles as NotLoaded and STAYS cached, so a
                // failing scan can never degrade into a scan on every call.
                _status = HookStatus.NotLoaded;
                try
                {
                    var t = FindMonacoType();
                    if (t == null) return;
                    // Bind by full signature, not by name. A name-only bind accepts a method whose parameters
                    // have drifted and then throws at Invoke time, where it reads as "the feature didn't work"
                    // rather than "the two addins disagree" — and for an out-parameter hook read through an
                    // object[] it may not even throw, just write back plausible-looking garbage.
                    var exact = t.GetMethod(_name, BindingFlags.Public | BindingFlags.Static, null, _takes, null);
                    if (exact != null && exact.ReturnType == _returns)
                    {
                        _mi = exact; _status = HookStatus.Bound; return;
                    }
                    // The type resolved, so ClarionAssistant IS loaded. Absent by name means an older build;
                    // present under another shape (or as overloads, none of which fit) means version skew.
                    bool byNameExists;
                    try { byNameExists = t.GetMethod(_name, BindingFlags.Public | BindingFlags.Static) != null; }
                    catch (AmbiguousMatchException) { byNameExists = true; }
                    _status = byNameExists ? HookStatus.WrongShape : HookStatus.OlderBuild;
                }
                catch { }
            }
        }

        /// <summary>Frozen contract (with CA-Terminal-1-CC):
        ///   bool NavigateToFileAndLine(string filePath, int line, int column)
        ///   line/column 1-based; true when it handled the request (covers the Monaco overlay ON and OFF, and
        ///   self-queues if the editor isn't ready yet); false only when it could not (bad/missing path).
        /// The Clarion source editor is replaced by ClarionAssistant's Monaco overlay and positioning an
        /// already-open Monaco editor has no public API, which is why that addin exposes this for us.</summary>
        private static readonly MonacoHook _hookNavigate =
            new MonacoHook("NavigateToFileAndLine", typeof(bool), typeof(string), typeof(int), typeof(int));

        /// <summary>Frozen contract (issue #26, with ClarionAssistant ticket #26a):
        ///   bool SetExecutionLine(string filePath, int line)
        ///   set: path + line &gt;= 1 paints one global marker, with no navigation or focus change. Returns
        ///   true when Monaco painted it, false when the overlay is OFF (caller paints the native marker).
        ///   clear: null/empty path or line &lt;= 0. Always returns true; idempotent.
        /// Unbound → callers keep the pre-#26 behaviour exactly and make no new calls.</summary>
        private static readonly MonacoHook _hookExecLine =
            new MonacoHook("SetExecutionLine", typeof(bool), typeof(string), typeof(int));

        /// <summary>Frozen contract:
        ///   bool TryGetActiveCursor(out string filePath, out int line, out int column)
        /// This one is read through Invoke with an object[] whose slots are written back, so a drifted
        /// parameter list would come back as plausible-looking values rather than a throw — which is why the
        /// by-ref types are spelled out here and the bind is exact.</summary>
        private static readonly MonacoHook _hookCursor =
            new MonacoHook("TryGetActiveCursor", typeof(bool),
                typeof(string).MakeByRefType(), typeof(int).MakeByRefType(), typeof(int).MakeByRefType());

        /// <summary>Set when more than one loaded assembly answers to <see cref="MonacoAssemblyName"/>;
        /// cleared by <see cref="RearmMonacoHooks"/>. Reported once per session rather than per scan.</summary>
        private static string _monacoDupeNote;

        /// <summary>The single AppDomain scan behind every hook. Requires the defining assembly to be named
        /// <see cref="MonacoAssemblyName"/>, and records when MORE THAN ONE loaded assembly answers to it:
        /// two ClarionAssistant builds in one process is the stale-copy case, where every hook binds to
        /// whichever loaded first and the user watches a feature behave like a version they are not running.
        /// Silently taking the first match is exactly how that stays invisible.</summary>
        private static Type FindMonacoType()
        {
            Type first = null;
            var copies = new List<string>();
            foreach (var asm in AppDomain.CurrentDomain.GetAssemblies())
            {
                string simple;
                try { simple = asm.GetName().Name; }
                catch { continue; }
                if (!string.Equals(simple, MonacoAssemblyName, StringComparison.OrdinalIgnoreCase)) continue;
                Type t;
                try { t = asm.GetType(MonacoTypeName, false); }
                catch { t = null; }
                if (t == null) continue;
                if (first == null) first = t;
                // Version and location are gathered independently: Location throws for some assemblies, and
                // losing the VERSION is what would make this note useless — telling the two copies apart is
                // the entire point of it.
                string ver, loc;
                try { ver = asm.GetName().Version.ToString(); } catch { ver = "<unknown version>"; }
                try { loc = asm.Location; } catch { loc = null; }
                copies.Add(ver + " @ " + (string.IsNullOrEmpty(loc) ? "<no file>" : loc));
            }
            if (copies.Count > 1)
            {
                _monacoDupeNote = copies.Count + " loaded copies of " + MonacoAssemblyName
                    + "; hooks bind to the first — " + string.Join(" | ", copies.ToArray());
            }
            return first;
        }

        /// <summary>Drop every cached resolution, misses included, so the next use re-scans. Called at session
        /// start: ClarionAssistant may have been enabled, or a newer build loaded, since the last miss was
        /// cached, and that miss would otherwise stand for the life of the IDE process.</summary>
        private static void RearmMonacoHooks()
        {
            _hookNavigate.Rearm(); _hookExecLine.Rearm(); _hookCursor.Rearm();
            _monacoDupeNote = null;
        }

        /// <summary>Re-scan at session start and say, once, what is actually wrong with the cross-addin hooks.
        /// Only the two conditions a user cannot otherwise discover are reported: a signature that has drifted
        /// (nothing else in either process would ever mention it, because every caller reads an unbound hook
        /// as "ClarionAssistant isn't here" and quietly takes the native path), and a second loaded copy.
        /// NotLoaded is deliberately silent — it is the normal state for anyone not using Monaco, and a
        /// console line about it every session would be noise.</summary>
        private void RearmAndReportMonacoHooks()
        {
            RearmMonacoHooks();
            var hooks = new[] { _hookNavigate, _hookExecLine, _hookCursor };
            foreach (var h in hooks)
            {
                if (h.Status == HookStatus.WrongShape) Console("err", "Monaco hook: " + h.Explain());
            }
            // After the hooks have resolved, so the scan has had a chance to spot a second copy.
            if (_monacoDupeNote != null) Console("warn", "Monaco hooks: " + _monacoDupeNote);
        }

        /// <summary>Open a source file in the Clarion editor and place the caret on <paramref name="line"/>
        /// (1-based). Used for click-to-navigate from the pane (breakpoint list, call-stack frame). Unlike
        /// the pause-time <see cref="JumpToLine"/>, this does NOT paint the yellow current-execution-line marker
        /// — clicking a breakpoint isn't an execution stop.
        ///
        /// Prefer ClarionAssistant's Monaco navigator when present: with the Monaco overlay on, our native
        /// caret moves land in the hidden editor behind Monaco and are invisible, so only that hook can
        /// position what the user sees. Its presence is also our Monaco-vs-stock detection — no config flag.
        ///
        /// Fallback (ClarionAssistant absent, or it declined) is the stock SharpDevelop editor. Opening a file
        /// the IDE hasn't loaded yet and positioning the caret in a single call races the editor's async
        /// document load and lands at the top, so we open first, then position once the view has settled (the
        /// same BeginInvoke-after-activation pattern <see cref="ReturnFocusToPad"/> relies on).
        /// FileService.JumpToFilePosition is 0-based (DebuggerService.JumpToCurrentLine internally passes
        /// line-1), so convert here.</summary>
        private void NavigateTo(string path, int line)
        {
            if (string.IsNullOrEmpty(path)) return;

            // ClarionAssistant Monaco navigator: owns the overlay-ON (reveal Monaco) vs overlay-OFF
            // (native caret) branch and self-queues if the page isn't ready. 1-based line + column.
            try
            {
                var nav = _hookNavigate.Method;
                if (nav != null)
                {
                    object handled = nav.Invoke(null, new object[] { path, line, 1 });
                    if (handled is bool && (bool)handled) return;
                }
            }
            catch { }

            // Native fallback (stock editor): open, then position on the next pump tick.
            int target = line > 0 ? line - 1 : 0;
            try
            {
                ICSharpCode.SharpDevelop.FileService.OpenFile(path);
                BeginInvoke((Action)(() =>
                {
                    try { ICSharpCode.SharpDevelop.FileService.JumpToFilePosition(path, target, 0); }
                    catch { }
                }));
            }
            catch { }
        }

        /// <summary>
        /// Remove the editor's current-line marker (the yellow → in the gutter) that JumpToCurrentLine
        /// paints on each pause. The IDE never clears it on its own for an external engine, so the arrow
        /// would otherwise linger in the Clarion source after the session ends.
        /// </summary>
        private static void ClearCurrentLineMarker()
        {
            try { ICSharpCode.SharpDevelop.Debugging.DebuggerService.RemoveCurrentLineMarker(); }
            catch { }
        }

        /// <summary>
        /// After JumpToLine moves the Clarion editor to the current line (which steals keyboard focus),
        /// bring the debugger pad back to front and refocus the WebView so the next configured
        /// shortcut is delivered to the debugger page rather than the Clarion editor. Posted via
        /// BeginInvoke so it runs after the editor's activation has settled.
        /// </summary>
        private void ReturnFocusToPad()
        {
            try
            {
                BeginInvoke((Action)(() =>
                {
                    try
                    {
                        var pad = ICSharpCode.SharpDevelop.Gui.WorkbenchSingleton.Workbench.GetPad(typeof(ClarionDebuggerPad));
                        if (pad != null) pad.BringPadToFront();
                        _webView.Focus();
                    }
                    catch { }
                }));
            }
            catch { }
        }

        private void Console(string level, string text) { Post("{\"type\":\"console\",\"level\":\"" + level + "\",\"text\":" + Str(text) + "}"); }

        private static string RegsJson(Dictionary<string, string> regs)
        {
            if (regs == null) return "null";
            var sb = new StringBuilder("{");
            bool first = true;
            foreach (var kv in regs) { if (!first) sb.Append(','); first = false; sb.Append('"').Append(kv.Key).Append("\":").Append(Str(kv.Value)); }
            sb.Append('}');
            return sb.ToString();
        }

        private static string StateName(DebugSessionState s)
        {
            switch (s) { case DebugSessionState.Launching: return "launching"; case DebugSessionState.Running: return "running"; case DebugSessionState.Paused: return "paused"; default: return "idle"; }
        }

        private static DebugControllerState ToControllerState(DebugSessionState s)
        {
            switch (s)
            {
                case DebugSessionState.Launching: return DebugControllerState.Launching;
                case DebugSessionState.Running:   return DebugControllerState.Running;
                case DebugSessionState.Paused:    return DebugControllerState.Paused;
                default:                          return DebugControllerState.Idle;
            }
        }

        /// <summary>
        /// Sends a message to the page, or buffers it if the WebView is not ready yet (see
        /// _pendingPosts). Callers never have to ask whether the page is up — that question is the
        /// trap this fix exists to remove, because getting it wrong failed silently.
        /// </summary>
        private void Post(string json)
        {
            lock (_postLock)
            {
                if (!_ready || _webView.CoreWebView2 == null)
                {
                    if (_pendingPosts.Count >= MaxPendingPosts)
                    {
                        _pendingPosts.Dequeue();   // drop oldest — newest state wins
                        if (!_pendingOverflowed)
                        {
                            _pendingOverflowed = true;
                            System.Diagnostics.Debug.WriteLine(
                                "[CADebuggerWeb] pre-ready post buffer hit " + MaxPendingPosts +
                                "; dropping oldest. The page may never have finished navigating.");
                        }
                    }
                    _pendingPosts.Enqueue(json);
                    return;
                }
            }
            try { _webView.CoreWebView2.PostWebMessageAsString(json); }
            catch { }
        }

        /// <summary>
        /// Delivers everything buffered before the page was ready, in the order it was produced.
        /// Called from OnNavigationCompleted once _ready is set.
        /// </summary>
        private void FlushPendingPosts()
        {
            string[] queued;
            lock (_postLock)
            {
                if (_pendingPosts.Count == 0) return;
                queued = _pendingPosts.ToArray();
                _pendingPosts.Clear();
                _pendingOverflowed = false;
            }
            foreach (var json in queued)
            {
                try { if (_webView.CoreWebView2 != null) _webView.CoreWebView2.PostWebMessageAsString(json); }
                catch { }
            }
        }

        /// <summary>Discards buffered messages — navigation failed or the view is going away.</summary>
        private void DiscardPendingPosts(string why)
        {
            int n;
            lock (_postLock)
            {
                n = _pendingPosts.Count;
                _pendingPosts.Clear();
                _pendingOverflowed = false;
            }
            if (n > 0)
                System.Diagnostics.Debug.WriteLine(
                    "[CADebuggerWeb] discarded " + n + " buffered message(s): " + why);
        }

        /// <summary>
        /// Pushes the data behind the About panel. Sent once on "ready" rather than on demand so the
        /// panel opens instantly and still works if the engine is unreachable.
        /// </summary>
        /// <remarks>
        /// The displayed version is the assembly's InformationalVersion, which the build stamps as
        /// Major.Minor.Patch.BuildNumber (build number = git commit count). Deliberately NOT read from
        /// the addin manifest's &lt;Identity version&gt;: that string is what AddinFinder compares against
        /// the release tag, it is bare Major.Minor.Patch by design, and display code must never become a
        /// reason to change it. Show the whole string — do not truncate to two components.
        /// </remarks>
        private void PushAbout()
        {
            string version, runtime = "not detected";
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                var info = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>();
                version = info != null && !string.IsNullOrEmpty(info.InformationalVersion)
                    ? info.InformationalVersion
                    : asm.GetName().Version.ToString();
            }
            catch { version = "unknown"; }

            try
            {
                if (_webView != null && _webView.CoreWebView2 != null)
                    runtime = _webView.CoreWebView2.Environment.BrowserVersionString;
            }
            catch { }

            var sb = new StringBuilder();
            sb.Append("{\"type\":\"about\"")
              .Append(",\"product\":\"CA Debugger\"")
              .Append(",\"version\":").Append(Str(version))
              .Append(",\"tagline\":\"Source-level debugger for the Clarion IDE\"")
              .Append(",\"publisher\":\"ClarionLive\"")
              .Append(",\"website\":\"https://github.com/ClarionLive/CA-Debugger\"")
              .Append(",\"engine\":\"ClarionDbg (32-bit, TSWD debug info)\"")
              .Append(",\"runtime\":").Append(Str("Microsoft Edge WebView2 " + runtime))
              .Append(",\"year\":\"2026\"}");
            Post(sb.ToString());
        }

        private void UI(Action a)
        {
            if (IsHandleCreated && InvokeRequired) BeginInvoke(a);
            else if (IsHandleCreated) a();
        }

        private static string Str(string s)
        {
            if (s == null) return "null";
            var sb = new StringBuilder(s.Length + 2);
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
                    default: if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4")); else sb.Append(c); break;
                }
            }
            sb.Append('"');
            return sb.ToString();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                // Was a session live at close? Capture BEFORE Stop. This decides whether the controller may go
                // Idle immediately (no live engine to race) or must stay non-idle until teardown confirms done.
                bool wasLive;
                try { wasLive = _svc.State != DebugSessionState.Idle; } catch { wasLive = false; }

                // Detach engine/gutter + WebView event handlers BEFORE Stop()/teardown so no late off-thread
                // callback (StateChanged/Exited fire off-thread) runs against a disposing pad. The
                // teardown-completion signal goes to the STATIC controller (safe post-dispose), not the WebView.
                _ready = false;
                _startQueued = false;
                // Late off-thread callbacks can still call Post() during teardown; with _ready false
                // those would buffer into a queue that will never be flushed. Drop them.
                try { DiscardPendingPosts("pad disposing"); } catch { }
                try { DetachProjectEvents(); } catch { }
                try { DetachServiceEvents(); } catch { }
                if (_coreForEvents != null)
                {
                    try { _coreForEvents.WebMessageReceived -= OnWebMessage; } catch { }
                    try { _coreForEvents.NavigationCompleted -= OnNavigationCompleted; } catch { }
                    _coreForEvents = null;
                }

                try { ClearExecutionLine(); } catch { }

                var svc = _svc;
                if (wasLive)
                {
                    // A session was live. _svc.Stop() blocks (WaitForExit(1500) + Kill) and runs off the UI
                    // thread. For an ATTACHED session Stop() DETACHES rather than quitting, so closing the pad never
                    // kills an app the user attached to (3f2d747f); and if the IDE exits before this task finishes,
                    // the engine sees its stdin close and detaches on its own (the engine contract). Do NOT Unregister now — that would let the controller report Idle and re-enable
                    // the toolbar Start while the old engine/target is still dying (close→reopen→re-run-same-exe
                    // would race a still-terminating process / file lock). Keep the controller's current
                    // non-idle state; only AFTER Stop() completes do we signal the controller (NotifyStopped),
                    // which returns to Idle iff the then-current target is genuinely idle, then Unregister this
                    // instance. Order matters: NotifyStopped before Unregister so a no-reopen close still drops
                    // to Idle (NotifyStopped sees _target==this whose session is now idle).
                    //
                    // THE PAD'S HANDLERS ARE GONE BY NOW (DetachServiceEvents above), and so is its page. TeardownLive
                    // keeps its OWN observer on the service until Stop has returned, so a detach that reports an error,
                    // or an attached engine Stop had to kill, still reaches the user - through the log and a dialog on
                    // this (UI) thread's context, captured here because the task below runs elsewhere (3f2d747f run 2).
                    var warn = DurableWarning.ForCurrentThread();
                    string attachedName = _lastAttachName;
                    System.Threading.Tasks.Task.Run(() =>
                    {
                        try { TeardownLive(svc, attachedName, warn); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] dispose stop: " + ex.Message); }
                        try { DebugSessionController.NotifyStopped(this); } catch { }
                        try { DebugSessionController.Unregister(this); } catch { }
                    });
                }
                else
                {
                    // No live session — safe to stop being the toolbar's target immediately (state already Idle).
                    try { DebugSessionController.Unregister(this); } catch { }
                    try { svc.Stop(); } catch { }
                }

                try { _gutter.Dispose(); } catch { }
                if (_webView != null) { try { _webView.Dispose(); } catch { } _webView = null; }
            }
            base.Dispose(disposing);
        }

        /// <summary>End a live session from a pad that is going away (3f2d747f, pipeline run 2). The pad's own handlers
        /// are already unsubscribed, and its page with them, so the risky outcomes of a teardown - a detach that
        /// reports an error, or an attached engine that had to be killed (bytes left planted: the app will probably
        /// crash) - would reach no one. A <see cref="TeardownObserver"/> is subscribed FIRST and stays subscribed until
        /// Stop has returned, and Stop raises both outcomes before it returns; <paramref name="warn"/> is the durable
        /// channel that does not need the page. A clean detach, or a launch, warns about nothing.</summary>
        internal static bool TeardownLive(ClarionDebuggerService svc, string attachedName, Action<string> warn)
        {
            using (new TeardownObserver(svc, attachedName, warn))
            {
                return svc.Stop();
            }
        }
    }

    /// <summary>Watches ONE teardown for an unsafe detach and reports it through <c>warn</c> (see
    /// <see cref="ClarionDebuggerWebView.TeardownLive"/>). Subscribes in its constructor, unsubscribes in Dispose.</summary>
    internal sealed class TeardownObserver : IDisposable
    {
        private readonly ClarionDebuggerService _svc;
        private readonly string _name;
        private readonly Action<string> _warn;

        public TeardownObserver(ClarionDebuggerService svc, string attachedName, Action<string> warn)
        {
            _svc = svc; _name = attachedName; _warn = warn;
            _svc.Detached += OnDetached;
            _svc.DetachAbandoned += OnAbandoned;
        }

        private void OnDetached(DebugDetach d)
        {
            // The warning is driven by the engine's `error` alone, exactly as on a live page (OnSvcDetached).
            if (d == null || string.IsNullOrEmpty(d.Error)) return;
            _warn(ClarionDebuggerWebView.DetachWarningText(string.IsNullOrEmpty(d.Name) ? _name : d.Name, d.Pid, d.Error));
        }

        private void OnAbandoned(AttachableProcess t)
        {
            _warn(ClarionDebuggerWebView.DetachWarningText(t != null && !string.IsNullOrEmpty(t.Name) ? t.Name : _name,
                t != null ? (uint?)t.Pid : null,
                "the engine did not detach in time and had to be killed, so breakpoints may still be planted"));
        }

        public void Dispose()
        {
            _svc.Detached -= OnDetached;
            _svc.DetachAbandoned -= OnAbandoned;
        }
    }

    /// <summary>A warning that must be SEEN although the pad that would have shown it is gone: a dated line in
    /// %LOCALAPPDATA%\CA Debugger\detach.log (the add-in has no other log), then a dialog posted to the IDE's UI
    /// thread. Posted, not sent, so it never blocks the teardown that raised it; with no UI context (the IDE is
    /// already past its message loop) it gets its own STA thread. Either half failing leaves the other.</summary>
    internal static class DurableWarning
    {
        public static string LogPath
        {
            get { return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CA Debugger", "detach.log"); }
        }

        /// <summary>Make a warner bound to the UI context of the CALLER (call it on the UI thread).</summary>
        public static Action<string> ForCurrentThread()
        {
            var ui = System.Threading.SynchronizationContext.Current;
            return text => Show(text, ui);
        }

        /// <summary>Where the log goes when <see cref="LogPath"/> cannot be written (%TEMP%\CA Debugger\detach.log).</summary>
        public static string FallbackLogPath
        {
            get { return Path.Combine(Path.GetTempPath(), "CA Debugger", "detach.log"); }
        }

        /// <summary>Which channels a warning actually went out on.</summary>
        [Flags]
        internal enum Channels { None = 0, Log = 1, FallbackLog = 2, PostedDialog = 4, ThreadDialog = 8 }

        public static Channels Show(string text, System.Threading.SynchronizationContext ui)
        {
            return Deliver(text, new[] { LogPath, FallbackLogPath }, ui, StartStaThread, ShowBox);
        }

        /// <summary>Log to the first of <paramref name="logPaths"/> that can be written, then show the dialog: posted
        /// to <paramref name="ui"/> when there is one, and on its own STA thread when there is none OR the post THROWS
        /// (a destroyed handle during IDE shutdown). The dialog does not depend on either log succeeding.</summary>
        internal static Channels Deliver(string text, IList<string> logPaths, System.Threading.SynchronizationContext ui,
                                         Action<Action> startStaThread, Action<string> showBox)
        {
            var sent = Channels.None;
            string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + "  " + text + Environment.NewLine;
            for (int i = 0; i < logPaths.Count; i++)
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(logPaths[i]));
                    File.AppendAllText(logPaths[i], line);
                    sent |= i == 0 ? Channels.Log : Channels.FallbackLog;
                    break;
                }
                catch { }   // try the next location; the dialog below goes out whatever happens here
            }
            if (ui != null)
            {
                try
                {
                    ui.Post(_ => showBox(text), null);
                    return sent | Channels.PostedDialog;
                }
                catch (Exception)
                {
                    // The UI context is going (its handle destroyed during IDE shutdown). Not swallowed: the dialog
                    // falls through to its own thread below.
                }
            }
            try
            {
                startStaThread(() => showBox(text));
                sent |= Channels.ThreadDialog;
            }
            catch { }
            return sent;
        }

        private static void ShowBox(string text)
        {
            try { MessageBox.Show(text, "CA Debugger", MessageBoxButtons.OK, MessageBoxIcon.Warning); } catch { }
        }

        private static void StartStaThread(Action body)
        {
            var t = new System.Threading.Thread(() => body()) { IsBackground = false };
            t.SetApartmentState(System.Threading.ApartmentState.STA);
            t.Start();
        }
    }
}
