using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows.Forms;
using ClarionDebugger.Services;
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

        private readonly ClarionDebuggerService _svc = new ClarionDebuggerService();
        private readonly EditorBreakpointService _gutter = new EditorBreakpointService();
        private readonly List<DebugBreakpoint> _pending = new List<DebugBreakpoint>(); // breakpoints while idle
        private readonly HashSet<string> _watched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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
            _webView = new WebView2 { Dock = DockStyle.Fill };
            Controls.Add(_webView);

            // Wire engine + gutter events via named handlers (stored implicitly by method group) so Dispose
            // can detach them BEFORE _svc.Stop()/teardown — no late callback can touch a half-disposed pad.
            _svc.StateChanged          += OnSvcStateChanged;
            _svc.Paused                += OnPaused;
            _svc.Resumed               += OnSvcResumed;
            _svc.HitReceived           += OnSvcHit;
            _svc.StackReceived         += OnSvcStack;
            _svc.WatchReceived         += OnSvcWatch;
            _svc.BreakpointSet         += OnSvcBreakpointSet;
            _svc.BreakpointRemoved     += OnSvcBreakpointRemoved;
            _svc.BreakpointListReceived += OnSvcBreakpointList;
            _svc.BreakpointError       += OnSvcBreakpointError;
            _svc.EngineError           += OnSvcEngineError;
            _svc.ModuleLoaded          += OnSvcModuleLoaded;
            _svc.ModuleUnloaded        += OnSvcModuleUnloaded;
            _svc.LogReceived           += OnSvcLog;
            _svc.Exited                += OnSvcExited;

            _gutter.GutterBreakpointAdded   += OnGutterAdded;
            _gutter.GutterBreakpointRemoved += OnGutterRemoved;

            HandleCreated += OnHandleCreated;

            // Become the live target for the IDE debug toolbar. The latest pad instance wins.
            DebugSessionController.Register(this);
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
            _svc.WatchReceived          -= OnSvcWatch;
            _svc.BreakpointSet          -= OnSvcBreakpointSet;
            _svc.BreakpointRemoved      -= OnSvcBreakpointRemoved;
            _svc.BreakpointListReceived -= OnSvcBreakpointList;
            _svc.BreakpointError        -= OnSvcBreakpointError;
            _svc.EngineError            -= OnSvcEngineError;
            _svc.ModuleLoaded           -= OnSvcModuleLoaded;
            _svc.ModuleUnloaded         -= OnSvcModuleUnloaded;
            _svc.LogReceived            -= OnSvcLog;
            _svc.Exited                 -= OnSvcExited;

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
        }

        private void OnSvcResumed(string mode) => UI(() => { Post("{\"type\":\"resumed\",\"mode\":" + Str(mode) + "}"); Console("info", "resumed (" + mode + ")"); });
        private void OnSvcHit(DebugHit hit) => UI(() => Console("hit", "*** HIT  " + (hit.Resolved ? hit.Module + " line " + hit.Line : hit.Va)));
        private void OnSvcStack(List<DebugStackFrame> frames) => UI(() => OnStack(frames));
        private void OnSvcWatch(DebugWatch w) => UI(() => OnWatch(w));
        private void OnSvcBreakpointSet(DebugBreakpoint bp) => UI(() => SendBps());
        private void OnSvcBreakpointRemoved(string m, int l) => UI(() => SendBps());
        private void OnSvcBreakpointList(List<DebugBreakpoint> list) => UI(() => SendBps());
        private void OnSvcBreakpointError(string m, int l, string err) => UI(() => Console("err", "breakpoint " + m + ":" + l + " — " + err));
        private void OnSvcEngineError(string msg) => UI(() => Console("err", "engine: " + msg));
        private void OnSvcModuleLoaded(DebugModule m) => UI(() => OnModuleLoaded(m));
        private void OnSvcModuleUnloaded(DebugModule m) => UI(() => Post("{\"type\":\"module-unloaded\",\"name\":" + Str(m.Name) + "}"));
        private void OnSvcLog(string s) => UI(() => Console("info", s));
        private void OnSvcExited(int code) => UI(() => { ClearCurrentLineMarker(); Console("info", "— session ended (exit " + code + ") —"); Post("{\"type\":\"clear\"}"); });

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
                // Don't promise a Start-retry: OnHandleCreated is one-shot and won't re-run. Recovery is
                // reopening the pad (which constructs a fresh WebView + re-runs init).
                UI(() => Console("err", "debugger view failed to initialize: " + (reason ?? "unknown") + " — reopen the CA Debugger pad to retry."));
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

                string json = e.TryGetWebMessageAsString();
                string action = JsonVal(json, "action");
                string data = JsonVal(json, "data");
                switch (action)
                {
                    case "ready":
                        Post("{\"type\":\"runstate\",\"state\":\"idle\"}");
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
                    case "watch":
                        if (!string.IsNullOrEmpty(data)) { _watched.Add(data); if (_svc.State == DebugSessionState.Paused) _svc.Watch(data); }
                        break;
                    case "unwatch": if (!string.IsNullOrEmpty(data)) _watched.Remove(data); break;
                    case "jump": Jump(data); break;
                    case "openbp": OpenBp(data); break;
                    case "bpremove": RemoveBp(data); break;
                    case "proclist":   // user asked to (re)list procedures — re-resolve the target if needed
                        if (string.IsNullOrEmpty(_exe)) TryAutoResolveExe();
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

        public void CmdContinue() { if (CurrentState == DebugSessionState.Paused) _svc.Continue(); }
        public void CmdStepOver() { if (CurrentState == DebugSessionState.Paused) _svc.StepOver(); }
        public void CmdStepInto() { if (CurrentState == DebugSessionState.Paused) _svc.StepInto(); }
        public void CmdStepOut()  { if (CurrentState == DebugSessionState.Paused) _svc.StepOut(); }

        public void CmdPause()
        {
            var s = CurrentState;
            if (s == DebugSessionState.Running || s == DebugSessionState.Launching) _svc.Pause();
        }

        public void CmdStop()
        {
            if (CurrentState == DebugSessionState.Idle) return;   // nothing to stop
            // Clear the editor's yellow current-line marker on the UI thread (it's a UI operation).
            ClearCurrentLineMarker();
            // _svc.Stop() blocks (WaitForExit(1500) + Kill); run it off the UI thread so the IDE doesn't
            // freeze. Results come back via the existing Exited/StateChanged -> UI() path.
            var svc = _svc;
            System.Threading.Tasks.Task.Run(() => { try { svc.Stop(); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] stop: " + ex.Message); } });
        }

        private void StartSession()
        {
            try
            {
                // The Target EXE field is intentionally gone — Start always sources the target from the app.
                // On EVERY Start we re-resolve from the active project and use the fresh result. A manual Browse
                // pick is honoured only as a ONE-SHOT tied to the solution/project context it was chosen for: if
                // that context has changed (or can't be confirmed the same), the stale pick is discarded and we
                // re-resolve / re-Browse rather than launching a hidden EXE against a different solution.
                if (!ResolveTargetForStart()) return;

                // Echo the resolved target so the console always confirms which process is about to launch.
                Console("info", "target: " + _exe);
                // merge gutter (red-dot) breakpoints set before launch
                foreach (var gb in _gutter.Snapshot())
                {
                    bool known = false;
                    foreach (var b in _pending) if (SameBp(b, gb.Module, gb.RequestedLine)) { known = true; break; }
                    if (!known) _pending.Add(gb);
                }
                Post("{\"type\":\"clear\"}");
                // Pre-load the solution's output DLLs so breakpoints set in DLL source bind before
                // launch (multi-DLL apps); other DLLs are still picked up automatically as they load.
                var solutionDlls = ProjectTargetService.ResolveSolutionDlls();
                Console("info", "starting: " + Path.GetFileName(_exe) + "  (" + _pending.Count + " breakpoint(s)"
                    + (solutionDlls.Count > 0 ? ", " + solutionDlls.Count + " solution DLL(s)" : "") + ")");
                _svc.StartSession(_exe, _pending.ToArray(), solutionDlls);

                // load static data symbols (file buffers) for the Variables tree, off the UI thread
                string exe = _exe;
                System.Threading.ThreadPool.QueueUserWorkItem(_ =>
                {
                    string g = ClarionDebuggerService.GetGlobalsJson(exe);
                    if (!string.IsNullOrEmpty(g))
                        UI(() => Post(g.Replace("\"event\":\"globals\"", "\"type\":\"globals\"")));
                });
                PushProcedures(exe);   // refresh the Procedures list against the just-resolved target
            }
            catch (Exception ex) { Console("err", "start failed: " + ex.Message); }
        }

        /// <summary>Enumerate the target's procedures + methods (static parse, off the UI thread) and send
        /// them to the page for the Procedures list. Clicking a row reuses the existing 'jump' handler, so
        /// no new inbound action is needed. Silent on failure (the list just stays empty).</summary>
        private void PushProcedures(string exe)
        {
            if (string.IsNullOrEmpty(exe)) return;
            System.Threading.ThreadPool.QueueUserWorkItem(_ =>
            {
                try
                {
                    var procs = ClarionDebuggerService.GetProcedures(exe);
                    var sb = new StringBuilder();
                    sb.Append("{\"type\":\"procedures\",\"procs\":[");
                    for (int i = 0; i < procs.Count; i++)
                    {
                        var p = procs[i];
                        if (i > 0) sb.Append(',');
                        sb.Append("{\"name\":").Append(Str(p.Name))
                          .Append(",\"module\":").Append(Str(p.Module))
                          .Append(",\"line\":").Append(p.Line)
                          .Append('}');
                    }
                    sb.Append("]}");
                    string json = sb.ToString();
                    UI(() => Post(json));
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
                    _exe = result;
                    _exeAuto = true;
                    _exeManualKey = null;
                    Console("info", "auto-detected target: " + Path.GetFileName(_exe));
                }
            }
            catch { }
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
            if (string.IsNullOrEmpty(spec)) return;
            int c = spec.LastIndexOf(':');
            if (c <= 0) return;
            string module = spec.Substring(0, c);
            int line; if (!int.TryParse(spec.Substring(c + 1), out line)) return;
            string path = ResolvePath(module);
            if (path != null) TryJump(path, line);
            else Console("info", "(can't resolve " + module + " — open the app's solution so the .red is active)");
        }

        /// <summary>Open a breakpoint's source in the Clarion editor using the exact .clw path the IDE
        /// gutter gave us (no fragile re-resolution). Data is "line\tfullPath".</summary>
        private void OpenBp(string data)
        {
            if (string.IsNullOrEmpty(data)) return;
            int t = data.IndexOf('\t');
            if (t <= 0) return;
            int line;
            if (!int.TryParse(data.Substring(0, t), out line)) return;
            string path = data.Substring(t + 1);
            if (!string.IsNullOrEmpty(path) && File.Exists(path)) TryJump(path, line);
            else Console("info", "(can't open " + path + " — file not found)");
        }

        /// <summary>Remove a breakpoint from the pane's "x". Removes the IDE gutter bookmark, which
        /// cascades through BreakPointRemoved → OnGutterBpRemoved (engine/pending + pane refresh) and
        /// clears the editor's red dot. Falls back to a direct removal if no bookmark is found (e.g. a
        /// pending bp whose editor was closed). Data is "module:line".</summary>
        private void RemoveBp(string data)
        {
            if (string.IsNullOrEmpty(data)) return;
            int c = data.LastIndexOf(':');
            if (c <= 0) return;
            string module = data.Substring(0, c);
            int line;
            if (!int.TryParse(data.Substring(c + 1), out line)) return;
            if (!_gutter.RemoveByModuleLine(module, line))
                OnGutterBpRemoved(module, line); // no gutter bookmark matched — keep the pane/engine consistent
        }

        // ------------------------------------------------------------------ host → page

        private void OnPaused(DebugPause p)
        {
            UI(() =>
            {
                // a 'watch' pause is the func-eval round-trip completing — NOT a fresh stop; don't cascade
                if (string.Equals(p.Reason, "watch", StringComparison.OrdinalIgnoreCase)) return;

                var sb = new StringBuilder();
                sb.Append("{\"type\":\"paused\",\"module\":").Append(Str(p.Module))
                  .Append(",\"proc\":").Append(Str(p.Proc))
                  .Append(",\"line\":").Append(p.Line)
                  .Append(",\"regs\":").Append(RegsJson(p.Regs)).Append('}');
                Post(sb.ToString());
                Console("pause", "paused [" + p.Reason + "]  " + (p.Resolved ? p.Module + " line " + p.Line + (p.Proc != null ? " in " + p.Proc : "") : "(unresolved)"));

                SendSource(p.ResolvedPath, p.Proc, p.Line);
                _svc.RequestStack();
                foreach (var name in _watched) _svc.Watch(name);

                if (!string.IsNullOrEmpty(p.ResolvedPath))
                {
                    TryJump(p.ResolvedPath, p.Line);
                    // JumpToCurrentLine activates the Clarion editor and grabs keyboard focus, so the
                    // next configured debug shortcut would be handled by the editor instead of this
                    // pane. Return focus to our pad so stepping shortcuts keep working in a loop.
                    ReturnFocusToPad();
                }
            });
        }

        private void OnStack(List<DebugStackFrame> frames)
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
                  .Append(",\"line\":").Append(f.Line).Append('}');
            }
            sb.Append("]}");
            Post(sb.ToString());
        }

        private void OnWatch(DebugWatch w)
        {
            var sb = new StringBuilder("{\"type\":\"watch\",\"name\":").Append(Str(w.Name))
                .Append(",\"found\":").Append(w.Found ? "true" : "false");
            if (w.Found)
                sb.Append(",\"value\":").Append(Str(w.Value))
                  .Append(",\"typeName\":").Append(Str(w.TypeName))
                  .Append(",\"threaded\":").Append(w.Threaded ? "true" : "false");
            sb.Append('}');
            Post(sb.ToString());
        }

        private void SendBps()
        {
            var sb = new StringBuilder("{\"type\":\"bplist\",\"bps\":[");
            var list = new List<DebugBreakpoint>(_svc.IsRunning ? _svc.Breakpoints : _pending.ToArray());

            // The engine's bp list carries no source path; the IDE gutter is the source of truth for
            // the .clw file. Build a (module|line) -> path map from the gutter so each row can carry
            // the exact path for click-to-open, in both running and stopped states.
            var paths = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var g in _gutter.Snapshot())
                {
                    if (string.IsNullOrEmpty(g.Path) || string.IsNullOrEmpty(g.Module)) continue;
                    paths[g.Module + "|" + g.Line] = g.Path;
                    paths[g.Module + "|" + g.RequestedLine] = g.Path;
                }
            }
            catch { }

            for (int i = 0; i < list.Count; i++)
            {
                if (i > 0) sb.Append(',');
                var b = list[i];
                string path = b.Path;
                if (string.IsNullOrEmpty(path) && b.Module != null)
                {
                    string p;
                    if (paths.TryGetValue(b.Module + "|" + b.Line, out p)
                        || paths.TryGetValue(b.Module + "|" + b.RequestedLine, out p)) path = p;
                }
                sb.Append("{\"module\":").Append(Str(b.Module))
                  .Append(",\"line\":").Append(b.Line)
                  .Append(",\"requested\":").Append(b.RequestedLine)
                  .Append(",\"path\":").Append(Str(path)).Append('}');
            }
            sb.Append("]}");
            Post(sb.ToString());
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

        /// <summary>Read ~±12 lines around the current line from the resolved .clw and show them.</summary>
        private void SendSource(string path, string proc, int line)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path)) return;
                string[] all = File.ReadAllLines(path);
                int start = Math.Max(1, line - 12);
                int end = Math.Min(all.Length, line + 12);
                var sb = new StringBuilder("{\"type\":\"source\",\"file\":").Append(Str(Path.GetFileName(path)))
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
            catch { }
        }

        // ------------------------------------------------------------------ gutter breakpoints

        private void OnGutterBpAdded(string module, int line)
        {
            Console("info", "gutter breakpoint: " + module + ":" + line);
            if (_svc.IsRunning) _svc.AddBreakpoint(module, line);
            else
            {
                foreach (var b in _pending) if (SameBp(b, module, line)) return;
                _pending.Add(new DebugBreakpoint { Module = module, RequestedLine = line, Line = line });
                SendBps();
            }
        }

        private void OnGutterBpRemoved(string module, int line)
        {
            if (_svc.IsRunning) _svc.RemoveBreakpoint(module, line);
            else { _pending.RemoveAll(b => SameBp(b, module, line)); SendBps(); }
        }

        private static bool SameBp(DebugBreakpoint b, string module, int line)
        {
            return string.Equals(b.Module, module, StringComparison.OrdinalIgnoreCase) && (b.RequestedLine == line || b.Line == line);
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

        private static void TryJump(string path, int line)
        {
            try { ICSharpCode.SharpDevelop.Debugging.DebuggerService.JumpToCurrentLine(path, line, 1, line, 1); }
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
        /// After TryJump moves the Clarion editor to the current line (which steals keyboard focus),
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

        private void Post(string json)
        {
            try { if (_ready && _webView.CoreWebView2 != null) _webView.CoreWebView2.PostWebMessageAsString(json); }
            catch { }
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

        // minimal extractor for the flat {action,data} messages from the page
        private static string JsonVal(string json, string key)
        {
            string search = "\"" + key + "\":";
            int i = json.IndexOf(search, StringComparison.Ordinal);
            if (i < 0) return null;
            i += search.Length;
            while (i < json.Length && json[i] == ' ') i++;
            if (i >= json.Length) return null;
            if (json[i] == 'n') return null; // null
            if (json[i] == '"')
            {
                i++;
                var sb = new StringBuilder();
                while (i < json.Length)
                {
                    char c = json[i];
                    if (c == '\\' && i + 1 < json.Length) { char n = json[i + 1]; sb.Append(n == 'n' ? '\n' : n == 't' ? '\t' : n == 'r' ? '\r' : n); i += 2; continue; }
                    if (c == '"') break;
                    sb.Append(c); i++;
                }
                return sb.ToString();
            }
            int s = i;
            while (i < json.Length && json[i] != ',' && json[i] != '}') i++;
            return json.Substring(s, i - s).Trim();
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
                try { DetachServiceEvents(); } catch { }
                if (_coreForEvents != null)
                {
                    try { _coreForEvents.WebMessageReceived -= OnWebMessage; } catch { }
                    try { _coreForEvents.NavigationCompleted -= OnNavigationCompleted; } catch { }
                    _coreForEvents = null;
                }

                try { ClearCurrentLineMarker(); } catch { }

                var svc = _svc;
                if (wasLive)
                {
                    // A session was live. _svc.Stop() blocks (WaitForExit(1500) + Kill) and runs off the UI
                    // thread. Do NOT Unregister now — that would let the controller report Idle and re-enable
                    // the toolbar Start while the old engine/target is still dying (close→reopen→re-run-same-exe
                    // would race a still-terminating process / file lock). Keep the controller's current
                    // non-idle state; only AFTER Stop() completes do we signal the controller (NotifyStopped),
                    // which returns to Idle iff the then-current target is genuinely idle, then Unregister this
                    // instance. Order matters: NotifyStopped before Unregister so a no-reopen close still drops
                    // to Idle (NotifyStopped sees _target==this whose session is now idle).
                    System.Threading.Tasks.Task.Run(() =>
                    {
                        try { svc.Stop(); } catch (Exception ex) { System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] dispose stop: " + ex.Message); }
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
    }
}
