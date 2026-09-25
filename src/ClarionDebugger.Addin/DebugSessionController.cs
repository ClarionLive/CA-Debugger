using System;
using System.Diagnostics;

namespace ClarionDebugger
{
    /// <summary>Debug run-state as observed by the IDE toolbar buttons. Mirrors
    /// ClarionDebugger.Services.DebugSessionState but lives here so the toolbar command/condition
    /// layer has no dependency on the engine service.</summary>
    public enum DebugControllerState
    {
        Idle,       // no live session
        Launching,  // engine started, target not yet loaded
        Running,    // target executing
        Paused      // target suspended at a breakpoint / step
    }

    /// <summary>
    /// The live debugger pad's command surface. Implemented by <see cref="Terminal.ClarionDebuggerWebView"/>.
    /// Each method is the single execution path for one toolbar/web command; the WebView's own web-message
    /// handler routes through these too, so the pad and the IDE toolbar share one code path.
    /// <para>
    /// EVERY TARGET CARRIES ITS OWN MARSHAL (fc8d63f5): the interface extends
    /// <see cref="System.ComponentModel.ISynchronizeInvoke"/>, and <see cref="DebugSessionController"/> posts
    /// each command through it whenever the caller is on the wrong thread. The commands are UI-thread code,
    /// and two of the forwarders are reached by REFLECTION from ClarionAssistant, on whatever thread it
    /// calls from. The marshal used to apply only to a target that happened to be a WinForms Control; any
    /// other implementation silently ran on the caller's thread, and it would have LOOKED as if it worked,
    /// because the call was forwarded. Requiring the mechanism in the type is what makes that impossible to
    /// forget: a Control gets it for free, and anything else does not compile until it says how.
    /// </para>
    /// </summary>
    public interface IDebugSessionTarget : System.ComponentModel.ISynchronizeInvoke
    {
        /// <summary>True once the hosted WebView has finished navigation and can accept commands.</summary>
        bool IsReady { get; }

        /// <summary>True when this target's engine has no live session (engine state == Idle). Read by the
        /// controller after a prior pad's teardown completes to decide whether the CURRENT target is genuinely
        /// idle (so Start may re-enable).</summary>
        bool IsSessionIdle { get; }

        void CmdStart();
        void CmdContinue();
        void CmdPause();
        void CmdStepOver();
        void CmdStepInto();
        void CmdStepOut();
        void CmdStop();

        /// <summary>Run to cursor. <paramref name="spec"/> is "module:line", or null/empty for the active
        /// Monaco editor's live cursor.</summary>
        void CmdRunToCursor(string spec);

        /// <summary>Break on the entry of the procedure that CONTAINS <paramref name="filePath"/>:<paramref
        /// name="line"/> (1-based) - the Monaco editor's cursor, in practice. The caller's position is only a
        /// lookup key: which procedure contains it, and where that procedure's entry is, are answered from the
        /// Procedures list the pad itself issued (e61e4f92, on afbc68c7's host-owned contract), never taken
        /// from the caller. Valid in any state: idle stages it, live arms it. Returns what happened: true when a
        /// breakpoint was sent or staged (or already was), false when nothing was set, with
        /// <paramref name="message"/> saying which (the Monaco toast's text on a miss).</summary>
        bool CmdBreakOnProcEntryAt(string filePath, int line, out string message);
    }

    /// <summary>
    /// Process-wide singleton that mediates between the native IDE debug toolbar (commands + the condition
    /// evaluator that greys them) and the live debugger pad. The pad registers itself on creation and
    /// unregisters on dispose; the controller forwards toolbar commands to it and mirrors its run-state so
    /// the condition evaluator can decide which buttons are enabled.
    ///
    /// HARDENING:
    /// - Every forwarder null/ready-guards and no-ops when there is no live, ready target.
    /// - Each forwarder also STATE-guards (mirrors the toolbar enable matrix) so a stale-enabled toolbar
    ///   click — e.g. one fired on an idle tick before a transition re-greyed the button — is a safe no-op
    ///   that never reaches the engine (prevents "session already running" / stepping while not paused).
    /// - Register stores the latest instance (the most recently created pad wins).
    /// - Unregister(target) only clears if <paramref name="target"/> is still the current one (race-safe
    ///   against a new pad having already registered).
    /// - SetState is instance-aware: an update from a sender that is not the current target is ignored, so a
    ///   stale/disposed pad cannot mutate the toolbar state.
    /// </summary>
    public static class DebugSessionController
    {
        private static readonly object _gate = new object();
        private static IDebugSessionTarget _target;
        private static DebugControllerState _state = DebugControllerState.Idle;

        /// <summary>Current run-state. Defaults to Idle when no pad is registered.</summary>
        public static DebugControllerState State
        {
            get { lock (_gate) return _state; }
        }

        /// <summary>True when a live pad is registered (a Start may be queued before it is ready).</summary>
        public static bool HasLiveTarget
        {
            get { lock (_gate) return _target != null; }
        }

        // ---------------------------------------------------------------- registration

        /// <summary>The newly-created pad registers itself. The latest instance wins. The Idle-seed is
        /// CONDITIONAL:
        /// - Same instance re-registering: no-op (preserve state).
        /// - New target when there was no prior target (old == null — the normal close→reopen path: the old pad
        ///   already Unregistered in its Dispose) OR the current state is already Idle: seed Idle so the fresh
        ///   pad reads no-live-session (it must not inherit a stale Running/Paused — there is no StateChanged
        ///   event to correct it).
        /// - New target while a PRIOR target is STILL registered with a live (non-idle) session: do NOT drop to
        ///   Idle. Preserve the outgoing session's non-idle state so Start stays disabled until the old target
        ///   unregisters/stops — publishing Idle here would re-enable Start against a still-running engine during
        ///   the close/reopen/replacement window. We do NOT stop the old target (it may be disposing — avoid a
        ///   new teardown race); we only refrain from prematurely re-enabling Start.</summary>
        public static void Register(IDebugSessionTarget target)
        {
            if (target == null) return;
            lock (_gate)
            {
                if (ReferenceEquals(_target, target)) return;   // same instance — preserve state

                var old = _target;
                _target = target;
                if (old == null || _state == DebugControllerState.Idle)
                    _state = DebugControllerState.Idle;         // no live prior session — fresh pad reads Idle
                // else: a prior target still owns a non-idle session — keep its state so Start stays disabled.
            }
        }

        /// <summary>The pad unregisters on dispose. Only clears the target reference if it is still the current
        /// one (race-safe — a no-op if a replacement pad already registered).
        ///
        /// IMPORTANT: Unregister does NOT force the state to Idle. For a pad whose session was LIVE at close,
        /// the engine teardown (_svc.Stop()) runs asynchronously and can take up to ~1.5s; driving Idle here —
        /// at the START of disposal — would re-enable the toolbar Start while the old engine/target is still
        /// terminating (close → reopen → re-run the SAME exe would race a still-dying process). On that path the
        /// WebView calls <see cref="NotifyStopped"/> only AFTER Stop() completes, and that is what returns the
        /// controller to Idle. For a pad that was already Idle at close, the state is already Idle, so leaving it
        /// untouched here is correct too.</summary>
        public static void Unregister(IDebugSessionTarget target)
        {
            if (target == null) return;
            lock (_gate)
            {
                if (!ReferenceEquals(_target, target)) return; // a replacement already took over — leave it
                _target = null;
                // Deliberately do NOT touch _state — see remarks. If this pad was idle, _state is already Idle;
                // if it was live, NotifyStopped (post-Stop) is the only thing that drives Idle.
            }
        }

        /// <summary>
        /// Called by a closing pad AFTER its engine teardown (_svc.Stop()/Exited) has CONFIRMED completed — from
        /// a background Task, safe post-dispose because it only touches this static controller, never the
        /// disposed WebView. Returns the controller to Idle only if the CURRENT target is genuinely idle:
        ///   - _target == null  : no live pad at all → Idle (no strand).
        ///   - _target.IsSessionIdle : the current (possibly freshly-reopened) pad has no live session → Idle,
        ///     re-enabling Start now that the old engine has actually died (close→reopen completion path).
        /// If the current target reports a LIVE session (a fresh pad already started its own), we leave its state
        /// alone — the old teardown completing must not stomp a new live session.
        ///
        /// The CALLER is checked too, which is what <paramref name="target"/> is for. "Stopped" is a claim about
        /// the pad making it, and ClarionDebuggerService.Stop() no longer publishes Idle when it could not
        /// confirm the engine process dead — so a caller that still reports a live session is telling us its
        /// teardown did not finish. Publishing Idle on that word would re-enable Start against a target still
        /// owned by the old process, which is the close→reopen→restart race this controller exists to prevent.
        /// The cost is deliberate and one-sided: after a teardown that never confirmed, Start stays disabled
        /// until the pad is closed and reopened (Unregister clears _target, and the next Register then reads
        /// Idle). A disabled Start after a failed kill is a far cheaper wrong answer than an enabled one.
        /// </summary>
        public static void NotifyStopped(IDebugSessionTarget target)
        {
            lock (_gate)
            {
                // The teardown that is reporting in must actually be over. A pad whose Stop() could not confirm
                // the process dead still reads non-idle, and its word for "stopped" is not good enough.
                try { if (target != null && !target.IsSessionIdle) return; }
                catch { }   // a throwing target can't be confirmed live either way — fall through to the check below

                bool currentIsIdle;
                try { currentIsIdle = _target == null || _target.IsSessionIdle; }
                catch { currentIsIdle = _target == null; } // a throwing target can't be confirmed live — only Idle if none
                if (currentIsIdle) _state = DebugControllerState.Idle;
            }
        }

        // ---------------------------------------------------------------- state mirror

        /// <summary>The pad pushes engine state here (called from its StateChanged handler, possibly off-thread).
        /// Instance-aware: ignored unless <paramref name="sender"/> is the currently-registered target, so a
        /// stale/disposed pad whose engine is winding down cannot stomp the live toolbar state.</summary>
        public static void SetState(IDebugSessionTarget sender, DebugControllerState state)
        {
            if (sender == null) return;
            lock (_gate)
            {
                if (!ReferenceEquals(_target, sender)) return; // not the live pad — ignore
                _state = state;
            }
            // No public StateChanged event: the condition evaluator pulls State live on each ApplicationIdle
            // re-evaluation (the same mechanism the native IsProcessRunning debug buttons use), so the toolbar
            // re-greys within one idle tick with nothing to subscribe to / marshal.
        }

        // ---------------------------------------------------------------- command forwarders
        // Each grabs the current target + state under the lock, then invokes outside the lock. A null /
        // not-yet-ready target, or a command that doesn't apply in the current state, is a silent no-op.

        /// <summary>Start a session. Idempotent: a second Start while Launching/Running/Paused is a no-op so it
        /// can never fall through to a second _svc.StartSession() (which throws "already running"). Only fires
        /// when Idle. Start defers internally until the WebView is ready, so it does not require IsReady here.</summary>
        public static void Start()
        {
            Invoke(t => t.CmdStart(), requireReady: false, allowed: s => s == DebugControllerState.Idle);
        }

        public static void Continue() { Invoke(t => t.CmdContinue(), allowed: IsPaused); }
        public static void StepOver() { Invoke(t => t.CmdStepOver(), allowed: IsPaused); }
        public static void StepInto() { Invoke(t => t.CmdStepInto(), allowed: IsPaused); }
        public static void StepOut()  { Invoke(t => t.CmdStepOut(),  allowed: IsPaused); }

        /// <summary>Run to the active Monaco editor's cursor line. Entry point for ClarionAssistant's editor
        /// context menu, reached by reflection. Frozen contract: public static void RunToCursor(), a silent
        /// no-op unless Paused with a ready pad. A null spec makes the pad resolve the live Monaco cursor.
        /// It and <see cref="BreakOnProcEntry"/> are the forwarders reached from OUTSIDE this addin, so they
        /// are the ones with no guarantee about the calling thread; <see cref="Invoke"/> marshals for this one
        /// and every void forwarder, and BreakOnProcEntry marshals for itself (it has an answer to wait for).</summary>
        public static void RunToCursor() { Invoke(t => t.CmdRunToCursor(null), allowed: IsPaused); }

        /// <summary>Break on the entry of the procedure containing <paramref name="filePath"/>:<paramref
        /// name="line"/> (1-based). Entry point for ClarionAssistant's editor context menu, reached by
        /// reflection (e61e4f92). Allowed in EVERY state, because break-on-entry means something while idle
        /// too (the pad stages it for the next Start). The pad resolves the procedure from its own list and
        /// still writes both outcomes to its Debug Console.
        /// <para>
        /// FROZEN CONTRACT (Diana, 2026-09-25, owner decision 5): ClarionAssistant shows its menu item whenever
        /// the debugger is loaded, pad open or not, and toasts a miss, so the caller has to be TOLD. True means
        /// a breakpoint was sent to the live engine (sent, not confirmed: the bp-set echo is async), staged for
        /// the next Start, or already staged. False means nothing was set. Either way <paramref name="message"/>
        /// is one line of plain text, never empty, at most <see cref="MaxMessage"/> characters, fit to show
        /// verbatim. This method never throws. It REPLACES the void (string, int) member, which no
        /// ClarionAssistant build ever bound; ClarionAssistant binds this one OPTIONALLY (PM decision 7), by
        /// exact signature and a bool return, so the members it requires are untouched.
        /// </para>
        /// <para>
        /// SYNCHRONOUS, unlike every other forwarder: <see cref="Invoke"/> posts with BeginInvoke and returns
        /// before the command has run, which is fine for a void command and useless for one with an answer.
        /// Off the pad's thread this marshals with the target's own blocking ISynchronizeInvoke.Invoke. From
        /// ClarionAssistant's context menu the caller IS the UI thread, so in practice it runs inline.
        /// </para></summary>
        public static bool BreakOnProcEntry(string filePath, int line, out string message)
        {
            string msg = null;
            bool ok = false;
            try
            {
                IDebugSessionTarget t;
                lock (_gate) t = _target;
                if (t == null) { message = NoPad; return false; }

                if (t.InvokeRequired)
                {
                    // The marshalled delegate runs the same body an on-thread caller does. It does NOT
                    // re-enter this method, so a target whose Invoke still reports InvokeRequired cannot
                    // recurse.
                    t.Invoke((Action)(() => ok = BreakOnProcEntryHere(t, filePath, line, out msg)), null);
                }
                else ok = BreakOnProcEntryHere(t, filePath, line, out msg);
            }
            catch (Exception ex)
            {
                Debug.WriteLine("[DebugSessionController] break on entry failed: " + ex.Message);
                ok = false;
                msg = "Break on entry failed: " + ex.Message;
            }
            message = OneLine(msg, ok);
            return ok;
        }

        /// <summary>The answer when no pad is registered; ClarionAssistant toasts it verbatim.</summary>
        internal const string NoPad = "Open the CA Debugger pad first.";

        /// <summary>The longest message <see cref="BreakOnProcEntry"/> returns (frozen contract: a toast).</summary>
        internal const int MaxMessage = 200;

        /// <summary>The on-thread half of <see cref="BreakOnProcEntry"/>. <paramref name="readBy"/> is the target
        /// the caller read. The current one is read again here, and a pad replaced while a marshal was in
        /// flight is refused rather than handed a position meant for its predecessor.</summary>
        private static bool BreakOnProcEntryHere(IDebugSessionTarget readBy, string filePath, int line, out string message)
        {
            IDebugSessionTarget t;
            lock (_gate) t = _target;
            if (t == null) { message = NoPad; return false; }
            if (!ReferenceEquals(t, readBy)) { message = "The CA Debugger pad was replaced; try again."; return false; }
            if (!SafeIsReady(t)) { message = "The CA Debugger pad is still loading; try again in a moment."; return false; }
            return t.CmdBreakOnProcEntryAt(filePath, line, out message);
        }

        /// <summary>Holds <see cref="BreakOnProcEntry"/>'s message to the contract: one line, never empty, at
        /// most <see cref="MaxMessage"/> characters.</summary>
        private static string OneLine(string text, bool ok)
        {
            string s = (text ?? "").Replace("\r\n", " ").Replace('\r', ' ').Replace('\n', ' ').Trim();
            if (s.Length == 0)
                s = ok ? "Break on entry: set." : "Break on entry: nothing was set, and the debugger gave no reason.";
            if (s.Length > MaxMessage) s = s.Substring(0, MaxMessage - 3) + "...";
            return s;
        }

        public static void Pause()
        {
            Invoke(t => t.CmdPause(), allowed: s => s == DebugControllerState.Running || s == DebugControllerState.Launching);
        }

        public static void Stop()
        {
            Invoke(t => t.CmdStop(), allowed: s => s != DebugControllerState.Idle);
        }

        private static bool IsPaused(DebugControllerState s) { return s == DebugControllerState.Paused; }

        private static void Invoke(Action<IDebugSessionTarget> action, bool requireReady = true, Func<DebugControllerState, bool> allowed = null)
        {
            IDebugSessionTarget t;
            DebugControllerState s;
            lock (_gate) { t = _target; s = _state; }
            if (t == null) return;

            // THREAD GUARD. Every target method is UI-thread code: they drive WebView2, and CmdRunToCursor
            // mutates the transient-breakpoint list with no lock of its own. The forwarders above are public
            // and RunToCursor is reached by REFLECTION from ClarionAssistant, so nothing here can assume the
            // caller is on the pad's thread.
            //
            // Marshal rather than reject. Every forwarder routed here is void by frozen contract, so a refusal is
            // unobservable to the caller — an off-thread context-menu command would just look like the
            // debugger ignoring the user, which is the silent failure this whole ticket is about.
            //
            // Re-entering Invoke on the pad's thread re-reads the target and re-runs the guards THERE, so a
            // state change while the post was in flight is still honoured; on that pass InvokeRequired is
            // false and it falls through, so this cannot recurse.
            //
            // Through the TARGET'S OWN marshal, which the interface requires (fc8d63f5). It used to be
            // `t as Control`, so a target that was not a Control ran on the caller's thread. A Control whose
            // handle is not created yet reports InvokeRequired false, so it still runs inline as it always
            // did - there is no thread to post to.
            bool offThread;
            try { offThread = t.InvokeRequired; }
            catch (Exception ex) { Debug.WriteLine("[DebugSessionController] InvokeRequired threw: " + ex.Message); return; }
            if (offThread)
            {
                try { t.BeginInvoke((Action)(() => Invoke(action, requireReady, allowed)), null); }
                catch (Exception ex) { Debug.WriteLine("[DebugSessionController] marshal failed: " + ex.Message); }
                return;
            }

            if (allowed != null && !allowed(s)) return;       // state-guard: stale-enabled click => no-op
            if (requireReady && !SafeIsReady(t)) return;
            try { action(t); }
            catch (Exception ex) { Debug.WriteLine("[DebugSessionController] forward failed: " + ex.Message); }
        }

        private static bool SafeIsReady(IDebugSessionTarget t)
        {
            try { return t.IsReady; }
            catch (Exception ex) { Debug.WriteLine("[DebugSessionController] IsReady threw: " + ex.Message); return false; }
        }
    }
}
