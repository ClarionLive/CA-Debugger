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
    /// </summary>
    public interface IDebugSessionTarget
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
        /// </summary>
        public static void NotifyStopped(IDebugSessionTarget target)
        {
            lock (_gate)
            {
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
