using System;
using System.Collections.Generic;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Windows.Forms;
using ClarionDebugger.Services;

namespace ClarionDebugger.Disassembly
{
    /// <summary>
    /// Phase 1 of the native disassembly pad: an owner-drawn view over the active engine session
    /// (<see cref="ClarionDebuggerService.Active"/>). On each pause it fetches a window of instructions
    /// at EIP (<c>disasm &lt;va&gt; N win</c>) and paints address / mnemonic / call-target / raw bytes
    /// with the current instruction highlighted.
    ///
    /// Unlike the read-only .asm editor approach this replaces, the "current line" is just a painted
    /// row — there is no IDE editor, no temp file, and no shared source-debug marker, so stepping here
    /// never yanks focus to an open .clw. Virtual scrolling over the whole address space (the two-bar
    /// Cladb model) and richer interaction come in later phases; for now it renders the fetched window.
    /// </summary>
    public sealed class DisassemblyView : Control
    {
        // The three request KINDS. They are no longer sent as the whole tag: see MakeTag — a tag is not a
        // thread, and three tag-keyed requests can be in flight across a thread switch.
        private const string WinTag = "win";      // (re)seat the window at an address (replaces the cache)
        private const string FwdTag = "winf";     // forward extension (append)
        private const string BwdTag = "winb";     // backward extension (prepend, via engine re-sync)
        private const int WindowCount = 200;      // instructions in a fresh window (engine caps at 200)
        private const int Batch = 64;             // instructions per edge extension
        private const int Edge = 8;               // start extending when this close to a cache edge
        private const int Context = 24;           // instructions to include ABOVE EIP in a fresh window
        private const int CoarseMax = 10000;      // resolution of the coarse address slider

        private ClarionDebuggerService _svc;   // the active session (null until one starts; rebinds via ActiveChanged)
        private readonly VScrollBar _coarse = new VScrollBar { Dock = DockStyle.Left };   // coarse address seek
        private readonly VScrollBar _scroll = new VScrollBar { Dock = DockStyle.Right };  // fine line scroll
        private readonly ToolStrip _bar = new ToolStrip { Dock = DockStyle.Top, GripStyle = ToolStripGripStyle.Hidden };
        private ToolStripButton _bContinue, _bOver, _bInto, _bOut, _bStop, _bSrc, _bCur;
        private ToolStripLabel _loc;
        private string _curPath, _curModule;   // source location of the current instruction (the stop's
                                               // symbol, its non-TSWD fallback, lives in _seat: SymbolFor)
        private int _curLine;

        /// <summary>Flat dark background for the stepping toolbar, to match the view.</summary>
        private sealed class DarkRenderer : ToolStripProfessionalRenderer
        {
            protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
            { e.Graphics.Clear(Color.FromArgb(37, 37, 38)); }
            protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e) { }
        }
        private readonly Font _font = new Font("Consolas", 9f);
        private readonly Font _fontBold = new Font("Consolas", 9f, FontStyle.Bold);

        /// <summary>A painted line: either an interleaved source-comment or one instruction.</summary>
        private struct Row
        {
            public bool IsSource;
            public string Source;             // "module:line   <source text>" (when IsSource)
            public DebugDisasmInstr Instr;    // the instruction (when !IsSource)
        }

        private List<DebugDisasmInstr> _instrs = new List<DebugDisasmInstr>();   // contiguous cache, sorted by VA
        private readonly List<Row> _rows = new List<Row>();             // display lines (source comments + instructions)
        private readonly HashSet<uint> _labels = new HashSet<uint>();   // VAs that are branch targets within the window
        private readonly HashSet<int> _sel = new HashSet<int>();        // selected display-row indices (for copy)
        private int _anchorRow = -1;                                    // shift-select anchor (display-row index; any row)
        private int _current = -1;   // index of the EIP row within _rows
        private uint _curVa;         // EIP VA (the highlighted instruction), 0 = none
        private bool _hasCur;

        // ----- which thread this listing is of -----
        //
        // The view follows the PAD's selection: one selected thread for the whole debugger, so the window
        // and the Call Stack can never disagree about whose execution point is on screen.
        //
        // WHAT IS AND IS NOT PER-THREAD, because it right-sizes the gate below: the instruction BYTES are
        // process memory, shared by every thread, so a listing decoded for one thread is not wrong code for
        // another. What IS per-thread is where the window was SEATED (the thread's EIP) and which row is
        // flagged `current`. A late reply therefore does not paint foreign code — it moves the view to a
        // thread you are no longer looking at and marks that thread's instruction as the current one.
        private uint _stoppedTid;    // the thread the engine stopped on (0 = unknown)
        private uint _selTid;        // the thread every panel is currently reading (0 = unknown)
        private List<DebugThread> _threads = new List<DebugThread>();   // for naming a thread in the banner
        private ToolStripLabel _thread;   // "viewing Thread N — not the stopped thread", or blank
        // THE SEAT LIFECYCLE - painted, in flight, awaiting registers, decoded-to-nothing, the epoch, the
        // edge-extension flags and the stop's symbol - is ONE OBJECT whose fields only its named transitions
        // can change (SeatState.cs, ticket 8f352618). Nothing in this file assigns seat state directly, and
        // the clearing rules are code there rather than prose here. The epoch is carried in the request TAG,
        // which the engine echoes verbatim, so a reply is matched to the state that asked for it with no
        // protocol change.
        private readonly SeatState _seat = new SeatState();
        private int _top;            // first visible row index
        private int _rowH = 16;
        private int _charW = 8;

        private static readonly Color Bg        = Color.FromArgb(24, 24, 24);
        private static readonly Color FgAddr    = Color.FromArgb(108, 116, 128);   // normal address (muted)
        private static readonly Color FgLabel   = Color.FromArgb(86, 156, 214);    // branch-target address (a "label")
        private static readonly Color FgMnem    = Color.FromArgb(212, 212, 212);   // normal mnemonic
        private static readonly Color FgFlow    = Color.FromArgb(214, 170, 100);   // control-flow mnemonic (call/jmp/jcc/ret)
        private static readonly Color FgOper    = Color.FromArgb(190, 190, 190);   // operands
        private static readonly Color FgBytes   = Color.FromArgb(95, 95, 95);
        private static readonly Color FgTarget  = Color.FromArgb(140, 198, 140);   // -> call target name
        private static readonly Color FgSource  = Color.FromArgb(106, 153, 85);    // interleaved .clw source line (comment)
        private static readonly Color FgHint    = Color.FromArgb(110, 110, 110);
        private static readonly Color CurBg     = Color.FromArgb(58, 66, 38);
        private static readonly Color CurBar    = Color.FromArgb(122, 162, 90);    // left accent on the current row
        private static readonly Color SepLine   = Color.FromArgb(45, 45, 45);      // column separator before bytes
        private static readonly Color SelBg     = Color.FromArgb(38, 79, 120);     // selected row(s) for copy

        public DisassemblyView()
        {
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint
                   | ControlStyles.UserPaint | ControlStyles.ResizeRedraw | ControlStyles.Selectable, true);
            TabStop = true;   // accept focus so Ctrl+C / Ctrl+A reach us
            BackColor = Bg;

            var menu = new ContextMenuStrip();
            menu.Items.Add("Copy\tCtrl+C", null, (s, e) => CopySelection());
            ContextMenuStrip = menu;
            Controls.Add(_scroll);
            Controls.Add(_coarse);
            _scroll.Scroll += (s, e) => { _top = e.NewValue; MaybeExtend(); SyncCoarse(); Invalidate(); };
            _coarse.Minimum = 0;
            _coarse.Maximum = CoarseMax + 199;     // LargeChange-1 so Value can reach CoarseMax
            _coarse.LargeChange = 200;
            _coarse.SmallChange = 20;
            _coarse.Scroll += OnCoarseScroll;

            BuildToolbar();
            Controls.Add(_bar);   // added last → docks across the full width at the top

            // Attach to whichever session is active now, and rebind when a new one starts (the pad that
            // starts a session registers itself as Active — see ClarionDebuggerService.StartSession).
            ClarionDebuggerService.ActiveChanged += OnActiveChanged;
            Bind(ClarionDebuggerService.Active);
        }

        /// <summary>Subscribe to a session's events and reflect its state. <paramref name="svc"/> may be null
        /// (no session yet) — the view stays idle until one starts.</summary>
        private void Bind(ClarionDebuggerService svc)
        {
            _svc = svc;
            // A different session (or none) knows nothing about the thread the old one was showing.
            _seat.Rebound();
            _stoppedTid = _selTid = 0;
            _threads = new List<DebugThread>();
            if (_svc != null)
            {
                _svc.Paused += OnPaused;
                _svc.DisasmReceived += OnDisasm;
                _svc.Exited += OnExited;
                _svc.StateChanged += OnState;
                // The pad owns the thread selection; this view reads it rather than keeping its own, so the
                // window and the Call Stack cannot disagree about whose execution point is on screen.
                _svc.ThreadsReceived += OnThreads;
                _svc.ThreadSelected += OnThreadSelected;
                // How the view learns the NEW thread's EIP after a switch: the inventory names threads but
                // carries no EIP, so the seat comes from the registers, which are already tid-stamped.
                _svc.RegsReceived += OnRegs;
                // A FAILED disasm produces NO disasm event at all — the engine answers "read failed"
                // on the error channel (DebugEngine.Disassembly.cs, the ReadCleanBlock guard). Without
                // this the seat latch is held by a reply that is never coming, which is the same
                // never-painted state an empty reply used to produce, reached by a quieter route.
                _svc.EngineError += OnEngineError;
            }
            UpdateThreadBanner();
            UpdateButtons(_svc?.State ?? DebugSessionState.Idle);
        }

        private void Unbind()
        {
            if (_svc == null) return;
            _svc.Paused -= OnPaused;
            _svc.DisasmReceived -= OnDisasm;
            _svc.Exited -= OnExited;
            _svc.StateChanged -= OnState;
            _svc.ThreadsReceived -= OnThreads;
            _svc.ThreadSelected -= OnThreadSelected;
            _svc.RegsReceived -= OnRegs;
            _svc.EngineError -= OnEngineError;
            _svc = null;
        }

        /// <summary>A pad started a new session (Active flipped). Rebind to it; if it is already paused,
        /// fill the window the same way a late open does — asking whose thread is selected rather than
        /// assuming the stopped one. Fires on the StartSession caller (the UI thread) — marshal anyway.</summary>
        private void OnActiveChanged()
        {
            if (InvokeRequired) { try { BeginInvoke((Action)OnActiveChanged); } catch { } return; }
            Unbind();
            Bind(ClarionDebuggerService.Active);
            SeatOnLateOpen();
        }

        // ----- stepping toolbar -----

        private const string TipOver = "Step over one instruction (run calls to completion)";
        private const string TipInto = "Step one machine instruction (into calls)";
        private const string TipOut  = "Step out of the procedure (source level)";

        /// <summary>Is the view following a thread other than the one execution stopped on? Both must be
        /// known: an unknown side is the ordinary single-thread case, where saying anything is noise. The
        /// same rule as the pad's viewingOtherThread, so the two never disagree about when to speak.</summary>
        private static bool IsOtherThread(uint selTid, uint stoppedTid)
        {
            return selTid != 0 && stoppedTid != 0 && selTid != stoppedTid;
        }

        /// <summary>A step button's tooltip. STEPPING IS DEFINED ON THE STOPPED THREAD (ticket 375d463b): while
        /// the view follows another one, Over/Into/Out still run the stopped thread, and the next stop brings
        /// the view back to it. That is correct engine behaviour and the buttons stay enabled — taking a
        /// control away is worse than explaining it — but it must not be a surprise, so the tooltip names the
        /// thread that will run and says the view will return to it. <paramref name="stoppedName"/> is null
        /// when the view is on the stopped thread, and the tooltip is then the plain one.</summary>
        private static string StepTip(string tip, string stoppedName)
        {
            if (stoppedName == null) return tip;
            return tip + " — on " + stoppedName + ", the stopped thread: stepping always runs it, and the view"
                 + " returns to it";
        }

        /// <summary>Re-word the step buttons for the thread the view is on. Called with the banner, which is
        /// re-derived on every selection, inventory, stop and seat change.</summary>
        private void UpdateStepTips()
        {
            string stopped = IsOtherThread(_selTid, _stoppedTid) ? ThreadName(_stoppedTid) : null;
            if (_bOver != null) _bOver.ToolTipText = StepTip(TipOver, stopped);
            if (_bInto != null) _bInto.ToolTipText = StepTip(TipInto, stopped);
            if (_bOut  != null) _bOut.ToolTipText  = StepTip(TipOut,  stopped);
        }

        private void BuildToolbar()
        {
            _bar.RenderMode = ToolStripRenderMode.Professional;
            _bar.Renderer = new DarkRenderer();
            _bar.BackColor = Color.FromArgb(37, 37, 38);
            _bar.ForeColor = Color.Gainsboro;
            _bar.Padding = new Padding(4, 2, 4, 2);
            // Instruction-granular stepping (this is a disassembly view): Over runs calls to completion
            // and stops at the next instruction; Into single-steps into calls. Out is source-level.
            _bContinue = AddButton("▶ Continue", "Resume until the next breakpoint or exception", () => _svc?.Continue());
            _bar.Items.Add(new ToolStripSeparator());
            _bOver  = AddButton("⤼ Over",  TipOver, () => _svc?.StepInstrOver());
            _bInto  = AddButton("⤷ Into",  TipInto, () => _svc?.StepInstr());
            _bOut   = AddButton("⤴ Out",   TipOut,  () => _svc?.StepOut());
            _bar.Items.Add(new ToolStripSeparator());
            _bCur   = AddButton("⌖ Current", "Go back to the current instruction of the thread being viewed (Alt+*)", Recentre);
            _bSrc   = AddButton("◧ Source", "Open the .clw source at the current line", ShowSource);
            _bar.Items.Add(new ToolStripSeparator());
            _bStop  = AddButton("■ Stop",  "Terminate the debug session", () => _svc?.Stop());
            // Amber, like the pad's own "not the stopped thread" badge, and right-aligned ahead of the
            // location so the two read as one status area. Hidden unless it has something to say.
            _thread = new ToolStripLabel("") { ForeColor = Color.FromArgb(220, 180, 90),
                Alignment = ToolStripItemAlignment.Right, AutoToolTip = false, Visible = false,
                ToolTipText = "The listing is showing a thread other than the one execution stopped on" };
            _bar.Items.Add(_thread);
            _loc = new ToolStripLabel("") { ForeColor = Color.FromArgb(150, 175, 150),
                Alignment = ToolStripItemAlignment.Right, AutoToolTip = false };
            _bar.Items.Add(_loc);
        }

        /// <summary>Open (and mark) the .clw at the current instruction's source line — explicit user
        /// action, so the focus jump to the editor is intended.</summary>
        private void ShowSource()
        {
            if (string.IsNullOrEmpty(_curPath) || _curLine <= 0) return;
            try { ICSharpCode.SharpDevelop.Debugging.DebuggerService.JumpToCurrentLine(_curPath, _curLine, 1, _curLine, 1); }
            catch { }
        }

        /// <summary>Refresh the location label + Show Source button from the current instruction's source.</summary>
        private void UpdateLocation()
        {
            bool hasSource = !string.IsNullOrEmpty(_curPath) && _curLine > 0;
            if (_bSrc != null) _bSrc.Enabled = hasSource && _svc?.State == DebugSessionState.Paused;
            if (_loc != null)
            {
                // The stop's symbol only while the strip's subject IS the stopped thread: it is per STOP,
                // so beside another thread's listing it would name the wrong thread's location.
                string sym = _seat.SymbolFor(_selTid, _stoppedTid);
                _loc.Text = _curLine > 0 && !string.IsNullOrEmpty(_curModule) ? _curModule + ":" + _curLine
                          : !string.IsNullOrEmpty(sym) ? sym
                          : "";
            }
        }

        private ToolStripButton AddButton(string text, string tip, Action onClick)
        {
            var b = new ToolStripButton(text) { ToolTipText = tip, ForeColor = Color.Gainsboro, AutoToolTip = false };
            b.Click += (s, e) => { try { onClick(); } catch { } };
            _bar.Items.Add(b);
            return b;
        }

        private void OnState(DebugSessionState s) => UI(() => UpdateButtons(s));

        private void UpdateButtons(DebugSessionState s)
        {
            bool paused = s == DebugSessionState.Paused;
            bool running = s == DebugSessionState.Running || s == DebugSessionState.Launching;
            if (_bContinue != null) _bContinue.Enabled = paused;
            if (_bOver  != null) _bOver.Enabled  = paused;
            if (_bInto  != null) _bInto.Enabled  = paused;
            if (_bOut   != null) _bOut.Enabled   = paused;
            if (_bStop  != null) _bStop.Enabled  = paused || running;
            UpdateRecentre();
            UpdateLocation();
        }

        /// <summary>GO BACK TO THE CURRENT INSTRUCTION (ticket 876ddf1d). The auto-centre can be lost — a
        /// coarse seek during a thread switch deliberately abandons the switch's seat (the scroll wins; see
        /// OnCoarseScroll), and any scroll moves the window off the current row — and without this there was
        /// no way back short of stepping. It re-seats on the SELECTED thread's EIP exactly as a thread switch
        /// does: a new epoch, then the registers, then the window. The selected thread, not the stopped one:
        /// the engine decodes the SELECTED thread, so seating on the stopped thread's address while another is
        /// selected would paint one thread's code under the other's banner (the blind-seat defect).
        /// An explicit action, so it is not refused because the thread is already painted — that is exactly
        /// the state of a user who scrolled away.</summary>
        private void Recentre()
        {
            if (_svc == null || _svc.State != DebugSessionState.Paused) return;
            if (_seat.BeginRecentre(_selTid)) _svc.RequestRegs();
        }

        /// <summary>Recentre needs a paused session and a thread to recentre ON: the seat goes through that
        /// thread's registers, which are tid-stamped.</summary>
        private void UpdateRecentre()
        {
            if (_bCur != null) _bCur.Enabled = _svc?.State == DebugSessionState.Paused && _selTid != 0;
        }

        // ----- engine session (events arrive on the reader thread → marshal to the UI thread) -----

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            SeatOnLateOpen();
        }

        /// <summary>Opened, reopened or rebound MID-STOP. The window has to be filled without waiting for
        /// the next step — but it must not guess whose code it is filling with.
        ///
        /// `_svc.CurrentVa` is the STOPPED thread's address, and since 381aabd7 the engine decodes the
        /// SELECTED thread. If another pad already selected a non-stopped thread, seating on CurrentVa
        /// paints one thread's address range decoded for another, with no current row and no banner —
        /// which is the exact mismatch this view exists to prevent, arriving through the one door that
        /// does not go past a stop event.
        ///
        /// So: ASK. The inventory is the only thing that reports a selection made before this view
        /// existed, and nothing used to request it — OnThreads was driven solely by the pad's own
        /// requests, so the "window-opened-late case" its comment described was unreachable.
        ///
        /// The CurrentVa seat below is a DEGRADATION PATH, not a second way of doing this. It is issued
        /// AFTER the inventory and is expected to lose: against a STAMPED engine its reply is dropped by
        /// the tid gate (we do not know our thread yet) and the inventory drives the real seat. It earns
        /// its place only against an engine that stamps nothing AND answers no inventory, where it is the
        /// only thing that fills the window and there is no selection for it to contradict.
        ///
        /// DO NOT PROMOTE IT. Moving it ahead of the inventory, making it unconditional, or "simplifying"
        /// this method down to it re-opens the blind-seat defect in full: it seats on the STOPPED thread's
        /// address while the engine decodes the SELECTED one. It will look like it works, because it does
        /// — on the common path where the two are the same thread. Nothing here can assert an ordering
        /// preference, so this comment is the guard.</summary>
        private void SeatOnLateOpen()
        {
            if (_svc == null || _svc.State != DebugSessionState.Paused) return;
            _svc.RequestThreads();            // FIRST: the only thing that reports a pre-existing selection
            // THE DEGRADATION SEAT STATES ITS OWN PRECONDITION rather than trusting a caller to establish
            // it. It is only safe while the view knows NOTHING — no selection, nothing painted, nothing in
            // flight — because CurrentVa is the STOPPED thread's address.
            //
            // Quinn-2 attacked this and judged it dead, reasoning that a wrongly-seated reply would need a
            // stamp matching a stale _selTid, which would mean the view already believed the right thread.
            // The hole: THE ENGINE STAMPS WITH THE SELECTED THREAD REGARDLESS OF THE VA IT WAS ASKED FOR.
            // A matching stamp proves which THREAD the engine answered about, not which ADDRESS it answered
            // with — and this request is entirely about an address. So the reply passes BOTH gates and
            // paints the stopped thread's code under the selected thread's banner.
            // And the epoch does not save it: with a thread already known, SeatOnSelectedThread returns at
            // its already-seated/already-seating guard BEFORE retiring anything, so nothing retires this
            // request. Reachable through a second OnHandleCreated — an undock/redock recreates the handle,
            // and unlike OnActiveChanged nothing resets the painted thread first — while viewing a non-stopped
            // thread. Relying on a caller to bump the epoch is the assumption that failed; this tests the
            // condition itself.
            if (!_seat.KnowsNothing(_selTid)) return;
            if (!string.IsNullOrEmpty(_svc.CurrentVa))
                _svc.RequestDisasmAt(_svc.CurrentVa, WindowCount, MakeTag(WinTag), Context);   // degradation path
        }

        private void OnPaused(DebugPause p)
        {
            if (string.IsNullOrEmpty(p.Va)) return;
            UI(() =>
            {
                // Taken from the STOP, not from the `threads` reply that follows it — that reply can fail
                // or be overtaken. It is also what stops the inventory triggering a second, pointless
                // reseat on every stop when the selection is (as it almost always is) the stopped thread.
                // A null Tid means an engine that does not name it: fall back to knowing nothing, where the
                // banner stays blank rather than naming a thread we would be guessing at.
                _selTid = _stoppedTid = TidOf(p.Tid);
                // A new stop resets the engine's selection to the stopped thread, so any request still in
                // flight was asked under a selection that no longer exists: SeatState.Stopped retires it,
                // records this stop's own request as the seat in flight (not painted until it lands), and
                // keeps the stop's symbol — the runtime location for non-TSWD stops.
                _seat.Stopped(_selTid, p.Sym);
                UpdateThreadBanner();
                // ASK, like the other two entry points. This was the only path that set _selTid from what
                // it happened to be told and never requested the inventory. If p.Tid is ABSENT while the
                // disasm reply IS stamped, _selTid stays 0 and the (now fail-closed) tid gate drops the
                // reply — and nothing on this path would recover, where before the gate changed it simply
                // painted. Reachability is UNPROVEN: the stop event and the disasm reply are stamped
                // through the same writer, so producing the mismatch needs a live engine and neither
                // Quinn-2 nor I could construct it statically. It is one line, and it removes a
                // "cannot happen" from a path that now fails closed.
                _svc?.RequestThreads();
                _svc?.RequestDisasmAt(p.Va, WindowCount, MakeTag(WinTag), Context);
            });
        }

        /// <summary>The tag sent with a request: its KIND plus the epoch that asked for it. The engine
        /// echoes the tag verbatim, so this is how a reply is matched to the state that wanted it without
        /// widening the protocol. '#' is safe in a tag — the stdin protocol is space-split, and
        /// <see cref="ClarionDebuggerService.RequestDisasmAt"/> puts the tag in its own positional slot;
        /// a tag containing a SPACE would shift `before` into the wrong argument, which is why the kind
        /// and the epoch are both space-free by construction.</summary>
        private string MakeTag(string kind) { return FormatTag(kind, _seat.Epoch); }

        /// <summary>The tag wire format, in one place so <see cref="ParseTag"/> cannot drift from it and so
        /// `protocolcheck`'s add-in counterpart can assert the round trip against the shipped code.</summary>
        private static string FormatTag(string kind, int epoch)
        {
            return kind + "#" + epoch.ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>Split a reply's tag back into kind + epoch. False when it is not one of ours at all.
        /// A tag with no '#' is an OLD-FORMAT tag (or another view's): treated as not ours, because it
        /// carries no epoch and so cannot be shown to belong to the thread on screen.</summary>
        private static bool ParseTag(string tag, out string kind, out int epoch)
        {
            kind = null; epoch = -1;
            if (string.IsNullOrEmpty(tag)) return false;
            int h = tag.IndexOf('#');
            if (h <= 0 || h == tag.Length - 1) return false;
            kind = tag.Substring(0, h);
            if (kind != WinTag && kind != FwdTag && kind != BwdTag) return false;
            return int.TryParse(tag.Substring(h + 1), NumberStyles.Integer, CultureInfo.InvariantCulture, out epoch);
        }

        /// <summary>Does a reply's stamped thread match the thread this view believes it is showing?
        ///
        /// Absent (null) is UNKNOWN, not a mismatch: an engine that does not stamp disasm leaves the epoch
        /// as the only gate, which is the correct pre-381aabd7 fallback. Treating absent as a mismatch
        /// would blank the view against an older engine — absent-means-unknown broken from the other side.
        ///
        /// A view that does not yet know its own thread (_selTid == 0) is the case that USED to fail open
        /// too, and that was wrong. A STAMPED reply arriving at such a view is not an absence of
        /// information — it is information the view would be DISCARDING in order to paint something it
        /// cannot label. That is how a late-opened window painted the stopped thread's VA, decoded for a
        /// different selected thread, with no current row and no banner. The two cases are not symmetric:
        /// an absent tid means the ENGINE said nothing, an unknown _selTid means WE have not asked yet —
        /// and the fix for not having asked is to ask, which the view now does (RequestThreads on late
        /// open and rebind), not to accept whatever turns up in the meantime.</summary>
        /// <summary>THE view's ONE uint? -> uint conversion, and the ONE definition of "unstamped".
        ///
        /// On the wire, "the engine did not say" is ABSENT, and 0 is a sentinel that must never be read as
        /// a real thread. The view keeps its own `uint` fields with a local `0 = unknown` convention, which
        /// is legitimate because it is not on the wire — but the conversion between the two has to happen
        /// in exactly one place, and it had drifted into four, of which one disagreed with the others: the
        /// seat assignment used `tid ?? _selTid`, so a stamped literal 0 became a seat of 0 and the view
        /// was then never marked painted, which is a second route into the same never-painted state the
        /// empty-reply latch produces. <see cref="TidMatches"/> had already been treating a stamped 0 as
        /// unstamped, so the two were 180 lines apart and disagreeing.
        ///
        /// This is here as a FUNCTION rather than a sentence because the sentence was already written, in
        /// the comment on OnThreads, and four authors eroded it without anyone deciding to. A claim a grep
        /// can check outlives a claim a reader has to honour.</summary>
        private static uint TidOf(uint? t) { return (t == null || t.Value == 0) ? 0u : t.Value; }

        private bool TidMatchesView(uint? tid) { return TidMatches(tid, _selTid); }

        /// <summary>The tid gate's whole rule, as a pure function of the reply's stamp and the thread the
        /// view believes it is showing — so `protocolcheck`'s add-in counterpart can assert the shipped
        /// rule rather than a restatement of it.</summary>
        private static bool TidMatches(uint? tid, uint selTid)
        {
            uint t = TidOf(tid);
            if (t == 0) return true;        // unstamped engine (absent OR a 0 sentinel): epoch is the only gate
            if (selTid == 0) return false;  // STAMPED, but we cannot say whose it is — drop
            return t == selTid;
        }

        // ----- following the pad's thread selection -----

        /// <summary>The thread inventory for this stop. It names the threads (a bare tid is useless in a
        /// banner) and reports who is stopped and who is selected — the engine's answer, not our guess.</summary>
        private void OnThreads(DebugThreadList list) => UI(() =>
        {
            if (list == null) return;
            _threads = list.Threads ?? new List<DebugThread>();
            // StoppedTid/SelectedTid are uint? (task 3b043dfc): on the WIRE and in the host's model, "the
            // engine did not say" is ABSENT, never 0. This view keeps its own uint fields with the local
            // `0 = unknown` convention documented at their declaration, and THE CONVERSION HAPPENS IN
            // TidOf AND NOWHERE ELSE — a claim a grep can check, which is why it replaced the sentence
            // that used to sit here saying the conversion happened "once, at the boundary". It said that
            // while already naming a second site in its own next clause, and by the time four authors had
            // been through this file there were four, one of which disagreed with the others.
            // Selected-else-stopped is preserved: show the selected thread if there is one, else the
            // stopped one.
            _stoppedTid = TidOf(list.StoppedTid);
            // A SelectedTid of literal 0 is a sentinel, not a selection, so it falls back to the stopped
            // thread exactly as an absent one does — which `?? 0` did not do.
            uint sel = TidOf(list.SelectedTid);
            uint nextSel = sel != 0 ? sel : _stoppedTid;
            _seat.SelectionMoving(_selTid, nextSel);
            _selTid = nextSel;
            UpdateThreadBanner();
            // THE WINDOW-OPENED-LATE CASE. A selection made before this view existed (or before it was
            // rebound) is reported here and nowhere else: without this the listing would sit on the stopped
            // thread showing no banner, while the pad's own banner says you are viewing another thread —
            // the exact mismatch this view is supposed to have stopped being capable of.
            SeatOnSelectedThread();
        });

        /// <summary>Re-seat the window on the selected thread, if it is not already there. The thread's EIP
        /// is not in the inventory, so this asks for its registers and seats on that reply; everything in
        /// flight is dropped first, because it was asked under the previous seat. The guards (already
        /// painted, already in flight, already decoded to nothing this episode) are SeatState.TryBeginSeat's.</summary>
        private void SeatOnSelectedThread()
        {
            if (_svc == null) return;
            if (_seat.TryBeginSeat(_selTid)) _svc.RequestRegs();
        }

        /// <summary>The engine's answer to a `thread N` request. <paramref name="tid"/> is the thread that
        /// was ASKED FOR and is null when the request was malformed, so a failure is never read as thread 0.
        /// On success the view re-seats on the new thread — but it does not yet know where that thread is,
        /// so it asks for its registers and seats on the reply.</summary>
        private void OnThreadSelected(uint? tid, bool ok, string error) => UI(() =>
        {
            // A refused or malformed select leaves the view exactly where it was. Re-rendering the banner
            // from unchanged state is deliberate: it must not start naming a thread the engine declined.
            uint chosen = TidOf(tid);
            if (!ok || chosen == 0) { UpdateThreadBanner(); return; }
            _seat.SelectionMoving(_selTid, chosen);   // deliberate switch: allow that thread a fresh try
            _selTid = chosen;
            UpdateThreadBanner();
            SeatOnSelectedThread();
        });

        /// <summary>Registers for a thread. Used ONLY to learn where a thread this view is currently
        /// seating is frozen — never as a reason to move the window on its own.
        ///
        /// <see cref="SeatState.AwaitRegs"/> is the "I asked for this" flag, and it is load-bearing: the pad
        /// requests registers for its own reasons (beginThreadSwitch sends one AFTER rewatch), so two
        /// regs replies arrive per thread switch. Without the flag the second, late one re-centred the
        /// listing on EIP and discarded whatever scroll position the user had moved to since.
        ///
        /// It is consumed on the FIRST matching reply (SeatState.TakeRegs), so the seat is driven once per
        /// request; the seat itself stays in flight until the LISTING lands.</summary>
        private void OnRegs(Dictionary<string, string> regs, uint? tid) => UI(() =>
        {
            if (regs == null) return;
            string eip; uint va;
            if (!regs.TryGetValue("eip", out eip) || !TryParseVa(eip, out va)) va = 0;   // 0 = no seat address
            if (!_seat.TakeRegs(TidOf(tid), va)) return;
            _svc?.RequestDisasmAt("0x" + va.ToString("X"), WindowCount, MakeTag(WinTag), Context);
        });

        /// <summary>An engine-level error ends any seat this view is waiting on.
        ///
        /// A disasm the engine cannot read emits NO disasm event — it reports on the error channel and
        /// returns — so the request that was in flight simply never lands. Releasing the latch here is what
        /// makes the "a later inventory can retry" claim true for that route as well; without it the empty
        /// reply is handled and the failed read is not, which is the same defect with a quieter cause.
        ///
        /// DELIBERATELY UNCONDITIONAL on the error text. Engine errors are not tagged, so this cannot tell
        /// a disasm failure from any other, and HOLDING the latch on a real disasm failure costs the pane
        /// for the rest of the stop.
        ///
        /// WHAT IT ACTUALLY COSTS, corrected — the first version of this comment said "one extra retry",
        /// which was optimistic. NOTHING re-requests on its own, so an unrelated error arriving mid-seat
        /// loses that seat until the next stop or selection change. That is more likely than it looks,
        /// because a declined variable edit emits on this same channel. It is still the right trade: a lost
        /// seat is recoverable by selecting the thread again, a held latch is not recoverable at all.
        ///
        /// AND IT DOES NOT RECORD A DECODE FAILURE. Recording SeatState.EmptyTid here would make the pane announce
        /// "the engine could not decode this thread's address" on the strength of an untagged error that may
        /// have been about something else entirely — the same fabricated fact the coarse-seek path was just
        /// fixed for. The pane falls back to "nothing to disassemble at this address", which is true whatever
        /// the error was. Leaving it unset also leaves the thread eligible for a retry, which is correct:
        /// unlike an empty reply, an error is no evidence that the address is undecodable.</summary>
        private void OnEngineError(string message) => UI(() =>
        {
            if (!_seat.Failed()) return;   // nothing waiting; not ours to clear
            UpdateThreadBanner();
            Invalidate();
        });

        /// <summary>Say whose execution point is on screen, in the pad's own words, and only when it is
        /// worth saying: while the view shows the thread the engine stopped on — nearly always — this is
        /// blank rather than noise. Mirrors the pad's banner so the two never word the same fact
        /// differently.</summary>
        private void UpdateThreadBanner()
        {
            if (_thread == null) return;
            string text = "";
            // DERIVED FROM THE PAINTED THREAD — never from _selTid, the one we INTEND to show. The rule is
            // SeatState.ForeignSeatedTid's, next to the only code that writes the painted thread: blank while
            // nothing is painted, or while what IS painted is not what we are now selecting.
            uint foreign = _seat.ForeignSeatedTid(_selTid, _stoppedTid);
            // The second clause says the step buttons' consequence in the one place that is always visible
            // (375d463b): pressing Step here runs the STOPPED thread and the view snaps back to it, and that
            // snap-back is only readable if it was announced.
            if (foreign != 0)
                text = "viewing " + ThreadName(foreign) + " — not the stopped thread · Step runs "
                     + ThreadName(_stoppedTid);
            _thread.Text = text;
            _thread.Visible = text.Length > 0;
            UpdateStepTips();
            UpdateRecentre();   // _selTid moves with the banner's inputs
        }

        /// <summary>Name a thread the way the pad names it: its Clarion thread number when the RTL gave one,
        /// otherwise the bare tid. Never invents a Clarion number.</summary>
        private string ThreadName(uint tid)
        {
            foreach (var t in _threads)
                if (t != null && t.Tid == tid)
                    return t.ClarionThread != null
                        ? "Thread " + t.ClarionThread.Value.ToString(CultureInfo.InvariantCulture)
                        : "tid " + tid.ToString(CultureInfo.InvariantCulture);
            return "tid " + tid.ToString(CultureInfo.InvariantCulture);
        }

        /// <summary>Two gates, answering two different questions, and a reply must pass BOTH.
        ///
        /// The EPOCH answers "is this reply still wanted?". It is the view's own bookkeeping: it knows the
        /// selection moved even when the engine would have decoded the same thread either side of the move,
        /// and it is what makes an in-flight winf/winb from before a switch droppable at all.
        ///
        /// The TID answers "whose code is this?". It is the ENGINE'S fact about what it actually read, not
        /// our model of it, and it catches what the epoch cannot: a reply decoded for a thread other than
        /// the one we believe is selected — an engine that resolved the selection differently, or a stop
        /// that moved it under us. Deriving the answer from the other side's real output rather than from
        /// our own bookkeeping is the whole reason to carry it.
        ///
        /// NEITHER OVERRIDES THE OTHER, deliberately. If they disagree, that disagreement is the signal,
        /// and the only safe reading of "one of my two independent checks says this listing is not what I
        /// think it is" is to not paint it. A precedence rule would mean choosing to believe one gate while
        /// the other says the screen would lie.
        ///
        /// An ABSENT tid (null) is not a mismatch — it means an engine that does not stamp disasm, where
        /// the epoch is all there is and the pre-381aabd7 behaviour is the correct fallback. Absent is
        /// "unknown", never "thread 0"; treating it as a mismatch would black out the view against an older
        /// engine, which is the absent-means-unknown rule broken from the other side.</summary>
        private void OnDisasm(string tag, List<DebugDisasmInstr> instrs, uint? tid)
        {
            string kind; int epoch;
            if (!ParseTag(tag, out kind, out epoch)) return;   // not ours
            // A reply from a superseded epoch: the thread selection (or the stop) moved on after it was
            // asked for. Dropping it is the whole point — it would re-seat the view on a thread the user
            // is no longer looking at and flag that thread's instruction as current.
            if (!_seat.IsCurrent(epoch)) return;
            UI(() =>
            {
                // Re-checked INSIDE the marshal: the epoch can move between the reader thread's test above
                // and this running on the UI thread, which is exactly the window a thread switch lands in.
                if (!_seat.IsCurrent(epoch)) return;
                if (!TidMatchesView(tid)) return;
                instrs = instrs ?? new List<DebugDisasmInstr>();
                var selVas = SelectedInstrVas();   // carry the copy-selection across the rebuild
                uint anchorVa = _anchorRow >= 0 && _anchorRow < _rows.Count ? InstrVaOfRow(_anchorRow) : 0;
                if (kind == WinTag)
                {
                    // THE SEAT'S BOOKKEEPING IS SETTLED FIRST, IN ONE CALL, BEFORE THE SCREEN CHANGES.
                    // SeatState.WindowLanded decides everything this reply means for the seat: whether it
                    // was a SEAT or a coarse SEEK (read before the in-flight state is released, since
                    // afterwards the two are indistinguishable), that only a reply which DECODED something
                    // paints, that an empty one UN-paints (the listing below is about to erase whatever the
                    // painted flag described), and that only an empty SEAT may claim "this thread's code
                    // could not be decoded". The reply's stamp goes in through TidOf; the tid gate above has
                    // already proved it agrees with _selTid.
                    var outcome = _seat.WindowLanded(TidOf(tid), _selTid, instrs.Count);
                    if (outcome == SeatState.WindowOutcome.EmptySeat)
                    {
                        // THE LOCATION STRIP IS A THREAD CLAIM TOO. The fields below describe the instruction
                        // that WAS current; this seat found none, and the listing is about to be erased.
                        // Leaving them let the pane say "no code to show for B" while the strip still read
                        // A's module:line with Show Source enabled â€” one click from jumping the IDE to
                        // another thread's source. Only an empty SEAT does this: after a plain seek the
                        // thread really is still stopped where the strip says. (The stop's symbol is not
                        // cleared: it is gated on read by SeatState.SymbolFor, and is still the true label
                        // for the stopped thread.)
                        _curPath = _curModule = null;
                        _curLine = 0;
                    }
                    // fresh window: replace the cache and centre on EIP (the flagged instruction)
                    _instrs = SortedUnique(instrs);
                    var cur = instrs.Find(d => d.Current);
                    _hasCur = cur != null && TryParseVa(cur.Va, out _curVa);
                    if (cur != null) { _curPath = cur.ResolvedPath; _curLine = cur.Line; _curModule = cur.Module; }
                    UpdateLocation();
                    // The banner reads the painted thread, which WindowLanded has just changed — set on a
                    // successful seat, cleared on an empty one. Re-deriving it here rather than leaving it
                    // to the next unrelated event is the other half of the fix: a correct painted thread
                    // that the banner has not re-read yet is the same defect one frame later.
                    UpdateThreadBanner();
                    Rebuild();
                    RemapSelection(selVas);
                    _anchorRow = anchorVa != 0 ? RowOfVa(anchorVa) : (_anchorRow < _rows.Count ? _anchorRow : -1);
                    int rows = VisibleRows();
                    _top = Math.Max(0, (_current < 0 ? 0 : _current) - rows / 3);
                }
                else
                {
                    // edge extension: keep the same instruction under the top of the view across the merge
                    uint anchor = TopInstrVa();
                    Merge(instrs);
                    _seat.ExtendLanded(kind == FwdTag);
                    Rebuild();
                    RemapSelection(selVas);
                    _anchorRow = anchorVa != 0 ? RowOfVa(anchorVa) : (_anchorRow < _rows.Count ? _anchorRow : -1);
                    int ai = RowOfVa(anchor);
                    if (ai >= 0) _top = ai;
                }
                SyncScroll();
                SyncCoarse();
                Invalidate();
            });
        }

        private void OnExited(int code) => UI(() =>
        {
            _instrs = new List<DebugDisasmInstr>();
            _rows.Clear();
            _labels.Clear();
            _sel.Clear(); _anchorRow = -1;
            _current = -1;
            _hasCur = false; _curVa = 0;
            _curPath = _curModule = null; _curLine = 0;
            // The process is gone, so there are no threads to be viewing and nothing in flight can be
            // answered: SeatState.Exited retires the outstanding replies, clears every seat field and the
            // stop's symbol.
            _seat.Exited();
            _stoppedTid = _selTid = 0;
            _threads = new List<DebugThread>();
            UpdateThreadBanner();
            UpdateLocation();
            Invalidate();
        });

        /// <summary>Rebuild the label set, display rows, and current-row index from the cache.</summary>
        private void Rebuild()
        {
            ComputeLabels();
            BuildRows();
            _current = _hasCur ? RowOfVa(_curVa) : -1;
        }

        /// <summary>If the view is scrolled near a cache edge, request the next batch (forward append /
        /// backward prepend). One request in flight per direction.</summary>
        private void MaybeExtend()
        {
            if (_instrs.Count == 0) return;
            if (_top <= Edge && _seat.TryBeginExtend(false))
                _svc?.RequestDisasmAt(HexVa(_instrs[0].Va), 1, MakeTag(BwdTag), Batch);
            if (_top + VisibleRows() >= _rows.Count - Edge && _seat.TryBeginExtend(true))
                _svc?.RequestDisasmAt(HexVa(_instrs[_instrs.Count - 1].Va), Batch, MakeTag(FwdTag));
        }

        /// <summary>VA of the first instruction at/below the top visible row, for keeping the view put
        /// across a merge. 0 when none.</summary>
        private uint TopInstrVa()
        {
            for (int i = Math.Max(0, _top); i < _rows.Count; i++)
            {
                if (_rows[i].IsSource) continue;
                uint v; if (TryParseVa(_rows[i].Instr.Va, out v)) return v;
            }
            return 0;
        }

        private int RowOfVa(uint va)
        {
            for (int i = 0; i < _rows.Count; i++)
            {
                if (_rows[i].IsSource) continue;
                uint v; if (TryParseVa(_rows[i].Instr.Va, out v) && v == va) return i;
            }
            return -1;
        }

        /// <summary>Merge new instructions into the cache (dedup by VA, keep sorted).</summary>
        private void Merge(List<DebugDisasmInstr> add)
        {
            var byVa = new SortedDictionary<uint, DebugDisasmInstr>();
            foreach (var d in _instrs) { uint v; if (TryParseVa(d.Va, out v)) byVa[v] = d; }
            foreach (var d in add)     { uint v; if (TryParseVa(d.Va, out v) && !byVa.ContainsKey(v)) byVa[v] = d; }
            _instrs = new List<DebugDisasmInstr>(byVa.Values);
        }

        private static List<DebugDisasmInstr> SortedUnique(List<DebugDisasmInstr> list)
        {
            var byVa = new SortedDictionary<uint, DebugDisasmInstr>();
            foreach (var d in list) { uint v; if (TryParseVa(d.Va, out v)) byVa[v] = d; }
            return new List<DebugDisasmInstr>(byVa.Values);
        }

        /// <summary>Normalise a VA string to the "0x..." form RequestDisasmAt validates.</summary>
        private static string HexVa(string va)
        {
            uint v;
            return TryParseVa(va, out v) ? "0x" + v.ToString("X") : (va ?? "");
        }

        /// <summary>Build the painted display list: above the first instruction of each module:line group,
        /// insert a source-comment row with the actual .clw text (read once per file, cached). Continuation
        /// instructions of the same statement are bare, so each statement reads as a labelled block.</summary>
        private void BuildRows()
        {
            _rows.Clear();
            var fileCache = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
            string prevKey = null;
            foreach (var d in _instrs)
            {
                // Header above the first instruction of each group: source line (.clw) when there's a
                // resolvable source line, else the containing function name (runtime/RTL code).
                string key = null, header = null;
                if (d.Line > 0 && !string.IsNullOrEmpty(d.Module))
                {
                    key = "S:" + d.Module + ":" + d.Line;
                    if (key != prevKey)
                    {
                        string text = SourceLineText(d.ResolvedPath, d.Line, fileCache);
                        string head = d.Module + ":" + d.Line;
                        header = string.IsNullOrEmpty(text) ? head : head + "   " + text;
                    }
                }
                else if (!string.IsNullOrEmpty(d.Func))
                {
                    key = "F:" + d.Func;
                    if (key != prevKey) header = d.Func;
                }
                if (header != null) _rows.Add(new Row { IsSource = true, Source = header });
                prevKey = key;
                _rows.Add(new Row { Instr = d });
            }
        }

        /// <summary>Trimmed text of a 1-based source line from a resolved .clw, or null if unavailable.
        /// Files are cached (path → lines) for the duration of one build.</summary>
        private static string SourceLineText(string path, int line, Dictionary<string, string[]> cache)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || line < 1) return null;
                string[] lines;
                if (!cache.TryGetValue(path, out lines))
                {
                    lines = File.Exists(path) ? File.ReadAllLines(path) : null;
                    cache[path] = lines;
                }
                if (lines == null || line > lines.Length) return null;
                return lines[line - 1].Trim();
            }
            catch { return null; }
        }

        /// <summary>Collect the set of in-window VAs that are the target of a branch/call, so they can be
        /// painted as labels. Targets are parsed from the operand text (e.g. "jne short 007B0871h").</summary>
        private void ComputeLabels()
        {
            _labels.Clear();
            foreach (var d in _instrs)
            {
                if (string.IsNullOrEmpty(d.Text)) continue;
                string mn = Mnemonic(d.Text);
                if (!IsFlow(mn)) continue;
                uint tgt;
                if (TryParseTrailingHex(d.Text, out tgt)) _labels.Add(tgt);
            }
        }

        // ----- scrolling -----

        private int TopOffset() => _bar.Height;   // toolbar reserves the top strip
        private int VisibleRows() => Math.Max(1, (Height - TopOffset()) / Math.Max(1, _rowH));

        private void SyncScroll()
        {
            int rows = VisibleRows();
            _scroll.Minimum = 0;
            _scroll.Maximum = Math.Max(0, _rows.Count - 1);
            _scroll.LargeChange = Math.Max(1, rows);
            _top = Math.Min(_top, Math.Max(0, _rows.Count - 1));
            _scroll.Value = Math.Min(_scroll.Maximum, Math.Max(_scroll.Minimum, _top));
        }

        protected override void OnResize(EventArgs e) { base.OnResize(e); SyncScroll(); Invalidate(); }

        protected override void OnMouseWheel(MouseEventArgs e)
        {
            int delta = -Math.Sign(e.Delta) * 3;
            _top = Math.Max(0, Math.Min(Math.Max(0, _rows.Count - 1), _top + delta));
            MaybeExtend();
            SyncScroll();
            SyncCoarse();
            Invalidate();
        }

        // ----- selection + copy -----

        private int RowAt(int y)
        {
            int top = TopOffset();
            if (y < top) return -1;
            int idx = _top + (y - top) / Math.Max(1, _rowH);
            return idx >= 0 && idx < _rows.Count ? idx : -1;
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            Focus();
            int row = RowAt(e.Y);
            if (row < 0) return;

            if (e.Button == MouseButtons.Right)
            {
                if (!_sel.Contains(row)) { _sel.Clear(); _sel.Add(row); _anchorRow = row; }
            }
            else if ((ModifierKeys & Keys.Shift) != 0 && _anchorRow >= 0 && _anchorRow < _rows.Count)
            {
                _sel.Clear();
                for (int i = Math.Min(_anchorRow, row); i <= Math.Max(_anchorRow, row); i++) _sel.Add(i);
            }
            else if ((ModifierKeys & Keys.Control) != 0)
            {
                if (!_sel.Remove(row)) _sel.Add(row);
                _anchorRow = row;
            }
            else
            {
                _sel.Clear(); _sel.Add(row); _anchorRow = row;
            }
            Invalidate();
        }

        protected override bool IsInputKey(Keys keyData)
        {
            if (keyData == (Keys.Control | Keys.C)) return true;   // claim Ctrl+C so it reaches OnKeyDown
            return base.IsInputKey(keyData);
        }

        /// <summary>Alt+* — Visual Studio's "Show Next Statement" — recentres on the current instruction.
        /// Taken here rather than in OnKeyDown because an Alt chord arrives as a system key, which the
        /// command-key pass sees first.</summary>
        protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
        {
            if (keyData == (Keys.Alt | Keys.Multiply)) { Recentre(); return true; }
            return base.ProcessCmdKey(ref msg, keyData);
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);
            if (e.Control && e.KeyCode == Keys.C) { CopySelection(); e.Handled = true; }
        }

        private void CopySelection()
        {
            if (_sel.Count == 0) return;
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < _rows.Count; i++)
                if (_sel.Contains(i)) sb.AppendLine(RowText(_rows[i]));
            try { if (sb.Length > 0) Clipboard.SetText(sb.ToString()); } catch { }
        }

        /// <summary>Plain-text form of a row for the clipboard, aligned into columns
        /// (addr | mnemonic+operands | -> target | bytes) so a multi-line copy stays readable.</summary>
        private static string RowText(Row row)
        {
            if (row.IsSource) return "; " + row.Source;
            var d = row.Instr;
            uint va; string addr = TryParseVa(d.Va, out va) ? va.ToString("X8") : (d.Va ?? "").Replace("0x", "");
            string target = string.IsNullOrEmpty(d.Target) ? "" : "-> " + d.Target;
            string bytes  = string.IsNullOrEmpty(d.Bytes) ? "" : SpaceBytes(d.Bytes);
            string s = (addr + ":").PadRight(10) + (d.Text ?? "");
            s = PadCol(s, 40);              // mnemonic+operands column
            if (target.Length > 0) s += target;
            s = PadCol(s, 72);             // call-target column; bytes start here
            return (s + bytes).TrimEnd();
        }

        /// <summary>Pad to a column, but if already at/past it, still leave a 2-space gap so a long
        /// field never butts straight into the next column.</summary>
        private static string PadCol(string s, int col) => s.Length >= col ? s + "  " : s.PadRight(col);

        private uint InstrVaOfRow(int row)
        {
            if (row < 0 || row >= _rows.Count || _rows[row].IsSource) return 0;
            uint v; return TryParseVa(_rows[row].Instr.Va, out v) ? v : 0;
        }

        /// <summary>Selected instruction VAs — used to carry the selection across a cache rebuild.</summary>
        private HashSet<uint> SelectedInstrVas()
        {
            var s = new HashSet<uint>();
            foreach (int i in _sel)
                if (i >= 0 && i < _rows.Count && !_rows[i].IsSource)
                { uint v; if (TryParseVa(_rows[i].Instr.Va, out v)) s.Add(v); }
            return s;
        }

        private void RemapSelection(HashSet<uint> vas)
        {
            _sel.Clear();
            if (vas.Count == 0) return;
            for (int i = 0; i < _rows.Count; i++)
                if (!_rows[i].IsSource) { uint v; if (TryParseVa(_rows[i].Instr.Va, out v) && vas.Contains(v)) _sel.Add(i); }
        }

        // ----- coarse address scrollbar (left) — fast seek across loaded memory -----

        private void OnCoarseScroll(object sender, ScrollEventArgs e)
        {
            uint lo = Lo(), hi = Hi();
            if (hi <= lo) return;
            uint va = (uint)(lo + (long)((double)e.NewValue / CoarseMax * (hi - lo)));
            // A SEEK IS A RESEAT, and it must retire what was in flight: clearing the extension FLAGS does
            // not recall the requests already sent, and an edge extension asked for at the old window's last
            // VA would pass BOTH gates and reach Merge — a sorted union with no contiguity test — gluing two
            // regions megabytes apart. SeatState.Seek also retires any "no code to show for Thread B" claim
            // NOW rather than when the reply lands, since from this moment the pane is an address seek.
            //
            // THE SEEK DELIBERATELY WINS OVER A PENDING SEAT (the PM's ruling on 876ddf1d): retiring the
            // replies abandons an in-flight thread-switch seat, and nothing re-asserts it — that would yank
            // the view away from where the user just scrolled. Do not "fix" this by re-seating after the
            // seek; the way back to the current instruction is the explicit Recentre action (Alt+*).
            _seat.Seek();
            _svc?.RequestDisasmAt("0x" + va.ToString("X"), WindowCount, MakeTag(WinTag));   // reseat the window there
        }

        /// <summary>Move the coarse thumb to reflect the top visible address (programmatic — does not
        /// re-trigger a seek, which only fires on the user's Scroll event).</summary>
        private void SyncCoarse()
        {
            uint lo = Lo(), hi = Hi();
            if (hi <= lo) return;
            uint top = TopInstrVa();
            if (top == 0) return;
            long rel = Math.Max(0, Math.Min((long)hi - lo, (long)top - lo));
            int v = (int)((double)rel / (hi - lo) * CoarseMax);
            _coarse.Value = Math.Max(_coarse.Minimum, Math.Min(CoarseMax, v));
        }

        private uint Lo()
        {
            if (_svc != null && _svc.MemLo != 0) return _svc.MemLo;
            uint v; return _instrs.Count > 0 && TryParseVa(_instrs[0].Va, out v) ? v : 0;
        }

        private uint Hi()
        {
            if (_svc != null && _svc.MemHi != 0) return _svc.MemHi;
            uint v; return _instrs.Count > 0 && TryParseVa(_instrs[_instrs.Count - 1].Va, out v) ? v + 0x1000 : 0;
        }

        // ----- paint -----

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.Clear(Bg);
            _rowH = _font.Height + 3;
            _charW = TextRenderer.MeasureText(g, "0", _font, Size.Empty, TextFormatFlags.NoPadding).Width;

            if (_rows.Count == 0)
            {
                // THREE DIFFERENT EMPTIES, AND EACH SAYS ONLY WHAT IT CAN SUPPORT. They were one message,
                // which asserted "no session" while often meaning something else entirely. Same
                // absent-versus-sentinel discipline the wire has, applied to the surface — and the same
                // rule that stops SeatState.EmptyTid being set by a coarse seek: a message is a claim, and
                // a claim needs the state that justifies it.
                //   1. a SEAT came back empty — the engine could not decode THAT THREAD's address. Only
                //      set when wasSeat, so this never speaks for a seek.
                //   2. we have a paused session and nothing is on screen — true after a seek into unmapped
                //      memory, and after an engine error abandoned a seat. It claims nothing about why.
                //   3. no session at all.
                string msg = _seat.EmptyTid != 0
                    ? "(no code to show for " + ThreadName(_seat.EmptyTid)
                      + " — the engine could not decode its current address)"
                    : (_svc != null && _svc.State == DebugSessionState.Paused)
                      ? "(nothing to disassemble at this address)"
                      : "(no disassembly — start a debug session and pause)";
                TextRenderer.DrawText(g, msg,
                    _font, new Point(_coarse.Width + 8, TopOffset() + 8), FgHint, TextFormatFlags.NoPadding);
                return;
            }

            const TextFormatFlags ff = TextFormatFlags.NoPadding | TextFormatFlags.NoPrefix;
            int leftEdge  = _coarse.Width;
            int rightEdge = Width - _scroll.Width;
            int xAddr  = leftEdge + 8;
            int xMnem  = xAddr + 10 * _charW;         // after "009810F2: "
            int xOper  = xMnem + 7 * _charW;          // after the mnemonic
            int xTarget= xMnem + 30 * _charW;         // call-target name column
            int bytesW = 17 * _charW;                 // raw bytes, right-aligned
            int xBytes = rightEdge - bytesW;
            int xSep   = xBytes - 8;                  // separator line before the bytes column

            int y0 = TopOffset();
            using (var sep = new Pen(SepLine)) g.DrawLine(sep, xSep, y0, xSep, Height);

            int rows = VisibleRows();
            for (int r = 0; r <= rows; r++)
            {
                int i = _top + r;
                if (i < 0 || i >= _rows.Count) break;
                var row = _rows[i];
                int y = y0 + r * _rowH;
                bool selected = _sel.Contains(i);

                if (selected)
                    using (var b = new SolidBrush(SelBg)) g.FillRectangle(b, leftEdge, y, rightEdge - leftEdge, _rowH);

                if (row.IsSource)
                {
                    // interleaved .clw source line — full-width comment above the statement's instructions
                    TextRenderer.DrawText(g, "; " + row.Source, _font, new Point(xAddr, y), FgSource, ff);
                    continue;
                }

                var d = row.Instr;
                bool cur = i == _current;
                uint va; bool haveVa = TryParseVa(d.Va, out va);
                bool isLabel = haveVa && _labels.Contains(va);

                if (cur)
                {
                    if (!selected) using (var b = new SolidBrush(CurBg)) g.FillRectangle(b, leftEdge, y, rightEdge - leftEdge, _rowH);
                    using (var b = new SolidBrush(CurBar)) g.FillRectangle(b, leftEdge, y, 3, _rowH);
                }

                // address (8-hex, ":"); branch targets render as bold blue labels
                string addr = haveVa ? va.ToString("X8") : (d.Va ?? "").Replace("0x", "");
                TextRenderer.DrawText(g, addr + ":", isLabel ? _fontBold : _font, new Point(xAddr, y),
                    isLabel ? FgLabel : FgAddr, ff);

                // mnemonic + operands (split on the first space); control-flow mnemonics get an accent
                string text = d.Text ?? "";
                string mn = Mnemonic(text);
                string oper = mn.Length < text.Length ? text.Substring(mn.Length).TrimStart() : "";
                TextRenderer.DrawText(g, mn, _font, new Point(xMnem, y), IsFlow(mn) ? FgFlow : FgMnem, ff);
                if (oper.Length > 0)
                    TextRenderer.DrawText(g, oper, _font, new Point(xOper, y), cur ? Color.White : FgOper, ff);

                if (!string.IsNullOrEmpty(d.Target))
                    TextRenderer.DrawText(g, "→ " + d.Target, _font, new Point(xTarget, y), FgTarget, ff);
                if (!string.IsNullOrEmpty(d.Bytes))
                    TextRenderer.DrawText(g, SpaceBytes(d.Bytes), _font, new Point(xBytes, y), FgBytes, ff);
            }
        }

        // ----- text helpers -----

        /// <summary>The mnemonic = the first whitespace-delimited token of the instruction text.</summary>
        private static string Mnemonic(string text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            int sp = text.IndexOf(' ');
            return sp < 0 ? text : text.Substring(0, sp);
        }

        /// <summary>Control-flow mnemonic (call / jmp / jcc / loop / ret) — gets the accent colour and
        /// contributes its target to the label set.</summary>
        private static bool IsFlow(string mn)
        {
            if (string.IsNullOrEmpty(mn)) return false;
            if (mn == "call" || mn == "ret" || mn == "retn" || mn == "jmp" || mn == "loop"
                || mn == "loope" || mn == "loopne") return true;
            return mn[0] == 'j';   // je/jne/jg/jl/jbe/jae/...
        }

        /// <summary>Parse a "0x7B0A2C" / "7B0A2C" VA into a u32. False on garbage.</summary>
        private static bool TryParseVa(string va, out uint result)
        {
            result = 0;
            if (string.IsNullOrEmpty(va)) return false;
            string s = va.Trim();
            if (s.StartsWith("0x") || s.StartsWith("0X")) s = s.Substring(2);
            return uint.TryParse(s, System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture, out result);
        }

        /// <summary>Pull the branch target VA out of an operand text like "jne short 007B0871h" or
        /// "jmp 0x7B08DD" — the trailing hex token (optional 'h' suffix). False when none.</summary>
        private static bool TryParseTrailingHex(string text, out uint result)
        {
            result = 0;
            if (string.IsNullOrEmpty(text)) return false;
            int end = text.Length;
            if (text[end - 1] == 'h' || text[end - 1] == 'H') end--;     // NASM trailing 'h'
            int start = end;
            while (start > 0 && Uri.IsHexDigit(text[start - 1])) start--;
            if (end - start < 4) return false;                            // too short to be an address
            return uint.TryParse(text.Substring(start, end - start), System.Globalization.NumberStyles.HexNumber,
                System.Globalization.CultureInfo.InvariantCulture, out result);
        }

        /// <summary>Group raw byte hex into space-separated pairs (C645AF00 -> "C6 45 AF 00").</summary>
        private static string SpaceBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return "";
            var sb = new System.Text.StringBuilder(hex.Length + hex.Length / 2);
            for (int i = 0; i < hex.Length; i += 2)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(hex, i, Math.Min(2, hex.Length - i));
            }
            return sb.ToString();
        }

        // ----- helpers -----

        private void UI(Action a)
        {
            if (IsDisposed || !IsHandleCreated) return;
            if (InvokeRequired) { try { BeginInvoke(a); } catch { } }
            else a();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                ClarionDebuggerService.ActiveChanged -= OnActiveChanged;
                Unbind();
                _font.Dispose();
                _fontBold.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
