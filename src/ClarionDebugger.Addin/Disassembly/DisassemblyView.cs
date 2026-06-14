using System;
using System.Collections.Generic;
using System.Drawing;
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
        private ToolStripButton _bContinue, _bOver, _bInto, _bOut, _bStop, _bSrc;
        private ToolStripLabel _loc;
        private string _curPath, _curModule, _curSym;   // source location of the current instruction
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
        private bool _pendFwd, _pendBwd;   // an edge extension is in flight (avoid duplicate requests)
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
            if (_svc != null)
            {
                _svc.Paused += OnPaused;
                _svc.DisasmReceived += OnDisasm;
                _svc.Exited += OnExited;
                _svc.StateChanged += OnState;
            }
            UpdateButtons(_svc?.State ?? DebugSessionState.Idle);
        }

        private void Unbind()
        {
            if (_svc == null) return;
            _svc.Paused -= OnPaused;
            _svc.DisasmReceived -= OnDisasm;
            _svc.Exited -= OnExited;
            _svc.StateChanged -= OnState;
            _svc = null;
        }

        /// <summary>A pad started a new session (Active flipped). Rebind to it; if it is already paused,
        /// pull a window at the live EIP. Fires on the StartSession caller (the UI thread) — marshal anyway.</summary>
        private void OnActiveChanged()
        {
            if (InvokeRequired) { try { BeginInvoke((Action)OnActiveChanged); } catch { } return; }
            Unbind();
            Bind(ClarionDebuggerService.Active);
            if (_svc != null && _svc.State == DebugSessionState.Paused && !string.IsNullOrEmpty(_svc.CurrentVa))
                _svc.RequestDisasmAt(_svc.CurrentVa, WindowCount, WinTag, Context);
        }

        // ----- stepping toolbar -----

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
            _bOver  = AddButton("⤼ Over",  "Step over one instruction (run calls to completion)", () => _svc?.StepInstrOver());
            _bInto  = AddButton("⤷ Into",  "Step one machine instruction (into calls)",           () => _svc?.StepInstr());
            _bOut   = AddButton("⤴ Out",   "Step out of the procedure (source level)",            () => _svc?.StepOut());
            _bar.Items.Add(new ToolStripSeparator());
            _bSrc   = AddButton("◧ Source", "Open the .clw source at the current line", ShowSource);
            _bar.Items.Add(new ToolStripSeparator());
            _bStop  = AddButton("■ Stop",  "Terminate the debug session", () => _svc?.Stop());
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
                _loc.Text = _curLine > 0 && !string.IsNullOrEmpty(_curModule) ? _curModule + ":" + _curLine
                          : !string.IsNullOrEmpty(_curSym) ? _curSym
                          : "";
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
            UpdateLocation();
        }

        // ----- engine session (events arrive on the reader thread → marshal to the UI thread) -----

        protected override void OnHandleCreated(EventArgs e)
        {
            base.OnHandleCreated(e);
            // Opened (or reopened) mid-session while already paused — fetch at the live EIP now instead
            // of waiting for the next step.
            if (_svc != null && _svc.State == DebugSessionState.Paused && !string.IsNullOrEmpty(_svc.CurrentVa))
                _svc.RequestDisasmAt(_svc.CurrentVa, WindowCount, WinTag, Context);
        }

        private void OnPaused(DebugPause p)
        {
            if (string.IsNullOrEmpty(p.Va)) return;
            UI(() =>
            {
                _curSym = p.Sym;   // runtime location for non-TSWD stops (TSWD line comes from the disasm)
                _svc?.RequestDisasmAt(p.Va, WindowCount, WinTag, Context);
            });
        }

        private void OnDisasm(string tag, List<DebugDisasmInstr> instrs)
        {
            if (tag != WinTag && tag != FwdTag && tag != BwdTag) return;   // not ours
            UI(() =>
            {
                instrs = instrs ?? new List<DebugDisasmInstr>();
                var selVas = SelectedInstrVas();   // carry the copy-selection across the rebuild
                uint anchorVa = _anchorRow >= 0 && _anchorRow < _rows.Count ? InstrVaOfRow(_anchorRow) : 0;
                if (tag == WinTag)
                {
                    // fresh window: replace the cache and centre on EIP (the flagged instruction)
                    _instrs = SortedUnique(instrs);
                    _pendFwd = _pendBwd = false;
                    var cur = instrs.Find(d => d.Current);
                    _hasCur = cur != null && TryParseVa(cur.Va, out _curVa);
                    if (cur != null) { _curPath = cur.ResolvedPath; _curLine = cur.Line; _curModule = cur.Module; }
                    UpdateLocation();
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
                    if (tag == FwdTag) _pendFwd = false; else _pendBwd = false;
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
            _pendFwd = _pendBwd = false;
            _curPath = _curModule = _curSym = null; _curLine = 0;
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
            if (!_pendBwd && _top <= Edge)
            {
                _pendBwd = true;
                _svc?.RequestDisasmAt(HexVa(_instrs[0].Va), 1, BwdTag, Batch);
            }
            if (!_pendFwd && _top + VisibleRows() >= _rows.Count - Edge)
            {
                _pendFwd = true;
                _svc?.RequestDisasmAt(HexVa(_instrs[_instrs.Count - 1].Va), Batch, FwdTag);
            }
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
            _svc?.RequestDisasmAt("0x" + va.ToString("X"), WindowCount, WinTag);   // reseat the window there
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
                TextRenderer.DrawText(g, "(no disassembly — start a debug session and pause)",
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
