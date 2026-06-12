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
    public sealed class ClarionDebuggerWebView : UserControl
    {
        private WebView2 _webView;
        private bool _ready, _initializing;

        private readonly ClarionDebuggerService _svc = new ClarionDebuggerService();
        private readonly EditorBreakpointService _gutter = new EditorBreakpointService();
        private readonly List<DebugBreakpoint> _pending = new List<DebugBreakpoint>(); // breakpoints while idle
        private readonly HashSet<string> _watched = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        private string _exe = "";
        private bool _exeAuto; // _exe came from auto-resolve (re-resolvable); a manual choice clears this

        public ClarionDebuggerWebView()
        {
            BackColor = Color.FromArgb(30, 30, 30);
            Dock = DockStyle.Fill;
            _webView = new WebView2 { Dock = DockStyle.Fill };
            Controls.Add(_webView);

            _svc.StateChanged += s => UI(() => Post("{\"type\":\"runstate\",\"state\":\"" + StateName(s) + "\"}"));
            _svc.Paused += OnPaused;
            _svc.Resumed += mode => UI(() => { Post("{\"type\":\"resumed\",\"mode\":" + Str(mode) + "}"); Console("info", "resumed (" + mode + ")"); });
            _svc.HitReceived += hit => UI(() => Console("hit", "*** HIT  " + (hit.Resolved ? hit.Module + " line " + hit.Line : hit.Va)));
            _svc.StackReceived += frames => UI(() => OnStack(frames));
            _svc.WatchReceived += w => UI(() => OnWatch(w));
            _svc.BreakpointSet += bp => UI(() => SendBps());
            _svc.BreakpointRemoved += (m, l) => UI(() => SendBps());
            _svc.BreakpointListReceived += list => UI(() => SendBps());
            _svc.BreakpointError += (m, l, err) => UI(() => Console("err", "breakpoint " + m + ":" + l + " — " + err));
            _svc.EngineError += msg => UI(() => Console("err", "engine: " + msg));
            _svc.LogReceived += s => UI(() => Console("info", s));
            _svc.Exited += code => UI(() => { ClearCurrentLineMarker(); Console("info", "— session ended (exit " + code + ") —"); Post("{\"type\":\"clear\"}"); });

            _gutter.GutterBreakpointAdded += (m, l, f) => UI(() => OnGutterBpAdded(m, l));
            _gutter.GutterBreakpointRemoved += (m, l, f) => UI(() => OnGutterBpRemoved(m, l));

            HandleCreated += OnHandleCreated;
        }

        private async void OnHandleCreated(object sender, EventArgs e)
        {
            if (_initializing || _ready) return;
            _initializing = true;
            try
            {
                var env = await WebView2EnvironmentCache.GetEnvironmentAsync();
                await _webView.EnsureCoreWebView2Async(env);
                var st = _webView.CoreWebView2.Settings;
                st.IsScriptEnabled = true;
                st.AreDefaultContextMenusEnabled = false;
                st.IsStatusBarEnabled = false;
                _webView.CoreWebView2.WebMessageReceived += OnWebMessage;
                _webView.CoreWebView2.NavigationCompleted += (s, ev) => { _ready = true; _initializing = false; };

                string html = GetHtmlPath();
                if (File.Exists(html))
                    _webView.CoreWebView2.Navigate(new Uri(html).AbsoluteUri + "?theme=dark");
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] init: " + ex.Message); }
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
                string json = e.TryGetWebMessageAsString();
                string action = JsonVal(json, "action");
                string data = JsonVal(json, "data");
                switch (action)
                {
                    case "ready": Post("{\"type\":\"runstate\",\"state\":\"idle\"}"); if (string.IsNullOrEmpty(_exe)) TryAutoResolveExe(); if (!string.IsNullOrEmpty(_exe)) Post("{\"type\":\"exe\",\"path\":" + Str(_exe) + "}"); break;
                    case "start": StartSession(); break;
                    case "continue": _svc.Continue(); break;
                    case "pause": _svc.Pause(); break;
                    case "stepover": _svc.StepOver(); break;
                    case "stepinto": _svc.StepInto(); break;
                    case "stepout": _svc.StepOut(); break;
                    case "stop": ClearCurrentLineMarker(); _svc.Stop(); break;
                    case "browse": Browse(); break;
                    case "setExe": _exe = data ?? ""; _exeAuto = false; break;
                    case "watch":
                        if (!string.IsNullOrEmpty(data)) { _watched.Add(data); if (_svc.State == DebugSessionState.Paused) _svc.Watch(data); }
                        break;
                    case "unwatch": if (!string.IsNullOrEmpty(data)) _watched.Remove(data); break;
                    case "jump": Jump(data); break;
                }
            }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] msg: " + ex.Message); }
        }

        private void StartSession()
        {
            try
            {
                // Auto-detected target: re-confirm against the current IDE solution at launch (the user may have
                // switched solutions since 'ready'), and also try to resolve when the field is still blank (the pad
                // may have opened before a solution loaded). Best-effort; never throw.
                if (_exeAuto || string.IsNullOrEmpty(_exe))
                {
                    try
                    {
                        string fresh = ProjectTargetService.ResolveTargetExe();
                        if (!string.IsNullOrEmpty(fresh))
                        {
                            if (!string.Equals(fresh, _exe, StringComparison.OrdinalIgnoreCase))
                            {
                                _exe = fresh;
                                _exeAuto = true;
                                Post("{\"type\":\"exe\",\"path\":" + Str(_exe) + "}");
                                Console("info", "target updated to: " + Path.GetFileName(_exe));
                            }
                        }
                        else if (_exeAuto)
                        {
                            // Could not confirm the auto-detected target for the CURRENT solution — refuse to launch a
                            // possibly-stale EXE. Keep _exe (don't wipe) so a transient resolve failure can retry on the
                            // next Start; the user can also Browse to choose explicitly.
                            Console("err", "Auto-detected target could no longer be confirmed for the current solution — press Start again or Browse to choose a Target EXE.");
                            return;
                        }
                    }
                    catch { }
                }
                if (string.IsNullOrEmpty(_exe) || !File.Exists(_exe)) { Console("err", "Pick a valid Target EXE first."); return; }
                // merge gutter (red-dot) breakpoints set before launch
                foreach (var gb in _gutter.Snapshot())
                {
                    bool known = false;
                    foreach (var b in _pending) if (SameBp(b, gb.Module, gb.RequestedLine)) { known = true; break; }
                    if (!known) _pending.Add(gb);
                }
                Post("{\"type\":\"clear\"}");
                Console("info", "starting: " + Path.GetFileName(_exe) + "  (" + _pending.Count + " breakpoint(s))");
                _svc.StartSession(_exe, _pending.ToArray());

                // load static data symbols (file buffers) for the Variables tree, off the UI thread
                string exe = _exe;
                System.Threading.ThreadPool.QueueUserWorkItem(_ =>
                {
                    string g = ClarionDebuggerService.GetGlobalsJson(exe);
                    if (!string.IsNullOrEmpty(g))
                        UI(() => Post(g.Replace("\"event\":\"globals\"", "\"type\":\"globals\"")));
                });
            }
            catch (Exception ex) { Console("err", "start failed: " + ex.Message); }
        }

        /// <summary>
        /// Auto-fill _exe from the IDE's active project when the field is still blank. Best-effort:
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
                    Console("info", "auto-detected target: " + Path.GetFileName(_exe));
                }
            }
            catch { }
        }

        private void Browse()
        {
            using (var dlg = new OpenFileDialog { Filter = "Clarion executables (*.exe)|*.exe|All files (*.*)|*.*" })
            {
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    _exe = dlg.FileName;
                    _exeAuto = false; // a manual pick is authoritative — don't re-resolve over it
                    Post("{\"type\":\"exe\",\"path\":" + Str(_exe) + "}");
                }
            }
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
            for (int i = 0; i < list.Count; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append("{\"module\":").Append(Str(list[i].Module))
                  .Append(",\"line\":").Append(list[i].Line)
                  .Append(",\"requested\":").Append(list[i].RequestedLine).Append('}');
            }
            sb.Append("]}");
            Post(sb.ToString());
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
            // reuse the service's resolver indirectly via a one-shot pause path is not available here;
            // fall back to scanning next to the EXE (generated source often sits there or via .red).
            try
            {
                if (string.IsNullOrEmpty(module) || module != Path.GetFileName(module)) return null;
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
                try { ClearCurrentLineMarker(); } catch { }
                try { _svc.Stop(); } catch { }
                try { _gutter.Dispose(); } catch { }
                if (_webView != null) { try { _webView.Dispose(); } catch { } _webView = null; }
            }
            base.Dispose(disposing);
        }
    }
}
