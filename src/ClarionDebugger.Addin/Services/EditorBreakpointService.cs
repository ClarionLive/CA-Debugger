using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using ICSharpCode.SharpDevelop.Debugging;
using ICSharpCode.TextEditor;
using ICSharpCode.TextEditor.Document;

namespace ClarionDebugger.Services
{
    /// <summary>
    /// Bridges the IDE's native breakpoint bookmarks (the editor gutter's red dots) to the CA
    /// Debugger. Listens to DebuggerService.BreakPointAdded/Removed, maps each bookmark's file to a
    /// TSWD module name (a generated-source file name IS the module name, e.g. clbrws011.clw), and
    /// raises typed add/remove notifications the pad forwards to the engine. Also provides
    /// ToggleAtCaret() so a toolbar button (or shortcut) can toggle the bookmark on the active
    /// editor line — a guaranteed creation path even where icon-bar clicks aren't wired.
    ///
    /// Deliberately does NOT register as DebuggerService.CurrentDebugger: the descriptor list is
    /// AddInTree-driven and replacing it risks breaking the native Debug button. Bookmarks are
    /// IDE-level and work without owning the debugger contract.
    /// </summary>
    public sealed class EditorBreakpointService : IDisposable
    {
        /// <summary>module, 1-based source line, full file path</summary>
        public event Action<string, int, string> GutterBreakpointAdded;
        public event Action<string, int, string> GutterBreakpointRemoved;

        private readonly EventHandler<BreakpointBookmarkEventArgs> _onAdded;
        private readonly EventHandler<BreakpointBookmarkEventArgs> _onRemoved;
        private bool _disposed;

        public EditorBreakpointService()
        {
            _onAdded = (s, e) => Raise(GutterBreakpointAdded, e.BreakpointBookmark);
            _onRemoved = (s, e) => Raise(GutterBreakpointRemoved, e.BreakpointBookmark);
            DebuggerService.BreakPointAdded += _onAdded;
            DebuggerService.BreakPointRemoved += _onRemoved;
        }

        public void Dispose()
        {
            if (_disposed) return;
            _disposed = true;
            try
            {
                DebuggerService.BreakPointAdded -= _onAdded;
                DebuggerService.BreakPointRemoved -= _onRemoved;
            }
            catch { }
        }

        private static void Raise(Action<string, int, string> evt, BreakpointBookmark bb)
        {
            if (evt == null || bb == null) return;
            string module;
            int line;
            if (TryMap(bb, out module, out line))
                evt(module, line, bb.FileName);
        }

        /// <summary>Map a bookmark to (module, 1-based line). Only .clw files are mappable.</summary>
        private static bool TryMap(BreakpointBookmark bb, out string module, out int line)
        {
            module = null; line = 0;
            try
            {
                string file = bb.FileName;
                if (string.IsNullOrEmpty(file)) return false;
                if (!file.EndsWith(".clw", StringComparison.OrdinalIgnoreCase)) return false;
                module = Path.GetFileName(file);
                // ICSharpCode bookmarks anchor on 0-based lines; the TSWD line table is 1-based.
                line = bb.LineNumber + 1;
                return line > 0;
            }
            catch { return false; }
        }

        /// <summary>All current IDE breakpoint bookmarks mapped to (module, line, file).</summary>
        public List<DebugBreakpoint> Snapshot()
        {
            var list = new List<DebugBreakpoint>();
            try
            {
                foreach (var bb in DebuggerService.Breakpoints)
                {
                    string module; int line;
                    if (TryMap(bb, out module, out line))
                        list.Add(new DebugBreakpoint { Module = module, RequestedLine = line, Line = line, Path = bb.FileName });
                }
            }
            catch { }
            return list;
        }

        /// <summary>
        /// Toggle a breakpoint bookmark on the active editor's caret line. Returns a short status
        /// string for the pad log, or null on success.
        /// </summary>
        public string ToggleAtCaret()
        {
            try
            {
                TextArea ta = GetActiveTextArea();
                if (ta == null) return "no active text editor";
                string file = null;
                try { file = ta.MotherTextEditorControl != null ? ta.MotherTextEditorControl.FileName : null; } catch { }
                if (string.IsNullOrEmpty(file)) file = ActiveDocumentPathFallback();
                if (string.IsNullOrEmpty(file)) return "could not determine the active file's path";
                if (!file.EndsWith(".clw", StringComparison.OrdinalIgnoreCase))
                    return "active file is not a .clw module (" + Path.GetFileName(file) + ")";

                int caretLine = ta.Caret.Line; // 0-based, matching ToggleBreakpointAt
                DebuggerService.ToggleBreakpointAt(ta.Document, file, caretLine);
                return null;
            }
            catch (Exception ex)
            {
                return "toggle failed: " + ex.Message;
            }
        }

        /// <summary>
        /// Remove the IDE gutter breakpoint bookmark matching (module, 1-based line). Removing the
        /// bookmark fires DebuggerService.BreakPointRemoved, which the pad already forwards to the
        /// engine/pending list — so the gutter red dot, the engine, and the pane all stay in sync.
        /// Returns true if a matching bookmark was found and removed.
        /// </summary>
        public bool RemoveByModuleLine(string module, int line)
        {
            return RemoveByModuleLine(module, line, null);
        }

        /// <summary>
        /// Remove the IDE gutter breakpoint bookmark matching (module, 1-based line), preferring the one
        /// in <paramref name="filePath"/> when the caller knows which file it means.
        /// <para>
        /// A module is a BARE .clw BASENAME. In a multi-DLL app two loaded DLLs can each hold a
        /// <c>clbrws011.clw</c> bookmarked at the same line, and this used to clear whichever of them
        /// <c>DebuggerService.Breakpoints</c> happened to enumerate first — so the pane's "x" on one
        /// breakpoint took the OTHER file's red dot away (task e80072f1).
        /// </para>
        /// <para>
        /// The order below is deliberate, and each step is the best answer available at that step:
        /// an exact file match when the caller named a file; otherwise the single match when there is
        /// only one, which cannot be the wrong one; and otherwise NOTHING, because several bookmarks
        /// claim (module, line) and picking one is a coin toss whose losing side silently clears a dot
        /// the user still wants. Returning false there hands the caller its existing fallback, which
        /// keeps the pane and the engine consistent without touching the gutter.
        /// </para>
        /// </summary>
        public bool RemoveByModuleLine(string module, int line, string filePath)
        {
            try
            {
                var matches = new List<BreakpointBookmark>();
                foreach (var bb in DebuggerService.Breakpoints)
                {
                    string m; int l;
                    if (TryMap(bb, out m, out l)
                        && string.Equals(m, module, StringComparison.OrdinalIgnoreCase) && l == line)
                        matches.Add(bb);
                }

                BreakpointBookmark target = null;
                if (!string.IsNullOrEmpty(filePath))
                    foreach (var bb in matches)
                        if (string.Equals(bb.FileName, filePath, StringComparison.OrdinalIgnoreCase)) { target = bb; break; }
                // Only when the caller named no file, or named one no bookmark carries, and there is
                // exactly one candidate — one candidate is unambiguous whatever the caller knew.
                if (target == null && matches.Count == 1) target = matches[0];
                if (target == null) return false;

                // Mirror the add path (ToggleAtCaret) so the IDE removes the bookmark AND
                // repaints the editor's icon-bar margin — clearing the red dot. RemoveMark
                // alone drops the SharpDevelop-level bookmark but leaves the open document's
                // gutter showing a stale dot until its next redraw. Toggling an existing
                // breakpoint off fires BreakPointRemoved exactly like a manual gutter removal,
                // so the engine/pending + pane cascade (OnGutterBpRemoved) still runs.
                if (target.Document != null)
                    DebuggerService.ToggleBreakpointAt(target.Document, target.FileName, target.LineNumber);
                else
                    ICSharpCode.SharpDevelop.Bookmarks.BookmarkManager.RemoveMark(target); // editor closed — no visible dot to repaint
                return true;
            }
            catch { }
            return false;
        }

        // ------------------------------------------------------------------ active editor discovery
        // Reflection walk (same strategy as EditorService): the Clarion IDE's editors all derive
        // from ICSharpCode TextEditorControl, but the workbench window types vary per editor kind.

        private static TextArea GetActiveTextArea()
        {
            var workbench = ICSharpCode.SharpDevelop.Gui.WorkbenchSingleton.Workbench;
            if (workbench == null) return null;
            object activeWindow = ReflectionHelpers.GetProp(workbench, "ActiveWorkbenchWindow") ?? ReflectionHelpers.GetProp(workbench, "ActiveContent");
            if (activeWindow == null) return null;
            object viewContent = ReflectionHelpers.GetProp(activeWindow, "ViewContent") ?? ReflectionHelpers.GetProp(activeWindow, "ActiveViewContent") ?? activeWindow;

            object editor = ReflectionHelpers.GetProp(viewContent, "TextEditorControl") ?? ReflectionHelpers.GetProp(viewContent, "Control");
            var ta = TextAreaFrom(editor);
            if (ta != null) return ta;

            var winControl = editor as System.Windows.Forms.Control;
            if (winControl != null) return FindTextArea(winControl);
            return null;
        }

        private static TextArea TextAreaFrom(object editor)
        {
            var tec = editor as TextEditorControl;
            if (tec != null)
            {
                try { return tec.ActiveTextAreaControl != null ? tec.ActiveTextAreaControl.TextArea : null; }
                catch { return null; }
            }
            return editor as TextArea;
        }

        private static TextArea FindTextArea(System.Windows.Forms.Control parent)
        {
            foreach (System.Windows.Forms.Control child in parent.Controls)
            {
                var ta = child as TextArea ?? TextAreaFrom(child);
                if (ta != null) return ta;
                var nested = FindTextArea(child);
                if (nested != null) return nested;
            }
            return null;
        }

        private static string ActiveDocumentPathFallback()
        {
            try
            {
                var workbench = ICSharpCode.SharpDevelop.Gui.WorkbenchSingleton.Workbench;
                object activeWindow = workbench != null ? ReflectionHelpers.GetProp(workbench, "ActiveWorkbenchWindow") : null;
                var toolTip = activeWindow != null ? ReflectionHelpers.GetProp(activeWindow, "ToolTipText") as string : null;
                if (!string.IsNullOrEmpty(toolTip) && toolTip.Contains("\\") && toolTip.Contains(".")) return toolTip;
            }
            catch { }
            return null;
        }
    }
}
