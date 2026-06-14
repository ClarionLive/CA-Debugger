using System.Windows.Forms;
using ICSharpCode.SharpDevelop.Gui;

namespace ClarionDebugger.Disassembly
{
    /// <summary>Helpers shared by the menu command and the WebView pad button.</summary>
    public static class DisassemblyTab
    {
        /// <summary>Open the Disassembly document tab, or focus it if already open. UI thread only.</summary>
        public static void ShowOrFocus()
        {
            var wb = WorkbenchSingleton.Workbench;
            if (wb == null) return;
            foreach (var v in wb.ViewContentCollection)
            {
                if (v is DisassemblyViewContent)
                {
                    if (v.WorkbenchWindow != null) v.WorkbenchWindow.SelectWindow();
                    return;
                }
            }
            wb.ShowView(new DisassemblyViewContent());
        }
    }

    /// <summary>A document tab (not a dockable pad) showing the native disassembly view, opened like a
    /// source file in the workbench document area. Read-only and single-instance (see
    /// <see cref="ShowDisassemblyCommand"/>). Hosts <see cref="DisassemblyView"/>, which attaches to the
    /// shared engine session and repaints on each pause.</summary>
    public class DisassemblyViewContent : AbstractViewContent
    {
        private DisassemblyView _view;

        public DisassemblyViewContent()
        {
            TitleName = "Disassembly";
            IsViewOnly = true;
            _view = new DisassemblyView();
        }

        public override Control Control
        {
            get { return _view; }
        }

        public override void Dispose()
        {
            if (_view != null) { _view.Dispose(); _view = null; }
            base.Dispose();
        }
    }
}
