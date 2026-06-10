using System.Windows.Forms;
using ClarionDebugger.Terminal;
using ICSharpCode.SharpDevelop.Gui;

namespace ClarionDebugger
{
    /// <summary>Dockable pad hosting the CA Debugger front-end. Phase 3: WebView2 panel
    /// (Terminal/debugger.html) over the ClarionDbg engine — call stack, watch-by-name, variables.</summary>
    public class ClarionDebuggerPad : AbstractPadContent
    {
        private ClarionDebuggerWebView _control;

        public override Control Control
        {
            get { return _control ?? (_control = new ClarionDebuggerWebView()); }
        }

        public override void Dispose()
        {
            if (_control != null) { _control.Dispose(); _control = null; }
            base.Dispose();
        }
    }
}
