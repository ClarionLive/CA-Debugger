using ICSharpCode.Core;
using ICSharpCode.SharpDevelop.Gui;

namespace ClarionDebugger.Disassembly
{
    /// <summary>Opens (or focuses) the Disassembly document tab. Single-instance: if one is already open
    /// it is brought to the front instead of opening a second.</summary>
    public class ShowDisassemblyCommand : AbstractMenuCommand
    {
        public override void Run()
        {
            DisassemblyTab.ShowOrFocus();
        }
    }
}
