using ICSharpCode.Core;
using ICSharpCode.SharpDevelop.Gui;

namespace ClarionDebugger
{
    // The 7 IDE-toolbar debug commands. Each forwards to DebugSessionController, which routes to the live
    // debugger pad's matching Cmd* method. Class names here MUST stay in sync with the class= attributes
    // on the ToolbarItems in ClarionDebugger.addin. The condition evaluator greys these per debug state, so
    // each Run() is a thin forwarder — the controller additionally no-ops when there is no live/ready pad.

    /// <summary>Start a debug session. Ensures the pad is open (so a target exists to register), then asks
    /// the controller to Start. The pad's CmdStart defers until its WebView is ready (NavigationCompleted),
    /// so firing immediately after BringPadToFront does not race a half-initialized WebView.</summary>
    public sealed class StartDebugCommand : AbstractMenuCommand
    {
        public override void Run()
        {
            // Opening the pad constructs the WebView (if not already), which registers it as the live target.
            var pad = WorkbenchSingleton.Workbench.GetPad(typeof(ClarionDebuggerPad));
            if (pad != null) pad.BringPadToFront();
            DebugSessionController.Start();
        }
    }

    public sealed class ContinueDebugCommand : AbstractMenuCommand
    {
        public override void Run() { DebugSessionController.Continue(); }
    }

    public sealed class PauseDebugCommand : AbstractMenuCommand
    {
        public override void Run() { DebugSessionController.Pause(); }
    }

    public sealed class StepOverDebugCommand : AbstractMenuCommand
    {
        public override void Run() { DebugSessionController.StepOver(); }
    }

    public sealed class StepIntoDebugCommand : AbstractMenuCommand
    {
        public override void Run() { DebugSessionController.StepInto(); }
    }

    public sealed class StepOutDebugCommand : AbstractMenuCommand
    {
        public override void Run() { DebugSessionController.StepOut(); }
    }

    public sealed class StopDebugCommand : AbstractMenuCommand
    {
        public override void Run() { DebugSessionController.Stop(); }
    }
}
