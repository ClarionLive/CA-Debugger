using System;
using ICSharpCode.Core;

namespace ClarionDebugger
{
    /// <summary>
    /// One condition evaluator that greys/un-greys all seven CA-Debugger toolbar buttons according to the
    /// live debug run-state held by <see cref="DebugSessionController"/>. The manifest wires each ToolbarItem
    /// inside a <c>&lt;Condition name="ClarionDebugState" debugbutton="Start|Continue|Pause|StepOver|StepInto|StepOut|Stop" action="Disable"&gt;</c>
    /// so this single class serves every button.
    ///
    /// Enable matrix:
    ///   Start                              -> Idle
    ///   Continue / StepOver / StepInto / StepOut -> Paused
    ///   Pause                              -> Running or Launching
    ///   Stop                               -> not Idle
    ///
    /// The IDE re-evaluates toolbar conditions on its ApplicationIdle cycle (the same mechanism that re-greys
    /// the native IsProcessRunning debug buttons), so reading the live state here is all that is needed for the
    /// buttons to track state transitions within one idle tick — no forced refresh.
    ///
    /// FAIL-SAFE: any unexpected input or exception returns false (button disabled). This must never throw
    /// inside the IDE's condition loop.
    /// </summary>
    public sealed class ClarionDebugStateConditionEvaluator : IConditionEvaluator
    {
        public bool IsValid(object caller, Condition condition)
        {
            try
            {
                if (condition == null) return false;
                string button = condition["debugbutton"];
                if (string.IsNullOrEmpty(button)) return false;

                DebugControllerState s = DebugSessionController.State;

                switch (button.Trim().ToLowerInvariant())
                {
                    case "start":    return s == DebugControllerState.Idle;
                    case "continue": return s == DebugControllerState.Paused;
                    case "stepover": return s == DebugControllerState.Paused;
                    case "stepinto": return s == DebugControllerState.Paused;
                    case "stepout":  return s == DebugControllerState.Paused;
                    case "pause":    return s == DebugControllerState.Running || s == DebugControllerState.Launching;
                    case "stop":     return s != DebugControllerState.Idle;
                    default:         return false;
                }
            }
            catch (Exception)
            {
                // Never let a condition-evaluation error bubble into the IDE toolbar loop.
                return false;
            }
        }
    }
}
