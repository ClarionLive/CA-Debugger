using System.Collections.Generic;

namespace ClarionDbg.Cli
{
    /// <summary>Maps Clarion EVENT() codes to their EVENT:* equate names (from libsrc EQUATES.CLW). A
    /// pure static lookup — used to annotate the Library State EVENT row WITHOUT calling into the runtime
    /// (calling a ClaRUN resolver on the stopped thread can trip the RTL's 0x6BEF5E4C fatal in a live
    /// ACCEPT loop). Field events ≤0x1F have aliases (e.g. 0x01 is both Accepted and MouseDown); the
    /// most common name is used.</summary>
    internal static class ClarionEvents
    {
        static readonly Dictionary<uint, string> Map = new Dictionary<uint, string>
        {
            // field events (0x01–0x1F)
            [0x01] = "EVENT:Accepted",     // also EVENT:MouseDown
            [0x02] = "EVENT:NewSelection",
            [0x03] = "EVENT:ScrollUp",
            [0x04] = "EVENT:ScrollDown",
            [0x05] = "EVENT:PageUp",
            [0x06] = "EVENT:PageDown",
            [0x07] = "EVENT:ScrollTop",
            [0x08] = "EVENT:ScrollBottom",
            [0x09] = "EVENT:Locate",
            [0x0a] = "EVENT:MouseUp",
            [0x0b] = "EVENT:MouseIn",
            [0x0c] = "EVENT:MouseOut",
            [0x0d] = "EVENT:MouseMove",
            [0x0f] = "EVENT:AlertKey",
            [0x10] = "EVENT:PreAlertKey",
            [0x11] = "EVENT:Dragging",
            [0x12] = "EVENT:Drag",
            [0x13] = "EVENT:Drop",
            [0x14] = "EVENT:ScrollDrag",
            [0x15] = "EVENT:TabChanging",
            [0x16] = "EVENT:Expanding",
            [0x17] = "EVENT:Contracting",
            [0x18] = "EVENT:Expanded",
            [0x19] = "EVENT:Contracted",
            [0x1a] = "EVENT:Rejected",
            [0x1b] = "EVENT:DroppingDown",
            [0x1c] = "EVENT:DroppedDown",
            [0x1d] = "EVENT:ScrollTrack",
            [0x1e] = "EVENT:ColumnResize",
            [0x1f] = "EVENT:HeaderPressed",
            // list-box field events
            [0x101] = "EVENT:Selected",
            [0x102] = "EVENT:Selecting",
            // window / field-independent events (0x201+)
            [0x201] = "EVENT:CloseWindow",
            [0x202] = "EVENT:CloseDown",
            [0x203] = "EVENT:OpenWindow",
            [0x204] = "EVENT:OpenFailed",
            [0x205] = "EVENT:LoseFocus",
            [0x206] = "EVENT:GainFocus",
            [0x207] = "EVENT:NestedLoop",
            [0x208] = "EVENT:Suspend",
            [0x209] = "EVENT:Resume",
            [0x20a] = "EVENT:Notify",
            [0x20b] = "EVENT:Timer",
            [0x20c] = "EVENT:DDErequest",
            [0x20d] = "EVENT:DDEadvise",
            [0x20e] = "EVENT:DDEdata",
            [0x20f] = "EVENT:DDEexecute",   // also EVENT:DDEcommand
            [0x210] = "EVENT:DDEpoke",
            [0x211] = "EVENT:DDEclosed",
            [0x220] = "EVENT:Move",
            [0x221] = "EVENT:Size",
            [0x222] = "EVENT:Restore",
            [0x223] = "EVENT:Maximize",
            [0x224] = "EVENT:Iconize",
            [0x225] = "EVENT:Completed",
            [0x230] = "EVENT:Moved",
            [0x231] = "EVENT:Sized",
            [0x232] = "EVENT:Restored",
            [0x233] = "EVENT:Maximized",
            [0x234] = "EVENT:Iconized",
            [0x235] = "EVENT:Docked",
            [0x236] = "EVENT:Undocked",
            [0x240] = "EVENT:BuildFile",
            [0x241] = "EVENT:BuildKey",
            [0x242] = "EVENT:BuildDone",
            [0x3ff] = "EVENT:DoResize",     // EVENT:User-1
            [0x400] = "EVENT:User",
            [0xfff] = "EVENT:Last",
        };

        /// <summary>The EVENT:* name for a code, "EVENT:User+N" for the user range (0x400–0xFFF), or null
        /// if unknown (caller shows just the number).</summary>
        public static string Name(uint ev)
        {
            if (Map.TryGetValue(ev, out var n)) return n;
            if (ev > 0x400 && ev < 0x1000) return $"EVENT:User+{ev - 0x400}";
            return null;
        }
    }
}
