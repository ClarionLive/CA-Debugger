using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    /// <summary>
    /// The LAST source line of each procedure and method, for the <c>endLine</c> member of the
    /// <c>symbols</c> event (ticket 6fa242ae).
    /// <para>
    /// WHY: the host resolves "the procedure containing file:line" (BreakOnProcEntry) by TRUE containment
    /// (PM ruling, 2026-09-22). From start lines alone it can only bound a procedure by the NEXT one's start,
    /// so a line in between - module data, a generated trailer - was attributed to the procedure above it.
    /// </para>
    /// <para>
    /// NOT AN ADDRESS RANGE. The ticket asked for the last record in [entry, next entry), the bound
    /// <see cref="TswdDebugInfo.DefinitionLine"/> uses. That bound misses the ROUTINES: measured on clbrws.exe
    /// on 2026-09-22, every procedure's routines are compiled at LOWER addresses than the procedure, directly
    /// before it (clbrws002.clw: routines at 0x2EF08-0x2F0AC, MAIN at 0x2F1D0). So [entry, next entry) holds
    /// the body alone, and BROWSEAUTHORS came out ending at line 254 while its routines run from 256 to 401.
    /// The host takes a routine to be part of its procedure and never a candidate itself, so a cursor in a
    /// routine would have been REFUSED. Before this change it was contained.
    /// </para>
    /// <para>
    /// THE RULE: the highest line of any +0x1C record that is
    /// <list type="bullet">
    /// <item>in the procedure's OWN compiland (same moduleIdx, the key DefinitionLine uses);</item>
    /// <item>OWNED by a procedure, method or routine (nearest symbol at or below its address), not by a
    /// runtime or "other" symbol, since generated glue is not a procedure's source; and</item>
    /// <item>on a line in [the procedure's start, the next procedure or method's start in that compiland).</item>
    /// </list>
    /// Source lines, not addresses, draw the boundary, because containment is a question about source. The
    /// start is DefinitionLine's, so it is anchored exactly as the <c>line</c> member is. The procedure's own
    /// first record normally satisfies all three tests, so a procedure with a start normally has an end.
    /// </para>
    /// <para>
    /// UNKNOWN IS 0, and the emitter OMITS the member for it, never writing 0 (the host reads absent as
    /// unknown). Unknown means the symbol is not a procedure or method, it has no start line, or its own
    /// records are owned by another symbol at the same entry, so nothing eligible reaches its start.
    /// ROUTINES GET NO endLine: their procedure's extent covers them, and the host uses a routine neither as a
    /// candidate nor as a bound. Kind "other" (<c>_main</c>, runtime symbols) gets none either.
    /// </para>
    /// <para>
    /// KNOWN LIMIT (as of 2026-09-22): the table can carry line values past EOF
    /// (<see cref="TswdDebugInfo.LineToRvasInModuleIdx"/>). For a compiland's LAST procedure, such a line has
    /// no upper bound to exclude it and extends the extent past EOF. No cursor can sit there, so containment
    /// is unaffected, but the number is not a real line.
    /// </para>
    /// </summary>
    internal sealed class ProcExtents
    {
        private readonly TswdDebugInfo _dbg;
        // compiland -> sorted lines of the records a procedure's extent may include (see the rule above)
        private readonly Dictionary<int, List<int>> _eligibleLines = new Dictionary<int, List<int>>();
        // compiland -> sorted start lines of its procedures and methods
        private readonly Dictionary<int, List<int>> _starts = new Dictionary<int, List<int>>();

        /// <summary>Index <paramref name="dbg"/> once. Built from the image's WHOLE symbol table, never from a
        /// filtered list: `symbols --kind procedure` drops routines from what is printed, and the extents must
        /// not move with that filter.</summary>
        internal ProcExtents(TswdDebugInfo dbg)
        {
            _dbg = dbg;
            if (dbg.AddrTable != null)
                foreach (var r in dbg.AddrTable)
                {
                    ProcSymbol owner;
                    if (!dbg.ResolveSymbol(r.Rva, out owner) || !IsSourceKind(owner)) continue;
                    Add(_eligibleLines, r.ModuleIdx, r.Line);
                }
            if (dbg.Symbols != null)
                foreach (var s in dbg.Symbols)
                {
                    if (!IsExtentKind(s)) continue;
                    int start = dbg.DefinitionLine(s);
                    if (start > 0) Add(_starts, s.ModuleIdx, start);
                }
            foreach (var l in _eligibleLines.Values) l.Sort();
            foreach (var l in _starts.Values) l.Sort();
        }

        private static void Add(Dictionary<int, List<int>> map, int key, int value)
        {
            List<int> l;
            if (!map.TryGetValue(key, out l)) { l = new List<int>(); map[key] = l; }
            l.Add(value);
        }

        /// <summary>A symbol that gets an extent: the host's candidates.</summary>
        private static bool IsExtentKind(ProcSymbol s)
        {
            return s.Kind == SymbolKind.Procedure || s.Kind == SymbolKind.Method;
        }

        /// <summary>A symbol whose code is a procedure's SOURCE: a candidate, or a routine inside one.</summary>
        private static bool IsSourceKind(ProcSymbol s)
        {
            return IsExtentKind(s) || s.Kind == SymbolKind.Routine;
        }

        /// <summary>The last source line of <paramref name="s"/>, or 0 = unknown. See the class summary for
        /// the rule and for what counts as unknown.</summary>
        internal int EndLine(ProcSymbol s)
        {
            if (s == null || !IsExtentKind(s)) return 0;
            int start = _dbg.DefinitionLine(s);
            if (start <= 0) return 0;

            int nextStart = int.MaxValue;
            List<int> starts;
            if (_starts.TryGetValue(s.ModuleIdx, out starts))
                foreach (int n in starts)
                    if (n > start) { nextStart = n; break; }

            List<int> lines;
            if (!_eligibleLines.TryGetValue(s.ModuleIdx, out lines)) return 0;
            // The largest eligible line below nextStart (binary search).
            int lo = 0, hi = lines.Count - 1, end = 0;
            while (lo <= hi) { int mid = (lo + hi) >> 1; if (lines[mid] < nextStart) { end = lines[mid]; lo = mid + 1; } else hi = mid - 1; }
            // Below the start means the procedure's OWN records were not eligible: another symbol shares its
            // entry and owns them (ResolveSymbol takes the last of equal entries). What was found then belongs
            // to an earlier procedure, so the extent is unknown rather than that.
            return end >= start ? end : 0;
        }
    }
}
