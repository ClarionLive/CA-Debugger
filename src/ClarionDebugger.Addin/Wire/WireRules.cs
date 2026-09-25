using System.Globalization;

namespace ClarionDebugger.Wire
{
    /// <summary>Rules for values that cross the wire, stated once for the host. Both sides of the bridge read
    /// them: the page's requests (PageMessages) and the engine commands built from them
    /// (ClarionDebuggerService).</summary>
    internal static class WireRules
    {
        /// <summary>The absent-tid rule, stated once for the host (6ac29815 #1; the engine's is TidIsKnown in
        /// DebugEngine.cs): a thread id is a real one only when it is present and not 0. Absent means the sender
        /// did not say, and 0 is a sentinel that must never be read as a thread. Every host reader and writer of
        /// a <c>uint?</c> tid asks here; tools/test-host-tid-members.ps1 fails an inline copy of the test.</summary>
        internal static bool TidIsKnown(uint? tid)
        {
            return tid.HasValue && tid.Value != 0;
        }

        /// <summary>An unsigned decimal, digits only (no sign, no whitespace, invariant culture); null reads as
        /// "not a number". The page's payloads (PageNumbers.TryUInt) and the engine's process listing read
        /// pids and ids with this one rule (40a252d0).</summary>
        internal static bool TryUInt(string s, out uint v)
        {
            v = 0;
            return s != null && uint.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out v);
        }

        /// <summary>The most bytes one Memory-panel read may ask for: the engine's cap (MemMaxLen in
        /// DebugEngine.cs), and the page's MEM_MAX.</summary>
        internal const int MemMaxLen = 4096;

        /// <summary>^0x[0-9A-Fa-f]{1,8}$ - the form the engine emits, and nothing that could split into a
        /// second word on the engine's space-separated stdin. Not a Regex: .NET's <c>$</c> also matches
        /// before a trailing newline, which on that stdin is a second COMMAND.</summary>
        internal static bool IsHexAddr(string s)
        {
            if (s == null || s.Length < 3 || s.Length > 10 || s[0] != '0' || s[1] != 'x') return false;
            for (int i = 2; i < s.Length; i++)
            {
                char c = s[i];
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
            }
            return true;
        }
    }
}
