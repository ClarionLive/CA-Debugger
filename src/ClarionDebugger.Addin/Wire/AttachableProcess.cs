using System.Globalization;

// Wire, not Terminal (40a252d0): the service lists and attaches to these, and it was the one Terminal type
// the Services layer still imported.
namespace ClarionDebugger.Wire
{
    /// <summary>One process the attach picker may offer, as the engine's <c>procs --json</c> listed it.</summary>
    public sealed class AttachableProcess
    {
        public uint Pid;
        public string Name;
        public string Path;
        public bool Tswd;
        /// <summary>The process's creation time as the engine listed it: a FILETIME (UTC, 100 ns ticks) in decimal,
        /// or null when the engine did not report one. It is what makes a listed pid an IDENTITY: the attach passes
        /// it as <c>--expect-start</c>, and the engine refuses a process whose start time differs (pid reused).</summary>
        public string Started;

        /// <summary>True for a start time the attach can pass on: 1..20 decimal digits (a 64-bit FILETIME) and
        /// nothing else, so it cannot carry a second argument onto the engine's command line.</summary>
        public static bool IsStartTime(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length > 20) return false;
            foreach (char c in s) if (c < '0' || c > '9') return false;
            ulong v;
            return ulong.TryParse(s, NumberStyles.None, CultureInfo.InvariantCulture, out v) && v != 0;
        }
    }
}
