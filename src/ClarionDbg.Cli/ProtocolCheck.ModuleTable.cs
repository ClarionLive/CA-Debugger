using System;
using System.Collections.Generic;
using System.IO;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// Same-named DLLs in two directories keep two module entries (1be3b82e item 2). Builds real PE files on
        /// disk (copies of ClarionDbg.Core.dll, a PE32 image, with the link time patched so they are two BUILDS)
        /// and runs the REAL preload through the engine constructor, then the REAL claim decider
        /// (<see cref="DebugEngine.ClaimUnmapped"/>) over those entries: a path match, a same-build copy, two
        /// same-build preloads and a third copy, and a different build of the same name.
        ///
        /// NOT COVERED: OnDllLoaded itself (it reads the mapped header from a live process); the live suite
        /// tools/test-engine-samename.ps1 covers it against the fixture.
        /// </summary>
        private static void CheckSameNameDllsKeepTheirEntries(List<string> failures, ClaimLog claims)
        {
            claims.Claim("two solution DLLs with one file name in two directories preload as two entries, each with its own "
                         + "path and PE; one DLL named in two spellings preloads once; a DLL mapping from a preloaded path "
                         + "claims that entry, a same-build copy from another directory claims the one matching preload, and "
                         + "two matching preloads, only a different build of the name, another name's same build or an unread link time "
                         + "claim nothing (a new entry).");

            string root = Path.Combine(Path.GetTempPath(), "cadbg-samename-" + Guid.NewGuid().ToString("N"));
            try
            {
                byte[] src = File.ReadAllBytes(typeof(PeImage).Assembly.Location);
                Func<string, uint, string, string> writeAs = (dir, stamp, file) =>
                {
                    string d = Path.Combine(root, dir);
                    Directory.CreateDirectory(d);
                    var b = (byte[])src.Clone();
                    int peOff = BitConverter.ToInt32(b, 0x3C);
                    BitConverter.GetBytes(stamp).CopyTo(b, peOff + 8);
                    string f = Path.Combine(d, file);
                    File.WriteAllBytes(f, b);
                    return f;
                };
                Func<string, uint, string> write = (dir, stamp) => writeAs(dir, stamp, "shared.dll");
                string a = write("A", 0x11111111), bPath = write("B", 0x22222222);
                string twinA = write("TwinA", 0x33333333), twinB = write("TwinB", 0x33333333);
                string copy = write("Copy", 0x33333333);
                string copyOfA = write("CopyOfA", 0x11111111);

                // Preload: A, B and A again spelled another way (upper case, through a ".." segment).
                string aAgain = Path.Combine(root, "B", "..", "A", "SHARED.DLL");
                var eng = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false, new[] { a, bPath, aAgain });
                var dlls = eng.ModulesForTest().FindAll(x => x.Preloaded);
                if (dlls.Count != 2)
                    failures.Add("same-name dlls: A, B and A-in-another-spelling preloaded " + dlls.Count + " entries, expected 2 (one per file)");
                var ea = dlls.Find(x => string.Equals(x.Path, DebugEngine.CanonicalImagePath(a), StringComparison.OrdinalIgnoreCase));
                var eb = dlls.Find(x => string.Equals(x.Path, DebugEngine.CanonicalImagePath(bPath), StringComparison.OrdinalIgnoreCase));
                if (ea == null || eb == null) { failures.Add("same-name dlls: A or B has no entry under its own path"); return; }
                if (ea.Pe == null || eb.Pe == null || ea.Pe.TimeDateStamp != 0x11111111 || eb.Pe.TimeDateStamp != 0x22222222)
                    failures.Add("same-name dlls: the two entries do not each carry their own file's PE");

                var table = eng.ModulesForTest();
                Func<string, uint, LoadedModule> claim = (path, stamp) =>
                    DebugEngine.ClaimUnmapped(table, DebugEngine.CanonicalImagePath(path), "shared.dll", stamp, ea.Pe.SizeOfImage);

                if (claim(bPath, 0x22222222) != eb) failures.Add("same-name dlls: B mapping from its own path did not claim B's entry");
                if (claim(a, 0x11111111) != ea) failures.Add("same-name dlls: A mapping from its own path did not claim A's entry");
                // B loads with A's link time (cannot happen, but it isolates the path branch from the build branch).
                if (claim(bPath, 0x11111111) != eb) failures.Add("same-name dlls: the path match must win over a same-build match elsewhere");
                if (claim(copyOfA, 0x11111111) != ea) failures.Add("same-name dlls: a same-build copy of A from another directory did not claim A's entry");
                if (claim(copyOfA, 0x44444444) != null) failures.Add("same-name dlls: a DIFFERENT build of shared.dll from another directory claimed an entry");
                if (claim(copyOfA, 0) != null) failures.Add("same-name dlls: an unreadable mapped header (link time 0) claimed an entry");

                var twins = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false, new[] { twinA, twinB });
                table = twins.ModulesForTest();
                if (table.FindAll(x => x.Preloaded).Count != 2)
                    failures.Add("same-name dlls: two identical builds in two directories must preload as two entries");
                if (claim(copy, 0x33333333) != null)
                    failures.Add("same-name dlls: a third copy matching TWO same-build preloads claimed one of them (it must be a new entry)");
                var tA = table.Find(x => x.Preloaded && string.Equals(x.Path, DebugEngine.CanonicalImagePath(twinA), StringComparison.OrdinalIgnoreCase));
                if (claim(twinA, 0x33333333) != tA || tA == null)
                    failures.Add("same-name dlls: with two same-build preloads, the path still claims its own");

                // The build test needs the NAME too, and a link time that was read: another DLL of the same build
                // identity is not this one, and a preload whose own header says 0 matches no unreadable header.
                var odd = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false,
                                          new[] { writeAs("Other", 0x55555555, "other.dll"), write("Zero", 0) });
                table = odd.ModulesForTest();
                if (claim(copy, 0x55555555) != null)
                    failures.Add("same-name dlls: shared.dll claimed other.dll's preload because their builds matched (the name must match too)");
                if (claim(copy, 0) != null)
                    failures.Add("same-name dlls: an unreadable mapped header (link time 0) claimed a preload whose link time is 0");
            }
            catch (Exception ex) { failures.Add("same-name dlls: " + ex.GetType().Name + ": " + ex.Message); }
            finally { try { Directory.Delete(root, true); } catch { } }
        }
    }
}
