using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal sealed partial class DebugEngine
    {
        // ------------------------------------------------------------------ module table

        /// <summary>Add a module entry from an already-parsed PE/TSWD (the EXE, or a pre-loaded
        /// solution DLL). LoadBase is filled in later when the image maps.</summary>
        private LoadedModule RegisterImageFromPe(string path, PeImage pe, TswdDebugInfo dbg, bool preloaded = false)
        {
            var m = new LoadedModule
            {
                Path = path,
                Name = (System.IO.Path.GetFileName(path) ?? path).ToLowerInvariant(),
                Pe = pe,
                Dbg = dbg,
                Preloaded = preloaded,
                PreloadPath = preloaded ? path : null,
                Size = pe != null ? pe.SizeOfImage : 0,
            };
            m.ResolveThreadedInfo();
            _modules.Add(m);
            return m;
        }

        /// <summary>Pre-parse a solution DLL off disk so its breakpoints resolve before launch.
        /// Failures are non-fatal (the DLL may be rebuilt/absent); it will re-parse at LOAD_DLL.
        /// <para>
        /// KEYED ON THE CANONICAL FULL PATH, not the file name (1be3b82e item 2). Two projects can each build a
        /// <c>shared.dll</c>, and a name key skipped the second one as "already known", so it had no entry of its
        /// own and, once loaded, took the first one's PE and TSWD.
        /// </para></summary>
        private void TryPreloadSolutionDll(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !System.IO.File.Exists(path)) return;
                path = CanonicalImagePath(path);
                foreach (var m in _modules) if (SamePath(m.Path, path)) return; // already known
                var pe = PeImage.Load(path);
                var dbg = TswdDebugInfo.TryFromPe(pe);
                RegisterImageFromPe(path, pe, dbg, preloaded: true);
            }
            catch { /* best-effort pre-load */ }
        }

        /// <summary>A file's path spelled the way <see cref="OnDllLoaded"/> learns a loaded image's path: the
        /// final path of an open handle (<see cref="GetPathFromHandle"/>), so a short 8.3 name, a different case
        /// or a relative path from the host compares equal to what the loader reports. Falls back to the full
        /// path when the file cannot be opened, and passes null through.</summary>
        internal static string CanonicalImagePath(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            try
            {
                using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                                               FileShare.ReadWrite | FileShare.Delete))
                {
                    string final = GetPathFromHandle((uint)fs.SafeFileHandle.DangerousGetHandle().ToInt64());
                    if (!string.IsNullOrEmpty(final)) return final;
                }
            }
            catch { /* unreadable: the full path is the best spelling left */ }
            try { return System.IO.Path.GetFullPath(path); } catch { return path; }
        }

        private static bool SamePath(string a, string b)
        {
            return !string.IsNullOrEmpty(a) && !string.IsNullOrEmpty(b) && string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// The unmapped entry a DLL that just mapped at <paramref name="path"/> takes over, or null for a new entry
        /// (1be3b82e item 2). The PATH decides: an entry whose canonical path is the one loaded. The file name
        /// alone decided before, so <c>C:\B\shared.dll</c> claimed <c>C:\A\shared.dll</c>'s preloaded entry and
        /// read its TSWD against B's code.
        /// <para>
        /// ONE FALLBACK, on build identity rather than name: an output copied beside the EXE loads from a path the
        /// host never named. A same-name PRELOADED entry is still that image when <see cref="SameBuild"/> proves
        /// it from <paramref name="mapped"/>, and only when exactly one entry does.
        /// </para>
        /// </summary>
        internal static LoadedModule ClaimUnmapped(IList<LoadedModule> modules, string path, string name, MappedBuild mapped)
        {
            foreach (var im in modules)
                if (im.LoadBase == 0 && SamePath(im.Path, path)) return im;
            LoadedModule same = null;
            foreach (var im in modules)
            {
                if (im.LoadBase != 0 || !im.Preloaded || im.Pe == null || im.Name != name) continue;
                if (!SameBuild(im.Pe, mapped)) continue;
                if (same != null) return null;   // two builds answer: neither is provably this one
                same = im;
            }
            return same;
        }

        /// <summary>What the engine could learn about the build of an image that just mapped: its file on disk
        /// when the mapped path reads (<see cref="DiskPe"/>), and the identity fields of the MAPPED header, read
        /// from the target. A field that did not read is 0, never a placeholder (fb5766d1 #2: the size reader
        /// used to answer a made-up 0x10000 for a bad header, and a preload of that size matched it).</summary>
        internal sealed class MappedBuild
        {
            public PeImage DiskPe;        // the mapped path's file, parsed; null when it does not read
            public uint Stamp;            // file header +8 (link time)
            public uint Size;             // optional header +56 (SizeOfImage)
            public uint CheckSum;         // optional header +64
            public uint DebugStamp;      // that entry's TimeDateStamp (+4)
            public uint DebugType;        // ... its Type (+12)
            public uint DebugSize;        // ... its SizeOfData (+16)
        }

        /// <summary>
        /// Is <paramref name="pre"/> (a preload's PE) provably the build that mapped (fb5766d1 #2)?
        /// <para>
        /// WHEN THE MAPPED FILE READS, ITS DEBUG DATA DECIDES: the first debug entry's bytes - for a Clarion image
        /// the whole TSWD blob the preload will be trusted to describe - must be byte-equal to the preload's, and the
        /// file's link time must be the one that mapped. Link time and size alone are not an identity: a rebuild can
        /// keep the size, and a stamp can repeat.
        /// </para>
        /// <para>
        /// ONLY WHEN IT DOES NOT READ, the mapped header decides, on everything the header can say: link time, size
        /// and checksum, and the first debug entry's type, link time and data size. Every one must equal the
        /// preload's, the link time and size must have read (non-zero), and the preload must carry a debug entry.
        /// A debug directory that did not read is all 0, which no real entry is (its type and size are set).
        /// </para>
        /// </summary>
        internal static bool SameBuild(PeImage pre, MappedBuild mapped)
        {
            if (pre == null || mapped == null || mapped.Stamp == 0 || mapped.Size == 0) return false;
            if (pre.TimeDateStamp != mapped.Stamp || pre.SizeOfImage != mapped.Size) return false;
            if (mapped.DiskPe != null)
                return mapped.DiskPe.TimeDateStamp == mapped.Stamp && PeImage.SameFirstDebugData(pre, mapped.DiskPe);
            PeImage.DebugEntry e;
            if (!pre.TryReadFirstDebugEntry(out e)) return false;
            return pre.CheckSum == mapped.CheckSum
                && e.Type == mapped.DebugType && e.TimeDateStamp == mapped.DebugStamp && e.SizeOfData == mapped.DebugSize;
        }

        /// <summary>Read <see cref="MappedBuild"/> through <paramref name="readU32"/>, which reads a U32 at an RVA of
        /// the mapped image (the target's memory live; a file in protocolcheck). The PE header sits at its file
        /// offset in memory, and the debug entry at its RVA. Any field that does not read stays 0.</summary>
        internal static MappedBuild ReadMappedBuild(Func<uint, uint> readU32, PeImage diskPe)
        {
            var b = new MappedBuild { DiskPe = diskPe };
            uint hdr = PeHeaderOffset(readU32);
            if (hdr == 0) return b;
            uint opt = hdr + 24;
            b.Stamp = readU32(hdr + 8);
            b.Size = readU32(opt + 56);
            b.CheckSum = readU32(opt + 64);
            uint dirRva = readU32(opt + 96 + 6 * 8), dirSize = readU32(opt + 96 + 6 * 8 + 4);
            if (dirRva != 0 && dirSize >= 28)
            {
                b.DebugStamp = readU32(dirRva + 4);
                b.DebugType = readU32(dirRva + 12);
                b.DebugSize = readU32(dirRva + 16);
            }
            return b;
        }

        /// <summary>The PE header's offset from the image base (e_lfanew), or 0 when it is out of range or the
        /// "PE\0\0" signature is not there. The one header locator both remote readers use (fb5766d1 #7a).</summary>
        internal static uint PeHeaderOffset(Func<uint, uint> readU32)
        {
            uint eLfanew = readU32(0x3C);
            if (eLfanew == 0 || eLfanew > 0x1000) return 0;
            return readU32(eLfanew) == 0x00004550 ? eLfanew : 0;
        }

        /// <summary>
        /// Keep two LIVE entries from sharing a Path (fb5766d1 #3). A same-build claim borrows the preload's path
        /// (<see cref="LoadedModule.PathBorrowed"/>); when <paramref name="just"/> maps and a live entry answers to
        /// the same Path, the BORROWER takes its own mapped path, since the other one is genuinely there. Returns
        /// the entries whose Path changed, so the caller can re-send the breakpoint list they own.
        /// </summary>
        internal static List<LoadedModule> YieldBorrowedPaths(IList<LoadedModule> modules, LoadedModule just)
        {
            var changed = new List<LoadedModule>();
            if (just == null || just.LoadBase == 0) return changed;
            foreach (var o in modules)
            {
                if (o == just || o.LoadBase == 0 || !SamePath(o.Path, just.Path)) continue;
                LoadedModule loser = just.PathBorrowed ? just : o.PathBorrowed ? o : null;
                if (loser == null) continue;   // neither borrowed: two genuine mappings of one path cannot coexist
                loser.Path = loser.MappedPath;
                if (!changed.Contains(loser)) changed.Add(loser);
                if (loser == just) break;
            }
            return changed;
        }

        /// <summary>Test seam: the module table as it stands (a copy), for protocolcheck's preload assertions.</summary>
        internal List<LoadedModule> ModulesForTest() { return new List<LoadedModule>(_modules); }

        /// <summary>Test seam: the REAL unmap handler for the image at <paramref name="baseVa"/>; protocolcheck
        /// sets the entry's LoadBase/MappedPath itself, since no process maps it.</summary>
        internal void DllUnloadedForTest(uint baseVa) { OnDllUnloaded(baseVa); }

        /// <summary>The mapped module whose [LoadBase, LoadBase+Size) contains <paramref name="va"/>,
        /// or null. Only mapped modules (LoadBase != 0) are candidates.</summary>
        private LoadedModule ModuleAt(uint va)
        {
            foreach (var m in _modules)
                if (m.LoadBase != 0 && m.ContainsVa(va)) return m;
            return null;
        }

        /// <summary>The mapped image by file name (e.g. school.exe), case-insensitive — used to re-resolve a
        /// reference node's type in its owning image's TSWD for lazy `expand`. Null if not loaded.</summary>
        private LoadedModule ModuleByName(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            foreach (var m in _modules)
                if (m.LoadBase != 0 && string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase)) return m;
            return null;
        }

        /// <summary>The mapped image named <paramref name="name"/> (case-insensitive) whose LoadBase is exactly
        /// <paramref name="loadBase"/>, or null (w8-expand-base). Two same-named DLLs are told apart by base, which
        /// <see cref="ModuleByName"/> cannot do; a base that names no mapped image of that name finds nothing,
        /// never the first image of the name.</summary>
        internal static LoadedModule ModuleByNameAndBase(IList<LoadedModule> modules, string name, uint loadBase)
        {
            if (string.IsNullOrEmpty(name) || loadBase == 0) return null;
            foreach (var m in modules)
                if (m.LoadBase == loadBase && string.Equals(m.Name, name, StringComparison.OrdinalIgnoreCase)) return m;
            return null;
        }

        /// <summary>Is <paramref name="bp"/> an arm-all copy (no image named, not single-target) whose logical
        /// breakpoint - same compiland, same REQUESTED line - is also held by an entry outside
        /// <paramref name="leaving"/>, armed or pending? Then it is redundant once that image unmaps.</summary>
        private bool HasArmAllSiblingOutside(UserBreakpoint bp, LoadedModule leaving)
        {
            if (!string.IsNullOrEmpty(bp.OwnerSpec) || bp.SingleTargetRequested) return false;
            foreach (var other in _bps)
                if (other != bp && other.Owner != leaving
                    && string.IsNullOrEmpty(other.OwnerSpec) && !other.SingleTargetRequested
                    && other.RequestedLine == bp.RequestedLine
                    && string.Equals(other.Module, bp.Module, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        /// <summary>EVERY loaded image whose TSWD carries this compiland, not just the first.
        /// <para>
        /// A .clw name is a BASENAME. Two DLLs in one solution can each contain a <c>clbrws011.clw</c>, and
        /// the old first-match lookup answering "the first one" is why a breakpoint set in the second DLL
        /// was never armed and the user's gutter dot silently never fired (task af81c054). The list is the
        /// honest answer to "which image owns this name"; the caller decides what to do with more than one.
        /// </para></summary>
        private List<LoadedModule> OwnersOfModule(string clwName)
        {
            var owners = new List<LoadedModule>();
            foreach (var m in _modules)
                if (m.HasDebug && m.Dbg.FindModuleIdx(clwName) >= 0) owners.Add(m);
            return owners;
        }

        /// <summary>Does <paramref name="m"/> answer to the image identity a caller named?
        /// <para>
        /// THE FORM OF THE SPEC DECIDES WHICH COMPARISON IS MADE, and there is NO FALLBACK between them.
        /// A spec carrying a directory separator is a PATH and is matched only against
        /// <see cref="LoadedModule.Path"/>; a bare name is matched only against
        /// <see cref="LoadedModule.Name"/>.
        /// </para>
        /// <para>
        /// FALLING BACK FROM PATH TO NAME REINTRODUCES THE BUG, which is why it is spelled out rather than
        /// left to read as an oversight. Two DLLs built from different projects routinely share a file
        /// name - <c>C:\App\Dll1\shared.dll</c> and <c>C:\App\Dll2\shared.dll</c> - and a caller that
        /// takes the trouble to name a full path is doing so precisely to tell those two apart. Matching
        /// the second against the first's name because the path did not match hands back the wrong image
        /// with full confidence, which is task af81c054 wearing a different hat. A path that names no
        /// loaded image matches NOTHING, and the breakpoint stays pending until that image maps - the
        /// honest answer when the one thing asked for is not here yet.
        /// </para>
        /// <para>
        /// The bare-name form stays because a caller may legitimately only know the name, and because it
        /// is unambiguous whenever only one loaded image has it.
        /// </para>
        /// <para>
        /// A NULL SPEC MATCHES NOTHING HERE. "The caller named no image" is a decision for the caller to
        /// make, not a match: treating null as "matches anything" inside this helper would silently arm an
        /// unqualified breakpoint in whichever image was asked about first, which is the bug.
        /// </para>
        /// <para>
        /// KNOWN LIMIT, recorded rather than papered over: the path comparison is exact (bar case). Both
        /// sides come from the engine (as of 2026-09-22) - the host echoes back the <c>ownerPath</c> the engine gave it -
        /// so they are the same string by construction. A future host that DERIVES the path from the
        /// project model instead could produce a different spelling of the same file (short 8.3 form, a
        /// mapped drive, a <c>\\?\</c> prefix) and would match nothing. That belongs with whatever builds
        /// that mapping, and it should canonicalize before it sends, not be smoothed over here by a
        /// fallback that cannot tell a different spelling from a different file.
        /// </para></summary>
        private static bool ImageMatches(LoadedModule m, string spec)
        {
            if (m == null || string.IsNullOrEmpty(spec)) return false;
            if (spec.IndexOf('\\') >= 0 || spec.IndexOf('/') >= 0)
                return !string.IsNullOrEmpty(m.Path) && string.Equals(m.Path, spec, StringComparison.OrdinalIgnoreCase);
            return !string.IsNullOrEmpty(m.Name) && string.Equals(m.Name, spec, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Resolve a live VA to its owning module + source line via that image's TSWD.
        /// Returns false when no mapped module owns it or the owner carries no debug info.</summary>
        private bool ResolveVa(uint va, out LoadedModule m, out int line, out int moduleIdx, out uint recRva)
        {
            line = 0; moduleIdx = -1; recRva = 0;
            m = ModuleAt(va);
            if (m == null || m.Dbg == null) return false;
            return m.Dbg.ResolveAddr(va - m.LoadBase, out line, out moduleIdx, out recRva);
        }

        /// <summary>How a data name resolved.</summary>
        internal enum DataResolve { Found, NotFound, Ambiguous }

        /// <summary>One location a data name could mean: which image, which module (null when the line table
        /// proves none), and whether it belongs to a genuine FILE record.</summary>
        internal sealed class DataCandidate
        {
            public string Image;
            public string Module;
            public bool FileRecord;
            public LoadedModule Owner;
            public TswdDebugInfo.DataLocation Loc;
            public DataSymbol Symbol;   // set by the watch-path head lookup, which walks the symbol's layout
        }

        /// <summary>
        /// Split a data name written <c>[image!][module!]name</c> (04d7b4c8). '!' starts a comment in Clarion, so
        /// no label holds one, and every '!' is a qualifier boundary. The qualifiers come off BEFORE anything
        /// splits the rest on '.': an image qualifier carries its own '.' (CLBRWS.EXE), and the page asks for a
        /// watch's children as "&lt;watch name&gt;.&lt;MEMBER&gt;". False for more than two qualifiers or an empty part.
        /// A two-part name leaves <paramref name="q1"/> open: an image or a module, decided against the candidates.
        /// </summary>
        internal static bool ParseQualified(string spec, out string q1, out string q2, out string rest)
        {
            q1 = null; q2 = null; rest = spec;
            if (string.IsNullOrEmpty(spec)) return false;
            string[] p = spec.Split('!');
            if (p.Length > 3) return false;
            foreach (var s in p) if (s.Length == 0) return false;
            rest = p[p.Length - 1];
            if (p.Length >= 2) q1 = p[0];
            if (p.Length == 3) q2 = p[1];
            return true;
        }

        /// <summary>
        /// The rule for a data name with several possible meanings (04d7b4c8, Owner decision 2: FAIL CLOSED).
        /// Qualifiers filter first: with two, the first names the image and the second the module; with one, it
        /// names an image if any candidate's image matches it, else a module. Each matches the full name or its
        /// stem, case-insensitively. Then two or more genuine FILE records among what is left are AMBIGUOUS: no
        /// candidate is chosen, and <paramref name="message"/> lists each in a form the user can watch instead.
        /// Otherwise the first candidate wins, and the caller lists candidates EXE first, as before.
        /// </summary>
        internal static DataResolve ChooseData(string name, string q1, string q2, IList<DataCandidate> cands,
                                               out DataCandidate chosen, out string message)
        {
            List<string> forms;
            return ChooseData(name, q1, q2, cands, out chosen, out message, out forms);
        }

        /// <summary><see cref="ChooseData(string, string, string, IList{DataCandidate}, out DataCandidate, out string)"/>,
        /// with, on <see cref="DataResolve.Ambiguous"/>, the candidate forms a user can watch instead
        /// (<see cref="PasteableForms"/>); null otherwise.</summary>
        internal static DataResolve ChooseData(string name, string q1, string q2, IList<DataCandidate> cands,
                                               out DataCandidate chosen, out string message, out List<string> forms)
        {
            chosen = null; message = null; forms = null;
            string image = null, module = null;
            if (q2 != null) { image = q1; module = q2; }
            else if (q1 != null)
            {
                foreach (var c in cands) if (NameMatches(c.Image, q1)) { image = q1; break; }
                if (image == null) module = q1;
            }
            var kept = new List<DataCandidate>();
            foreach (var c in cands)
                if ((image == null || NameMatches(c.Image, image)) && (module == null || NameMatches(c.Module, module)))
                    kept.Add(c);
            if (kept.Count == 0) return DataResolve.NotFound;

            var files = kept.FindAll(c => c.FileRecord);
            if (files.Count >= 2)
            {
                string note;
                var all = AmbiguityForms(name, image != null, files, out note);
                message = "ambiguous: " + string.Join(", ", all) + " - watch one of these" + (note != null ? " (" + note + ")" : "");
                forms = PasteableForms(all);
                return DataResolve.Ambiguous;
            }
            chosen = kept[0];
            return DataResolve.Found;
        }

        /// <summary>The forms a watch can actually take: pasteable, and not shared with another candidate (a
        /// shared form would only answer "ambiguous" again). The `sym` reply lists these (3517fd15 item 8).</summary>
        internal static List<string> PasteableForms(List<string> forms)
        {
            var once = new List<string>();
            foreach (var f in forms)
                if (IsPasteableWatchName(f) && forms.FindAll(x => string.Equals(x, f, StringComparison.OrdinalIgnoreCase)).Count == 1)
                    once.Add(f);
            return once;
        }

        /// <summary>The characters a watch name may hold (3517fd15 item 4; the host's IsValidWatchName accepts
        /// these, '-' included from wave 7). A suggested form with any other character cannot be pasted back.</summary>
        internal const string WatchNamePunctuation = "_:$.!@-";

        internal static bool IsPasteableWatchName(string form)
        {
            if (string.IsNullOrEmpty(form)) return false;
            foreach (char c in form)
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                      || WatchNamePunctuation.IndexOf(c) >= 0)) return false;
            return true;
        }

        /// <summary>
        /// One form per candidate that a watch resolves back to it, each as short as tells the candidates apart.
        /// Qualifier schemes are tried in order: the MODULE alone, then the image alone, then both (3517fd15 item
        /// 4). A module name is the source file the user is looking at, and an image name is the one that tends
        /// to hold characters a watch name cannot (a space in "My App.exe"). A user who NAMED an image keeps it.
        /// Within a scheme, candidates the qualifiers do not set apart are named through their own record, as a
        /// watch path: clbrws.exe's CWUTIL.CLW holds OUTFILE$OUTFILE@:RECORD and INFILE$INFILE@:RECORD, and both
        /// answer to BUFFER (measured 2026-09-25). The first scheme whose forms are all distinct and all pasteable
        /// wins; failing that, <paramref name="note"/> says why the forms given cannot all be used.
        /// </summary>
        internal static List<string> AmbiguityForms(string name, bool imageNamed, List<DataCandidate> files, out string note)
        {
            var schemes = imageNamed
                ? new[] { new[] { true, false }, new[] { true, true } }
                : new[] { new[] { false, true }, new[] { true, false }, new[] { true, true } };
            List<string> best = null; bool bestApart = false;
            foreach (var sc in schemes)
            {
                bool apart;
                var forms = FormsUnder(name, files, sc[0], sc[1], out apart);
                if (apart && forms.TrueForAll(IsPasteableWatchName)) { note = null; return forms; }
                if (best == null || (apart && !bestApart)) { best = forms; bestApart = apart; }
            }
            note = bestApart ? "some have no form a watch name can hold" : "some cannot be told apart by name";
            return best;
        }

        /// <summary>The forms under one qualifier scheme; <paramref name="apart"/> is false when two coincide or
        /// a module qualifier is needed for a candidate the line table gives no module.</summary>
        private static List<string> FormsUnder(string name, List<DataCandidate> files, bool withImage, bool withModule,
                                               out bool apart)
        {
            Func<DataCandidate, bool, string> form = (c, viaRecord) =>
                (withImage ? c.Image + "!" : "") + (withModule ? (c.Module ?? "?") + "!" : "")
                + (viaRecord ? c.Loc.Container + "." : "") + name;
            var count = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in files) { string f = form(c, false); int n; count.TryGetValue(f, out n); count[f] = n + 1; }

            var forms = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            apart = true;
            foreach (var c in files)
            {
                bool alone = count[form(c, false)] == 1 && !(withModule && c.Module == null);
                string f = form(c, !alone && c.Loc.Container != null);
                if ((withModule && c.Module == null) || !seen.Add(f)) apart = false;
                forms.Add(f);
            }
            return forms;
        }

        private static bool NameMatches(string actual, string asked)
        {
            if (string.IsNullOrEmpty(actual) || string.IsNullOrEmpty(asked)) return false;
            if (string.Equals(actual, asked, StringComparison.OrdinalIgnoreCase)) return true;
            int dot = actual.LastIndexOf('.');
            return dot > 0 && string.Equals(actual.Substring(0, dot), asked, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Every debuggable image, the EXE first; a DLL only once it has mapped.
        /// <para>
        /// A preloaded solution DLL that has not mapped (not loaded yet, or never) is left out: it has no live
        /// address, so a name it holds would be read at its bare RVA, and as a second candidate it made a FILE
        /// record that the mapped image holds alone read as ambiguous. Two same-named DLLs are two preloads since
        /// 1be3b82e, so one of them loading before the other is the ordinary case, not a rarity.
        /// </para></summary>
        private IEnumerable<LoadedModule> ImagesExeFirst()
        {
            if (_exe != null && _exe.Dbg != null) yield return _exe;
            foreach (var m in _modules)
                if (m != _exe && m.Dbg != null && m.LoadBase != 0) yield return m;
        }

        /// <summary>Resolve a data name (global / record buffer / field), optionally qualified
        /// <c>[image!][module!]name</c>, across all debuggable images through <see cref="ChooseData"/>. Returns
        /// the owning image so the caller can form a live VA + threaded eval against the right
        /// .cwtls/THR$GetInstance. On <see cref="DataResolve.Ambiguous"/>, <paramref name="ambiguity"/> is the
        /// message to show, and there is no location: nothing may be read or offered for edit.</summary>
        private DataResolve ResolveDataAcrossModules(string spec, out LoadedModule owner, out TswdDebugInfo.DataLocation loc,
                                                     out string ambiguity)
        {
            List<string> forms;
            return ResolveDataAcrossModules(spec, out owner, out loc, out ambiguity, out forms);
        }

        /// <summary>The same, with the watchable forms of an ambiguous name (see <see cref="PasteableForms"/>).</summary>
        private DataResolve ResolveDataAcrossModules(string spec, out LoadedModule owner, out TswdDebugInfo.DataLocation loc,
                                                     out string ambiguity, out List<string> forms)
        {
            loc = default(TswdDebugInfo.DataLocation);
            owner = null; ambiguity = null;
            DataCandidate c;
            var r = ResolveData(ImagesExeFirst(), spec, out c, out ambiguity, out forms);
            if (r == DataResolve.Found) { owner = c.Owner; loc = c.Loc; }
            return r;
        }

        /// <summary>The whole lookup over any image list, in the order given: parse the qualifiers, collect every
        /// image's best-ranked candidates, <see cref="ChooseData"/>. Static so the offline `data` command runs
        /// exactly what a live watch runs.</summary>
        internal static DataResolve ResolveData(IEnumerable<LoadedModule> images, string spec, out DataCandidate chosen,
                                                out string ambiguity)
        {
            List<string> forms;
            return ResolveData(images, spec, out chosen, out ambiguity, out forms);
        }

        internal static DataResolve ResolveData(IEnumerable<LoadedModule> images, string spec, out DataCandidate chosen,
                                                out string ambiguity, out List<string> forms)
        {
            chosen = null; ambiguity = null; forms = null;
            string q1, q2, name;
            if (!ParseQualified(spec, out q1, out q2, out name)) return DataResolve.NotFound;
            var cands = new List<DataCandidate>();
            foreach (var m in images)
            {
                if (m == null || m.Dbg == null) continue;
                foreach (var l in m.Dbg.DataNameCandidates(name))
                    cands.Add(new DataCandidate
                    {
                        Image = m.Name, Module = m.Dbg.ModuleNameForIdx(l.ModuleIdx),
                        FileRecord = TswdDebugInfo.IsFileRecordLocation(name, l), Owner = m, Loc = l,
                    });
            }
            return ChooseData(name, q1, q2, cands, out chosen, out ambiguity, out forms);
        }

        /// <summary>The data SYMBOL a watch path's head names, by the same rule: qualifiers from
        /// <paramref name="q1"/>/<paramref name="q2"/>, and two genuine FILE record symbols of that name are
        /// ambiguous. <paramref name="members"/> (".A.B") only completes each form in the message.</summary>
        private DataResolve ResolveDataSymbolAcrossModules(string head, string members, string q1, string q2,
                                                           out LoadedModule owner, out DataSymbol symbol, out string ambiguity)
        {
            DataCandidate c;
            var r = ResolveDataSymbol(ImagesExeFirst(), head, members, q1, q2, out c, out ambiguity);
            owner = c != null ? c.Owner : null;
            symbol = c != null ? c.Symbol : null;
            return r;
        }

        /// <summary><see cref="ResolveDataSymbolAcrossModules"/> over any image list (see <see cref="ResolveData"/>).</summary>
        internal static DataResolve ResolveDataSymbol(IEnumerable<LoadedModule> images, string head, string members,
                                                      string q1, string q2, out DataCandidate chosen, out string ambiguity)
        {
            var cands = new List<DataCandidate>();
            foreach (var m in images)
            {
                if (m == null || m.Dbg == null) continue;
                foreach (var ds in m.Dbg.DataSymbolsNamed(head))
                    cands.Add(new DataCandidate
                    {
                        Image = m.Name, Module = m.Dbg.ModuleNameForIdx(ds.ModuleIdx),
                        FileRecord = TswdDebugInfo.IsFileRecordName(ds.Name), Owner = m, Symbol = ds,
                    });
            }
            return ChooseData(head + members, q1, q2, cands, out chosen, out ambiguity);
        }

        /// <summary>
        /// Split a watch PATH written <c>[image!][module!]HEAD.MEMBER...</c>: the qualifiers first, through
        /// <see cref="ParseQualified"/>, then the rest on '.'. The other order would cut CLBRWS.EXE!CUS:RECORD.CUS:NAME
        /// at the image's own '.'. False when the name is not a path (no member) or is malformed.
        /// <paramref name="members"/> is the ".A.B" tail after the head, as written.
        /// </summary>
        internal static bool SplitWatchPath(string name, out string q1, out string q2, out string head, out string members)
        {
            head = null; members = null;
            string rest;
            if (!ParseQualified(name, out q1, out q2, out rest)) return false;
            int dot = rest.IndexOf('.');
            if (dot <= 0) return false;
            head = rest.Substring(0, dot);
            members = rest.Substring(dot);
            return true;
        }

        /// <summary>A DLL mapped into the target. Resolve its path (via the file handle), parse its
        /// TSWD off disk (or reuse a pre-loaded solution entry), set its live base, and arm any
        /// breakpoints it owns. Tier 3 (no TSWD) is still registered for correct VA attribution.</summary>
        private void OnDllLoaded(uint hFile, uint baseVa)
        {
            try
            {
                // An attach's synthetic LOAD_DLL events may carry no file handle (and never an image name), so
                // fall back to asking the target's memory (DebugEngine.Attach.cs). That answer is the loader's
                // spelling, so it is canonicalized like a preloaded path before anything compares it.
                string path = GetPathFromHandle(hFile) ?? CanonicalImagePath(PathFromMappedImage(baseVa));
                string name = !string.IsNullOrEmpty(path)
                    ? System.IO.Path.GetFileName(path).ToLowerInvariant()
                    : $"(0x{baseVa:x})";

                // The mapped file, parsed once: the claim's build test reads it, and a new entry keeps it.
                PeImage diskPe = null;
                if (!string.IsNullOrEmpty(path) && System.IO.File.Exists(path))
                {
                    try { diskPe = PeImage.Load(path); } catch { diskPe = null; }
                }

                // reuse a pre-loaded solution DLL entry (already has Pe/Dbg parsed): the same file, by path
                LoadedModule m = ClaimUnmapped(_modules, path, name, ReadMappedBuild(rva => ReadU32(baseVa + rva), diskPe));

                if (m != null)
                {
                    m.LoadBase = baseVa;
                    m.MappedPath = path;
                    if (m.Path == null && path != null) m.Path = path;
                    // A same-build claim from another copy KEEPS (borrows) the preloaded Path. The host has already
                    // learned that path as the owner of every breakpoint bound here, and learns an owner once
                    // (ClarionDebuggerService.LearnBpOwner), so renaming it now would split a row from its later
                    // bp-del. That is sound only because ClaimUnmapped proved the SAME build (SameBuild, exactly one
                    // match): the preload's TSWD and symbols describe the image that mapped. The borrow ends if the
                    // preload's own file maps too (YieldBorrowedPaths below).
                    else if (path != null && !SamePath(m.Path, path))
                        Console.WriteLine($"  module: {path} is the same build as preloaded {m.Path}; using that entry");
                }
                else
                {
                    PeImage pe = diskPe; TswdDebugInfo dbg = null;
                    if (pe != null)
                    {
                        try { dbg = TswdDebugInfo.TryFromPe(pe); } catch { pe = null; dbg = null; }
                    }
                    m = new LoadedModule { Path = path, Name = name, Pe = pe, Dbg = dbg, MappedPath = path };
                    m.ResolveThreadedInfo();
                    m.Size = pe != null ? pe.SizeOfImage : ReadRemoteSizeOfImage(baseVa);
                    m.LoadBase = baseVa;
                    _modules.Add(m);
                }
                _liveSyms = null;   // SPIKE: import-symbol table is stale once the module set changes
                if (m.Size == 0) m.Size = ReadRemoteSizeOfImage(baseVa);

                // Two live entries never share a Path (fb5766d1 #3): ImageMatches, |img= narrowing and every
                // ownerPath compare on it. A borrower that yields re-keys its breakpoints on the host through the
                // existing bp-list event (it replaces the host's list wholesale), not through a new wire field.
                var yielded = YieldBorrowedPaths(_modules, m);
                foreach (var y in yielded)
                    Console.WriteLine($"  module: {y.Path} now answers to its own path (its preload's file mapped too)");
                if (yielded.Count > 0 && EmitJson) Console.WriteLine("@JSON " + Json.BpList(_bps));

                PlantOwnBps(m);         // bps already bound to this image (pre-loaded solution DLL)
                ResolvePendingFor(m);    // pending bps whose compiland this image carries
                if (EmitJson) Console.WriteLine("@JSON " + Json.ModuleLoaded(m));
            }
            finally
            {
                CloseHandleValue(hFile);
            }
        }

        /// <summary>A DLL unmapped: drop its armed bytes, return its breakpoints to pending, and
        /// remove it from the table so stale addresses no longer attribute to it.</summary>
        private void OnDllUnloaded(uint baseVa)
        {
            LoadedModule m = null;
            foreach (var im in _modules) if (im.LoadBase == baseVa && im != _exe) { m = im; break; }
            if (m == null) return;

            foreach (var bp in _bps.ToArray())
            {
                if (bp.Owner != m) continue;
                foreach (var rva in bp.Rvas) _armed.Remove(bp.Owner.LoadBase + rva);
                if (HasArmAllSiblingOutside(bp, m))
                {
                    // An arm-all copy whose breakpoint lives on in another image is DROPPED, not returned to
                    // pending (af81c054, pipeline run 1). A pending copy was re-bound on reload AND the
                    // surviving sibling copied itself in again, so the image got two breakpoints - and the
                    // stale one, carrying whatever properties it had when the image left, won every hit.
                    // The sibling re-arms this image when it maps, with the current properties.
                    _bps.Remove(bp);
                    Console.WriteLine($"bp: dropped {bp.Module}:{bp.Line} with {m.Name} (armed elsewhere; re-arms on reload)");
                    if (EmitJson) Console.WriteLine("@JSON " + Json.BpDel(bp));   // Owner still set: the host needs its ownerPath
                    continue;
                }
                bp.Owner = null;          // back to pending; re-arms if the DLL reloads
                bp.ModuleIdx = -1;
            }
            if (EmitJson) Console.WriteLine("@JSON " + Json.ModuleUnloaded(m));
            // Its addresses no longer hold our code (another image may map there next), so a stale-hit claim on
            // them would rewind a thread that the NEW image's own INT3 stopped (DebugEngine.Attach.cs).
            ForgetPlantedIn(m.LoadBase, m.Size);

            // Keep the pre-loaded solution entry (Pe/Dbg) around but mark it unmapped so it re-arms on
            // reload; drop runtime-discovered DLLs so the table doesn't grow across load/unload churn.
            // A borrowed or yielded path goes back to the preload's own, so the next mapping of that file claims
            // it by path; its breakpoints were returned to pending or dropped above, so none still names it.
            if (m.Preloaded && m.Pe != null)
            {
                m.LoadBase = 0;
                m.MappedPath = null;
                if (m.PreloadPath != null && !SamePath(m.Path, m.PreloadPath))
                {
                    m.Path = m.PreloadPath;
                    // The host learns a row's owner once and never unlearns it (LearnBpOwner), so a row that learned
                    // the yielded path would not match this image's next bp-set under the preload path, and would
                    // stay behind as a row nobody can remove (2026-10-03 host audit). The full list re-sync, which the
                    // host applies by replacement, hands it back the now-pending owner (null), to learn afresh.
                    if (EmitJson) Console.WriteLine("@JSON " + Json.BpList(_bps));
                }
            }
            else _modules.Remove(m);
            _liveSyms = null;   // SPIKE: import-symbol table is stale once the module set changes
        }

        /// <summary>The target's mapped PE header offset for the image at <paramref name="baseVa"/>, or 0 (fb5766d1
        /// #7a: the one locator, <see cref="PeHeaderOffset"/>, that every remote header read goes through).</summary>
        private uint RemotePeHeaderOffset(uint baseVa)
        {
            return PeHeaderOffset(rva => ReadU32(baseVa + rva));
        }

        /// <summary>Read SizeOfImage straight from the target's mapped PE header (fallback when the
        /// DLL path/file is unavailable), so VA attribution still has a valid module span. The 0x10000 floor
        /// is for ATTRIBUTION ONLY: build identity reads the real field through ReadMappedBuild, where a header
        /// that does not read is 0 and matches nothing.</summary>
        private uint ReadRemoteSizeOfImage(uint baseVa)
        {
            uint hdr = RemotePeHeaderOffset(baseVa);
            if (hdr == 0) return 0x10000; // sane floor if the header looks odd
            uint size = ReadU32(baseVa + hdr + 24 + 56);
            return size != 0 ? size : 0x10000;
        }
    }
}
