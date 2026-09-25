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
                Size = pe != null ? pe.SizeOfImage : 0,
            };
            m.ResolveThreadedInfo();
            _modules.Add(m);
            return m;
        }

        /// <summary>Pre-parse a solution DLL off disk so its breakpoints resolve before launch.
        /// Failures are non-fatal (the DLL may be rebuilt/absent); it will re-parse at LOAD_DLL.</summary>
        private void TryPreloadSolutionDll(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !System.IO.File.Exists(path)) return;
                string name = System.IO.Path.GetFileName(path).ToLowerInvariant();
                foreach (var m in _modules) if (m.Name == name) return; // already known
                var pe = PeImage.Load(path);
                var dbg = TswdDebugInfo.TryFromPe(pe);
                RegisterImageFromPe(path, pe, dbg, preloaded: true);
            }
            catch { /* best-effort pre-load */ }
        }

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
            chosen = null; message = null;
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
                message = AmbiguityMessage(name, image != null, files);
                return DataResolve.Ambiguous;
            }
            chosen = kept[0];
            return DataResolve.Found;
        }

        /// <summary>"ambiguous: A, B - watch one of these", each form as short as tells the candidates apart:
        /// the image when they span images (or the user named one), the module when one image holds two.</summary>
        private static string AmbiguityMessage(string name, bool imageNamed, List<DataCandidate> files)
        {
            var images = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var perImage = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in files)
            {
                string key = c.Image ?? "";
                images.Add(key);
                int n; perImage.TryGetValue(key, out n); perImage[key] = n + 1;
            }
            bool withImage = imageNamed || images.Count > 1;
            bool withModule = false;
            foreach (var n in perImage.Values) if (n > 1) withModule = true;

            // A field whose image and module do not set it apart is named through its own record instead, as a
            // watch path: clbrws.exe's CWUTIL.CLW holds OUTFILE$OUTFILE@:RECORD and INFILE$INFILE@:RECORD, and
            // both answer to BUFFER (measured 2026-09-25).
            Func<DataCandidate, bool, string> form = (c, viaRecord) =>
                (withImage ? c.Image + "!" : "") + (withModule ? (c.Module ?? "?") + "!" : "")
                + (viaRecord ? c.Loc.Container + "." : "") + name;
            var count = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var c in files) { string f = form(c, false); int n; count.TryGetValue(f, out n); count[f] = n + 1; }

            var forms = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            bool unclear = false;
            foreach (var c in files)
            {
                bool apart = count[form(c, false)] == 1 && !(withModule && c.Module == null);
                string f = form(c, !apart && c.Loc.Container != null);
                if ((withModule && c.Module == null) || !seen.Add(f)) unclear = true;
                forms.Add(f);
            }
            return "ambiguous: " + string.Join(", ", forms) + " - watch one of these"
                   + (unclear ? " (some cannot be told apart by name)" : "");
        }

        private static bool NameMatches(string actual, string asked)
        {
            if (string.IsNullOrEmpty(actual) || string.IsNullOrEmpty(asked)) return false;
            if (string.Equals(actual, asked, StringComparison.OrdinalIgnoreCase)) return true;
            int dot = actual.LastIndexOf('.');
            return dot > 0 && string.Equals(actual.Substring(0, dot), asked, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>Every debuggable image, the EXE first.</summary>
        private IEnumerable<LoadedModule> ImagesExeFirst()
        {
            if (_exe != null && _exe.Dbg != null) yield return _exe;
            foreach (var m in _modules)
                if (m != _exe && m.Dbg != null) yield return m;
        }

        /// <summary>Resolve a data name (global / record buffer / field), optionally qualified
        /// <c>[image!][module!]name</c>, across all debuggable images through <see cref="ChooseData"/>. Returns
        /// the owning image so the caller can form a live VA + threaded eval against the right
        /// .cwtls/THR$GetInstance. On <see cref="DataResolve.Ambiguous"/>, <paramref name="ambiguity"/> is the
        /// message to show, and there is no location: nothing may be read or offered for edit.</summary>
        private DataResolve ResolveDataAcrossModules(string spec, out LoadedModule owner, out TswdDebugInfo.DataLocation loc,
                                                     out string ambiguity)
        {
            loc = default(TswdDebugInfo.DataLocation);
            owner = null; ambiguity = null;
            DataCandidate c;
            var r = ResolveData(ImagesExeFirst(), spec, out c, out ambiguity);
            if (r == DataResolve.Found) { owner = c.Owner; loc = c.Loc; }
            return r;
        }

        /// <summary>The whole lookup over any image list, in the order given: parse the qualifiers, collect every
        /// image's best-ranked candidates, <see cref="ChooseData"/>. Static so the offline `data` command runs
        /// exactly what a live watch runs.</summary>
        internal static DataResolve ResolveData(IEnumerable<LoadedModule> images, string spec, out DataCandidate chosen,
                                                out string ambiguity)
        {
            chosen = null; ambiguity = null;
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
            return ChooseData(name, q1, q2, cands, out chosen, out ambiguity);
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
                // fall back to asking the target's memory (DebugEngine.Attach.cs).
                string path = GetPathFromHandle(hFile) ?? PathFromMappedImage(baseVa);
                string name = !string.IsNullOrEmpty(path)
                    ? System.IO.Path.GetFileName(path).ToLowerInvariant()
                    : $"(0x{baseVa:x})";

                // reuse a pre-loaded solution DLL entry (already has Pe/Dbg parsed) if names match
                LoadedModule m = null;
                foreach (var im in _modules)
                    if (im.LoadBase == 0 && im.Name == name) { m = im; break; }

                if (m != null)
                {
                    m.LoadBase = baseVa;
                    if (m.Path == null && path != null) m.Path = path;
                }
                else
                {
                    PeImage pe = null; TswdDebugInfo dbg = null;
                    if (!string.IsNullOrEmpty(path) && System.IO.File.Exists(path))
                    {
                        try { pe = PeImage.Load(path); dbg = TswdDebugInfo.TryFromPe(pe); } catch { pe = null; dbg = null; }
                    }
                    m = new LoadedModule { Path = path, Name = name, Pe = pe, Dbg = dbg };
                    m.ResolveThreadedInfo();
                    m.Size = pe != null ? pe.SizeOfImage : ReadRemoteSizeOfImage(baseVa);
                    m.LoadBase = baseVa;
                    _modules.Add(m);
                }
                _liveSyms = null;   // SPIKE: import-symbol table is stale once the module set changes
                if (m.Size == 0) m.Size = ReadRemoteSizeOfImage(baseVa);

                PlantOwnBps(m);          // bps already bound to this image (pre-loaded solution DLL)
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
            if (m.Preloaded && m.Pe != null) m.LoadBase = 0;
            else _modules.Remove(m);
            _liveSyms = null;   // SPIKE: import-symbol table is stale once the module set changes
        }

        /// <summary>Read SizeOfImage straight from the target's mapped PE header (fallback when the
        /// DLL path/file is unavailable), so VA attribution still has a valid module span.</summary>
        private uint ReadRemoteSizeOfImage(uint baseVa)
        {
            uint eLfanew = ReadU32(baseVa + 0x3C);
            if (eLfanew == 0 || eLfanew > 0x1000) return 0x10000; // sane floor if the header looks odd
            uint optOff = baseVa + eLfanew + 24;
            uint size = ReadU32(optOff + 56);
            return size != 0 ? size : 0x10000;
        }
    }
}
