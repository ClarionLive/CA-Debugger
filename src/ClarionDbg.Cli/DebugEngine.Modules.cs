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

        /// <summary>Resolve a data name (global / record buffer / field) across all debuggable images,
        /// preferring the EXE. Returns the owning image so the caller can form a live VA + threaded
        /// eval against the right .cwtls/THR$GetInstance.</summary>
        private bool ResolveDataAcrossModules(string name, out LoadedModule owner, out TswdDebugInfo.DataLocation loc)
        {
            loc = default(TswdDebugInfo.DataLocation);
            owner = null;
            if (_exe != null && _exe.Dbg != null && _exe.Dbg.ResolveDataName(name, out loc)) { owner = _exe; return true; }
            foreach (var m in _modules)
            {
                if (m == _exe || m.Dbg == null) continue;
                if (m.Dbg.ResolveDataName(name, out loc)) { owner = m; return true; }
            }
            return false;
        }

        /// <summary>A DLL mapped into the target. Resolve its path (via the file handle), parse its
        /// TSWD off disk (or reuse a pre-loaded solution entry), set its live base, and arm any
        /// breakpoints it owns. Tier 3 (no TSWD) is still registered for correct VA attribution.</summary>
        private void OnDllLoaded(uint hFile, uint baseVa)
        {
            try
            {
                string path = GetPathFromHandle(hFile);
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
