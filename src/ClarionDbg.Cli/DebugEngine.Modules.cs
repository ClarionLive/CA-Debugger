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

        /// <summary>The mapped, debuggable module that owns a TSWD compiland by name (e.g. clbrws011.clw),
        /// or null when no loaded image carries it yet (deferred breakpoint).</summary>
        private LoadedModule OwnerOfModule(string clwName)
        {
            foreach (var m in _modules)
                if (m.HasDebug && m.Dbg.FindModuleIdx(clwName) >= 0) return m;
            return null;
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

            foreach (var bp in _bps)
            {
                if (bp.Owner != m) continue;
                foreach (var rva in bp.Rvas) _armed.Remove(bp.Owner.LoadBase + rva);
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
