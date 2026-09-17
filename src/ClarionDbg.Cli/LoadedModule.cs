using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    /// <summary>
    /// One image mapped into the debuggee: the EXE plus every loaded DLL. The module table is the
    /// foundation for multi-DLL debugging — all live VA math is done relative to the owning image's
    /// <see cref="LoadBase"/>, and address/symbol resolution goes through that image's <see cref="Dbg"/>.
    ///
    /// Capability tier (set at registration):
    ///   1 = TSWD present AND source resolvable by the host  -> full source-level debugging
    ///   2 = TSWD present, source not resolvable             -> address->line + symbols (stack only)
    ///   3 = no TSWD (ClaRUN, Windows, non-debug DLLs)       -> base+size+name for attribution only
    /// The engine itself only knows TSWD-present (1/2 share <see cref="Dbg"/>) vs absent (3, Dbg null);
    /// the host (addin) decides 1-vs-2 from source resolvability and drives the source UI accordingly.
    /// </summary>
    internal sealed class LoadedModule
    {
        public string Path;            // full disk path (EXE arg, or GetFinalPathNameByHandle of the DLL)
        public string Name;            // file name, lowercased (e.g. myapp.dll)
        public uint LoadBase;          // runtime base from the debug event (honors ASLR/relocation)
        public uint Size;              // PE SizeOfImage — defines [LoadBase, LoadBase+Size)
        public PeImage Pe;             // null when the file could not be read (rare; Tier 3 keeps base+size)
        public TswdDebugInfo Dbg;      // null for Tier 3 (no TSWD)
        public bool Preloaded;         // true = registered from the solution list (kept on unload); false = runtime-discovered (dropped on unload)

        // per-module threaded-data eval (Tier 1/2 only; 0 when the image has no .cwtls / no import)
        public uint CwtlsLo, CwtlsHi;          // .cwtls section RVA range (file-aligned Span: may include padding)
        public uint CwtlsDataSize;             // .cwtls VirtualSize — the DECLARED threaded-data size, which is
                                               // what the RTL allocates per thread. CwtlsHi-CwtlsLo is
                                               // max(VirtualSize, SizeOfRawData) and so can run up to
                                               // FileAlignment-1 bytes past a real instance block, into
                                               // unrelated heap. Harmless for the template range (it only
                                               // covers this image's own padding); NOT harmless for an
                                               // instance-block window, which would over-refuse writes to
                                               // whatever the allocator put next.
        public uint ThrGetInstanceIatRva;      // IAT slot RVA of ClaRUN.dll!THR$GetInstance

        public bool HasDebug { get { return Dbg != null; } }
        public bool HasThreadedData { get { return CwtlsHi != 0 && ThrGetInstanceIatRva != 0; } }

        public bool ContainsVa(uint va) { return va >= LoadBase && va < LoadBase + Size; }

        /// <summary>Build per-module threaded-eval ranges from the parsed PE (.cwtls + THR$GetInstance IAT).</summary>
        public void ResolveThreadedInfo()
        {
            if (Pe == null) return;
            var cwtls = Pe.FindSection(".cwtls");
            uint iat = Pe.FindImportIatSlotRva("ClaRUN.dll", "THR$GetInstance");
            if (cwtls != null)
            {
                CwtlsLo = cwtls.VirtualAddress;
                CwtlsHi = cwtls.VirtualAddress + cwtls.Span;
                CwtlsDataSize = cwtls.VirtualSize != 0 ? cwtls.VirtualSize : cwtls.Span;
            }
            ThrGetInstanceIatRva = iat;
        }
    }
}
