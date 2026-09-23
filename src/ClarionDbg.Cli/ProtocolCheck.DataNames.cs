using System;
using System.Collections.Generic;
using System.Text;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// The FILE-record SHAPE test that the module-data panel and the name index share (04d7b4c8 item 2).
        /// The two callers want different verdicts on a scoped PROC::FILE$PRE:RECORD, so the predicate is
        /// scope-agnostic and DataNameRank adds its own no-"::" condition. CheckFieldNameResolvesToFileRecord
        /// covers that rank half. This covers the shape half, including the name the old ":RECORD" suffix
        /// test got wrong. That the panel CALLS it is source-level only (tools/test-file-record-predicate.ps1).
        /// </summary>
        private static void CheckFileRecordShape(List<string> failures, ClaimLog claims)
        {
            claims.Claim("one FILE-record shape test (carries '$', ends \":RECORD\", any case, scoped or not) is "
                         + "true for FILE$PRE:RECORD and PROC::FILE$PRE:RECORD, and false for a form's "
                         + "HISTORY::PRE:RECORD, a '$' name without the suffix, the suffix without a '$', and null.");

            var yes = new[] { "COUNTRIES$COU:RECORD", "countries$cou:record", "UPDATE::LOCAL$COU:RECORD" };
            var no  = new[] { "HISTORY::COU:RECORD", "VMT$COUNTRYGROUP", "COU:RECORD", "SAVE:COUNTRY", "", null };
            foreach (var n in yes)
                if (!TswdDebugInfo.IsFileRecordName(n))
                    failures.Add("file-record shape: " + n + " is a file record buffer's name but was not recognised");
            foreach (var n in no)
                if (TswdDebugInfo.IsFileRecordName(n))
                    failures.Add("file-record shape: " + (n ?? "(null)") + " was counted as a file record buffer");
        }

        /// <summary>
        /// The name index built by the PARSER, not by hand (04d7b4c8 item 3). CheckFieldNameResolvesToFileRecord
        /// drives RegisterDataName with hand-built DataLocations; nothing else tested the three places
        /// BuildDataNameIndex feeds it. This builds a minimal TSWD blob (<see cref="BuildNameIndexBlob"/>),
        /// hands it to the real TswdDebugInfo constructor, and asks ResolveDataName. The three sites:
        ///  (a) every data symbol registers its OWN name, container null (a static and the groups themselves);
        ///  (b) a symbol whose typeRef resolves to a GROUP registers each member through RegisterTypeLeaves;
        ///  (c) a symbol whose typeRef does NOT resolve registers the legacy tag-0C field records.
        /// Each field pair repeats demoleg's shape: a form's HISTORY:: copy at a LOWER RVA, so it
        /// registers first, then the FILE record buffer that must win.
        ///
        /// NOT COVERED: that the blob is byte-faithful to real compiler output in every respect. It holds only
        /// the fields the constructor reads on this path, laid out as TswdDebugInfo documents them. Each
        /// symbol's path is asserted (Type group vs Fields only), so a fixture that silently fell into the
        /// other branch fails rather than passes. A real image would pin more, but would need an app built
        /// with full debug info checked into the repo.
        /// </summary>
        private static void CheckDataNameIndexFromParsedBlob(List<string> failures, ClaimLog claims)
        {
            claims.Claim("the name index BuildDataNameIndex builds from a PARSED TSWD blob resolves a static and "
                         + "a group to their own RVA with no container, a NESTED group's leaf through the recursive "
                         + "leaf walk, and a field repeated by a HISTORY:: copy registered first to the FILE record buffer - through both the typeRef-group leaf path "
                         + "and the legacy field-record path. Not covered: byte-faithfulness to real compiler output.");

            TswdDebugInfo dbg;
            try { dbg = new TswdDebugInfo(BuildNameIndexBlob(), 0, 0x1000, 0x2000, 0x10000); }
            catch (Exception ex) { failures.Add("parsed name index: the fixture blob did not parse - " + ex.Message); return; }

            // Which path each symbol took. Without this, a fixture whose group typeRef stopped resolving would
            // fall back to the field-record scan and the resolution lines below could still pass.
            var byName = new Dictionary<string, DataSymbol>(StringComparer.OrdinalIgnoreCase);
            foreach (var ds in dbg.DataSymbols) byName[ds.Name] = ds;
            if (dbg.DataSymbols.Count != 5)
                failures.Add("parsed name index: the parser found " + dbg.DataSymbols.Count + " data symbol(s) in the fixture, expected 5");
            foreach (var g in new[] { "HISTORY::COU:RECORD", "COUNTRIES$COU:RECORD" })
            {
                DataSymbol ds;
                if (!byName.TryGetValue(g, out ds) || ds.Type == null || ds.Type.Kind != TypeKind.Group)
                    failures.Add("parsed name index: " + g + " did not take the typeRef-GROUP path (site b)");
            }
            foreach (var g in new[] { "HISTORY::CUS:RECORD", "CUSTOMER$CUS:RECORD" })
            {
                DataSymbol ds;
                if (!byName.TryGetValue(g, out ds) || (ds.Type != null && ds.Type.Kind == TypeKind.Group)
                    || ds.Fields == null || ds.Fields.Count != 1)
                    failures.Add("parsed name index: " + g + " did not take the legacy field-record path (site c)");
            }

            Action<string, uint, string> expect = (name, rva, container) =>
            {
                TswdDebugInfo.DataLocation loc;
                if (!dbg.ResolveDataName(name, out loc))
                    failures.Add("parsed name index: " + name + " did not resolve at all");
                else if (loc.Rva != rva || !string.Equals(loc.Container, container, StringComparison.Ordinal))
                    failures.Add("parsed name index: " + name + " resolved to 0x" + loc.Rva.ToString("X") + " in "
                                 + (loc.Container ?? "(no container)") + ", expected 0x" + rva.ToString("X") + " in "
                                 + (container ?? "(no container)"));
            };
            // (a) own names
            expect("SAV:TOTAL", 0x3200, null);
            expect("HISTORY::COU:RECORD", 0x3000, null);
            expect("COUNTRIES$COU:RECORD", 0x5000, null);
            // (b) typeRef group leaves: top-level members at their offsets, and a NESTED group's leaf,
            // which only the recursive leaf walk registers
            expect("COU:COUNTRY", 0x5000, "COUNTRIES$COU:RECORD");
            expect("COU:CODE", 0x5004, "COUNTRIES$COU:RECORD");
            expect("COU:CITY", 0x5008, "COUNTRIES$COU:RECORD");
            // (c) legacy field records
            expect("CUS:NAME", 0x5100, "CUSTOMER$CUS:RECORD");
        }

        /// <summary>
        /// A minimal TSWD blob for <see cref="CheckDataNameIndexFromParsedBlob"/>: one module, no line tables,
        /// five data symbols. Offsets are blob-relative (base 0). The layout follows TswdDebugInfo: TOC at 0,
        /// module-name array + pool, an empty line/address region, the symbol pool, the +0x28 backref array,
        /// then the +0x2C record stream holding the type, member and data records. Every typeRef/memberRef
        /// is relative to the stream start. Text is RVA 0x1000..0x2000, so the data RVAs at 0x3000+ are
        /// classified as data.
        /// </summary>
        private static byte[] BuildNameIndexBlob()
        {
            const uint Backref = 0x00C0FFEE;
            var names = new[] { "HISTORY::COU:RECORD", "COUNTRIES$COU:RECORD", "COU:COUNTRY", "COU:CODE", "COU:ADDRESS", "COU:CITY",
                                "HISTORY::CUS:RECORD", "CUSTOMER$CUS:RECORD", "CUS:NAME", "SAV:TOTAL" };

            // Symbol pool: a leading NUL so every name is NUL-preceded, as SymbolNameAt requires.
            var pool = new List<byte> { 0 };
            var nameRef = new Dictionary<string, uint>();
            foreach (var n in names) { nameRef[n] = (uint)pool.Count; pool.AddRange(Encoding.ASCII.GetBytes(n)); pool.Add(0); }
            while (pool.Count % 4 != 0) pool.Add(0);

            const int modArray = 0x40, modPool = 0x44, modRange = 0x50, lines = 0x58, symPool = lines;
            int symNameArray = symPool + pool.Count;
            int t2c = symNameArray + 4;                       // one backref entry
            const int streamLen = 0x200;
            int t34 = t2c + streamLen;
            var b = new byte[t34 + 0x40];

            Action<int, uint> u32 = (at, v) => BitConverter.GetBytes(v).CopyTo(b, at);
            u32(0x00, TswdDebugInfo.TswdMagic);
            u32(0x04, 0x38);
            u32(0x08, modArray); u32(0x0C, modPool); u32(0x10, modRange);
            u32(0x14, lines); u32(0x18, lines); u32(0x1C, lines);
            u32(0x20, (uint)symPool); u32(0x24, 1); u32(0x28, (uint)symNameArray); u32(0x2C, (uint)t2c);
            u32(0x30, (uint)names.Length); u32(0x34, (uint)t34);

            u32(modArray, 0);                                 // module 0's name at pool offset 0
            Encoding.ASCII.GetBytes("demo.clw").CopyTo(b, modPool);
            // modRange stays zero: no code slice.
            pool.ToArray().CopyTo(b, symPool);
            u32(symNameArray, Backref);                       // backref value -> module index 0

            // Stream records, at stream-relative offsets.
            // Record extents: a member is 13 bytes, a group 9 + 4 per member. Keep them apart.
            const uint tLong = 0x10, mCity = 0x180, tAddr = 0x190, mCountry = 0x30, mCode = 0x40, mAddr = 0x1A0, tGroup = 0x50;
            Action<uint, uint> s32 = (rel, v) => u32(t2c + (int)rel, v);
            Action<uint, byte> s8 = (rel, v) => b[t2c + (int)rel] = v;

            s8(tLong, 0x11); s32(tLong + 1, 4);               // LONG

            // A nested GROUP member (COU:ADDRESS, holding COU:CITY). Only RegisterTypeLeaves recurses into it;
            // the Fields list is top-level only, so COU:CITY resolving proves site (b) ran, not (c).
            s8(mCity, 0x0C); s32(mCity + 1, tLong); s32(mCity + 5, nameRef["COU:CITY"]); s32(mCity + 9, 0);
            s8(tAddr, 0x08); s32(tAddr + 1, 4); s32(tAddr + 5, 1); s32(tAddr + 9, mCity);

            s8(mCountry, 0x0C); s32(mCountry + 1, tLong); s32(mCountry + 5, nameRef["COU:COUNTRY"]); s32(mCountry + 9, 0);
            s8(mCode, 0x0C);    s32(mCode + 1, tLong);    s32(mCode + 5, nameRef["COU:CODE"]);       s32(mCode + 9, 4);
            s8(mAddr, 0x0C);    s32(mAddr + 1, tAddr);    s32(mAddr + 5, nameRef["COU:ADDRESS"]);    s32(mAddr + 9, 8);
            s8(tGroup, 0x08); s32(tGroup + 1, 12); s32(tGroup + 5, 3);
            s32(tGroup + 9, mCountry); s32(tGroup + 13, mCode); s32(tGroup + 17, mAddr);

            // A data record: 04 typeRef | nameRef rva backref | tail. Returns the stream offset of nameRef,
            // which is the parser's `o`.
            Func<uint, uint, string, uint, uint> data = (rel, typeRef, name, rva) =>
            {
                s8(rel, 0x04); s32(rel + 1, typeRef);
                s32(rel + 5, nameRef[name]); s32(rel + 9, rva); s32(rel + 13, Backref);
                return rel + 5;
            };

            // (b) two symbols sharing the group type, as LIKE() does. HISTORY at the lower RVA.
            data(0x70, tGroup, "HISTORY::COU:RECORD", 0x3000);
            data(0x90, tGroup, "COUNTRIES$COU:RECORD", 0x5000);

            // (c) typeRef that does not resolve, so the parser takes the aggregate tail + tag-0C field records.
            // The same u32 is the parent key those field records match.
            Action<uint, uint, string, uint> legacy = (rel, key, name, rva) =>
            {
                uint o = data(rel, key, name, rva);
                s8(o + 12, 0x00); s8(o + 13, 0x08); s32(o + 14, 8); s32(o + 18, 1);   // aggregate, size 8, 1 field
                uint p = o + 22 + 4;                          // past the one-entry child-pointer array
                s8(p, 0x0C); s32(p + 5, nameRef["CUS:NAME"]); s32(p + 9, 0); s32(p + 13, key);
                s8(p + 17, 0x11); s32(p + 18, 4);
            };
            legacy(0xB0, 0x7FFF0001, "HISTORY::CUS:RECORD", 0x3100);
            legacy(0x100, 0x7FFF0002, "CUSTOMER$CUS:RECORD", 0x5100);

            // (a) a scalar static: its typeRef resolves to a LONG, not a group; scalar tail disc=code.
            uint so = data(0x150, tLong, "SAV:TOTAL", 0x3200);
            s8(so + 12, 0x11); s32(so + 13, 4);
            return b;
        }
    }
}
