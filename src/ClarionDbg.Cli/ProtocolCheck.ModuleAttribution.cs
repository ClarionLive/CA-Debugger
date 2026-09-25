using System;
using System.Collections.Generic;
using System.Text;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// Per-symbol module ATTRIBUTION (52458d89), through the real TswdDebugInfo constructor over a blob built
        /// here (<see cref="BuildAttributionBlob"/>). The mismodel it guards against: reading a symbol's +0x28
        /// backref slot as an index into the module-name array. The fixture's backref slots all land INSIDE the
        /// three-name range, so an out-of-range test cannot catch the mismodel. Slot 1 means C.CLW, not B.CLW,
        /// and slot 2 is shared by two modules. The old attribution read the slot as the module: it passed
        /// P2 and P5, whose slot 0 does mean A.CLW, and failed every other line.
        ///
        /// NOT COVERED: the readers themselves. Program's `symbols --module` / `globals --module` filters compare
        /// ModuleIdx with FindModuleIdx; that comparison is asserted here, not the command. The module-data
        /// panel's predicate (<see cref="DebugEngine.InFrameModule"/>) is asserted, not the live handler that calls it.
        /// </summary>
        private static void CheckModuleAttributionFromParsedBlob(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a parsed TSWD blob whose backref slots all fall inside the module-name range attributes "
                         + "each code symbol to the line-table module at its entry (a prologue before its first record, "
                         + "and glue with no record, through its slot's agreed module, which only symbols with a record AT their "
                         + "entry set, so a mid-procedure stray hit does not vote, or failing those its boundary symbols), a boundary symbol its slot cannot settle "
                         + "to none (-1), each data symbol to its slot's agreed module or to none when the slot names two; "
                         + "the definition line follows it, and the module-data filter never matches an unproven module.");

            TswdDebugInfo dbg;
            try { dbg = new TswdDebugInfo(BuildAttributionBlob(), 0, 0x0F00, 0x2000, 0x10000); }
            catch (Exception ex) { failures.Add("module attribution: the fixture blob did not parse - " + ex.Message); return; }

            if (dbg.ModuleNames.Count != 3)
                failures.Add("module attribution: the fixture has " + dbg.ModuleNames.Count + " module name(s), expected 3");

            var code = new Dictionary<string, ProcSymbol>(StringComparer.Ordinal);
            foreach (var s in dbg.Symbols) code[s.Name] = s;
            var data = new Dictionary<string, DataSymbol>(StringComparer.Ordinal);
            foreach (var d in dbg.DataSymbols) data[d.Name] = d;

            // name -> (backref slot, expected module or null for unproven, expected definition line or -1 = not asserted)
            Action<string, int, string, int> expectCode = (name, slot, module, defLine) =>
            {
                ProcSymbol s;
                if (!code.TryGetValue(name, out s)) { failures.Add("module attribution: code symbol " + name + " was not parsed"); return; }
                if (s.BackrefSlot != slot)
                    failures.Add("module attribution: " + name + " has backref slot " + s.BackrefSlot + ", expected " + slot + " (fixture)");
                int want = module == null ? -1 : dbg.FindModuleIdx(module);
                if (s.ModuleIdx != want)
                    failures.Add("module attribution: " + name + " (slot " + slot + ") was attributed to "
                                 + (dbg.ModuleNameForIdx(s.ModuleIdx) ?? "none (" + s.ModuleIdx + ")") + ", expected "
                                 + (module ?? "none"));
                if (defLine >= 0 && dbg.DefinitionLine(s) != defLine)
                    failures.Add("module attribution: " + name + " definition line " + dbg.DefinitionLine(s) + ", expected " + defLine);
            };
            Action<string, int, string> expectData = (name, slot, module) =>
            {
                DataSymbol d;
                if (!data.TryGetValue(name, out d)) { failures.Add("module attribution: data symbol " + name + " was not parsed"); return; }
                if (d.BackrefSlot != slot)
                    failures.Add("module attribution: " + name + " has backref slot " + d.BackrefSlot + ", expected " + slot + " (fixture)");
                int want = module == null ? -1 : dbg.FindModuleIdx(module);
                if (d.ModuleIdx != want)
                    failures.Add("module attribution: data " + name + " (slot " + slot + ") was attributed to "
                                 + (dbg.ModuleNameForIdx(d.ModuleIdx) ?? "none (" + d.ModuleIdx + ")") + ", expected "
                                 + (module ?? "none"));
            };

            // The lowest symbol: no record below it, and its first record is past its entry. Its slot 2 settles
            // nothing, so only the line table can name A.
            expectCode("P0", 2, "A.CLW", 1);
            expectCode("P1", 1, "C.CLW", 10);        // slot 1 is in range and names B; its code is C's
            expectCode("P2", 0, "A.CLW", 5);         // control: slot 0 does mean A
            expectCode("P5", 0, "A.CLW", 40);        // prologue before its first record: A is B.CLW's tail
            // No record of its own: P6's record lies above it, past its range, so slot 1's C decides.
            expectCode("GLUE$$$__attach_process", 1, "C.CLW", -1);
            expectCode("P3", 2, "A.CLW", 20);        // slot 2's voters disagree, but each has its own record
            expectCode("P4", 2, "B.CLW", 30);
            // Mid-procedure, as the scan's stray hits are: the line table says C. It must not vote, or slot 0
            // would name A and C and P5 would lose A.CLW.
            expectCode("STRAY", 0, "C.CLW", -1);
            expectCode("P6", 1, null, -1);           // on a boundary (A below, B above) its slot's C is neither
            // A PROGRAM module's _main: a prologue with no record, alone in its slot. Its boundary vote is
            // the slot's only one, so it and the slot's data take its own first record's module.
            expectCode("PM", 3, "C.CLW", 60);
            expectData("G3", 3, "C.CLW");
            expectData("G1", 1, "C.CLW");
            expectData("G2", 2, null);               // slot 2 names A and B: fail closed

            // What `symbols --module C` keeps: the filter compares ModuleIdx with FindModuleIdx.
            int c = dbg.FindModuleIdx("C");
            var kept = new List<string>();
            foreach (var s in dbg.Symbols) if (s.ModuleIdx == c) kept.Add(s.Name);
            kept.Sort(StringComparer.Ordinal);
            string got = string.Join(",", kept);
            if (got != "GLUE$$$__attach_process,P1,PM,STRAY")
                failures.Add("module attribution: the --module C filter keeps [" + got + "], expected [GLUE$$$__attach_process,P1,PM,STRAY]");

            // The module-data panel's filter: a data symbol with no proven module is in no frame's module, and
            // a frame whose module is unknown shows nothing, even though -1 == -1.
            if (!DebugEngine.InFrameModule(2, 2) || DebugEngine.InFrameModule(2, 1)
                || DebugEngine.InFrameModule(-1, -1) || DebugEngine.InFrameModule(2, -1) || DebugEngine.InFrameModule(-1, 2))
                failures.Add("module attribution: InFrameModule must hold only for two equal proven modules");
        }

        /// <summary>
        /// A minimal TSWD blob for <see cref="CheckModuleAttributionFromParsedBlob"/>. Offsets are blob-relative
        /// (base 0) and follow TswdDebugInfo: the TOC at 0; the module-name offset array and pool; an 8-byte
        /// zeroed range entry per module (no +0x10 code slices); empty line tables A and B; the +0x1C address
        /// table of {u32 rva, u16 line, u16 moduleIdx}; the symbol pool; the +0x28 backref array; then the
        /// +0x2C stream, which holds the scalar type and the 12-byte definitions. Text is RVA 0x0F00..0x2000.
        ///
        /// Modules: 0 A.CLW, 1 B.CLW, 2 C.CLW. Backref slots: 0 -> A's code, 1 -> C's code, 2 -> code of both
        /// A and B, 3 -> only a boundary symbol. Code, in address order:
        ///   P0 @0x0F80 slot 2: first record 0x0F90 (A, line 1), none below it
        ///   P1 @0x1000 slot 1: records 0x1000 (C, line 10), 0x1010 (C, 11)
        ///   STRAY @0x1008 slot 0: a definition in the middle of P1's code, with no record at its entry
        ///   P2 @0x1100 slot 0: record 0x1100 (A, 5)
        ///   P3 @0x1200 slot 2: record 0x1200 (A, 20)
        ///   P4 @0x1300 slot 2: records 0x1300 (B, 30), 0x13F0 (B, 31)
        ///   P5 @0x1400 slot 0: first record 0x1408 (A, 40), so the record below its entry is B's 0x13F0
        ///   GLUE$$$__attach_process @0x1500 slot 1: no record in [0x1500, 0x1600)
        ///   P6 @0x1600 slot 1: first record 0x1608 (B, 50); the record below its entry is A's 0x1408
        ///   PM @0x1700 slot 3, the slot's only code: first record 0x1710 (C, 60), B's 0x1608 below it
        /// Data at 0x3000 (G1, slot 1), 0x3004 (G2, slot 2) and 0x3008 (G3, slot 3).
        /// </summary>
        private static byte[] BuildAttributionBlob()
        {
            var modules = new[] { "A.CLW", "B.CLW", "C.CLW" };
            uint[] backref = { 0xB0000A00, 0xB0000C00, 0xB00AB000, 0xB0000C03 };   // slot i's value, distinct from any other field

            var names = new[] { "P0@F", "P1@F", "P2@F", "P3@F", "P4@F", "P5@F", "GLUE$$$__attach_process", "STRAY", "P6@F", "PM", "G1", "G2", "G3" };
            var pool = new List<byte> { 0 };                  // leading NUL: every name NUL-preceded
            var nameRef = new Dictionary<string, uint>();
            foreach (var n in names) { nameRef[n] = (uint)pool.Count; pool.AddRange(Encoding.ASCII.GetBytes(n)); pool.Add(0); }
            while (pool.Count % 4 != 0) pool.Add(0);

            var modPoolBytes = new List<byte>();
            var modOff = new uint[modules.Length];
            for (int i = 0; i < modules.Length; i++)
            { modOff[i] = (uint)modPoolBytes.Count; modPoolBytes.AddRange(Encoding.ASCII.GetBytes(modules[i])); modPoolBytes.Add(0); }
            while (modPoolBytes.Count % 4 != 0) modPoolBytes.Add(0);

            // {rva, line, module}, ascending
            var recs = new[]
            {
                new[] { 0x0F90u, 1u, 0u },
                new[] { 0x1000u, 10u, 2u }, new[] { 0x1010u, 11u, 2u },
                new[] { 0x1100u, 5u, 0u },
                new[] { 0x1200u, 20u, 0u },
                new[] { 0x1300u, 30u, 1u }, new[] { 0x13F0u, 31u, 1u },
                new[] { 0x1408u, 40u, 0u },
                new[] { 0x1608u, 50u, 1u },
                new[] { 0x1710u, 60u, 2u },
            };

            const int modArray = 0x40;
            int modPool = modArray + 4 * modules.Length;
            int modRange = modPool + modPoolBytes.Count;
            int lines = modRange + 8 * modules.Length;      // tables A and B are empty: both start here
            int addrTable = lines;
            int symPool = addrTable + 8 * recs.Length;
            int symNameArray = symPool + pool.Count;
            int t2c = symNameArray + 4 * backref.Length;
            const int streamLen = 0x100;
            int t34 = t2c + streamLen;
            var b = new byte[t34 + 0x40];

            Action<int, uint> u32 = (at, v) => BitConverter.GetBytes(v).CopyTo(b, at);
            Action<int, ushort> u16 = (at, v) => BitConverter.GetBytes(v).CopyTo(b, at);
            u32(0x00, TswdDebugInfo.TswdMagic);
            u32(0x04, 0x38);
            u32(0x08, modArray); u32(0x0C, (uint)modPool); u32(0x10, (uint)modRange);
            u32(0x14, (uint)lines); u32(0x18, (uint)lines); u32(0x1C, (uint)addrTable);
            u32(0x20, (uint)symPool); u32(0x24, (uint)backref.Length); u32(0x28, (uint)symNameArray);
            u32(0x2C, (uint)t2c); u32(0x30, (uint)names.Length); u32(0x34, (uint)t34);

            for (int i = 0; i < modules.Length; i++) u32(modArray + 4 * i, modOff[i]);
            modPoolBytes.ToArray().CopyTo(b, modPool);
            for (int i = 0; i < recs.Length; i++)
            {
                int at = addrTable + 8 * i;
                u32(at, recs[i][0]); u16(at + 4, (ushort)recs[i][1]); u16(at + 6, (ushort)recs[i][2]);
            }
            pool.ToArray().CopyTo(b, symPool);
            for (int i = 0; i < backref.Length; i++) u32(symNameArray + 4 * i, backref[i]);

            // Stream: a LONG type at +0x10, then definitions. A data definition is `04 typeRef | nameRef rva
            // backref | tail` and its scalar tail says code 0x11, size 4. Code definitions are the bare triple.
            const int tLong = 0x10;
            b[t2c + tLong] = 0x11; u32(t2c + tLong + 1, 4);
            int p = t2c + 0x20;
            Action<string, uint, int> def = (name, rva, slot) =>
            {
                u32(p, nameRef[name]); u32(p + 4, rva); u32(p + 8, backref[slot]);
                p += 16;
            };
            def("P0@F", 0x0F80, 2);
            def("P1@F", 0x1000, 1);
            def("P2@F", 0x1100, 0);
            def("P3@F", 0x1200, 2);
            def("P4@F", 0x1300, 2);
            def("P5@F", 0x1400, 0);
            def("GLUE$$$__attach_process", 0x1500, 1);
            def("STRAY", 0x1008, 0);
            def("P6@F", 0x1600, 1);
            def("PM", 0x1700, 3);
            Action<string, uint, int> dataDef = (name, rva, slot) =>
            {
                b[p] = 0x04; u32(p + 1, tLong);
                int o = p + 5;
                u32(o, nameRef[name]); u32(o + 4, rva); u32(o + 8, backref[slot]);
                b[o + 12] = 0x11; u32(o + 13, 4);
                p += 0x20;
            };
            dataDef("G1", 0x3000, 1);
            dataDef("G2", 0x3004, 2);
            dataDef("G3", 0x3008, 3);
            return b;
        }
    }
}
