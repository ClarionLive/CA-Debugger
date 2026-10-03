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
                         + "claim nothing (a new entry); a readable copy with the same link time and size but different debug data "
                         + "claims nothing, and an unreadable one claims only when its mapped header's link time, size, checksum and "
                         + "debug entry (type, link time, data size) all read and match, so a header with no size never matches a "
                         + "preload of the old 0x10000 floor, and two copies with empty debug data are not one build (fb5766d1 #2).");

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

                PeImage.DebugEntry fixtureDbg;
                if (!ea.Pe.TryReadFirstDebugEntry(out fixtureDbg) || fixtureDbg.SizeOfData == 0)
                { failures.Add("same-name dlls: fixture precondition - ClarionDbg.Core.dll has no debug entry, so no build identity can be tested"); return; }

                var table = eng.ModulesForTest();
                // A READABLE mapped file: its own PE is what ClaimUnmapped compares, mapped with link time `stamp`.
                Func<string, uint, LoadedModule> claim = (path, stamp) =>
                {
                    var disk = PeImage.Load(path);
                    var mb = new DebugEngine.MappedBuild { DiskPe = disk, Stamp = stamp, Size = disk.SizeOfImage };
                    return DebugEngine.ClaimUnmapped(table, DebugEngine.CanonicalImagePath(path), "shared.dll", mb);
                };

                if (claim(bPath, 0x22222222) != eb) failures.Add("same-name dlls: B mapping from its own path did not claim B's entry");
                if (claim(a, 0x11111111) != ea) failures.Add("same-name dlls: A mapping from its own path did not claim A's entry");
                // B loads with A's link time (cannot happen, but it isolates the path branch from the build branch).
                if (claim(bPath, 0x11111111) != eb) failures.Add("same-name dlls: the path match must win over a same-build match elsewhere");
                if (claim(copyOfA, 0x11111111) != ea) failures.Add("same-name dlls: a same-build copy of A from another directory did not claim A's entry");
                if (claim(copyOfA, 0x44444444) != null) failures.Add("same-name dlls: a DIFFERENT build of shared.dll from another directory claimed an entry");
                if (claim(copyOfA, 0) != null) failures.Add("same-name dlls: an unreadable mapped header (link time 0) claimed an entry");

                // fb5766d1 #2, READABLE: the same link time and size, one byte of debug data different, is another build.
                byte[] aBytes = File.ReadAllBytes(a);
                var aPe = new PeImage(aBytes);
                int dbgEntryOff = (int)aPe.RvaToOffset(aPe.DebugDirRva);
                int peHdr = BitConverter.ToInt32(aBytes, 0x3C), optHdr = peHdr + 24;
                Func<string, Action<byte[]>, string> writeVariant = (dir, patch) =>
                {
                    var b = (byte[])aBytes.Clone();
                    patch(b);
                    string d = Path.Combine(root, dir);
                    Directory.CreateDirectory(d);
                    string f = Path.Combine(d, "shared.dll");
                    File.WriteAllBytes(f, b);
                    return f;
                };
                string otherDebug = writeVariant("OtherDebug", b => b[fixtureDbg.PointerToRawData + fixtureDbg.SizeOfData / 2] ^= 0xFF);
                if (claim(otherDebug, 0x11111111) != null)
                    failures.Add("same-name dlls: a readable copy whose debug data differs (same link time and size) claimed A's entry");

                // UNREADABLE: the mapped header alone (DiskPe null), read through the REAL ReadMappedBuild over the bytes.
                Func<byte[], LoadedModule> claimHeader = bytes =>
                    DebugEngine.ClaimUnmapped(table, Path.Combine(root, "Gone", "shared.dll"), "shared.dll",
                                              DebugEngine.ReadMappedBuild(FileAsMapped(bytes), null));
                Func<Action<byte[]>, byte[]> variant = patch => { var b = (byte[])aBytes.Clone(); patch(b); return b; };
                if (claimHeader(aBytes) != ea)
                    failures.Add("same-name dlls (control): an unreadable copy whose mapped header matches A in every field did not claim A's entry");
                if (claimHeader(variant(b => BitConverter.GetBytes(0x1234u).CopyTo(b, optHdr + 64))) != null)
                    failures.Add("same-name dlls: an unreadable copy with a different PE checksum claimed A's entry");
                if (claimHeader(variant(b => BitConverter.GetBytes(0x7777u).CopyTo(b, dbgEntryOff + 4))) != null)
                    failures.Add("same-name dlls: an unreadable copy whose debug entry has a different link time claimed A's entry");
                if (claimHeader(variant(b => BitConverter.GetBytes(fixtureDbg.SizeOfData + 1).CopyTo(b, dbgEntryOff + 16))) != null)
                    failures.Add("same-name dlls: an unreadable copy whose debug entry has a different data size claimed A's entry");
                if (claimHeader(variant(b => BitConverter.GetBytes(0u).CopyTo(b, optHdr + 96 + 6 * 8 + 4))) != null)
                    failures.Add("same-name dlls: an unreadable copy with no debug directory claimed A's entry");
                if (claimHeader(variant(b => BitConverter.GetBytes(0u).CopyTo(b, peHdr))) != null)
                    failures.Add("same-name dlls: an unreadable copy with no PE signature claimed A's entry");

                // The old size reader answered 0x10000 for a header whose SizeOfImage reads 0, and a preload of that
                // size then matched. The identity read must say 0, and 0 matches nothing.
                var fabPath = writeAs("Fab", 0x66666666, "fab.dll");
                byte[] fab = File.ReadAllBytes(fabPath);
                BitConverter.GetBytes(0x10000u).CopyTo(fab, optHdr + 56);
                File.WriteAllBytes(fabPath, fab);
                var fabEng = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false, new[] { fabPath });
                var fabTable = fabEng.ModulesForTest();
                byte[] fabMapped = (byte[])fab.Clone();
                BitConverter.GetBytes(0u).CopyTo(fabMapped, optHdr + 56);
                var fabBuild = DebugEngine.ReadMappedBuild(FileAsMapped(fabMapped), null);
                if (fabBuild.Size != 0)
                    failures.Add("same-name dlls: a mapped header whose SizeOfImage is 0 read as size 0x" + fabBuild.Size.ToString("X") + ", not 0");
                if (DebugEngine.ClaimUnmapped(fabTable, Path.Combine(root, "Gone", "fab.dll"), "fab.dll", fabBuild) != null)
                    failures.Add("same-name dlls: a mapped header with no SizeOfImage claimed a preload of size 0x10000");
                if (DebugEngine.ClaimUnmapped(fabTable, Path.Combine(root, "Gone", "fab.dll"), "fab.dll",
                                              DebugEngine.ReadMappedBuild(FileAsMapped(fab), null)) == null)
                    failures.Add("same-name dlls (control): the fab.dll header with its size intact did not claim its preload");

                // Empty debug data is no identity: two files whose debug entries both say 0 bytes compare nothing.
                Func<string, string> writeEmptyDebug = dir =>
                {
                    string f = writeAs(dir, 0x77777777, "nodebug.dll");
                    byte[] nb = File.ReadAllBytes(f);
                    BitConverter.GetBytes(0u).CopyTo(nb, dbgEntryOff + 16);
                    File.WriteAllBytes(f, nb);
                    return f;
                };
                string emptyPre = writeEmptyDebug("EmptyPre"), emptyCopy = writeEmptyDebug("EmptyCopy");
                var emptyTable = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false, new[] { emptyPre }).ModulesForTest();
                var emptyDisk = PeImage.Load(emptyCopy);
                if (DebugEngine.ClaimUnmapped(emptyTable, DebugEngine.CanonicalImagePath(emptyCopy), "nodebug.dll",
                        new DebugEngine.MappedBuild { DiskPe = emptyDisk, Stamp = 0x77777777, Size = emptyDisk.SizeOfImage }) != null)
                    failures.Add("same-name dlls: two copies whose debug data is EMPTY were taken for the same build");

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

        /// <summary>A U32 reader over a PE FILE laid out as the loader would map it, for ReadMappedBuild: an RVA below
        /// the first section is a header offset (the same in file and memory), any other goes through the section
        /// table. A file whose headers do not parse reads as raw offsets; anything out of range reads 0, as an
        /// unreadable page does.</summary>
        private static Func<uint, uint> FileAsMapped(byte[] bytes)
        {
            PeImage pe = null;
            try { pe = new PeImage(bytes); } catch { pe = null; }
            uint firstSection = uint.MaxValue;
            if (pe != null) foreach (var s in pe.Sections) firstSection = Math.Min(firstSection, s.VirtualAddress);
            return rva =>
            {
                long off = (pe == null || rva < firstSection) ? rva : pe.RvaToOffset(rva);
                return (off < 0 || off + 4 > bytes.Length) ? 0u : BitConverter.ToUInt32(bytes, (int)off);
            };
        }

        /// <summary>
        /// Two LIVE entries never share a Path (fb5766d1 #3), through the REAL <see cref="DebugEngine.YieldBorrowedPaths"/>
        /// and the REAL unmap handler. A same-build claim borrows its preload's path; when the preload's own file maps
        /// too, the borrower takes its mapped path, whichever of the two mapped last, and on unmap a preloaded entry
        /// answers to its preload path again.
        /// </summary>
        private static void CheckBorrowedPathsYield(List<string> failures, ClaimLog claims)
        {
            claims.Claim("when a preload's own file maps while a same-build copy holds that preload's path, the copy's entry "
                         + "takes its own mapped path and the new entry keeps the preload path (either mapping order); entries "
                         + "on different paths are left alone; and an unmapped preload answers to its preload path again, re-sending "
                         + "the breakpoint list when that moved its path, so a host row that learned the yielded path does not "
                         + "survive as a ghost (and an unmap that moves no path re-sends nothing).");

            const string pre = @"C:\App\Dll1\shared.dll", cpy = @"C:\App\Exe\shared.dll";
            Func<string, string, uint, bool, LoadedModule> mk = (path, mapped, b, preloaded) => new LoadedModule
            { Path = path, MappedPath = mapped, LoadBase = b, Name = "shared.dll", Preloaded = preloaded, PreloadPath = preloaded ? pre : null };

            // Copy mapped first (borrowed the preload's path), then the preload's own file maps.
            var borrower = mk(pre, cpy, 0x10000000, true);
            var genuine = mk(pre, pre, 0x20000000, false);
            var changed = DebugEngine.YieldBorrowedPaths(new List<LoadedModule> { borrower, genuine }, genuine);
            if (changed.Count != 1 || changed[0] != borrower || borrower.Path != cpy || genuine.Path != pre)
                failures.Add("borrowed paths: after the preload's own file mapped, the copy must answer to " + cpy + " and the new entry to "
                             + pre + "; got copy=" + borrower.Path + " new=" + genuine.Path + " changed=" + changed.Count);

            // The other order: the genuine image is live, and the borrower is the one that just mapped.
            borrower = mk(pre, cpy, 0x10000000, true);
            genuine = mk(pre, pre, 0x20000000, false);
            changed = DebugEngine.YieldBorrowedPaths(new List<LoadedModule> { genuine, borrower }, borrower);
            if (changed.Count != 1 || changed[0] != borrower || borrower.Path != cpy || genuine.Path != pre)
                failures.Add("borrowed paths: a borrower mapping while the genuine image is live must take its own path; got copy="
                             + borrower.Path + " genuine=" + genuine.Path + " changed=" + changed.Count);

            // Control: a borrower alone, and a borrower beside an image on another path, keep their paths.
            borrower = mk(pre, cpy, 0x10000000, true);
            var other = mk(@"C:\App\Dll2\shared.dll", @"C:\App\Dll2\shared.dll", 0x20000000, false);
            changed = DebugEngine.YieldBorrowedPaths(new List<LoadedModule> { borrower, other }, other);
            if (changed.Count != 0 || borrower.Path != pre || other.Path != @"C:\App\Dll2\shared.dll")
                failures.Add("borrowed paths (control): a borrower with no image genuinely at its path must keep it; got " + borrower.Path);

            // An unmapped borrower is not live, so it does not collide.
            borrower = mk(pre, null, 0, true);
            genuine = mk(pre, pre, 0x20000000, false);
            changed = DebugEngine.YieldBorrowedPaths(new List<LoadedModule> { borrower, genuine }, genuine);
            if (changed.Count != 0 || borrower.Path != pre)
                failures.Add("borrowed paths: an UNMAPPED preload yielded its path to a live image");

            // The REAL unmap handler restores the preload path of an entry that had yielded it.
            string root = Path.Combine(Path.GetTempPath(), "cadbg-yield-" + Guid.NewGuid().ToString("N"));
            try
            {
                Directory.CreateDirectory(root);
                string dll = Path.Combine(root, "shared.dll");
                File.Copy(typeof(PeImage).Assembly.Location, dll);
                var eng = new DebugEngine("protocolcheck", null, null, null, null, false, 0, false, new[] { dll });
                var e = eng.ModulesForTest().Find(x => x.Preloaded);
                if (e == null) { failures.Add("borrowed paths: the fixture DLL did not preload"); return; }
                string prePath = e.Path;
                eng.EmitJson = true;
                e.LoadBase = 0x30000000; e.MappedPath = cpy; e.Path = cpy;   // as after a yield
                string outp = CaptureConsole(() => eng.DllUnloadedForTest(0x30000000));
                if (e.LoadBase != 0 || e.MappedPath != null || e.Path != prePath)
                    failures.Add("borrowed paths: an unmapped preload must answer to its preload path " + prePath + " again; got Path="
                                 + e.Path + " MappedPath=" + e.MappedPath + " LoadBase=0x" + e.LoadBase.ToString("X"));
                // The host keeps a learned owner, so the path change must reach it as a full list re-sync.
                if (outp.IndexOf("\"event\":\"bp-list\"", StringComparison.Ordinal) < 0)
                    failures.Add("borrowed paths: an unmap that moved the path back to the preload's sent no bp-list: " + outp.Trim());
                // Control: an unmap that changes no path sends none.
                e.LoadBase = 0x30000000; e.MappedPath = prePath;
                outp = CaptureConsole(() => eng.DllUnloadedForTest(0x30000000));
                if (outp.IndexOf("\"event\":\"bp-list\"", StringComparison.Ordinal) >= 0 || e.LoadBase != 0)
                    failures.Add("borrowed paths (control): an unmap that changed no path sent a bp-list: " + outp.Trim());
            }
            catch (Exception ex) { failures.Add("borrowed paths: " + ex.GetType().Name + ": " + ex.Message); }
            finally { try { Directory.Delete(root, true); } catch { } }
        }

        /// <summary>
        /// `expand` with the row's imgBase as a 5th argument names ONE image (w8-expand-base), through the REAL
        /// <see cref="DebugEngine.ExpandImage"/> the handler resolves with, and every expandable row carries that base,
        /// through the REAL row builder. NOT COVERED: the handler's TSWD type lookup (needs a real image's types).
        /// </summary>
        private static void CheckExpandBaseNamesOneImage(List<string> failures, ClaimLog claims)
        {
            claims.Claim("expand with a 0x-hex 5th argument resolves the mapped image with that name AND base, so two same-named "
                         + "DLLs are told apart; a base matching no mapped image of that name, another name's base, an unmapped "
                         + "image or a malformed base resolves nothing; four arguments keep the first image of the name; and every "
                         + "expandable row (by-ref group and array-of-group element) carries imgBase as 0x + 8 hex digits next to module.");

            var x = new LoadedModule { Name = "shared.dll", LoadBase = 0x10000000 };
            var y = new LoadedModule { Name = "shared.dll", LoadBase = 0x20000000 };
            var z = new LoadedModule { Name = "other.dll", LoadBase = 0x30000000 };
            var u = new LoadedModule { Name = "shared.dll", LoadBase = 0 };
            var table = new List<LoadedModule> { u, x, y, z };
            Func<string, LoadedModule> exp = b => DebugEngine.ExpandImage(table,
                b == null ? new[] { "expand", "1", "shared.dll", "5", "0x400000" }
                          : new[] { "expand", "1", "shared.dll", "5", "0x400000", b });

            if (exp(null) != x) failures.Add("expand base: four arguments must keep the first MAPPED image of the name");
            if (exp("0x20000000") != y) failures.Add("expand base: 0x20000000 did not resolve the second shared.dll");
            if (exp("0x10000000") != x) failures.Add("expand base: 0x10000000 did not resolve the first shared.dll");
            if (exp("0X20000000") != y) failures.Add("expand base: an upper-case 0X prefix was refused");
            if (DebugEngine.ExpandImage(table, new[] { "expand", "1", "SHARED.DLL", "5", "0x400000", "0x20000000" }) != y)
                failures.Add("expand base: the module name must match case-insensitively");
            foreach (var bad in new[] { "0x30000000", "0x40000000", "0x0", "0x00000000" })
                if (exp(bad) != null) failures.Add("expand base: " + bad + " names no mapped shared.dll but resolved one (fail closed)");
            foreach (var bad in new[] { "20000000", "0x", "0x123456789", "0x020000000", "1020000000", "0xZZ", "0x2000000g", "-0x1", "0x+1", "" })
                if (exp(bad) != null) failures.Add("expand base: malformed base '" + bad + "' resolved an image");

            var eng = NewEngine();
            var grp = new ClarionType { Kind = TypeKind.Group, Size = 8, TypeRef = 7, Members = new List<TypeMember>() };
            var arr = new ClarionType { Kind = TypeKind.Array, Length = 2, LoBound = 1, ElemSize = 8, ElemType = grp, Size = 16 };
            string a = eng.NodeJsonForTest("A", arr, 0x18, 0, 16, 0, 0x400000, "shared.dll", 0x20000000, null, true);
            if (Count(a, "\"ref\":true") != 2 || Count(a, "\"module\":\"shared.dll\",\"imgBase\":\"0x20000000\"") != 2)
                failures.Add("expand base: each array-of-group element row must carry module then imgBase 0x20000000: " + a);
            string a0 = eng.NodeJsonForTest("A", arr, 0x18, 0, 16, 0, 0x400000, "shared.dll", null, true);
            if (Count(a0, "\"imgBase\":\"0x00000000\"") != 2)
                failures.Add("expand base: a row of an image at base 0 must still carry imgBase as 8 hex digits: " + a0);

            // A by-ref group reads its pointer slot, so it reads THIS process.
            var self = System.Diagnostics.Process.GetCurrentProcess();
            IntPtr slot = System.Runtime.InteropServices.Marshal.AllocHGlobal(4);
            try
            {
                System.Runtime.InteropServices.Marshal.WriteInt32(slot, 0x12345678);
                var live = NewEngine();
                live.SetProcessHandleForTest(self.Handle);
                var refType = new ClarionType { Kind = TypeKind.Reference, Size = 4, Referent = grp };
                string r = live.NodeJsonForTest("R", refType, 0x16, 0, 4, 0, unchecked((uint)slot.ToInt32()), "shared.dll", 0x0ABCDEF0, null, true);
                if (r.IndexOf("\"ref\":true", StringComparison.Ordinal) < 0
                    || r.IndexOf("\"module\":\"shared.dll\",\"imgBase\":\"0x0ABCDEF0\"", StringComparison.Ordinal) < 0)
                    failures.Add("expand base: a by-ref group row must carry module then imgBase 0x0ABCDEF0: " + r);
            }
            finally { System.Runtime.InteropServices.Marshal.FreeHGlobal(slot); }
        }

        /// <summary>
        /// A preloaded image that has not mapped is not a data candidate (1be3b82e item 2). Through the REAL watch
        /// handler on a parsed image (the attribution blob, whose A.CLW holds an ORDERS$ORD:RECORD), with a second,
        /// unmapped image carrying the same debug info, as a same-named DLL that has not loaded yet does. Counted
        /// in, it made the record ambiguous; it has no live address to read either.
        /// </summary>
        private static void CheckUnmappedImageIsNoDataCandidate(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a watch of a FILE record the one mapped image holds resolves to that image while a preloaded image "
                         + "with the same debug info has not mapped, instead of answering ambiguous; the same watch with both "
                         + "mapped stays ambiguous (the control).");

            TswdDebugInfo dbg;
            try { dbg = new TswdDebugInfo(BuildAttributionBlob(), 0, 0x0F00, 0x2000, 0x10000); }
            catch (Exception ex) { failures.Add("unmapped image: the fixture blob did not parse - " + ex.Message); return; }

            const string spec = "A.CLW!ORDERS$ORD:RECORD";
            var eng = NewEngine();
            eng.EmitJson = true;
            eng.AddUnmappedImageForTest(dbg, "ghost.dll");
            string outp = CaptureConsole(() => eng.WatchWithImageForTest(dbg, "attr.exe", spec));
            if (outp.IndexOf("ambiguous", StringComparison.Ordinal) >= 0 || outp.IndexOf("\"found\":true", StringComparison.Ordinal) < 0)
                failures.Add("unmapped image: " + spec + " with an unmapped ghost.dll did not resolve to attr.exe: " + outp.Trim());

            // Control: the same second image, MAPPED, is a real second candidate, so the rule above is about mapping.
            var both = NewEngine();
            both.EmitJson = true;
            both.AddUnmappedImageForTest(dbg, "ghost.dll");
            both.MapImagesForTest(0x10000000);
            outp = CaptureConsole(() => both.WatchWithImageForTest(dbg, "attr.exe", spec));
            if (outp.IndexOf("\"error\":\"ambiguous: ", StringComparison.Ordinal) < 0)
                failures.Add("unmapped image (control): " + spec + " with ghost.dll MAPPED must be ambiguous: " + outp.Trim());
        }
    }
}
