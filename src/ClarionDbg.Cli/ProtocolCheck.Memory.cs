using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// The `mem` read behind the Memory panel (ticket 633d8b2f), against THIS process's address space: a
        /// committed page followed by a reserved, unreadable one, with bytes the harness planted.
        ///
        /// Three properties, each of which the raw ReadProcessMemory it replaced got wrong or never had:
        ///  1. a span that runs off the end of readable memory returns the bytes before the edge, rather
        ///     than failing the whole read;
        ///  2. a byte under a planted INT3 (a user breakpoint or a call-skip temp) reads as the ORIGINAL
        ///     byte, and a 0xCC that nobody planted still reads as 0xCC (so the fix is "un-patch OUR
        ///     bytes", not "hide every 0xCC");
        ///  3. the reqId the request carried comes back on the reply, and on a refusal, so the host can
        ///     match a reply to its request.
        /// And the bounds: 1..MemMaxLen, and no span past 0xFFFFFFFF (ReadBlock's uint arithmetic would
        /// wrap it to page 0).
        ///
        /// NOT COVERED: the pause loop's dispatch of the verb (its paused-only status is CheckResumeVerbs's
        /// list), and a real debuggee's breakpoints.
        /// </summary>
        private static void CheckMemReadIsCleanAndPageSafe(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a `mem` read returns the readable bytes before an unreadable page instead of failing, "
                         + "shows the original byte under every planted INT3 (user breakpoint and call-skip temp) "
                         + "while an unplanted 0xCC stays 0xCC, echoes the request's reqId on the reply and on a "
                         + "refusal, and refuses a length outside 1.." + DebugEngine.MemMaxLen + " or a span past "
                         + "0xFFFFFFFF. Not covered: the pause loop's dispatch, a real debuggee.");

            var self = System.Diagnostics.Process.GetCurrentProcess();
            IntPtr region = VirtualAlloc(IntPtr.Zero, (UIntPtr)0x2000u, MemReserve, PageNoAccess);
            if (region == IntPtr.Zero) { failures.Add("mem control: could not reserve two pages in this process"); return; }
            try
            {
                if (VirtualAlloc(region, (UIntPtr)0x1000u, MemCommitFlag, PageReadWriteFlag) == IntPtr.Zero)
                { failures.Add("mem control: could not commit the first page"); return; }

                uint page = unchecked((uint)region.ToInt32());
                var pattern = new byte[0x1000];
                for (int i = 0; i < pattern.Length; i++) pattern[i] = (byte)(0x20 + (i % 0x5F));
                pattern[0xFF0] = 0xCC;   // a user breakpoint sits here; the original byte was 0x55
                pattern[0xFF4] = 0xCC;   // a call-skip temp sits here; the original byte was 0x66
                pattern[0xFF8] = 0xCC;   // a real 0xCC in the target that nobody planted
                Marshal.Copy(pattern, 0, region, pattern.Length);

                var eng = NewEngine();
                eng.SetProcessHandleForTest(self.Handle);
                eng.PlantForTest(page + 0xFF0, 0x55, false);
                eng.PlantForTest(page + 0xFF4, 0x66, true);

                uint addr; int len, read; string reqId; byte[] buf;

                // ---- 1+2: a 64-byte read from 0xFE0 has 32 readable bytes, then the reserved page.
                string err = eng.MemReadForTest(Parts("0x" + (page + 0xFE0).ToString("X"), "64", "7"),
                                                out addr, out len, out reqId, out buf, out read);
                if (err != null)
                    failures.Add("mem: a read that runs into an unreadable page was refused (" + err + ") - it must "
                                 + "return the 32 readable bytes before the edge");
                else
                {
                    if (read != 32)
                        failures.Add("mem: a read running into an unreadable page returned " + read + " bytes, expected 32");
                    if (read > 0x10 && buf[0x10] != 0x55)
                        failures.Add("mem: the byte under a planted user breakpoint read 0x" + buf[0x10].ToString("X2")
                                     + ", expected its original 0x55");
                    if (read > 0x14 && buf[0x14] != 0x66)
                        failures.Add("mem: the byte under a planted call-skip temp read 0x" + buf[0x14].ToString("X2")
                                     + ", expected its original 0x66");
                    if (read > 0x18 && buf[0x18] != 0xCC)
                        failures.Add("mem: an UNPLANTED 0xCC read as 0x" + buf[0x18].ToString("X2")
                                     + " - the read must restore only the bytes the engine planted");
                    if (read > 0x11 && buf[0x11] != pattern[0xFF1])
                        failures.Add("mem: an ordinary byte beside a breakpoint read wrong");
                    if (reqId != "7") failures.Add("mem: the trailing reqId was not parsed (got " + (reqId ?? "null") + ")");
                    if (len != 64) failures.Add("mem: the requested len was not kept for the reply (got " + len + ")");

                    string json = Json.Mem(addr, buf, read, len, reqId);
                    if (!json.EndsWith(",\"reqId\":\"7\"}", StringComparison.Ordinal))
                        failures.Add("mem: the reply does not carry the request's reqId: " + json);
                    if (json.IndexOf("\"read\":32,", StringComparison.Ordinal) < 0 || json.IndexOf("\"len\":64,", StringComparison.Ordinal) < 0)
                        failures.Add("mem: the reply does not state both the requested len and the bytes read: " + json);
                }

                // Without a reqId the reply has no reqId member (the legacy form, and what `mem` typed at the
                // console gets).
                if (Json.Mem(0x1000, new byte[] { 1 }, 1, 1).IndexOf("reqId", StringComparison.Ordinal) >= 0)
                    failures.Add("mem: a reply to a request with no reqId invented one");

                // ---- a read wholly inside the unreadable page is refused, and the refusal is correlatable.
                err = eng.MemReadForTest(Parts("0x" + (page + 0x1000).ToString("X"), "16", "8"),
                                         out addr, out len, out reqId, out buf, out read);
                if (err == null || err.IndexOf("read failed", StringComparison.Ordinal) < 0)
                    failures.Add("mem: a read of an unreadable page was not refused as a failed read (" + (err ?? "null") + ")");
                else
                {
                    string refusal = Json.MemError(addr, len, reqId, err);
                    if (refusal.IndexOf("\"reqId\":\"8\"", StringComparison.Ordinal) < 0
                        || refusal.IndexOf("\"error\":", StringComparison.Ordinal) < 0
                        || refusal.IndexOf("\"read\":0,", StringComparison.Ordinal) < 0)
                        failures.Add("mem: a refusal does not carry reqId, error and read:0: " + refusal);
                }

                // ---- bounds. The top of the cap is ACCEPTED (a whole committed page), one past it is not.
                err = eng.MemReadForTest(Parts("0x" + page.ToString("X"), DebugEngine.MemMaxLen.ToString(), "9"),
                                         out addr, out len, out reqId, out buf, out read);
                if (err != null || read != DebugEngine.MemMaxLen)
                    failures.Add("mem bounds: a " + DebugEngine.MemMaxLen + "-byte read of a committed page was not "
                                 + "returned whole (" + (err ?? "read " + read) + ")");
                foreach (var bad in new[] { "0", "-1", (DebugEngine.MemMaxLen + 1).ToString(), "x" })
                {
                    err = eng.MemReadForTest(Parts("0x" + page.ToString("X"), bad, "9"), out addr, out len, out reqId, out buf, out read);
                    if (err == null || err.IndexOf("length", StringComparison.Ordinal) < 0)
                        failures.Add("mem bounds: length '" + bad + "' was not refused as a length");
                    if (reqId != "9") failures.Add("mem bounds: a refused length lost its reqId");
                }

                // The wrap: 0xFFFFFFF0 + 32 ends past the address space. Its CONTROL is 0xFFFFFFF0 + 16, which
                // ends exactly at it and must reach the read (and fail there, as kernel space), not the guard.
                err = eng.MemReadForTest(Parts("0xFFFFFFF0", "32", "10"), out addr, out len, out reqId, out buf, out read);
                if (err == null || err.IndexOf("past the end", StringComparison.Ordinal) < 0)
                    failures.Add("mem bounds: a span past 0xFFFFFFFF was not refused (" + (err ?? "null") + ")");
                err = eng.MemReadForTest(Parts("0xFFFFFFF0", "16", "10"), out addr, out len, out reqId, out buf, out read);
                if (err == null || err.IndexOf("past the end", StringComparison.Ordinal) >= 0)
                    failures.Add("mem bounds control: a span ending exactly at 4 GB was refused by the wrap guard ("
                                 + (err ?? "null") + ") - the guard is off by one");

                err = eng.MemReadForTest(Parts("0xZZ", "16", "11"), out addr, out len, out reqId, out buf, out read);
                if (err == null || err.IndexOf("bad address", StringComparison.Ordinal) < 0 || reqId != "11")
                    failures.Add("mem: a malformed address was not refused with its reqId");
            }
            finally { VirtualFree(region, UIntPtr.Zero, MemRelease); }
        }

        /// <summary>
        /// The read-only `addr` member the Memory panel's "View memory" uses, against the real NodeJson.
        ///
        /// `va` is the EDIT grant: the host issues an edit tuple for a row only when it carries one, and wave
        /// 3 hardened that contract. So "View memory" on a group, an array, a vetoed shared-template row, or
        /// a reference could not borrow `va` without handing out pencils. This asserts the split: every row
        /// with storage carries `addr`, a row's `va` (when it has one) equals its `addr`, and adding `addr`
        /// gave no row a `va` it did not have. A by-ref group row's `addr` stays the TARGET (what `expand`
        /// reads), exactly once; a null reference carries none.
        ///
        /// NOT COVERED: Globals-tree (@GLOBALS) file-buffer rows, which are static and carry no address.
        /// </summary>
        private static void CheckVarRowAddrIsNotAnEditGrant(List<string> failures, ClaimLog claims)
        {
            claims.Claim("every variable row with storage carries a read-only `addr` (group, array, vetoed and "
                         + "editable scalar alike) equal to its `va` where it has one, without gaining a `va`; a "
                         + "by-ref group row's single `addr` is its target and a null reference has none. Not "
                         + "covered: the static Globals-tree file-buffer rows.");

            var lng = new ClarionType { Kind = TypeKind.Int, Size = 4 };
            var grp = new ClarionType
            {
                Kind = TypeKind.Group, Size = 8, TypeRef = 0x77,
                Members = new List<TypeMember>
                {
                    new TypeMember { Name = "FIRST",  Offset = 0, Type = lng },
                    new TypeMember { Name = "SECOND", Offset = 4, Type = lng },
                },
            };
            var arr = new ClarionType { Kind = TypeKind.Array, Size = 8, Length = 2, LoBound = 1, ElemSize = 4, ElemType = lng };
            const string vetoNote = "no thread instance - shared template value";

            var eng = NewEngine();

            // A group: itself and both members addressed. Vetoed, it still has every address and no va.
            foreach (bool editable in new[] { true, false })
            {
                string g = eng.NodeJsonForTest("G", grp, 0x08, 0, 8, 0, 0x400000, "m.clw", editable ? null : vetoNote, editable);
                string tag = editable ? "group" : "vetoed group";
                if (!TopLevelHas(g, "\"addr\":\"0x400000\""))
                    failures.Add("row addr: a " + tag + " row carries no addr of its own: " + g);
                if (g.IndexOf("\"addr\":\"0x400004\"", StringComparison.Ordinal) < 0)
                    failures.Add("row addr: a " + tag + "'s second member carries no addr");
                if (TopLevelHas(g, "\"va\":"))
                    failures.Add("row addr: a " + tag + " row gained a va - that is an edit grant for the whole group");
                int va = CountVa(g);
                if (va != (editable ? 2 : 0))
                    failures.Add("row addr: a " + tag + " has " + va + " va member(s), expected " + (editable ? 2 : 0)
                                 + " - addr must not change which rows are editable");
            }

            // An array: the row and its elements.
            string a = eng.NodeJsonForTest("A", arr, 0x18, 0, 8, 0, 0x400000, "m.clw", vetoNote, false);
            if (!TopLevelHas(a, "\"addr\":\"0x400000\"") || a.IndexOf("\"addr\":\"0x400004\"", StringComparison.Ordinal) < 0)
                failures.Add("row addr: an array row or its element carries no addr: " + a);
            if (CountVa(a) != 0) failures.Add("row addr: a vetoed array gained a va");

            // Scalars: an editable one carries va == addr; a vetoed one carries addr and no va.
            string s = eng.NodeJsonForTest("S", null, 0x11, 0, 4, 0, 0x400010, "m.clw", null, true);
            if (s.IndexOf("\"va\":\"0x400010\"", StringComparison.Ordinal) < 0 || s.IndexOf("\"addr\":\"0x400010\"", StringComparison.Ordinal) < 0)
                failures.Add("row addr: an editable scalar does not carry va and addr at the same address: " + s);
            string sv = eng.NodeJsonForTest("S", null, 0x11, 0, 4, 0, 0x400010, "m.clw", vetoNote, false);
            if (sv.IndexOf("\"addr\":\"0x400010\"", StringComparison.Ordinal) < 0 || CountVa(sv) != 0)
                failures.Add("row addr: a vetoed scalar should carry addr and no va: " + sv);

            // No storage, no addr.
            string z = eng.NodeJsonForTest("Z", null, 0x11, 0, 4, 0, 0, "m.clw", null, true);
            if (z.IndexOf("\"addr\":", StringComparison.Ordinal) >= 0)
                failures.Add("row addr: a row at address 0 claims an addr: " + z);

            // A by-ref group: the slot holds a pointer, and the row's one addr is the TARGET. This needs a real
            // slot to read, so it reads THIS process: a 4-byte slot holding 0x12345678, and one holding 0.
            var self = System.Diagnostics.Process.GetCurrentProcess();
            var refType = new ClarionType { Kind = TypeKind.Reference, Size = 4, Referent = grp };
            IntPtr slot = Marshal.AllocHGlobal(8);
            try
            {
                Marshal.WriteInt32(slot, 0x12345678);
                Marshal.WriteInt32(slot, 4, 0);
                var live = NewEngine();
                live.SetProcessHandleForTest(self.Handle);
                uint slotVa = unchecked((uint)slot.ToInt32());
                string r = live.NodeJsonForTest("R", refType, 0x16, 0, 4, 0, slotVa, "m.clw", null, true);
                if (r.IndexOf("\"ref\":true", StringComparison.Ordinal) < 0)
                    failures.Add("row addr control: the by-ref group did not build as a ref row: " + r);
                if (Occurrences(r, "\"addr\":") != 1 || r.IndexOf("\"addr\":\"0x12345678\"", StringComparison.Ordinal) < 0)
                    failures.Add("row addr: a by-ref group row must carry exactly one addr, its target 0x12345678: " + r);
                string rn = live.NodeJsonForTest("R", refType, 0x16, 0, 4, 0, slotVa + 4, "m.clw", null, true);
                if (rn.IndexOf("\"addr\":", StringComparison.Ordinal) >= 0)
                    failures.Add("row addr: a NULL reference claims an addr: " + rn);
            }
            finally { Marshal.FreeHGlobal(slot); }
        }

        private const uint MemCommitFlag = 0x1000, PageReadWriteFlag = 0x04;

        private static string[] Parts(params string[] args)
        {
            var p = new string[args.Length + 1];
            p[0] = "mem";
            Array.Copy(args, 0, p, 1, args.Length);
            return p;
        }

        private static int Occurrences(string s, string what)
        {
            int n = 0, i = 0;
            while ((i = s.IndexOf(what, i, StringComparison.Ordinal)) >= 0) { n++; i += what.Length; }
            return n;
        }

        /// <summary>True when <paramref name="member"/> appears among the row's OWN members: the text at
        /// nesting depth 1, so a descendant row's member does not count wherever "children" sits. Strings are
        /// skipped whole, because values like "{…}" and names like "[1]" carry brackets.</summary>
        private static bool TopLevelHas(string row, string member)
        {
            var own = new System.Text.StringBuilder();
            int depth = 0; bool inStr = false;
            for (int i = 0; i < row.Length; i++)
            {
                char c = row[i];
                if (inStr)
                {
                    if (depth == 1) own.Append(c);
                    if (c == '\\' && i + 1 < row.Length) { i++; if (depth == 1) own.Append(row[i]); }
                    else if (c == '"') inStr = false;
                    continue;
                }
                if (c == '{' || c == '[') { depth++; if (depth == 1) continue; }
                else if (c == '}' || c == ']') { depth--; continue; }
                else if (c == '"') inStr = true;
                if (depth == 1) own.Append(c);
            }
            return own.ToString().IndexOf(member, StringComparison.Ordinal) >= 0;
        }
    }
}
