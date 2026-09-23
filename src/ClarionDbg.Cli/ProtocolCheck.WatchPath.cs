using System;
using System.Collections.Generic;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    internal static partial class ProtocolCheck
    {
        /// <summary>
        /// The watch-path walker (ticket 3a0c915d): `watch HEAD.MEMBER[.MEMBER]` walks the head's own layout,
        /// adding each member's byte offset, and follows ONE reference, at the head only, by reading the
        /// pointer in its slot on every call. Drives the shipped DebugEngine.WalkWatchPath over hand-built
        /// ClarionTypes with a fake pointer reader, so no process is needed.
        ///
        /// Two defects it exists to catch, each run as a mutation on 2026-09-23 and seen red: a walker that
        /// ignores member offsets (every member reads the group's first bytes), and one that walks a reference
        /// head from its frame SLOT instead of the pointer the slot holds (the members read stack bytes).
        ///
        /// NOT COVERED: how HandleWatchCommand picks the head (current-frame local first, then a global data
        /// symbol), what it emits for each outcome, and the THREADed-member mapping. Those need a paused
        /// target with parsed TSWD; the live acceptance is pinning BRW1::JOB:JobID on clbrws.
        /// </summary>
        private static void CheckWatchPathWalker(List<string> failures, ClaimLog claims)
        {
            claims.Claim("a watch path walks a group's members by OFFSET (nested groups add up, member names match "
                         + "in any case), and a local reference head is followed through the POINTER its slot "
                         + "holds, read again on every walk; an unknown member, an empty segment or a member of a "
                         + "scalar is a miss; a reference or array below the head, a class reference head and a "
                         + "global reference head are refused as unsupported; a null or unreadable head pointer is "
                         + "a bad reference. Not covered: head lookup, emitted events, THREADed members.");

            // G: A LONG@0, S STRING(4)@4, SUB GROUP@8 { X LONG@0, Y LONG@4 }, R &GROUP@16, ARR LONG,DIM(2)@20
            var longT = new ClarionType { Kind = TypeKind.Int, Tag = 0x11, Size = 4 };
            var strT = new ClarionType { Kind = TypeKind.String, Tag = 0x18, Size = 4, Length = 4 };
            var sub = Group(8, M("X", 0, longT), M("Y", 4, longT));
            var inner = Group(4, M("Z", 0, longT));
            var refT = new ClarionType { Kind = TypeKind.Reference, Tag = 0x16, Size = 4, Referent = inner };
            var arrT = new ClarionType { Kind = TypeKind.Array, Tag = 0x18, Size = 8, ElemType = longT, ElemSize = 4, Length = 2, LoBound = 1 };
            var g = Group(28, M("A", 0, longT), M("S", 4, strT), M("SUB", 8, sub), M("R", 16, refT), M("ARR", 20, arrT));
            const uint gVa = 0x1000;
            Func<uint, uint?> noRead = va => { failures.Add("watch path: a head that must not be dereferenced read a pointer at 0x" + va.ToString("X")); return null; };

            ExpectLeaf(failures, "G.A", g, 0x08, false, gVa, noRead, 0x1000, longT);
            ExpectLeaf(failures, "G.S", g, 0x08, false, gVa, noRead, 0x1004, strT);
            ExpectLeaf(failures, "G.SUB.Y", g, 0x08, false, gVa, noRead, 0x100C, longT);   // 0x1000 + 8 + 4
            ExpectLeaf(failures, "G.sub.x", g, 0x08, true, gVa, noRead, 0x1008, longT);    // case-insensitive
            ExpectOutcome(failures, "G.NOPE", g, 0x08, false, gVa, noRead, DebugEngine.WatchPathOutcome.Miss, null);
            ExpectOutcome(failures, "G.", g, 0x08, false, gVa, noRead, DebugEngine.WatchPathOutcome.Miss, null);
            ExpectOutcome(failures, "G..A", g, 0x08, false, gVa, noRead, DebugEngine.WatchPathOutcome.Miss, null);
            ExpectOutcome(failures, "G.A.X", g, 0x08, false, gVa, noRead, DebugEngine.WatchPathOutcome.Miss, null);
            ExpectOutcome(failures, "G.R.Z", g, 0x08, true, gVa, noRead, DebugEngine.WatchPathOutcome.Unsupported, DebugEngine.PathUnsupported);
            ExpectOutcome(failures, "G.ARR", g, 0x08, true, gVa, noRead, DebugEngine.WatchPathOutcome.Unsupported, DebugEngine.PathUnsupported);
            ExpectOutcome(failures, "L.X", longT, 0x11, true, gVa, noRead, DebugEngine.WatchPathOutcome.Miss, null);

            // Q: the QUEUE:BROWSE:1 shape measured on clbrws (3a0c915d item 0) - a local 0x16 reference to a
            // group whose first member is at +0. The slot is at 0x2000 and holds 0x9000, then 0xA000.
            var q = Group(60, M("BRW1::JOB:JOBID", 0, longT), M("BRW1::JOB:JOB_DESC", 6, strT));
            var qRef = new ClarionType { Kind = TypeKind.Reference, Tag = 0x16, Size = 4, Referent = q };
            const uint slot = 0x2000;
            uint held = 0x9000;
            int reads = 0;
            Func<uint, uint?> heap = va =>
            {
                reads++;
                if (va != slot) failures.Add("watch path: the reference head read a pointer at 0x" + va.ToString("X") + ", not its slot 0x2000");
                return held;
            };
            ExpectLeaf(failures, "QUEUE:BROWSE:1.BRW1::JOB:JOB_DESC", qRef, 0x16, true, slot, heap, 0x9006, strT);
            held = 0xA000;   // the runtime moved the buffer between pauses: the next walk must follow it
            ExpectLeaf(failures, "QUEUE:BROWSE:1.brw1::job:jobid", qRef, 0x16, true, slot, heap, 0xA000, longT);
            if (reads != 2)
                failures.Add("watch path: two walks of a reference head read its pointer " + reads + " time(s), expected 2 - a cached pointer is a stored address");
            // code 0x16 with a type record that points straight at the group (no Reference hop) is still by-ref
            ExpectLeaf(failures, "QD.BRW1::JOB:JOB_DESC", q, 0x16, true, slot, heap, 0xA006, strT);

            held = 0;
            ExpectOutcome(failures, "QN.BRW1::JOB:JOBID", qRef, 0x16, true, slot, heap, DebugEngine.WatchPathOutcome.BadReference, DebugEngine.PathNullRef);
            ExpectOutcome(failures, "QU.BRW1::JOB:JOBID", qRef, 0x16, true, slot, va => null, DebugEngine.WatchPathOutcome.BadReference, DebugEngine.PathUnreadableRef);
            ExpectOutcome(failures, "QG.BRW1::JOB:JOBID", qRef, 0x16, false, slot, noRead, DebugEngine.WatchPathOutcome.Unsupported, DebugEngine.PathUnsupported);

            // WINRESIZE's shape: a reference to a class, whose first data member sits after the VMT at +4
            var cls = Group(51, M("APPSTRATEGY", 4, longT), M("AUTOTRANSPARENT", 5, longT));
            var clsRef = new ClarionType { Kind = TypeKind.Reference, Tag = 0x16, Size = 4, Referent = cls };
            ExpectOutcome(failures, "WINRESIZE.APPSTRATEGY", clsRef, 0x16, true, slot, noRead, DebugEngine.WatchPathOutcome.Unsupported, DebugEngine.PathClassRef);
        }

        private static ClarionType Group(uint size, params TypeMember[] members)
        {
            return new ClarionType { Kind = TypeKind.Group, Tag = 0x08, Size = size, Members = new List<TypeMember>(members) };
        }

        private static TypeMember M(string name, int offset, ClarionType type)
        {
            return new TypeMember { Name = name, Offset = offset, Type = type };
        }

        private static DebugEngine.WatchPathOutcome Walk(string path, ClarionType head, byte code, bool local, uint headVa,
                                                         Func<uint, uint?> read, out uint leafVa, out ClarionType leafType, out string error)
        {
            var parts = new List<string>(path.Split('.'));
            parts.RemoveAt(0);
            return DebugEngine.WalkWatchPath(head, code, local, headVa, parts, read, out leafVa, out leafType, out error);
        }

        private static void ExpectLeaf(List<string> failures, string path, ClarionType head, byte code, bool local, uint headVa,
                                       Func<uint, uint?> read, uint wantVa, ClarionType wantType)
        {
            uint va; ClarionType t; string error;
            var o = Walk(path, head, code, local, headVa, read, out va, out t, out error);
            if (o != DebugEngine.WatchPathOutcome.Ok)
                failures.Add("watch path " + path + ": expected a leaf at 0x" + wantVa.ToString("X") + ", got " + o + " (" + (error ?? "no error") + ")");
            else if (va != wantVa)
                failures.Add("watch path " + path + ": leaf at 0x" + va.ToString("X") + ", expected 0x" + wantVa.ToString("X"));
            else if (!ReferenceEquals(t, wantType))
                failures.Add("watch path " + path + ": the leaf carried the wrong member's type");
        }

        private static void ExpectOutcome(List<string> failures, string path, ClarionType head, byte code, bool local, uint headVa,
                                          Func<uint, uint?> read, DebugEngine.WatchPathOutcome want, string wantError)
        {
            uint va; ClarionType t; string error;
            var o = Walk(path, head, code, local, headVa, read, out va, out t, out error);
            if (o != want)
                failures.Add("watch path " + path + ": expected " + want + ", got " + o + (o == DebugEngine.WatchPathOutcome.Ok ? " at 0x" + va.ToString("X") : ""));
            else if (wantError != null && error != wantError)
                failures.Add("watch path " + path + ": error '" + error + "', expected '" + wantError + "'");
        }
    }
}
