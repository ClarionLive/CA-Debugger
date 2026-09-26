using System;
using System.Collections.Generic;

namespace ClarionDbg.Cli
{
    // The re-arm hold (ticket ca29e2da). See DebugEngine.Stepping.cs for the design, and ProtocolCheck.cs for
    // the claim registry and NewEngine.
    internal static partial class ProtocolCheck
    {
        /// <summary>A thread table for the hold: a suspend count per tid, which tids WE hold a suspend on, and
        /// which have TF set. A resume with no suspend of ours outstanding, or a second suspend while one is, is
        /// recorded as an error rather than absorbed, because either one unbalances a real thread's count.</summary>
        private sealed class FakeThreadOps : DebugEngine.ThreadOps
        {
            public readonly Dictionary<uint, int> Count = new Dictionary<uint, int>();
            public readonly HashSet<uint> Ours = new HashSet<uint>();
            public readonly HashSet<uint> Tf = new HashSet<uint>();
            public readonly HashSet<uint> Exited = new HashSet<uint>();
            public readonly List<string> Errors = new List<string>();
            public int Suspends;

            public int Get(uint tid) { int c; return Count.TryGetValue(tid, out c) ? c : 0; }

            public override bool Suspend(uint tid)
            {
                if (!Ours.Add(tid)) { Errors.Add("suspended 0x" + tid.ToString("X") + " while already holding it"); return false; }
                Count[tid] = Get(tid) + 1;
                Suspends++;
                return true;
            }

            public override void Resume(uint tid)
            {
                if (!Ours.Remove(tid)) { Errors.Add("resumed 0x" + tid.ToString("X") + " with no suspend of ours outstanding"); return; }
                if (Exited.Contains(tid)) Errors.Add("resumed 0x" + tid.ToString("X") + " after it exited - its handle was not let go at the exit");
                Count[tid] = Get(tid) - 1;
            }

            public override void Forget(uint tid) { Ours.Remove(tid); }

            public override bool TrapFlagSet(uint tid) { return Tf.Contains(tid); }
        }

        /// <summary>One event of a hold scenario: the event, the threads whose TF is set when it arrives (what the
        /// handlers would have left), and the suspend counts of T1,T2,T3[,T4] wanted at its continue (null = not
        /// checked).</summary>
        private sealed class HoldStep
        {
            public byte[] Ev; public uint[] Tf; public string Want;
            public Action Before;   // runs before the event is delivered, e.g. a command at a stop
            public HoldStep(byte[] ev, uint[] tf, string want) { Ev = ev; Tf = tf; Want = want; }
            public HoldStep(byte[] ev, uint[] tf, string want, Action before) : this(ev, tf, want) { Before = before; }
        }

        /// <summary>
        /// The re-arm hold, on the REAL debug loop fed a script of events, with a fake thread table in place of
        /// SuspendThread / ResumeThread / the TF read. T1 hits a user breakpoint (or T2 a step's call-skip temp),
        /// and while it steps off the restored byte every other live thread must be suspended once; the hold must
        /// end at the stepper's single-step, and equally when its event is passed to the app, when it exits, at the
        /// process's exit and at a detach. T3 starts suspended by the app (count 1) and must end at 1. The hold is
        /// never taken for a thread that owes no re-plant (a step trap, a call-skip) or whose TF is clear, a thread
        /// created during the hold is held too, and when a held thread's queued hit on the same breakpoint makes it
        /// a stepper as well, the hold passes to it at the first stepper's trap and the INT3 goes back once, at the
        /// LAST owed step.
        ///
        /// NOT COVERED: the Win32 implementation (Win32ThreadOps) and whether a real race is closed. The live
        /// suites run the real thread operations; see tools\test-bp-threaded.ps1.
        /// </summary>
        private static void CheckRearmHold(List<string> failures, ClaimLog claims)
        {
            const uint T1 = 0xFFFFFF10, T2 = 0xFFFFFF20, T3 = 0xFFFFFF30, T4 = 0xFFFFFF40;
            const uint Base = 0x00400000, Va = 0x00401100, TempVa = 0x00401300;
            const uint Ex = Native.EXCEPTION_DEBUG_EVENT;
            Func<uint, uint, byte[]> bp = (tid, va) => DebugEngine.DebugEventForTest(Ex, tid, Native.EXCEPTION_BREAKPOINT, va);
            Func<uint, byte[]> ss = tid => DebugEngine.DebugEventForTest(Ex, tid, Native.EXCEPTION_SINGLE_STEP, 0);
            Func<uint, byte[]> av = tid => DebugEngine.DebugEventForTest(Ex, tid, 0xC0000005, 0x00401234);
            Func<uint, uint, byte[]> bare = (code, tid) => DebugEngine.DebugEventForTest(code, tid, 0, 0);
            var none = new uint[0];

            int scenarios = 0;
            // Runs one scenario and checks every continue it names, the fake's errors, and that every thread still
            // alive ends with the count it started with. Returns the fake and the re-plant trace for extra checks.
            Func<string, Action<DebugEngine>, List<HoldStep>, int, uint[], Tuple<FakeThreadOps, List<uint>, DebugEngine>> run =
                (name, arm, steps, detachAt, alive) =>
            {
                scenarios++;
                var eng = NewEngine();
                eng.ArmUserBpForTest(Base, Va, null, null, 0, null);
                if (arm != null) arm(eng);
                var ops = new FakeThreadOps();
                ops.Count[T3] = 1;   // suspended by the app before any of this
                var order = new[] { T1, T2, T3, T4 };
                Func<string> counts = () =>
                {
                    var c = new List<string>();
                    foreach (var t in order) if (t != T4 || ops.Count.ContainsKey(T4)) c.Add(ops.Get(t).ToString());
                    return string.Join(",", c);
                };
                List<uint> trace = null;
                string escaped = null;
                CaptureConsole(() =>
                {
                    try
                    {
                        trace = eng.RunRearmHoldScriptForTest(ops, new[] { T1, T2, T3 }, steps.ConvertAll(s => s.Ev),
                            i =>
                            {
                                if (steps[i].Before != null) steps[i].Before();
                                ops.Tf.Clear(); foreach (var t in steps[i].Tf) ops.Tf.Add(t);
                                if (BitConverter.ToUInt32(steps[i].Ev, 0) == Native.EXIT_THREAD_DEBUG_EVENT)
                                    ops.Exited.Add(BitConverter.ToUInt32(steps[i].Ev, 8));
                            },
                            i =>
                            {
                                if (steps[i].Want != null && counts() != steps[i].Want)
                                    failures.Add("rearm hold (" + name + "): at event " + i + "'s continue the suspend counts of "
                                                 + "T1..T" + (ops.Count.ContainsKey(T4) ? 4 : 3) + " are " + counts()
                                                 + ", expected " + steps[i].Want);
                            },
                            detachAt);
                    }
                    catch (Exception ex) { escaped = ex.GetType().Name + ": " + ex.Message; }
                });
                if (escaped != null) failures.Add("rearm hold (" + name + "): the loop threw " + escaped);
                foreach (var e in ops.Errors) failures.Add("rearm hold (" + name + "): " + e);
                foreach (var t in alive)
                {
                    int want = t == T3 ? 1 : 0;
                    if (ops.Get(t) != want)
                        failures.Add("rearm hold (" + name + "): thread 0x" + t.ToString("X") + " ends with suspend count "
                                     + ops.Get(t) + ", expected " + want + " - a hold outlived its way out");
                }
                if (eng.HeldCountForTest != 0)
                    failures.Add("rearm hold (" + name + "): the engine still records " + eng.HeldCountForTest + " held thread(s)");
                return Tuple.Create(ops, trace ?? new List<uint>(), eng);
            };
            var all3 = new[] { T1, T2, T3 };

            // The stepper's single-step ends the hold, and the INT3 goes back at that trap.
            var r = run("single-step", null, new List<HoldStep>
            {
                new HoldStep(bp(T1, Va), new[] { T1 }, "0,1,2"),
                new HoldStep(ss(T1), none, "0,0,1"),
            }, -1, all3);
            if (r.Item2.Count != 1 || r.Item2[0] != Va)
                failures.Add("rearm hold (single-step): INT3s written [" + Hex(r.Item2) + "], expected [0x" + Va.ToString("X") + "]");

            // Its next event passed to the app: the app's handler runs, not one instruction. TF still reads set,
            // so only the continue status can end the hold here.
            run("exception passed to the app", null, new List<HoldStep>
            {
                new HoldStep(bp(T1, Va), new[] { T1 }, "0,1,2"),
                new HoldStep(av(T1), new[] { T1 }, "0,0,1"),
            }, -1, all3);

            // It exits before its step: the owed INT3 is paid at the exit, and TF (still reading set) cannot keep it holder.
            r = run("stepper exits", null, new List<HoldStep>
            {
                new HoldStep(bp(T1, Va), new[] { T1 }, "0,1,2"),
                new HoldStep(bare(Native.EXIT_THREAD_DEBUG_EVENT, T1), new[] { T1 }, "0,0,1"),
            }, -1, new[] { T2, T3 });
            if (r.Item2.Count != 1 || r.Item2[0] != Va)
                failures.Add("rearm hold (stepper exits): INT3s written [" + Hex(r.Item2) + "], expected [0x" + Va.ToString("X")
                             + "] - a thread that exits owing a step must not leave the byte restored");

            // The process exits: that event is never continued, so nothing reconciles after it.
            run("process exits", null, new List<HoldStep>
            {
                new HoldStep(bp(T1, Va), new[] { T1 }, "0,1,2"),
                new HoldStep(bare(Native.EXIT_PROCESS_DEBUG_EVENT, T1), new[] { T1 }, null),
            }, -1, new[] { T2, T3 });

            // A detach arrives while held: nobody resumes the others once the debugger has let go.
            run("detach", null, new List<HoldStep>
            {
                new HoldStep(bp(T1, Va), new[] { T1 }, "0,1,2"),
                new HoldStep(bare(Native.OUTPUT_DEBUG_STRING_EVENT, T2), new[] { T1 }, null),
            }, 1, all3);

            // A step session and its call-skip: step traps owe no re-plant, and a call-skip runs with TF clear.
            r = run("step session and call-skip", e =>
            {
                e.ArmStepOverSessionForTest(T1, 0x00401200, TempVa);
                e.ArmCallSkipForTest(TempVa, 0, 0x0012FF00, 0x0012FE00, 0x0012FF40, 0);
            }, new List<HoldStep>
            {
                new HoldStep(bare(Native.OUTPUT_DEBUG_STRING_EVENT, T2), none, "0,0,1"),
                new HoldStep(ss(T1), new[] { T1 }, "0,0,1"),
            }, -1, all3);
            if (r.Item1.Suspends != 0)
                failures.Add("rearm hold (step session and call-skip): " + r.Item1.Suspends + " suspend(s) with no re-plant owed");

            // Another thread passing the stepping thread's call-skip temp is held for ONE step, inside a step session.
            r = run("temp re-arm", e => e.ArmStepOverSessionForTest(T1, 0x00401200, TempVa), new List<HoldStep>
            {
                new HoldStep(bp(T2, TempVa), new[] { T2 }, "1,0,2"),
                new HoldStep(ss(T2), none, "0,0,1"),
            }, -1, all3);
            if (r.Item2.Count != 1 || r.Item2[0] != TempVa)
                failures.Add("rearm hold (temp re-arm): INT3s written [" + Hex(r.Item2) + "], expected [0x" + TempVa.ToString("X") + "]");

            // A held thread's hit on the SAME breakpoint was queued behind T1's. T1 keeps the hold until its trap;
            // then it passes to T2; the INT3 goes back once, at T2's trap, not under T2 at T1's.
            r = run("queued hit on a held thread", null, new List<HoldStep>
            {
                new HoldStep(bp(T1, Va), new[] { T1 }, "0,1,2"),
                new HoldStep(bp(T2, Va), new[] { T1, T2 }, "0,1,2"),
                new HoldStep(ss(T1), new[] { T2 }, "1,0,2"),
                new HoldStep(ss(T2), none, "0,0,1"),
            }, -1, all3);
            if (r.Item2.Count != 1 || r.Item2[0] != Va)
                failures.Add("rearm hold (queued hit on a held thread): INT3s written [" + Hex(r.Item2) + "], expected [0x"
                             + Va.ToString("X") + "] once, at the last owed step");

            // setip on a thread whose queued hit on the SAME breakpoint arrived behind the stepper's (wave 7 pipeline
            // run 1). T2's re-plant is handed over while T1 still owes its step off Va: 0xCC must not go back under
            // T1 then, or T1 takes the same hit twice. It goes back once, at T1's trap.
            DebugEngine setIpEng = null;
            r = run("setip handover while another thread owes the step", e => setIpEng = e, new List<HoldStep>
            {
                new HoldStep(bp(T1, Va), new[] { T1 }, "0,1,2"),
                new HoldStep(bp(T2, Va), new[] { T1 }, "0,1,2"),
                new HoldStep(ss(T1), none, "0,0,1", () => setIpEng.HandOverRearmForTest(T2, 0x00401500)),
            }, -1, all3);
            if (r.Item2.Count != 1 || r.Item2[0] != Va)
                failures.Add("rearm hold (setip handover while another thread owes the step): INT3s written [" + Hex(r.Item2)
                             + "], expected [0x" + Va.ToString("X") + "] once, at T1's trap - not also at the handover");

            // A HELD thread exits (killed from outside, say): nothing is left to resume, and the release skips it.
            run("held thread exits", null, new List<HoldStep>
            {
                new HoldStep(bp(T1, Va), new[] { T1 }, "0,1,2"),
                new HoldStep(bare(Native.EXIT_THREAD_DEBUG_EVENT, T2), new[] { T1 }, null),
                new HoldStep(ss(T1), none, null),
            }, -1, new[] { T1, T3 });

            // A thread created during the hold is held too, and released with the rest.
            run("thread created during the hold", null, new List<HoldStep>
            {
                new HoldStep(bp(T1, Va), new[] { T1 }, "0,1,2"),
                new HoldStep(bare(Native.CREATE_THREAD_DEBUG_EVENT, T4), new[] { T1 }, "0,1,2,1"),
                new HoldStep(ss(T1), none, "0,0,1,0"),
            }, -1, new[] { T1, T2, T3, T4 });

            // A re-plant is owed but TF is clear (the context could not be written): no step is coming, so no hold.
            r = run("owed re-plant, TF clear", null, new List<HoldStep>
            {
                new HoldStep(bp(T1, Va), none, "0,0,1"),
            }, -1, all3);
            if (r.Item1.Suspends != 0)
                failures.Add("rearm hold (owed re-plant, TF clear): " + r.Item1.Suspends + " suspend(s) for a thread with no step coming");

            claims.Claim("the re-arm hold, on the real debug loop in " + scenarios + " scripted scenarios with a fake thread "
                         + "table: a thread stepping off a restored INT3 runs alone, every other thread suspended exactly "
                         + "once; the hold ends at its single-step, when its event is passed to the app, when it exits (the "
                         + "owed INT3 then paid), at the process's exit and at a detach; it is never taken for a step trap, "
                         + "a call-skip or a clear TF; a held thread that exits is not resumed; setip's re-arm handover does not re-plant under a thread still owing its step; a thread created during it is held; a queued hit on a held thread takes "
                         + "the hold over at the first stepper's trap and the INT3 goes back once, at the last; every count "
                         + "ends where it began, including an app-suspended thread's.");
        }

        private static string Hex(List<uint> vas)
        {
            return string.Join(",", vas.ConvertAll(v => "0x" + v.ToString("X")));
        }
    }
}
