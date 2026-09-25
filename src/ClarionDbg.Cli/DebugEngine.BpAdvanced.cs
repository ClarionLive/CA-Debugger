using System;
using System.Globalization;
using System.Text.RegularExpressions;
using ClarionDbg.Core;

namespace ClarionDbg.Cli
{
    /// <summary>
    /// Advanced breakpoint behaviour — the centralized "should this hit actually pause?" decision shared
    /// by conditional breakpoints, hit counts, and tracepoints. All three hang off one path so the engine
    /// evaluates them in a fixed order: condition gate → hit-count rule → tracepoint (log+resume) → pause.
    ///
    /// Value access reuses the same resolution the Watch panel uses (<see cref="ResolveDataAcrossModules"/>
    /// + <see cref="FormatValueAt"/>), and reads SYNCHRONOUSLY at hit time — including THREADed (.cwtls)
    /// data, which resolves to the HITTING thread's instance through the same read-only THR$GetInstance
    /// emulation the Watch panel uses (<see cref="TryResolveThreadedInstance"/>). Nothing here runs target
    /// code, so the whole decision still answers inline.
    ///
    /// This file used to say a func-eval round-trip was required and that threaded data could not be read
    /// inline. That stopped being true at 992d3e4, and the claim outliving it is the whole of 465a3873: the
    /// bail it justified made every condition, hit count and {NAME} token over a THREADed name read 0 — not
    /// unsupported, quietly WRONG. If a comment here ever says something cannot be done, check it against
    /// the code before believing it.
    /// </summary>
    internal sealed partial class DebugEngine
    {
        /// <summary>The logical breakpoint planted at this address, or null (a plain INT3 with no
        /// advanced properties, or an anonymous --rva breakpoint). Several gutter lines can snap to one
        /// address; the first match wins (advanced-property collisions on one address are unsupported).</summary>
        private UserBreakpoint FindBpAt(LoadedModule m, uint rva)
        {
            if (m == null) return null;
            foreach (var b in _bps)
                if (b.Owner == m && b.Rvas.Contains(rva)) return b;
            return null;
        }

        /// <summary>Centralized decision for a breakpoint that carries advanced properties. Returns true to
        /// pause (a real stop), false to resume silently. Order: condition gate, then hit-count rule (over
        /// condition-satisfied hits), then tracepoint (log + resume). Side effect: increments HitCount.
        ///
        /// <paramref name="tid"/>/<paramref name="hThread"/> are the HITTING thread — the one whose .cwtls
        /// instances a condition or token has to read. A THREADed name means nothing without them: the same
        /// breakpoint on two threads is two different values.</summary>
        private bool ShouldPauseAtBp(UserBreakpoint bp, uint tid, IntPtr hThread)
        {
            // A hit is an EPISODE, exactly like a stop, and this is its single entrance — every hit-time
            // value read below goes through here. The .cwtls block cache is only valid while the target is
            // frozen at one debug event, and a NON-PAUSING hit never reaches PausedWait (it returns
            // DBG_CONTINUE straight from OnUserBp), which is precisely the case a conditional breakpoint
            // exists to produce: hit many times, pausing none of them. Clearing here is what "resolve fresh
            // per hit" means in practice — nothing survives from the last hit or the last stop, while the
            // several names of one condition or trace message still share one emulation per image.
            ClearThreadedBlockCache();

            // 1) Condition gate — false ⇒ resume silently; indeterminate ⇒ pause and surface why.
            if (!string.IsNullOrEmpty(bp.Condition))
            {
                string why;
                bool? cond = TryEvalCondition(bp.Condition, tid, hThread, out why);
                if (cond == false) return false;
                if (cond == null)
                {
                    Console.WriteLine($"  bp {bp.Module}:{bp.Line}: condition '{bp.Condition}' could not be evaluated"
                                      + (why != null ? " (" + why + ")" : "") + " — pausing");
                    return true;
                }
            }

            // 2) Hit count — counts hits whose condition passed; rule unmet ⇒ resume silently.
            bp.HitCount++;
            if (!string.IsNullOrEmpty(bp.HitMode))
            {
                bool satisfied;
                switch (bp.HitMode)
                {
                    case "eq":  satisfied = bp.HitCount == bp.HitValue; break;
                    case "gte": satisfied = bp.HitCount >= bp.HitValue; break;
                    case "mod": satisfied = bp.HitValue > 0 && (bp.HitCount % bp.HitValue) == 0; break;
                    default:    satisfied = true; break;
                }
                if (!satisfied) return false;
            }

            // 3) Tracepoint — interpolate {var} tokens, log, and keep running (never pauses).
            if (bp.Trace != null)
            {
                EmitTrace(bp, InterpolateTrace(bp.Trace, tid, hThread));
                return false;
            }

            return true;
        }

        private void EmitTrace(UserBreakpoint bp, string message)
        {
            Console.WriteLine($"  [TRACE] {bp.Module}:{bp.Line}: {message}");
            if (EmitJson) Console.WriteLine("@JSON " + Json.Trace(bp.Module, bp.Line, message, bp.HitCount));
        }

        // ------------------------------------------------------------------ condition evaluation

        /// <summary>Evaluate a simple <c>LHS &lt;op&gt; RHS</c> condition against live target memory.
        /// LHS is a data name (global / module-static / record buffer / record field — the same scope the
        /// Watch panel resolves, THREADed names included, read on the hitting thread). RHS is a numeric
        /// literal, a quoted string, or another data name. Returns the boolean result, or null when it
        /// cannot be evaluated (unparseable, unresolvable, or unreadable). <paramref name="why"/> is the reason
        /// when there is one to give: a name several FILE records answer to (3517fd15 item 4) says which, since
        /// "could not be evaluated" alone leaves the user no way to fix the condition.</summary>
        private bool? TryEvalCondition(string expr, uint tid, IntPtr hThread, out string why)
        {
            why = null;
            if (string.IsNullOrWhiteSpace(expr)) return true;

            string op; int opPos, opLen;
            if (!FindOperator(expr, out op, out opPos, out opLen)) return null;

            string lhsName = expr.Substring(0, opPos).Trim();
            string rhsRaw = expr.Substring(opPos + opLen).Trim();
            if (lhsName.Length == 0 || rhsRaw.Length == 0) return null;

            double lnum; string lstr;
            int lk = ReadVarValue(lhsName, tid, hThread, out lnum, out lstr, out why);
            if (lk == 0) return null; // unresolvable / unreadable ⇒ indeterminate

            // Resolve RHS: quoted string literal, numeric literal, or a second data name.
            bool rhsString; double rnum = 0; string rstr = null;
            if (rhsRaw[0] == '\'' || rhsRaw[0] == '"')
            {
                rhsString = true; rstr = StripQuotes(rhsRaw);
            }
            else if (double.TryParse(rhsRaw, NumberStyles.Any, CultureInfo.InvariantCulture, out rnum))
            {
                rhsString = false;
            }
            else
            {
                int rk = ReadVarValue(rhsRaw, tid, hThread, out rnum, out rstr, out why);
                if (rk == 0) return null;
                rhsString = rk == 2;
            }

            int cmp;
            if (lk == 2 || rhsString)
            {
                // string domain — render either side to text and compare ordinally
                string a = lk == 2 ? (lstr ?? "") : lnum.ToString(CultureInfo.InvariantCulture);
                string b = rhsString ? (rstr ?? "") : rnum.ToString(CultureInfo.InvariantCulture);
                cmp = string.CompareOrdinal(a, b);
            }
            else
            {
                cmp = lnum.CompareTo(rnum);
            }
            return ApplyOp(op, cmp);
        }

        /// <summary>Apply a comparison operator to the sign of (LHS - RHS).</summary>
        private static bool ApplyOp(string op, int cmp)
        {
            switch (op)
            {
                case "==": case "=": return cmp == 0;
                case "!=": case "<>": return cmp != 0;
                case ">":  return cmp > 0;
                case ">=": return cmp >= 0;
                case "<":  return cmp < 0;
                case "<=": return cmp <= 0;
                default:   return false;
            }
        }

        /// <summary>Locate the comparison operator, preferring the earliest two-char operator, then the
        /// earliest single-char one. Good enough for the supported grammar (operators never appear inside
        /// a bare data name; a stray operator char inside a quoted RHS sits after the real operator).</summary>
        private static bool FindOperator(string s, out string op, out int pos, out int len)
        {
            op = null; pos = -1; len = 0;
            int best = int.MaxValue; string bestOp = null;
            foreach (var o in new[] { ">=", "<=", "==", "!=", "<>" })
            {
                int idx = s.IndexOf(o, StringComparison.Ordinal);
                if (idx >= 0 && idx < best) { best = idx; bestOp = o; }
            }
            if (bestOp != null) { op = bestOp; pos = best; len = 2; return true; }
            foreach (var o in new[] { ">", "<", "=" })
            {
                int idx = s.IndexOf(o, StringComparison.Ordinal);
                if (idx >= 0 && idx < best) { best = idx; bestOp = o; }
            }
            if (bestOp != null) { op = bestOp; pos = best; len = 1; return true; }
            return false;
        }

        // ------------------------------------------------------------------ tracepoint interpolation

        /// <summary>Substitute <c>{name}</c> tokens with the live value of each data name, read on the
        /// hitting thread. A name that cannot be read renders as <c>{?name}</c> so the message still logs.</summary>
        private string InterpolateTrace(string template, uint tid, IntPtr hThread)
        {
            if (string.IsNullOrEmpty(template)) return string.Empty;
            return Regex.Replace(template, @"\{([^{}]+)\}", mm =>
            {
                string nm = mm.Groups[1].Value.Trim();
                double n; string s;
                int k = ReadVarValue(nm, tid, hThread, out n, out s);
                if (k == 1) return n.ToString(CultureInfo.InvariantCulture);
                if (k == 2) return s ?? string.Empty;
                return "{?" + nm + "}";
            });
        }

        // ------------------------------------------------------------------ synchronous value read

        /// <summary>Read a data name's CURRENT value synchronously at hit time, on the thread that hit.
        /// Returns 0 = not found / unreadable, 1 = numeric (num set), 2 = string (str set). Reuses the Watch
        /// panel's name resolution AND its THREADed instance resolution; numeric scalars are decoded raw
        /// (locale/quote-proof), everything else falls back to the shared display formatter.
        /// <para><paramref name="ambiguity"/> is the message when an ambiguous name is why it could not be read
        /// (null otherwise). This overload comes FIRST: tools/test-threaded-template-rule.ps1 extracts the body by
        /// its signature's first match.</para></summary>
        private int ReadVarValue(string name, uint tid, IntPtr hThread, out double num, out string str, out string ambiguity)
        {
            num = 0; str = null;
            TswdDebugInfo.DataLocation loc; LoadedModule owner;
            // An ambiguous name (two FILE records, 04d7b4c8) is unreadable too: a condition pauses and says so.
            if (ResolveDataAcrossModules(name, out owner, out loc, out ambiguity) != DataResolve.Found) return 0;

            uint templateVa = owner.LoadBase + loc.Rva;
            uint va = templateVa;
            // Over the symbol's SPAN, through the shared test (ef0a941d). A start-only test here read a
            // symbol straddling into the template as ordinary data and answered the condition from the
            // template — changing whether the developer stops, with nothing on screen to doubt.
            var span = ClassifyTemplateSpan(owner, templateVa, loc.Size);
            if (span == TemplateSpan.Straddling)
                return 0;   // only part of it is this thread's: indeterminate, as in `default` below — a
                            // condition pauses and says so, a tracepoint prints {?name}
            if (span == TemplateSpan.StartsInside)
            {
                // Same resolver, same vocabulary as the Watch panel and the Variables tree (see
                // DebugEngine.Locals.cs) — one shape for "what does this THREADed name read here", not three.
                uint instanceVa; string reason;
                switch (TryResolveThreadedInstance(owner, templateVa, tid, hThread, out instanceVa, out reason))
                {
                    case ThreadedResolve.Ok:
                        va = instanceVa;
                        break;

                    case ThreadedResolve.Unallocated:
                        // The hitting thread has never touched this data, so there is no instance. Its first
                        // touch starts from the template's initial value, so that IS what the condition is
                        // asking about — the same answer the Watch row gives, annotated there and silent here.
                        break;

                    case ThreadedResolve.Template:
                        // Not a Clarion thread: the shared template is what code here reads. Real value.
                        break;

                    default:
                        // DELIBERATELY NOT the panels' fallback. A panel row must show something, so Locals
                        // falls back to the template and labels it. A gate must not: answering a condition
                        // from the wrong thread's data is a silent wrong answer, and the whole point of this
                        // ticket is that a quiet 0 is worse than an admitted "don't know". Indeterminate
                        // instead — the caller pauses and prints why.
                        return 0;
                }
            }

            byte code = loc.TypeCode;
            switch (code)
            {
                case 0x11: case 0x12: case 0x13: case 0x25:
                    return ReadScalarNumeric(va, code, loc.Size, out num) ? 1 : 0;
                case 0x23: case 0x24: // DECIMAL / PDECIMAL — formatted then parsed
                {
                    string disp = FormatValueAt(code, 0, loc.Size, 0, va);
                    double d;
                    if (double.TryParse(disp, NumberStyles.Any, CultureInfo.InvariantCulture, out d)) { num = d; return 1; }
                    str = disp; return 2;
                }
                default: // STRING / GROUP / reference / unknown — compare as text
                    str = StripQuotes(FormatValueAt(code, 0, loc.Size, 0, va));
                    return 2;
            }
        }

        private int ReadVarValue(string name, uint tid, IntPtr hThread, out double num, out string str)
        {
            string ambiguity;
            return ReadVarValue(name, tid, hThread, out num, out str, out ambiguity);
        }

        /// <summary>Decode a scalar numeric type (LONG/ULONG/SHORT/BYTE/SREAL/REAL) to a double.</summary>
        private bool ReadScalarNumeric(uint va, byte code, uint size, out double val)
        {
            val = 0;
            int need = (code == 0x13 || code == 0x25) ? (size == 8 ? 8 : 4)
                                                      : (size == 1 ? 1 : size == 2 ? 2 : 4);
            var b = new byte[need];
            if (ReadBlock(va, b) < need) return false;
            switch (code)
            {
                case 0x11: val = need == 1 ? (sbyte)b[0] : need == 2 ? BitConverter.ToInt16(b, 0) : BitConverter.ToInt32(b, 0); return true;
                case 0x12: val = need == 1 ? b[0]        : need == 2 ? BitConverter.ToUInt16(b, 0) : BitConverter.ToUInt32(b, 0); return true;
                case 0x13: case 0x25: val = need == 8 ? BitConverter.ToDouble(b, 0) : BitConverter.ToSingle(b, 0); return true;
                default: return false;
            }
        }

        /// <summary>Strip one wrapping pair of single or double quotes (the display formatter wraps
        /// strings in single quotes; a quoted RHS literal uses either).</summary>
        private static string StripQuotes(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 2) return s;
            char a = s[0], z = s[s.Length - 1];
            if ((a == '\'' && z == '\'') || (a == '"' && z == '"')) return s.Substring(1, s.Length - 2);
            return s;
        }
    }
}
