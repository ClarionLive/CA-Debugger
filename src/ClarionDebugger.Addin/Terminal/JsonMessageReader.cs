using System;
using System.Globalization;
using System.Text;

namespace ClarionDebugger.Terminal
{
    /// <summary>
    /// Reads one named field out of a JSON object sent by the debugger page.
    /// <para>
    /// THE THREAT MODEL THIS EXISTS FOR. The debuggee is untrusted: procedure and module names come from the
    /// target's TSWD debug info, are shown in the Procedures pane and the Source view, and come back to the
    /// host through the WebView bridge. The extractor this replaces searched for <c>"key":</c> with
    /// <see cref="string.IndexOf(string, StringComparison)"/> and no notion of where strings start and end,
    /// so a value could impersonate a field simply by containing <c>"line":9</c> — and the first match won,
    /// wherever it sat. The page worked around that by ORDERING its payloads, putting untrusted fields last,
    /// and the old doc comment told every future payload to keep doing so. Field order is not a boundary:
    /// it holds only while every sender remembers, and it fails silently the first time one does not.
    /// </para>
    /// <para>
    /// So this walks the object properly — tracking string and escape state, and skipping nested containers
    /// whole — and matches only members of the TOP-LEVEL object. Every inbound payload is flat (the outer
    /// <c>{action,data}</c> envelope, and the flat object inside <c>data</c>), so nothing needs to reach into
    /// a nested one, and "the key I found was actually inside something else" stops being expressible.
    /// </para>
    /// <para>
    /// The one reader that DOES go inside is <see cref="ForEachObject"/>, and it does so on purpose: it hands
    /// back each nested object whole, to be read with <see cref="ReadField"/> in turn, so the top-level rule
    /// still holds for every object it is applied to. It exists for rows the host forwards but did not build
    /// (afbc68c7).
    /// </para>
    /// </summary>
    internal static class JsonMessageReader
    {
        /// <summary>The value of <paramref name="key"/> in the top-level object of <paramref name="json"/>,
        /// or null when it is absent, is JSON <c>null</c>, or the text is not a well-formed object.
        /// <para>
        /// A string comes back unescaped; a number, <c>true</c> or <c>false</c> comes back as its literal
        /// text, which is what the call sites hand to <c>int.TryParse</c> / <c>uint.TryParse</c>. An object
        /// or array value reads as null: it is not a scalar, no inbound payload carries one, and returning
        /// its raw text would let a caller expecting a string quietly use a blob of JSON as one.
        /// </para>
        /// <para>
        /// MALFORMED INPUT READS AS ABSENT, on purpose. This sits on a path that must never throw — a throw
        /// here reaches the WebView message handler and kills the command — and "absent" is a state every
        /// caller already handles, because a field the page did not send has always been null.
        /// </para></summary>
        public static string ReadField(string json, string key)
        {
            if (string.IsNullOrEmpty(json) || string.IsNullOrEmpty(key)) return null;

            int i = 0;
            SkipWhitespace(json, ref i);
            if (i >= json.Length || json[i] != '{') return null;
            i++;

            while (true)
            {
                SkipWhitespace(json, ref i);
                if (i >= json.Length) return null;

                char c = json[i];
                if (c == '}') return null;          // ran out of members without finding it
                if (c == ',') { i++; continue; }
                if (c != '"') return null;          // a member name must be a quoted string

                string name = ReadString(json, ref i);
                if (name == null) return null;      // unterminated or illegally escaped name

                SkipWhitespace(json, ref i);
                if (i >= json.Length || json[i] != ':') return null;
                i++;
                SkipWhitespace(json, ref i);

                // The value is walked either way. Skipping it properly is what stops the NEXT member's name
                // being read out of the middle of this one's text.
                bool wanted = string.Equals(name, key, StringComparison.Ordinal);
                string value = ReadValue(json, ref i, wanted);
                // A "did the scan advance?" guard used to sit here — `if (i <= before && i >= json.Length)
                // return null;` — and it could not fire. ReadValue's first statement sets i = -1 whenever i
                // is ALREADY at or past the end, so `i >= json.Length` can hold only when the scan advanced
                // to exactly the end, which contradicts `i <= before`. A value that genuinely does not
                // advance (`{"a":,"b":1}`) leaves i below the end, and the ','/'}'/return-null cases at the
                // top of this loop decide it — they also guarantee termination, which is what the guard
                // looked like it was there for. Removed rather than kept unverified: by house rule 3 a
                // guard no case can isolate is not a guard. See the empty-value checks in
                // tools/test-addin-json.ps1 for the shapes that used to reach it.
                if (i < 0) return null;             // malformed value; nothing after it can be trusted
                if (wanted) return value;
            }
        }

        /// <summary>Call <paramref name="visit"/> with the text of every OBJECT anywhere inside
        /// <paramref name="json"/>, innermost first, so each one can be read with <see cref="ReadField"/>.
        /// Returns false, having visited nothing, when the text is not one well-formed value.
        /// <para>
        /// This is how the host reads rows it did not build. The engine's Variables rows reach the page
        /// verbatim - nested <c>children</c> and all - and the ones that can be edited carry the address and
        /// type the page will later send back. The host records those tuples on the way OUT (afbc68c7), and
        /// a flat reader cannot see a member inside a group's children. Malformed input visits NOTHING
        /// rather than the objects before the fault: a partial walk would grant some rows of a reply the
        /// host could not read, which is a harder state to reason about than granting none.
        /// </para></summary>
        public static bool ForEachObject(string json, Action<string> visit)
        {
            if (string.IsNullOrEmpty(json) || visit == null) return false;
            var found = new System.Collections.Generic.List<string>();
            int i = 0;
            SkipWhitespace(json, ref i);
            if (!WalkValue(json, ref i, found)) return false;
            SkipWhitespace(json, ref i);
            if (i != json.Length) return false;     // trailing text after the value
            foreach (var o in found) visit(o);
            return true;
        }

        /// <summary>Walk one value at <paramref name="i"/>, collecting every object's text into
        /// <paramref name="found"/>. False on malformed input.</summary>
        private static bool WalkValue(string json, ref int i, System.Collections.Generic.List<string> found)
        {
            if (i >= json.Length) return false;
            char c = json[i];
            if (c == '"') return ReadString(json, ref i) != null;
            if (c == '{')
            {
                int start = i;
                i++;
                SkipWhitespace(json, ref i);
                if (i < json.Length && json[i] == '}') { i++; found.Add(json.Substring(start, i - start)); return true; }
                while (true)
                {
                    SkipWhitespace(json, ref i);
                    if (i >= json.Length || json[i] != '"' || ReadString(json, ref i) == null) return false;
                    SkipWhitespace(json, ref i);
                    if (i >= json.Length || json[i] != ':') return false;
                    i++;
                    SkipWhitespace(json, ref i);
                    if (!WalkValue(json, ref i, found)) return false;
                    SkipWhitespace(json, ref i);
                    if (i >= json.Length) return false;
                    if (json[i] == ',') { i++; continue; }
                    if (json[i] != '}') return false;
                    i++;
                    found.Add(json.Substring(start, i - start));
                    return true;
                }
            }
            if (c == '[')
            {
                i++;
                SkipWhitespace(json, ref i);
                if (i < json.Length && json[i] == ']') { i++; return true; }
                while (true)
                {
                    SkipWhitespace(json, ref i);
                    if (!WalkValue(json, ref i, found)) return false;
                    SkipWhitespace(json, ref i);
                    if (i >= json.Length) return false;
                    if (json[i] == ',') { i++; continue; }
                    if (json[i] != ']') return false;
                    i++;
                    return true;
                }
            }
            // number, true, false, null: at least one character, up to the next structural one.
            int s = i;
            while (i < json.Length && json[i] != ',' && json[i] != '}' && json[i] != ']'
                   && json[i] != ' ' && json[i] != '\t' && json[i] != '\r' && json[i] != '\n') i++;
            return i > s;
        }

        /// <summary>Consume one value. Returns its text only when <paramref name="capture"/>, so skipping a
        /// member costs no allocation. Sets <paramref name="i"/> to -1 on malformed input.</summary>
        private static string ReadValue(string json, ref int i, bool capture)
        {
            if (i >= json.Length) { i = -1; return null; }

            char c = json[i];

            if (c == '"')
            {
                string s = ReadString(json, ref i);
                if (s == null) { i = -1; return null; }
                return capture ? s : null;
            }

            if (c == '{' || c == '[')
            {
                if (!SkipContainer(json, ref i)) { i = -1; return null; }
                return null;                        // not a scalar — see the summary
            }

            // number, true, false, null: runs to the next structural character. Safe to scan raw, because
            // none of these can contain a quote, a comma or a brace.
            int start = i;
            while (i < json.Length && json[i] != ',' && json[i] != '}' && json[i] != ']') i++;
            if (!capture) return null;
            string raw = json.Substring(start, i - start).Trim();
            if (raw.Length == 0) return null;
            return string.Equals(raw, "null", StringComparison.Ordinal) ? null : raw;
        }

        /// <summary>Read a quoted string starting at the opening quote, leaving <paramref name="i"/> just
        /// past the closing one. Null if it is unterminated or carries an escape JSON does not define —
        /// which is the whole point: this is the only function that decides where a string ENDS, so a quote
        /// inside a value can never be mistaken for the end of it.</summary>
        private static string ReadString(string json, ref int i)
        {
            i++;                                    // past the opening quote
            var sb = new StringBuilder();
            while (i < json.Length)
            {
                char c = json[i];

                if (c == '"') { i++; return sb.ToString(); }

                if (c == '\\')
                {
                    i++;
                    if (i >= json.Length) return null;
                    switch (json[i])
                    {
                        case '"':  sb.Append('"');  break;
                        case '\\': sb.Append('\\'); break;
                        case '/':  sb.Append('/');  break;
                        case 'b':  sb.Append('\b'); break;
                        case 'f':  sb.Append('\f'); break;
                        case 'n':  sb.Append('\n'); break;
                        case 'r':  sb.Append('\r'); break;
                        case 't':  sb.Append('\t'); break;
                        case 'u':
                        {
                            if (i + 4 >= json.Length) return null;
                            int cp;
                            if (!int.TryParse(json.Substring(i + 1, 4), NumberStyles.HexNumber,
                                              CultureInfo.InvariantCulture, out cp)) return null;
                            sb.Append((char)cp);
                            i += 4;
                            break;
                        }
                        default: return null;       // not a JSON escape; refuse rather than guess
                    }
                    i++;
                    continue;
                }

                sb.Append(c);
                i++;
            }
            return null;                            // unterminated
        }

        /// <summary>Step over a whole object or array, starting at its opening bracket. Strings inside it go
        /// through <see cref="ReadString"/>, so a brace or bracket inside a string value cannot unbalance
        /// the count — the failure the old extractor had no way to avoid.</summary>
        private static bool SkipContainer(string json, ref int i)
        {
            int depth = 0;
            while (i < json.Length)
            {
                char c = json[i];
                if (c == '"')
                {
                    if (ReadString(json, ref i) == null) return false;
                    continue;
                }
                if (c == '{' || c == '[') { depth++; i++; continue; }
                if (c == '}' || c == ']')
                {
                    depth--;
                    i++;
                    if (depth == 0) return true;
                    if (depth < 0) return false;
                    continue;
                }
                i++;
            }
            return false;                           // unterminated
        }

        private static void SkipWhitespace(string json, ref int i)
        {
            while (i < json.Length)
            {
                char c = json[i];
                if (c != ' ' && c != '\t' && c != '\r' && c != '\n') return;
                i++;
            }
        }
    }
}
