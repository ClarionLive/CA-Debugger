using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Xml;

namespace ClarionDebugger.Services
{
    /// <summary>
    /// A .cwproj (MSBuild XML) read for the CA Debugger's target: its OutputType and OutputName as MSBuild would
    /// read them for one configuration and platform, and the Conditions Clarion writes. Pure apart from
    /// <see cref="Read"/>, which loads the file; ProjectTargetService decides which project is the target.
    /// Moved out of ProjectTargetService (fb5766d1) with the bodies unchanged and the names shortened, since the
    /// class now says what is read: ReadCwproj became <see cref="Read"/> (and internal), ReadCwprojOutput
    /// <see cref="ReadOutput"/>, ReadCwprojFirstDeclared ReadFirstDeclared.
    /// </summary>
    internal static class CwprojReader
    {
        /// <summary>
        /// Read OutputType + OutputName from the .cwproj as MSBuild would for the ACTIVE configuration and
        /// platform (0214f33a). Matches by LOCAL element name (case-insensitive, XML-namespace-tolerant); the XML
        /// is parsed with DTD processing prohibited and no external resolver. <paramref name="config"/> and
        /// <paramref name="platform"/> are the IDE's, or null when it did not say: the project's own defaults
        /// (its <c>'$(Configuration)' == ''</c> group) then stand in. Returns false if nothing declares an
        /// OutputType, or on any failure. A condition it cannot evaluate is logged once per project and the
        /// read falls back to the rule it replaced (see <see cref="ReadOutput"/>).
        /// </summary>
        internal static bool Read(string cwprojPath, string config, string platform, out string outputType, out string outputName)
        {
            outputType = null; outputName = null;
            try
            {
                if (string.IsNullOrEmpty(cwprojPath) || !File.Exists(cwprojPath)) return false;

                var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
                using (var reader = XmlReader.Create(cwprojPath, settings))
                {
                    var doc = new XmlDocument();
                    doc.Load(reader);
                    string unevaluated;
                    bool ok = ReadOutput(doc, config, platform, out outputType, out outputName, out unevaluated);
                    if (unevaluated != null) LogUnevaluatedOnce(cwprojPath, unevaluated);
                    return ok;
                }
            }
            catch { outputType = null; outputName = null; return false; }
        }

        private static readonly HashSet<string> s_loggedUnevaluated = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        private static void LogUnevaluatedOnce(string cwprojPath, string condition)
        {
            lock (s_loggedUnevaluated)
                if (!s_loggedUnevaluated.Add(cwprojPath + "|" + condition)) return;
            System.Diagnostics.Debug.WriteLine("[CADebuggerWeb] " + cwprojPath + ": cannot evaluate Condition \"" + condition
                + "\"; its OutputType/OutputName are read by the first-declared rule instead");
        }

        /// <summary>
        /// OutputType and OutputName from a parsed .cwproj. Every PropertyGroup (and property) whose Condition is
        /// absent or evaluates TRUE for (<paramref name="config"/>, <paramref name="platform"/>) applies, in
        /// document order, and a later value replaces an earlier one - MSBuild's own rule. The conditions it
        /// evaluates are the ones Clarion writes: <c>'$(Configuration)|$(Platform)' == 'X|Y'</c>,
        /// <c>'$(Configuration)' == 'X'</c>, <c>'$(Platform)' == 'Y'</c>, each also with <c>!=</c>
        /// (<see cref="TryEvaluateCondition"/>).
        /// <para>
        /// ANYTHING ELSE FALLS BACK, WHOLE. If a condition on an element that could set either property cannot be
        /// evaluated, <paramref name="unevaluated"/> names it and both properties are read by the rule this
        /// replaced: the first unconditioned group declaring an OutputType, else the first declaring one at all,
        /// both values from that one group. Half an evaluation could pair one configuration's OutputType with
        /// another's OutputName.
        /// </para></summary>
        internal static bool ReadOutput(XmlDocument doc, string config, string platform,
                                              out string outputType, out string outputName, out string unevaluated)
        {
            outputType = null; outputName = null; unevaluated = null;
            var groups = new List<XmlNode>();
            foreach (XmlNode n in doc.GetElementsByTagName("*"))
                if (string.Equals(n.LocalName, "PropertyGroup", StringComparison.OrdinalIgnoreCase)) groups.Add(n);

            // The IDE did not say (null or empty: an empty name is no configuration either): the project's own
            // defaults, from its '$(Configuration)' == '' group.
            if (string.IsNullOrEmpty(config)) config = DefaultProperty(groups, "Configuration");
            if (string.IsNullOrEmpty(platform)) platform = DefaultProperty(groups, "Platform");

            string type = null, name = null;
            foreach (XmlNode group in groups)
            {
                bool groupApplies = true;
                string groupCond = ConditionOf(group);
                bool groupKnown = groupCond == null || TryEvaluateCondition(groupCond, config, platform, out groupApplies);

                foreach (XmlNode child in group.ChildNodes)
                {
                    bool isType = string.Equals(child.LocalName, "OutputType", StringComparison.OrdinalIgnoreCase);
                    bool isName = string.Equals(child.LocalName, "OutputName", StringComparison.OrdinalIgnoreCase);
                    if (!isType && !isName) continue;
                    if (!groupKnown) { unevaluated = groupCond; break; }
                    if (!groupApplies) continue;
                    string childCond = ConditionOf(child);
                    bool childApplies = true;
                    if (childCond != null && !TryEvaluateCondition(childCond, config, platform, out childApplies))
                    {
                        unevaluated = childCond;
                        break;
                    }
                    if (!childApplies) continue;
                    string value = child.InnerText != null ? child.InnerText.Trim() : null;
                    if (isType) type = value; else name = value;
                }
                if (unevaluated != null) break;
            }

            if (unevaluated != null) return ReadFirstDeclared(groups, out outputType, out outputName);
            if (string.IsNullOrEmpty(type)) return false;
            outputType = type;
            outputName = string.IsNullOrEmpty(name) ? null : name;
            return true;
        }

        /// <summary>The rule ReadOutput falls back to, as it stood before 0214f33a: the first PropertyGroup
        /// that declares an OutputType and has no Condition; failing that, the first that declares one at all.
        /// Both values come from that one group.</summary>
        private static bool ReadFirstDeclared(List<XmlNode> groups, out string outputType, out string outputName)
        {
            outputType = null; outputName = null;
            string fallbackType = null, fallbackName = null;
            bool haveFallback = false;
            foreach (XmlNode group in groups)
            {
                string gType = null, gName = null;
                foreach (XmlNode child in group.ChildNodes)
                {
                    if (gType == null && string.Equals(child.LocalName, "OutputType", StringComparison.OrdinalIgnoreCase))
                        gType = child.InnerText != null ? child.InnerText.Trim() : null;
                    else if (gName == null && string.Equals(child.LocalName, "OutputName", StringComparison.OrdinalIgnoreCase))
                        gName = child.InnerText != null ? child.InnerText.Trim() : null;
                }
                if (string.IsNullOrEmpty(gType)) continue; // group doesn't declare OutputType — skip
                if (ConditionOf(group) == null) { outputType = gType; outputName = gName; return true; }
                if (!haveFallback) { fallbackType = gType; fallbackName = gName; haveFallback = true; }
            }
            if (!haveFallback) return false;
            outputType = fallbackType; outputName = fallbackName;
            return true;
        }

        /// <summary>A default the project gives itself: the value of the first <paramref name="property"/> element
        /// that is unconditioned or conditioned on that property being empty (<c>'$(Configuration)' == ''</c>).</summary>
        private static string DefaultProperty(List<XmlNode> groups, string property)
        {
            foreach (XmlNode group in groups)
            {
                if (ConditionOf(group) != null) continue;
                foreach (XmlNode child in group.ChildNodes)
                {
                    if (!string.Equals(child.LocalName, property, StringComparison.OrdinalIgnoreCase)) continue;
                    string cond = ConditionOf(child);
                    if (cond != null && !IsEmptyTest(cond, property)) continue;
                    string v = child.InnerText != null ? child.InnerText.Trim() : null;
                    if (!string.IsNullOrEmpty(v)) return v;
                }
            }
            return null;
        }

        private static bool IsEmptyTest(string condition, string property)
        {
            var m = s_conditionRx.Match(condition);
            return m.Success && m.Groups["op"].Value == "=="
                && string.Equals(m.Groups["left"].Value.Trim(), "$(" + property + ")", StringComparison.OrdinalIgnoreCase)
                && m.Groups["right"].Value.Trim().Length == 0;
        }

        private static string ConditionOf(XmlNode node)
        {
            var a = node.Attributes != null ? node.Attributes["Condition"] : null;
            return a != null && a.Value != null && a.Value.Trim().Length > 0 ? a.Value : null;
        }

        private static readonly Regex s_conditionRx = new Regex(
            @"^\s*'(?<left>[^']*)'\s*(?<op>==|!=)\s*'(?<right>[^']*)'\s*\z");

        /// <summary>Evaluate an MSBuild Condition of the forms <c>'$(Configuration)|$(Platform)' == 'X|Y'</c>,
        /// <c>'$(Configuration)' == 'X'</c> or <c>'$(Platform)' == 'Y'</c>, or any of them with <c>!=</c>, compared
        /// without regard to case as MSBuild compares. False - "cannot say" - for any other shape, for a property it
        /// does not know the value of (null or empty), and for a right side that names a property.</summary>
        internal static bool TryEvaluateCondition(string condition, string config, string platform, out bool result)
        {
            result = false;
            if (condition == null) return false;
            var m = s_conditionRx.Match(condition);
            if (!m.Success) return false;
            string left = m.Groups["left"].Value.Trim(), right = m.Groups["right"].Value.Trim();
            if (right.IndexOf("$(", StringComparison.Ordinal) >= 0) return false;
            if (left.IndexOf("$(Configuration)", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                if (string.IsNullOrEmpty(config)) return false;
                left = Regex.Replace(left, @"\$\(Configuration\)", config.Replace("$", "$$"), RegexOptions.IgnoreCase);
            }
            if (left.IndexOf("$(Platform)", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                if (string.IsNullOrEmpty(platform)) return false;
                left = Regex.Replace(left, @"\$\(Platform\)", platform.Replace("$", "$$"), RegexOptions.IgnoreCase);
            }
            if (left.IndexOf("$(", StringComparison.Ordinal) >= 0) return false;   // another property: not ours to know
            bool equal = string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
            result = m.Groups["op"].Value == "==" ? equal : !equal;
            return true;
        }
    }
}
