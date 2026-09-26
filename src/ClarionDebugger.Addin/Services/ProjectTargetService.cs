using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Xml;

namespace ClarionDebugger.Services
{
    /// <summary>
    /// Best-effort resolver for the CA Debugger's "Target EXE" field. Polls the running Clarion IDE
    /// (SharpDevelop) for the open solution/active project via reflection — no compile-time dependency
    /// on the project model — parses each project's .cwproj (MSBuild XML) on disk for its OutputType/
    /// OutputName, picks the single executable project, and resolves its built .exe via the project's
    /// .red redirection (falling back to projectDir and projectDir\bin). Every reflection hop and
    /// file/XML read degrades to null on failure: this NEVER throws into the IDE message pump.
    /// </summary>
    public static class ProjectTargetService
    {
        /// <summary>Why a resolve came back with the target it did, or with none (0214f33a): the pad states it on
        /// the target bar, so "several EXEs, pick one" is not shown as the same nothing as "no solution".</summary>
        public enum TargetOutcome { Resolved, NoSolution, NoExe, SeveralExes, Failed }

        /// <summary>The note for no solution open; the pad also states it when the solution closes.</summary>
        public const string NoSolutionNote = "No solution open";

        /// <summary>A resolve's answer: <see cref="Path"/> (null unless Resolved) and why.</summary>
        public sealed class TargetResolution
        {
            public TargetOutcome Outcome;
            public string Path;
            /// <summary>Which rule chose it: "startup", "active" or "only" (the one EXE in the solution).</summary>
            public string Source;

            /// <summary>The one plain-text line the target bar shows beside a missing or unconfirmed target, or
            /// null when there is nothing to say.</summary>
            public string Note
            {
                get
                {
                    switch (Outcome)
                    {
                        case TargetOutcome.NoSolution: return NoSolutionNote;
                        case TargetOutcome.NoExe: return "No EXE project in this solution";
                        case TargetOutcome.SeveralExes: return "Several EXEs in this solution - pick one (Browse)";
                        case TargetOutcome.Failed: return "Could not read the solution's projects";
                        default: return null;
                    }
                }
            }
        }

        /// <summary>
        /// Resolve the open app's EXE - its full path, a best guess when it is not built yet - and say how, or why
        /// there is none (callers fall back to Browse). Three rules, in order (0214f33a):
        ///   1. the startup project the user SET (Solution.Preferences.StartupProject), when its .cwproj is an
        ///      executable - what the IDE's own Run would start;
        ///   2. the ACTIVE project, when it is an executable;
        ///   3. the solution's only executable project (the DLL-belongs-to-EXE guard).
        /// Otherwise no target, and why: no EXE, or several with none marked as the one (Browse decides).
        /// The member names are the SharpDevelop 2.1 ones, verified against the C10, C11 and C12 IDE binaries
        /// (2026-09-25); a hop that is absent reads as null and that rule is skipped. Never throws.
        /// </summary>
        public static TargetResolution ResolveTarget()
        {
            try
            {
                object currentProject, solution;
                IList projects = GetSolutionProjects(out currentProject, out solution);
                if (solution == null) return new TargetResolution { Outcome = TargetOutcome.NoSolution };

                object chosen; string chosenOutputName, source;
                TargetOutcome outcome = Choose(GetStartupProject(solution), currentProject, projects,
                    p => { string t, n; return ReadProjectOutput(p, solution, out t, out n) && IsExecutable(t) ? (n ?? "") : null; },
                    out chosen, out chosenOutputName, out source);
                if (outcome != TargetOutcome.Resolved) return new TargetResolution { Outcome = outcome };

                string path = ExePathFor(chosen, NonEmpty(chosenOutputName));
                return path == null ? new TargetResolution { Outcome = TargetOutcome.Failed }
                                    : new TargetResolution { Outcome = TargetOutcome.Resolved, Path = path, Source = source };
            }
            catch { return new TargetResolution { Outcome = TargetOutcome.Failed }; }
        }

        /// <summary>The three rules, over what the IDE gave: <paramref name="exeOutputName"/> answers a project's
        /// OutputName when it is an EXECUTABLE ("" for none declared) and null when it is not. Resolved sets
        /// <paramref name="chosen"/>, its output name and which rule chose it; NoExe and SeveralExes set nothing.</summary>
        internal static TargetOutcome Choose(object startup, object active, IList projects, Func<object, string> exeOutputName,
                                             out object chosen, out string outputName, out string source)
        {
            chosen = null; outputName = null; source = null;
            // 1) The startup project, 2) the active project: each only when its cwproj is an executable.
            if (startup != null && (outputName = exeOutputName(startup)) != null) { chosen = startup; source = "startup"; return TargetOutcome.Resolved; }
            if (active != null && (outputName = exeOutputName(active)) != null) { chosen = active; source = "active"; return TargetOutcome.Resolved; }

            // 3) Else scan the solution; require EXACTLY ONE executable project.
            int exeCount = 0;
            object only = null; string onlyName = null;
            if (projects != null)
                foreach (object proj in projects)
                {
                    if (proj == null) continue;
                    string n = exeOutputName(proj);
                    if (n == null) continue;
                    exeCount++;
                    only = proj; onlyName = n;
                }
            // zero or more-than-one executable projects → can't decide; let the user Browse.
            if (exeCount == 0) return TargetOutcome.NoExe;
            if (exeCount > 1) return TargetOutcome.SeveralExes;
            chosen = only; outputName = onlyName; source = "only";
            return TargetOutcome.Resolved;
        }

        /// <summary>The startup project the user SET, or null when none is set (or it is unreadable).
        /// <para>
        /// ONLY the preferences' property. Solution.StartupProject is not "the one set": in the C12 IDE (its IL read
        /// 2026-09-25) it returns the preferences' choice, else the FIRST project whose IsStartable is true - so with
        /// two EXEs and none chosen it names one arbitrarily, and "Several EXEs - pick one" could never be said.
        /// SolutionPreferences.StartupProject returns null unless a project GUID was stored for it.
        /// </para></summary>
        private static object GetStartupProject(object solution)
        {
            object prefs = ReflectionHelpers.GetProp(solution, "Preferences");
            return ReflectionHelpers.GetProp(prefs, "StartupProject");
        }

        /// <summary>A project's OutputType/OutputName, read from its .cwproj under the configuration and platform
        /// the IDE has active for it (see ReadCwproj).</summary>
        private static bool ReadProjectOutput(object project, object solution, out string outType, out string outName)
        {
            string fn = ReflectionHelpers.GetProp(project, "FileName") as string;
            string config, platform;
            ActiveConfiguration(project, solution, out config, out platform);
            return ReadCwproj(fn, config, platform, out outType, out outName);
        }

        /// <summary>The configuration and platform the IDE has active for <paramref name="project"/>: the project's
        /// own ActiveConfiguration/ActivePlatform, else the solution preferences'. Null when unreadable; the
        /// .cwproj's own defaults then apply (ReadCwproj).</summary>
        private static void ActiveConfiguration(object project, object solution, out string config, out string platform)
        {
            object prefs = ReflectionHelpers.GetProp(solution, "Preferences");
            config = NonEmpty(ReflectionHelpers.GetProp(project, "ActiveConfiguration") as string)
                  ?? NonEmpty(ReflectionHelpers.GetProp(prefs, "ActiveConfiguration") as string);
            platform = NonEmpty(ReflectionHelpers.GetProp(project, "ActivePlatform") as string)
                    ?? NonEmpty(ReflectionHelpers.GetProp(prefs, "ActivePlatform") as string);
        }

        private static string NonEmpty(string s) { return string.IsNullOrEmpty(s) ? null : s; }

        /// <summary>The built EXE's path for the chosen project, or null when it has no usable file name.</summary>
        private static string ExePathFor(object chosen, string chosenOutputName)
        {
            try
            {
                string fileName = ReflectionHelpers.GetProp(chosen, "FileName") as string;
                if (string.IsNullOrEmpty(fileName)) return null;
                string projectDir = Path.GetDirectoryName(fileName);
                if (string.IsNullOrEmpty(projectDir)) return null;
                // OutputName is a repo-controlled value: SafeBaseName keeps it a bare file name, never a path.
                string baseName = SafeBaseName(chosenOutputName, fileName);
                if (string.IsNullOrEmpty(baseName)) return null;
                string exeName = baseName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? baseName : baseName + ".exe";
                return ResolveExePath(projectDir, exeName);
            }
            catch { return null; }
        }

        private static bool IsExecutable(string outputType)
        {
            return string.Equals(outputType, "Exe", StringComparison.OrdinalIgnoreCase)
                || string.Equals(outputType, "WinExe", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Resolve the built output DLLs of every non-executable project in the open solution, so the
        /// debug engine can pre-load their TSWD and bind DLL breakpoints before launch (multi-DLL apps).
        /// Each path is resolved the same way as the EXE (.red redirection, then projectDir, then bin)
        /// and only existing files are returned. Never throws into the IDE pump — returns an empty list
        /// on any failure.
        /// </summary>
        public static List<string> ResolveSolutionDlls()
        {
            var dlls = new List<string>();
            try
            {
                object currentProject, solution;
                IList projects = GetSolutionProjects(out currentProject, out solution);
                if (projects == null) return dlls;

                foreach (object proj in projects)
                {
                    if (proj == null) continue;
                    string fn = ReflectionHelpers.GetProp(proj, "FileName") as string;
                    string outType, outName;
                    if (!ReadProjectOutput(proj, solution, out outType, out outName)) continue;
                    if (IsExecutable(outType)) continue;          // EXE handled by ResolveTarget

                    string projectDir = Path.GetDirectoryName(fn);
                    if (string.IsNullOrEmpty(projectDir)) continue;

                    string baseName = SafeBaseName(outName, fn);
                    if (string.IsNullOrEmpty(baseName)) continue;
                    string dllName = baseName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)
                        ? baseName : baseName + ".dll";

                    string path = ResolveExePath(projectDir, dllName); // generic file resolver (red/dir/bin)
                    if (!string.IsNullOrEmpty(path) && File.Exists(path) &&
                        !dlls.Exists(d => string.Equals(d, path, StringComparison.OrdinalIgnoreCase)))
                        dlls.Add(path);
                }
            }
            catch { }
            return dlls;
        }

        /// <summary>OutputName sanitized to a bare base file name (no path/rooted/.. — repo-controlled
        /// value, never trust as a path), falling back to the .cwproj base name. Null when unusable.</summary>
        private static string SafeBaseName(string outName, string cwprojPath)
        {
            string baseName = outName;
            if (!string.IsNullOrEmpty(baseName))
            {
                baseName = baseName.Trim();
                bool unsafeName = baseName.Length == 0
                    || Path.IsPathRooted(baseName)
                    || baseName.IndexOf('\\') >= 0
                    || baseName.IndexOf('/') >= 0
                    || baseName.IndexOf("..", StringComparison.Ordinal) >= 0
                    || baseName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0;
                if (unsafeName) baseName = null;
            }
            if (string.IsNullOrEmpty(baseName))
                baseName = Path.GetFileNameWithoutExtension(cwprojPath);
            return string.IsNullOrEmpty(baseName) ? null : baseName;
        }

        // ------------------------------------------------------------------ IDE reflection

        /// <summary>
        /// Reflect ICSharpCode.SharpDevelop.Project.ProjectService for the active project and the open
        /// solution's projects. Prefers the flat OpenSolution.Projects (SharpDevelop flattens it);
        /// falls back to a recursive walk of solution-folder collections. Any null hop → returns an
        /// empty/absent list (and null currentProject).
        /// </summary>
        /// <summary>
        /// Returns a stable identity for the IDE's currently-open solution+active-project context, or null
        /// if no solution is open. Used to tie a one-shot manual Browse selection to the context it was made
        /// in: if this key changes between Starts, a previously-Browsed target is stale and must be discarded.
        /// Best-effort; never throws (degrades to null).
        /// </summary>
        public static string GetActiveContextKey()
        {
            try
            {
                Assembly asm = Assembly.Load("ICSharpCode.SharpDevelop");
                if (asm == null) return null;
                Type psType = asm.GetType("ICSharpCode.SharpDevelop.Project.ProjectService");
                if (psType == null) return null;

                object solution = ReflectionHelpers.GetStaticProp(psType, "OpenSolution");
                if (solution == null) return null;
                string solutionFile = ReflectionHelpers.GetProp(solution, "FileName") as string;
                if (string.IsNullOrEmpty(solutionFile)) return null;

                object current = ReflectionHelpers.GetStaticProp(psType, "CurrentProject");
                string projectFile = current != null ? ReflectionHelpers.GetProp(current, "FileName") as string : null;

                return (solutionFile + "|" + (projectFile ?? "")).ToLowerInvariant();
            }
            catch { return null; }
        }

        private static IList GetSolutionProjects(out object currentProject, out object solution)
        {
            currentProject = null;
            solution = null;
            try
            {
                Assembly asm = Assembly.Load("ICSharpCode.SharpDevelop");
                if (asm == null) return null;
                Type psType = asm.GetType("ICSharpCode.SharpDevelop.Project.ProjectService");
                if (psType == null) return null;

                currentProject = ReflectionHelpers.GetStaticProp(psType, "CurrentProject");

                solution = ReflectionHelpers.GetStaticProp(psType, "OpenSolution");
                if (solution == null) return null;

                // Prefer the flat Projects enumerable when present (SharpDevelop flattens it).
                object projectsObj = ReflectionHelpers.GetProp(solution, "Projects");
                IList flat = projectsObj as IList ?? ToList(projectsObj as IEnumerable);
                if (flat != null && flat.Count > 0) return flat;

                // Fallback: recursively collect project-like nodes from solution-folder collections.
                var result = new List<object>();
                CollectProjects(solution, result, 0, new HashSet<object>(ReferenceEqualityComparer.Instance));
                return result;
            }
            catch { return null; }
        }

        /// <summary>
        /// Recursively gather project-like nodes from a solution / solution-folder node. A node is a
        /// project when it exposes a string FileName ending in ".cwproj"; otherwise we descend into any
        /// child enumerable it exposes (Projects/Folders/SolutionFolders/Items/Children). Guarded
        /// against cycles (visited set, reference identity) and runaway depth (cap 8). Degrades to a
        /// no-op on any reflection failure.
        /// </summary>
        private static void CollectProjects(object node, List<object> result, int depth, HashSet<object> visited)
        {
            if (node == null || depth > 8) return;
            try
            {
                if (!visited.Add(node)) return;

                string fn = ReflectionHelpers.GetProp(node, "FileName") as string;
                if (!string.IsNullOrEmpty(fn) && fn.EndsWith(".cwproj", StringComparison.OrdinalIgnoreCase))
                {
                    result.Add(node);
                    // A project node won't itself contain nested projects; nothing more to do here.
                    return;
                }

                // Descend into any child collection this node exposes.
                string[] childMembers = { "Projects", "Folders", "SolutionFolders", "Items", "Children" };
                foreach (string member in childMembers)
                {
                    object childObj = ReflectionHelpers.GetProp(node, member);
                    if (childObj is string) continue;
                    IEnumerable seq = childObj as IEnumerable;
                    if (seq == null) continue;
                    foreach (object child in seq)
                        CollectProjects(child, result, depth + 1, visited);
                }
            }
            catch { }
        }

        private static IList ToList(IEnumerable seq)
        {
            if (seq == null) return null;
            try
            {
                var list = new List<object>();
                foreach (object o in seq) list.Add(o);
                return list;
            }
            catch { return null; }
        }

        // ------------------------------------------------------------------ cwproj (MSBuild XML)

        /// <summary>
        /// Read OutputType + OutputName from the .cwproj as MSBuild would for the ACTIVE configuration and
        /// platform (0214f33a). Matches by LOCAL element name (case-insensitive, XML-namespace-tolerant); the XML
        /// is parsed with DTD processing prohibited and no external resolver. <paramref name="config"/> and
        /// <paramref name="platform"/> are the IDE's, or null when it did not say: the project's own defaults
        /// (its <c>'$(Configuration)' == ''</c> group) then stand in. Returns false if nothing declares an
        /// OutputType, or on any failure. A condition it cannot evaluate is logged once per project and the
        /// read falls back to the rule it replaced (see <see cref="ReadCwprojOutput"/>).
        /// </summary>
        private static bool ReadCwproj(string cwprojPath, string config, string platform, out string outputType, out string outputName)
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
                    bool ok = ReadCwprojOutput(doc, config, platform, out outputType, out outputName, out unevaluated);
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
        internal static bool ReadCwprojOutput(XmlDocument doc, string config, string platform,
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

            if (unevaluated != null) return ReadCwprojFirstDeclared(groups, out outputType, out outputName);
            if (string.IsNullOrEmpty(type)) return false;
            outputType = type;
            outputName = string.IsNullOrEmpty(name) ? null : name;
            return true;
        }

        /// <summary>The rule ReadCwprojOutput falls back to, as it stood before 0214f33a: the first PropertyGroup
        /// that declares an OutputType and has no Condition; failing that, the first that declares one at all.
        /// Both values come from that one group.</summary>
        private static bool ReadCwprojFirstDeclared(List<XmlNode> groups, out string outputType, out string outputName)
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

        private static readonly System.Text.RegularExpressions.Regex s_conditionRx = new System.Text.RegularExpressions.Regex(
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
                left = System.Text.RegularExpressions.Regex.Replace(left, @"\$\(Configuration\)", config.Replace("$", "$$"),
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            }
            if (left.IndexOf("$(Platform)", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                if (string.IsNullOrEmpty(platform)) return false;
                left = System.Text.RegularExpressions.Regex.Replace(left, @"\$\(Platform\)", platform.Replace("$", "$$"),
                    System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            }
            if (left.IndexOf("$(", StringComparison.Ordinal) >= 0) return false;   // another property: not ours to know
            bool equal = string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
            result = m.Groups["op"].Value == "==" ? equal : !equal;
            return true;
        }

        // ------------------------------------------------------------------ exe resolution

        /// <summary>
        /// Resolve exeName under projectDir. Order: (1) the project's .red *.exe redirection,
        /// (2) projectDir\exeName, (3) projectDir\bin\exeName. If none exist, return the best-guess
        /// projectDir\exeName so the field still shows the intended target — the caller's StartSession
        /// guard already blocks launch on a missing file.
        /// </summary>
        private static string ResolveExePath(string projectDir, string exeName)
        {
            // 1) Via .red redirection. Prefer an already-loaded instance (read-only — safe). Only the
            //    throwaway construct+load path must NOT publish to RedFileService.Active, otherwise it
            //    would poison ClarionDebuggerService.GetRedService() for a later debug session.
            try
            {
                RedFileService red = RedFileService.Active;
                if (red == null)
                {
                    var info = ClarionVersionService.Detect();
                    var cfg = info != null ? info.GetCurrentConfig() : null;
                    red = new RedFileService();
                    red.LoadForProject(projectDir, cfg, publishActive: false);
                }
                if (red != null)
                {
                    string viaRed = red.ResolveFrom(exeName, projectDir, "Debug32", "Release32", "Debug", "Release", "Common");
                    if (!string.IsNullOrEmpty(viaRed) && File.Exists(viaRed)) return viaRed;
                }
            }
            catch { }

            // 2) projectDir\exeName
            try
            {
                string p = Path.Combine(projectDir, exeName);
                if (File.Exists(p)) return p;
            }
            catch { }

            // 3) projectDir\bin\exeName
            try
            {
                string p = Path.Combine(projectDir, "bin", exeName);
                if (File.Exists(p)) return p;
            }
            catch { }

            // Best-guess so the field still shows the intended target (launch guard validates existence).
            try { return Path.Combine(projectDir, exeName); }
            catch { return null; }
        }

        // ------------------------------------------------------------------ cycle guard

        /// <summary>Reference-identity comparer so the visited-set guards against object-graph cycles.</summary>
        private sealed class ReferenceEqualityComparer : IEqualityComparer<object>
        {
            public static readonly ReferenceEqualityComparer Instance = new ReferenceEqualityComparer();
            public new bool Equals(object x, object y) { return ReferenceEquals(x, y); }
            public int GetHashCode(object obj) { return System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(obj); }
        }
    }
}
