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
        /// <summary>
        /// Returns the full path to the open app's EXE (best-guess if the file isn't built yet), or
        /// null if the IDE has no project / the active project isn't an EXE and the solution doesn't
        /// have exactly one EXE project. Callers can fall back to Browse() on null.
        /// </summary>
        public static string ResolveTargetExe()
        {
            try
            {
                object currentProject;
                IList projects = GetSolutionProjects(out currentProject);

                // Two-stage selection:
                //   1. If the active project's .cwproj is an executable (Exe/WinExe), use it.
                //   2. Otherwise scan the solution and use it ONLY if EXACTLY ONE project is an
                //      executable (the DLL-belongs-to-EXE guard); zero or >1 → bail to Browse.
                object chosen = null;
                string chosenOutputName = null;

                // 1) Prefer the active project if its cwproj is an executable.
                if (currentProject != null)
                {
                    string fn = ReflectionHelpers.GetProp(currentProject, "FileName") as string;
                    string outType, outName;
                    if (ReadCwproj(fn, out outType, out outName) && IsExecutable(outType))
                    {
                        chosen = currentProject;
                        chosenOutputName = outName;
                    }
                }

                // 2) Else scan the solution; require EXACTLY ONE executable project.
                if (chosen == null && projects != null)
                {
                    int exeCount = 0;
                    foreach (object proj in projects)
                    {
                        if (proj == null) continue;
                        string fn = ReflectionHelpers.GetProp(proj, "FileName") as string;
                        string outType, outName;
                        if (ReadCwproj(fn, out outType, out outName) && IsExecutable(outType))
                        {
                            exeCount++;
                            chosen = proj;
                            chosenOutputName = outName;
                        }
                    }
                    // zero or more-than-one executable projects → can't decide; let the user Browse.
                    if (exeCount != 1) return null;
                }

                if (chosen == null) return null;

                string fileName = ReflectionHelpers.GetProp(chosen, "FileName") as string;
                if (string.IsNullOrEmpty(fileName)) return null;
                string projectDir = Path.GetDirectoryName(fileName);
                if (string.IsNullOrEmpty(projectDir)) return null;

                // OutputName may be absent/whitespace → fall back to the .cwproj base name.
                string baseName = chosenOutputName;
                if (!string.IsNullOrEmpty(baseName))
                {
                    baseName = baseName.Trim();
                    // Repo-controlled value — must be a bare file name, never a path. Reject rooted/UNC/separator/.. so
                    // auto-resolve can't be driven to probe or launch an attacker-chosen absolute/UNC target via Path.Combine.
                    bool unsafeName = baseName.Length == 0
                        || Path.IsPathRooted(baseName)
                        || baseName.IndexOf('\\') >= 0
                        || baseName.IndexOf('/') >= 0
                        || baseName.IndexOf("..", StringComparison.Ordinal) >= 0
                        || baseName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0;
                    if (unsafeName) baseName = null;
                }
                if (string.IsNullOrEmpty(baseName))
                    baseName = Path.GetFileNameWithoutExtension(fileName);
                if (string.IsNullOrEmpty(baseName)) return null;

                string exeName = baseName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                    ? baseName
                    : baseName + ".exe";

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
                object currentProject;
                IList projects = GetSolutionProjects(out currentProject);
                if (projects == null) return dlls;

                foreach (object proj in projects)
                {
                    if (proj == null) continue;
                    string fn = ReflectionHelpers.GetProp(proj, "FileName") as string;
                    string outType, outName;
                    if (!ReadCwproj(fn, out outType, out outName)) continue;
                    if (IsExecutable(outType)) continue;          // EXE handled by ResolveTargetExe

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
        private static IList GetSolutionProjects(out object currentProject)
        {
            currentProject = null;
            try
            {
                Assembly asm = Assembly.Load("ICSharpCode.SharpDevelop");
                if (asm == null) return null;
                Type psType = asm.GetType("ICSharpCode.SharpDevelop.Project.ProjectService");
                if (psType == null) return null;

                currentProject = ReflectionHelpers.GetStaticProp(psType, "CurrentProject");

                object solution = ReflectionHelpers.GetStaticProp(psType, "OpenSolution");
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
        /// Read OutputType + OutputName from the .cwproj, taking BOTH from the SAME PropertyGroup so a
        /// conditioned group can't contribute a mismatched name. Matches by LOCAL element name
        /// (case-insensitive, XML-namespace-tolerant). Selection: the first PropertyGroup that declares
        /// an OutputType and has no Condition attribute (unconditioned); failing that, the first
        /// PropertyGroup that declares an OutputType regardless of condition. OutputName may be null
        /// (the caller falls back to the .cwproj base name). The XML is parsed with DTD processing
        /// prohibited and no external resolver. Returns false if no PropertyGroup declares an OutputType
        /// or on any failure.
        /// </summary>
        private static bool ReadCwproj(string cwprojPath, out string outputType, out string outputName)
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

                    // First-declaring fallback (any condition), used only if no unconditioned group wins.
                    string fallbackType = null, fallbackName = null;
                    bool haveFallback = false;

                    foreach (XmlNode group in doc.GetElementsByTagName("*"))
                    {
                        if (!string.Equals(group.LocalName, "PropertyGroup", StringComparison.OrdinalIgnoreCase))
                            continue;

                        // Read this group's OutputType / OutputName from its direct children.
                        string gType = null, gName = null;
                        foreach (XmlNode child in group.ChildNodes)
                        {
                            if (gType == null && string.Equals(child.LocalName, "OutputType", StringComparison.OrdinalIgnoreCase))
                                gType = child.InnerText != null ? child.InnerText.Trim() : null;
                            else if (gName == null && string.Equals(child.LocalName, "OutputName", StringComparison.OrdinalIgnoreCase))
                                gName = child.InnerText != null ? child.InnerText.Trim() : null;
                        }

                        if (string.IsNullOrEmpty(gType)) continue; // group doesn't declare OutputType — skip

                        bool conditioned = group.Attributes != null && group.Attributes["Condition"] != null;
                        if (!conditioned)
                        {
                            // First unconditioned group with an OutputType wins outright.
                            outputType = gType;
                            outputName = gName;
                            return true;
                        }

                        if (!haveFallback)
                        {
                            fallbackType = gType;
                            fallbackName = gName;
                            haveFallback = true;
                        }
                    }

                    if (haveFallback)
                    {
                        outputType = fallbackType;
                        outputName = fallbackName;
                        return true;
                    }
                }
                return false; // no PropertyGroup declared an OutputType
            }
            catch { outputType = null; outputName = null; return false; }
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
