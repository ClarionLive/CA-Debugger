using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace ClarionDebugger.Services
{
    /// <summary>
    /// Represents a single redirection entry: *.ext = path
    /// </summary>
    public class RedEntry
    {
        public string Pattern { get; set; }   // e.g. "*.clw", "*.inc", "*.*"
        public string RawPath { get; set; }    // original path with macros
        public string ResolvedPath { get; set; } // path with macros expanded
    }

    /// <summary>
    /// A parsed section from the .red file (e.g. [Common], [Debug32])
    /// </summary>
    public class RedSection
    {
        public string Name { get; set; }
        public List<RedEntry> Entries { get; set; }

        public RedSection()
        {
            Entries = new List<RedEntry>();
        }
    }

    /// <summary>
    /// Parses Clarion .red (redirection) files and resolves file paths.
    /// The .red file tells the compiler/IDE where to find source files,
    /// includes, libraries, images, etc.
    /// </summary>
    public class RedFileService
    {
        private readonly Dictionary<string, RedSection> _sections;
        private readonly Dictionary<string, string> _macros;
        private string _redFilePath;

        /// <summary>The most-recently-loaded instance, so static helpers can resolve generated files.</summary>
        public static RedFileService Active { get; private set; }

        public string RedFilePath => _redFilePath;
        public IReadOnlyDictionary<string, RedSection> Sections => _sections;
        public IReadOnlyDictionary<string, string> Macros => _macros;

        public RedFileService()
        {
            _sections = new Dictionary<string, RedSection>(StringComparer.OrdinalIgnoreCase);
            _macros = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Load and parse a .red file using macros from the version config.
        /// </summary>
        public bool Load(string redFilePath, Dictionary<string, string> macros)
        {
            if (string.IsNullOrEmpty(redFilePath) || !File.Exists(redFilePath))
                return false;

            _redFilePath = redFilePath;
            _sections.Clear();
            _macros.Clear();

            if (macros != null)
            {
                foreach (var kv in macros)
                    _macros[kv.Key] = kv.Value;
            }

            // Ensure standard macros exist
            if (!_macros.ContainsKey("BIN") && !string.IsNullOrEmpty(redFilePath))
                _macros["BIN"] = Path.GetDirectoryName(redFilePath);

            if (!_macros.ContainsKey("ROOT") && _macros.ContainsKey("root"))
                _macros["ROOT"] = _macros["root"];

            if (!_macros.ContainsKey("REDDIR") && _macros.ContainsKey("reddir"))
                _macros["REDDIR"] = _macros["reddir"];

            try
            {
                Parse(File.ReadAllLines(redFilePath));
                Active = this;
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Load from a ClarionVersionConfig (convenience method).
        /// </summary>
        public bool Load(ClarionVersionConfig config)
        {
            if (config == null || string.IsNullOrEmpty(config.RedFilePath))
                return false;

            var macros = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (config.Macros != null)
            {
                foreach (var kv in config.Macros)
                    macros[kv.Key] = kv.Value;
            }

            if (!macros.ContainsKey("ROOT") && !string.IsNullOrEmpty(config.RootPath))
                macros["ROOT"] = config.RootPath;

            if (!macros.ContainsKey("BIN") && !string.IsNullOrEmpty(config.BinPath))
                macros["BIN"] = config.BinPath;

            return Load(config.RedFilePath, macros);
        }

        /// <summary>
        /// Load the effective .red file for a project directory.
        /// If a .red file exists in the project directory, it completely
        /// supersedes the version-level .red file.
        /// </summary>
        public bool LoadForProject(string projectDirectory, ClarionVersionConfig config)
        {
            if (config == null) return false;

            var macros = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (config.Macros != null)
            {
                foreach (var kv in config.Macros)
                    macros[kv.Key] = kv.Value;
            }

            if (!macros.ContainsKey("ROOT") && !string.IsNullOrEmpty(config.RootPath))
                macros["ROOT"] = config.RootPath;

            if (!macros.ContainsKey("BIN") && !string.IsNullOrEmpty(config.BinPath))
                macros["BIN"] = config.BinPath;

            // Check for a local .red file in the project directory
            if (!string.IsNullOrEmpty(projectDirectory) && Directory.Exists(projectDirectory))
            {
                string localRed = FindLocalRedFile(projectDirectory);
                if (localRed != null)
                    return Load(localRed, macros);
            }

            // Fall back to the version-level .red
            if (!string.IsNullOrEmpty(config.RedFilePath))
                return Load(config.RedFilePath, macros);

            return false;
        }

        /// <summary>
        /// Look for a .red file in a project directory.
        /// </summary>
        private static string FindLocalRedFile(string directory)
        {
            try
            {
                string[] redFiles = Directory.GetFiles(directory, "*.red", SearchOption.TopDirectoryOnly);
                if (redFiles.Length > 0)
                    return redFiles[0];
            }
            catch { }
            return null;
        }

        private void Parse(string[] lines)
        {
            RedSection current = null;

            foreach (string rawLine in lines)
            {
                string line = rawLine.Trim();

                // Skip empty lines and comments
                if (string.IsNullOrEmpty(line) || line.StartsWith("--"))
                    continue;

                // Section header: [SectionName]
                if (line.StartsWith("[") && line.EndsWith("]"))
                {
                    string name = line.Substring(1, line.Length - 2).Trim();
                    current = new RedSection { Name = name };
                    _sections[name] = current;
                    continue;
                }

                // Entry: pattern = path1;path2;...
                if (current != null && line.Contains("="))
                {
                    int eqIdx = line.IndexOf('=');
                    string pattern = line.Substring(0, eqIdx).Trim();
                    string pathsPart = line.Substring(eqIdx + 1).Trim().TrimEnd(';');

                    // A single entry can have multiple semicolon-separated paths,
                    // but typically each line is one path. Handle both.
                    string[] paths = pathsPart.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
                    foreach (string p in paths)
                    {
                        string rawPath = p.Trim();
                        if (string.IsNullOrEmpty(rawPath)) continue;

                        current.Entries.Add(new RedEntry
                        {
                            Pattern = pattern,
                            RawPath = rawPath,
                            ResolvedPath = ExpandMacros(rawPath)
                        });
                    }
                }
            }
        }

        private string ExpandMacros(string path)
        {
            return Regex.Replace(path, @"%(\w+)%", m =>
            {
                string key = m.Groups[1].Value;
                string value;
                if (_macros.TryGetValue(key, out value))
                    return value;
                return m.Value; // leave unexpanded if unknown
            });
        }

        /// <summary>
        /// Resolve a filename to its full path by searching the redirection entries.
        /// Searches the specified sections in order (defaults to Common).
        /// Returns the first existing match, or null.
        /// </summary>
        public string Resolve(string fileName, params string[] sectionNames)
        {
            return ResolveFrom(fileName, null, sectionNames);
        }

        /// <summary>
        /// Resolve a filename to its full path, anchoring RELATIVE redirection paths (.\ , ..\)
        /// to <paramref name="baseDir"/> (the project/app directory) instead of the process CWD.
        /// Clarion redirection relative paths are relative to the project being built, so callers
        /// that know the app directory should pass it here. Absolute entries are unaffected.
        /// Searches the specified sections in order (defaults to Common). Returns the first existing match, or null.
        /// </summary>
        public string ResolveFrom(string fileName, string baseDir, params string[] sectionNames)
        {
            if (string.IsNullOrEmpty(fileName)) return null;

            if (sectionNames == null || sectionNames.Length == 0)
                sectionNames = new[] { "Common" };

            foreach (string sectionName in sectionNames)
            {
                RedSection section;
                if (!_sections.TryGetValue(sectionName, out section))
                    continue;

                foreach (var entry in section.Entries)
                {
                    if (MatchesPattern(fileName, entry.Pattern))
                    {
                        string candidate = Path.Combine(entry.ResolvedPath, fileName);
                        try
                        {
                            // Redirection relative paths are relative to the project dir, not the IDE's CWD.
                            if (!Path.IsPathRooted(candidate) && !string.IsNullOrEmpty(baseDir))
                                candidate = Path.Combine(baseDir, candidate);
                            candidate = Path.GetFullPath(candidate);
                            if (File.Exists(candidate))
                                return candidate;
                        }
                        catch { }
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Get all search directories for a given file extension in the specified section.
        /// </summary>
        public List<string> GetSearchPaths(string extension, string sectionName = "Common")
        {
            var result = new List<string>();
            if (string.IsNullOrEmpty(extension)) return result;

            if (!extension.StartsWith("."))
                extension = "." + extension;

            string testName = "test" + extension;

            RedSection section;
            if (!_sections.TryGetValue(sectionName, out section))
                return result;

            foreach (var entry in section.Entries)
            {
                if (MatchesPattern(testName, entry.Pattern))
                {
                    string resolved = entry.ResolvedPath;
                    if (!string.IsNullOrEmpty(resolved) && !result.Contains(resolved))
                        result.Add(resolved);
                }
            }

            return result;
        }

        /// <summary>
        /// Simple wildcard pattern matching for .red patterns like *.clw, *.inc, *.*
        /// </summary>
        private static bool MatchesPattern(string fileName, string pattern)
        {
            // Handle *.* (matches everything)
            if (pattern == "*.*") return true;

            // Handle *.ext
            if (pattern.StartsWith("*."))
            {
                string patExt = pattern.Substring(1); // ".clw"
                // Handle single-char wildcards like *.tp?
                if (patExt.Contains("?"))
                {
                    string fileExt = Path.GetExtension(fileName);
                    if (fileExt.Length != patExt.Length) return false;
                    for (int i = 0; i < patExt.Length; i++)
                    {
                        if (patExt[i] != '?' && char.ToLowerInvariant(patExt[i]) != char.ToLowerInvariant(fileExt[i]))
                            return false;
                    }
                    return true;
                }

                return fileName.EndsWith(patExt, StringComparison.OrdinalIgnoreCase);
            }

            // Exact match fallback
            return string.Equals(fileName, pattern, StringComparison.OrdinalIgnoreCase);
        }
    }
}
