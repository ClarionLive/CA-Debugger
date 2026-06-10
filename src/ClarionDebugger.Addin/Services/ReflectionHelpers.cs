using System;
using System.Reflection;

namespace ClarionDebugger.Services
{
    /// <summary>
    /// Shared reflection accessors used to reach Clarion IDE (SharpDevelop) internals without a
    /// compile-time dependency. The NonPublic binding flags are deliberate: several workbench /
    /// project / solution members are internal in the Clarion IDE build.
    /// </summary>
    internal static class ReflectionHelpers
    {
        public static object GetProp(object obj, string name)
        {
            if (obj == null) return null;
            try
            {
                // NonPublic: some workbench window properties are internal in the Clarion IDE build
                var p = obj.GetType().GetProperty(name, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                return p != null ? p.GetValue(obj, null) : null;
            }
            catch { return null; }
        }

        public static object GetStaticProp(Type type, string name)
        {
            if (type == null) return null;
            try
            {
                var p = type.GetProperty(name, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);
                return p != null ? p.GetValue(null, null) : null;
            }
            catch { return null; }
        }
    }
}
