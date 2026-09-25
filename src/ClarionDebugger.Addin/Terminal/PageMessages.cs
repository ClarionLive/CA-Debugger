using System;
using System.Collections.Generic;
using System.Globalization;
using ClarionDebugger.Wire;

namespace ClarionDebugger.Terminal
{
    // Typed forms of what the debugger page sends the host (afbc68c7, bridge hardening stage 2).
    //
    // THE THREAT MODEL is JsonMessageReader's: the debuggee is untrusted, its names and values reach the page,
    // and the page's messages come back here. Each request is parsed ONCE, into a type, by the Parse method
    // beside it - and a Parse that returns null means "drop the message". A handler never sees a half-read
    // payload and never picks fields out of raw text, which is what the eighteen scattered JsonVal calls
    // used to do one field at a time.
    //
    // The wire formats are UNCHANGED except where a request stopped carrying something the host must not
    // trust (break-on-entry now names a host-issued procedure id). The delimiter-separated payloads - "a|b|c"
    // and "module:line" - are typed here too rather than converted to JSON, because converting them would
    // move risk into the page for no gain: every field in them is validated again by the service before it
    // reaches the engine.
    //
    // THERE IS NO RULE ABOUT FIELD ORDER. The reader these DTOs replaced searched for "key": with no idea where
    // strings began or ended, and payloads were ordered - untrusted content last - to work around it. That was
    // never a boundary, and ae5b678a stage 1 retired it: every field here is read by key through
    // JsonMessageReader, which matches only top-level members, so a sender may order its members however
    // reads best.

    /// <summary>The outer <c>{action, data}</c> envelope every page message arrives in.</summary>
    internal sealed class PageEnvelope
    {
        public string Action;
        /// <summary>The request's payload: a plain string, or JSON text for the requests that carry an object.
        /// Null when the page sent none.</summary>
        public string Data;

        /// <summary>Null when <paramref name="json"/> is not an object with a string <c>action</c>.</summary>
        public static PageEnvelope Parse(string json)
        {
            string action = JsonMessageReader.ReadField(json, "action");
            if (string.IsNullOrEmpty(action)) return null;
            return new PageEnvelope { Action = action, Data = JsonMessageReader.ReadField(json, "data") };
        }
    }

    /// <summary>A <c>module:line</c> reference (jump, bpremove, runtocursor). Split on the LAST colon, so the
    /// module part may itself contain one; the service validates the module name before it is used.</summary>
    internal sealed class ModuleLineRequest
    {
        public string Module;
        public int Line;

        public static ModuleLineRequest Parse(string spec)
        {
            if (string.IsNullOrEmpty(spec)) return null;
            int c = spec.LastIndexOf(':');
            if (c <= 0) return null;
            int line;
            if (!PageNumbers.TryInt(spec.Substring(c + 1), out line)) return null;
            return new ModuleLineRequest { Module = spec.Substring(0, c), Line = line };
        }
    }

    /// <summary>Lazy reference expansion: <c>reqId|module|typeRef|addr</c>.</summary>
    internal sealed class ExpandRequest
    {
        public int ReqId;
        public string Module;
        public uint TypeRef;
        public string Addr;

        public static ExpandRequest Parse(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var a = data.Split('|');
            int rq; uint tr;
            if (a.Length != 4 || !PageNumbers.TryInt(a[0], out rq) || !PageNumbers.TryUInt(a[2], out tr)) return null;
            return new ExpandRequest { ReqId = rq, Module = a[1], TypeRef = tr, Addr = a[3] };
        }
    }

    /// <summary>One call-stack frame's locals: <c>reqId|va|ebp</c>.</summary>
    internal sealed class FrameLocalsRequest
    {
        public int ReqId;
        public string Va;
        public string Ebp;

        public static FrameLocalsRequest Parse(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var a = data.Split('|');
            int rq;
            if (a.Length != 3 || !PageNumbers.TryInt(a[0], out rq)) return null;
            return new FrameLocalsRequest { ReqId = rq, Va = a[1], Ebp = a[2] };
        }
    }

    /// <summary>A Memory-panel read: <c>reqId|0xADDR|len</c>. The address must be hex with its 0x and fit in 32
    /// bits (<see cref="WireRules.IsHexAddr"/>), and len must be 1..<see cref="MaxLen"/> (the engine's cap).
    /// Anything else returns null and is dropped, like every other request here.</summary>
    internal sealed class MemRequest
    {
        public const int MaxLen = WireRules.MemMaxLen;

        public int ReqId;
        public string Addr;
        public int Len;

        public static MemRequest Parse(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            var a = data.Split('|');
            int rq, len;
            if (a.Length != 3 || !PageNumbers.TryInt(a[0], out rq) || rq < 0) return null;
            if (!WireRules.IsHexAddr(a[1])) return null;
            if (!PageNumbers.TryInt(a[2], out len) || len < 1 || len > MaxLen) return null;
            return new MemRequest { ReqId = rq, Addr = a[1], Len = len };
        }
    }

    /// <summary>Open a breakpoint's source by the exact path the gutter gave: <c>line\tfullPath</c>.</summary>
    internal sealed class OpenBpRequest
    {
        public int Line;
        public string Path;

        public static OpenBpRequest Parse(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            int t = data.IndexOf('\t');
            int line;
            if (t <= 0 || !PageNumbers.TryInt(data.Substring(0, t), out line)) return null;
            return new OpenBpRequest { Line = line, Path = data.Substring(t + 1) };
        }
    }

    /// <summary>Break on a procedure's entry: <c>{"id": "..."}</c>, where the id is one the HOST issued with
    /// the Procedures list it last sent (see <see cref="ProcedureIds"/>).
    /// <para>
    /// The page used to send the row's module and line, and the host armed whatever it was told. Those came
    /// from the row, but nothing made the host check that they still did: any module:line the page named
    /// became a persistent breakpoint. The page now names a row, and the host looks up what that row means.
    /// </para></summary>
    internal sealed class BreakOnProcEntryRequest
    {
        public string ProcId;

        public static BreakOnProcEntryRequest Parse(string data)
        {
            string id = JsonMessageReader.ReadField(data, "id");
            if (string.IsNullOrEmpty(id)) return null;
            return new BreakOnProcEntryRequest { ProcId = id };
        }
    }

    /// <summary>Advanced breakpoint properties from the Breakpoints pane:
    /// <c>{module, line, condition, hitMode, hitValue, trace}</c>. Module and line are required; the rest
    /// are passed on as sent, and the handler normalises them.</summary>
    internal sealed class BpPropsRequest
    {
        public string Module;
        public int Line;
        public string Condition;
        public string HitMode;
        public int HitValue;
        public string Trace;

        public static BpPropsRequest Parse(string data)
        {
            string module = JsonMessageReader.ReadField(data, "module");
            if (string.IsNullOrEmpty(module)) return null;
            int line;
            if (!PageNumbers.TryInt(JsonMessageReader.ReadField(data, "line"), out line)) return null;
            int hitValue;
            if (!PageNumbers.TryInt(JsonMessageReader.ReadField(data, "hitValue"), out hitValue)) hitValue = 0;
            return new BpPropsRequest
            {
                Module = module,
                Line = line,
                Condition = JsonMessageReader.ReadField(data, "condition"),
                HitMode = JsonMessageReader.ReadField(data, "hitMode"),
                HitValue = hitValue,
                Trace = JsonMessageReader.ReadField(data, "trace")
            };
        }
    }

    /// <summary>Write a value into a live variable: <c>{va, typeCode, size, places, tid, value}</c>. The
    /// first five are the row's own edit metadata, which the host checks against what it ISSUED (see
    /// <see cref="EditGrants"/>); only <c>value</c> is the user's.</summary>
    internal sealed class EditVarRequest
    {
        public string Va;
        public string TypeCode;
        public int Size;
        public int Places;
        /// <summary>The thread the row was read on, or null when the page had no selection to name.</summary>
        public uint? Tid;
        public string Value;

        public static EditVarRequest Parse(string data)
        {
            if (string.IsNullOrEmpty(data)) return null;
            int size, places;
            PageNumbers.ReadEditTuple(data, out size, out places);
            uint tid;
            bool haveTid = PageNumbers.TryUInt(JsonMessageReader.ReadField(data, "tid"), out tid);
            return new EditVarRequest
            {
                Va = JsonMessageReader.ReadField(data, "va"),
                TypeCode = JsonMessageReader.ReadField(data, "typeCode"),
                Size = size,
                Places = places,
                Tid = haveTid ? (uint?)tid : null,
                Value = JsonMessageReader.ReadField(data, "value") ?? string.Empty
            };
        }
    }

    /// <summary>Attach to a running process (3f2d747f): the data is the pid, in decimal. Null for anything
    /// else, pid 0 included (no process has it). A parsed pid is only a LOOKUP KEY: the host attaches only to a
    /// pid it listed itself (<see cref="ListedProcesses"/>).</summary>
    internal sealed class AttachRequest
    {
        public uint Pid;

        public static AttachRequest Parse(string data)
        {
            uint pid;
            if (!PageNumbers.TryUInt(data, out pid) || pid == 0) return null;
            return new AttachRequest { Pid = pid };
        }
    }

    /// <summary>The processes the host last LISTED to the page, by pid (3f2d747f).
    /// <para>
    /// An attach names a pid, and a pid is just a number: forwarded unchecked, anything that could put a message
    /// on the bridge could debug any process this user can open. So the host attaches only to a pid it put in
    /// its own most recent <c>procs</c> reply, the same way <see cref="ProcedureIds"/> and
    /// <see cref="EditGrants"/> honour only what the host issued.
    /// </para>
    /// <para>
    /// ONE LISTING, ONE ATTACH. <see cref="Take"/> empties the table, so a listing cannot be replayed into a
    /// second attach; the picker asks again each time it opens. A refresh BEGINS its generation at once, so
    /// while a new listing is being read the old pids resolve to nothing, and only that generation's result
    /// may be installed (a slow, older listing cannot overwrite a newer one).
    /// </para></summary>
    internal sealed class ListedProcesses
    {
        private Dictionary<uint, AttachableProcess> _byPid = new Dictionary<uint, AttachableProcess>();
        private int _generation;

        /// <summary>Start listing <paramref name="generation"/>: every pid listed before it stops resolving now.</summary>
        public void Begin(int generation)
        {
            _generation = generation;
            _byPid = new Dictionary<uint, AttachableProcess>();
        }

        /// <summary>Install listing <paramref name="generation"/>. False, installing nothing, unless it is still
        /// the current generation.</summary>
        public bool Replace(int generation, IEnumerable<AttachableProcess> procs)
        {
            if (generation != _generation) return false;
            var t = new Dictionary<uint, AttachableProcess>();
            if (procs != null)
                foreach (var p in procs)
                    if (p != null && p.Pid != 0) t[p.Pid] = p;
            _byPid = t;
            return true;
        }

        /// <summary>The listed process with <paramref name="pid"/>, or null when the current listing does not
        /// hold it. A hit EMPTIES the table: one listing authorises one attach.</summary>
        public AttachableProcess Take(uint pid)
        {
            AttachableProcess p;
            if (!_byPid.TryGetValue(pid, out p)) return null;
            _byPid = new Dictionary<uint, AttachableProcess>();
            return p;
        }

        public int Count { get { return _byPid.Count; } }

        public void Clear() { _byPid = new Dictionary<uint, AttachableProcess>(); }
    }

    /// <summary>The one number parser for page payloads: invariant culture, integer syntax only, null reads
    /// as "not a number".</summary>
    internal static class PageNumbers
    {
        public static bool TryInt(string s, out int v)
        {
            v = 0;
            return s != null && int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out v);
        }

        public static bool TryUInt(string s, out uint v)
        {
            return WireRules.TryUInt(s, out v);
        }

        /// <summary>The size and places of an edit tuple, read ONE way (6ac29815 #2). The grant is recorded from
        /// the engine's row and the edit is checked from the page's echo of it; two readers with different
        /// defaults would refuse a legitimate edit with nothing on screen to say why. A missing or
        /// non-integer member reads as 0.</summary>
        public static void ReadEditTuple(string obj, out int size, out int places)
        {
            TryInt(JsonMessageReader.ReadField(obj, "size"), out size);
            TryInt(JsonMessageReader.ReadField(obj, "places"), out places);
        }
    }
}
