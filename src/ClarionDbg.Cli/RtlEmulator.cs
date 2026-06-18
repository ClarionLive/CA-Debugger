using System;
using System.Collections.Generic;
using Iced.Intel;

namespace ClarionDbg.Cli
{
    /// <summary>A tiny READ-ONLY x86 emulator for evaluating Clarion RTL accessor functions (the Cla$*
    /// getters) without running them in the debuggee. It executes the real getter code but every debuggee
    /// memory access is a ReadProcessMemory (never a write), CALLs into the runtime are emulated, and the
    /// few imports that matter (TlsGetValue / GetCurrentThreadId) are intrinsics. This lets us read EVENT/
    /// FIELD/FOCUS/… exactly as the RTL computes them — including selector/flag logic — while parked
    /// anywhere (incl. inside TakeEvent), with zero re-entrancy and zero side effects.
    ///
    /// Scope: the small instruction subset these accessors use. Unsupported instructions / unknown CALL
    /// targets throw <see cref="NotSupported"/>, which the caller turns into "&lt;unavailable&gt;".</summary>
    internal sealed class RtlEmulator
    {
        public sealed class NotSupported : Exception { public NotSupported(string m) : base(m) { } }

        public readonly List<string> Trace = new List<string>();   // diagnostics

        // modeled stack: a private window; accesses inside it hit this buffer, everything else is a
        // read-only debuggee fetch. Based high so it won't collide with real heap/module addresses.
        const uint StackBase = 0x60000000;
        const int StackSize = 0x10000;
        readonly byte[] _stack = new byte[StackSize];

        readonly Func<uint, int, byte[]> _readMem;     // debuggee read (addr, len)
        readonly Func<uint, uint> _tlsGetValue;        // TlsGetValue(index) -> slot value
        readonly uint _curThreadId;                    // GetCurrentThreadId() intrinsic
        readonly uint _teb;                            // stopped thread's TEB (for GetLastError)
        readonly Func<uint, string> _importAtSlot;     // IAT slot VA -> imported function name
        readonly Func<uint, bool> _isCode;             // is this VA emulatable runtime code?

        readonly Dictionary<Register, uint> _r = new Dictionary<Register, uint>();
        bool _zf, _cf, _sf;
        const uint RetSentinel = 0xDEAD0000;           // top-level return address; ret here = done

        public RtlEmulator(Func<uint, int, byte[]> readMem, Func<uint, uint> tlsGetValue, uint curThreadId,
                           uint teb, Func<uint, string> importAtSlot, Func<uint, bool> isCode)
        {
            _readMem = readMem; _tlsGetValue = tlsGetValue; _curThreadId = curThreadId; _teb = teb;
            _importAtSlot = importAtSlot; _isCode = isCode;
        }

        /// <summary>Run the function at <paramref name="va"/> (zero args) and return EAX. Optionally seed EAX
        /// (used by dispatcher getters that pass a selector in EAX before the call).</summary>
        public uint Call(uint va, uint eaxSeed = 0)
        {
            _shadow.Clear(); Array.Clear(_stack, 0, _stack.Length); Trace.Clear();   // fresh state so one emulator can run many getters
            foreach (Register reg in new[] { Register.EAX, Register.EBX, Register.ECX, Register.EDX,
                                             Register.ESI, Register.EDI, Register.EBP })
                _r[reg] = 0;
            _r[Register.EAX] = eaxSeed;
            _r[Register.ESP] = StackBase + StackSize - 0x100;
            _zf = _cf = _sf = false;
            Push(RetSentinel);
            Run(va);
            return _r[Register.EAX];
        }

        void Run(uint eip)
        {
            for (int steps = 0; steps < 100000; steps++)
            {
                if (eip == RetSentinel) return;
                var code = FetchCode(eip);
                var dec = Decoder.Create(32, new ByteArrayCodeReader(code));
                dec.IP = eip;
                var insn = dec.Decode();
                if (insn.IsInvalid) throw new NotSupported($"bad insn @0x{eip:X}");
                uint next = (uint)insn.NextIP;

                switch (insn.Mnemonic)
                {
                    case Mnemonic.Mov:   SetDst(insn, GetSrc(insn)); break;
                    case Mnemonic.Movzx: SetDst(insn, GetSrc(insn)); break;        // src already zero-extended by width
                    case Mnemonic.Movsx: SetDst(insn, SignExtend(insn, GetSrc(insn))); break;
                    case Mnemonic.Lea:   _r[insn.Op0Register] = EffAddr(insn); break;
                    case Mnemonic.Push:  Push(ReadOperand(insn, 0)); break;   // push's operand is Op0
                    case Mnemonic.Pop:   SetReg(insn.Op0Register, Pop()); break;
                    case Mnemonic.Add:   { uint a = GetDst(insn), b = GetSrc(insn); uint v = a + b; SetFlagsArith(v, a, b, false); SetDst(insn, v); } break;
                    case Mnemonic.Sub:   { uint a = GetDst(insn), b = GetSrc(insn); uint v = a - b; SetFlagsArith(v, a, b, true); SetDst(insn, v); } break;
                    case Mnemonic.Inc:   { uint v = GetDst(insn) + 1; SetZSF(v); SetDst(insn, v); } break;
                    case Mnemonic.Dec:   { uint v = GetDst(insn) - 1; SetZSF(v); SetDst(insn, v); } break;
                    case Mnemonic.And:   { uint v = GetDst(insn) & GetSrc(insn); _cf = false; SetZSF(v); SetDst(insn, v); } break;
                    case Mnemonic.Or:    { uint v = GetDst(insn) | GetSrc(insn); _cf = false; SetZSF(v); SetDst(insn, v); } break;
                    case Mnemonic.Xor:   { uint v = GetDst(insn) ^ GetSrc(insn); _cf = false; SetZSF(v); SetDst(insn, v); } break;
                    case Mnemonic.Cmp:   { uint a = GetDst(insn), b = GetSrc(insn); SetFlagsArith(a - b, a, b, true); } break;
                    case Mnemonic.Test:  { uint v = GetDst(insn) & GetSrc(insn); _cf = false; SetZSF(v); } break;
                    case Mnemonic.Shl:   { uint v = GetDst(insn) << (int)(GetSrc(insn) & 31); SetZSF(v); SetDst(insn, v); } break;
                    case Mnemonic.Shr:   { uint v = GetDst(insn) >> (int)(GetSrc(insn) & 31); SetZSF(v); SetDst(insn, v); } break;
                    case Mnemonic.Sar:   { uint v = (uint)((int)GetDst(insn) >> (int)(GetSrc(insn) & 31)); SetZSF(v); SetDst(insn, v); } break;
                    case Mnemonic.Bt:    _cf = ((GetDst(insn) >> (int)(GetSrc(insn) & 31)) & 1) != 0; break;
                    case Mnemonic.Neg:   { uint a = GetDst(insn); uint v = (uint)(-(int)a); _cf = a != 0; SetZSF(v); SetDst(insn, v); } break;
                    case Mnemonic.Not:   SetDst(insn, ~GetDst(insn)); break;
                    case Mnemonic.Cdq:   _r[Register.EDX] = (_r[Register.EAX] & 0x80000000) != 0 ? 0xFFFFFFFF : 0; break;
                    case Mnemonic.Cwde:  _r[Register.EAX] = (uint)(short)(_r[Register.EAX] & 0xFFFF); break;
                    case Mnemonic.Imul:  { uint v = (uint)((int)GetDst(insn) * (int)(insn.OpCount >= 2 ? GetSrc(insn) : GetDst(insn))); SetZSF(v); SetDst(insn, v); } break;
                    case Mnemonic.Idiv:  { long n = ((long)(int)_r[Register.EDX] << 32) | _r[Register.EAX]; int d = (int)GetDst(insn); if (d == 0) throw new NotSupported("idiv0"); _r[Register.EAX] = (uint)(int)(n / d); _r[Register.EDX] = (uint)(int)(n % d); } break;
                    case Mnemonic.Nop:   break;
                    case Mnemonic.Movsd: RepMovs(insn, 4); break;
                    case Mnemonic.Movsb: RepMovs(insn, 1); break;
                    case Mnemonic.Stosd: RepStos(insn, 4); break;
                    case Mnemonic.Stosb: RepStos(insn, 1); break;
                    case Mnemonic.Pushad: { uint sp = _r[Register.ESP]; Push(_r[Register.EAX]); Push(_r[Register.ECX]); Push(_r[Register.EDX]); Push(_r[Register.EBX]); Push(sp); Push(_r[Register.EBP]); Push(_r[Register.ESI]); Push(_r[Register.EDI]); } break;
                    case Mnemonic.Popad: { _r[Register.EDI] = Pop(); _r[Register.ESI] = Pop(); _r[Register.EBP] = Pop(); Pop(); _r[Register.EBX] = Pop(); _r[Register.EDX] = Pop(); _r[Register.ECX] = Pop(); _r[Register.EAX] = Pop(); } break;

                    case Mnemonic.Jmp:
                        if (insn.Op0Kind == OpKind.Memory) { eip = DerefImport(insn, ref next) ? next : Read32(EffAddr(insn)); continue; }
                        eip = (uint)insn.NearBranchTarget; continue;

                    case Mnemonic.Call:
                    {
                        uint target = insn.Op0Kind == OpKind.Memory ? Read32(EffAddr(insn)) : (uint)insn.NearBranchTarget;
                        Trace.Add($"call 0x{target:X} (from 0x{eip:X})");
                        if (TryIntrinsic(target)) break;                // emulated import; eax/esp set, fall through to next
                        Push(next);
                        eip = target; continue;
                    }

                    case Mnemonic.Ret:
                    {
                        uint ra = Pop();
                        if (insn.OpCount > 0) _r[Register.ESP] += (uint)insn.Immediate32;   // ret N (stdcall)
                        eip = ra; continue;
                    }

                    default:
                        if (IsJcc(insn.Mnemonic)) { if (TakeJcc(insn.Mnemonic)) { eip = (uint)insn.NearBranchTarget; continue; } break; }
                        if (Setcc(insn.Mnemonic, out bool sv)) { SetDst(insn, sv ? 1u : 0u); break; }
                        throw new NotSupported($"{insn.Mnemonic} @0x{eip:X}");
                }
                eip = next;
            }
            throw new NotSupported("step limit");
        }

        // ---- intrinsics for the imports that matter ----
        bool TryIntrinsic(uint target)
        {
            // CALL/JMP through an import thunk: `jmp dword [iatSlot]` (FF 25 slot). Resolve the import name.
            string name = ImportNameOfThunk(target);
            if (name == null) { if (!_isCode(target)) throw new NotSupported($"call non-code 0x{target:X}"); return false; }
            switch (name)
            {
                case "TlsGetValue":
                    // stdcall(index): the index was pushed by the caller, so it's at [esp].
                    uint idx = Read32(_r[Register.ESP]);
                    _r[Register.EAX] = _tlsGetValue(idx);
                    _r[Register.ESP] += 4;                      // stdcall pops its 1 arg
                    Trace.Add($"TlsGetValue({idx})=0x{_r[Register.EAX]:X}");
                    return true;
                case "GetCurrentThreadId":
                    _r[Register.EAX] = _curThreadId;
                    return true;
                case "GetLastError":                         // RTL save/restores it around work; TEB+0x34 = LastError
                    _r[Register.EAX] = ReadN(_teb + 0x34, 4);
                    return true;
                case "SetLastError":                         // stdcall(1): no-op (read-only), just pop the arg
                    _r[Register.ESP] += 4;
                    return true;
                case "GetKeyState":                          // stdcall(1): live OS keyboard state — not memory-readable
                    _r[Register.EAX] = 0;                     // degrade to 0 (KEYSTATE/KEYCHAR best-effort)
                    _r[Register.ESP] += 4;
                    return true;
                case "EnterCriticalSection":                 // stdcall(1): read-only emulation needs no locking
                case "LeaveCriticalSection":
                    _r[Register.ESP] += 4;
                    return true;
                default:
                    throw new NotSupported($"import {name}");
            }
        }

        string ImportNameOfThunk(uint target)
        {
            var b = _readMem(target, 6);
            if (b.Length >= 6 && b[0] == 0xFF && b[1] == 0x25)   // jmp dword [imm32]
                return _importAtSlot(BitConverter.ToUInt32(b, 2));
            return null;
        }

        bool DerefImport(Instruction insn, ref uint next) => false;   // jmp [mem] handled inline above

        // ---- operands ----
        uint GetSrc(Instruction insn) => ReadOperand(insn, 1);
        uint GetDst(Instruction insn) => ReadOperand(insn, 0);
        void SetDst(Instruction insn, uint v) => WriteOperand(insn, 0, v);

        uint ReadOperand(Instruction insn, int op)
        {
            var kind = insn.GetOpKind(op);
            return kind switch
            {
                OpKind.Register => RegVal(insn.GetOpRegister(op)),
                OpKind.Memory => ReadMemSized(EffAddr(insn), insn.MemorySize),
                OpKind.Immediate8 or OpKind.Immediate8to32 or OpKind.Immediate16
                    or OpKind.Immediate32 or OpKind.Immediate8to16 => (uint)insn.GetImmediate(op),
                _ => throw new NotSupported($"opkind {kind}")
            };
        }

        void WriteOperand(Instruction insn, int op, uint v)
        {
            var kind = insn.GetOpKind(op);
            if (kind == OpKind.Register) SetReg(insn.GetOpRegister(op), v);
            else if (kind == OpKind.Memory) WriteMem(EffAddr(insn), v, insn.MemorySize);
            else throw new NotSupported($"write opkind {kind}");
        }

        uint EffAddr(Instruction insn)
        {
            uint a = 0;
            if (insn.MemoryBase != Register.None) a += RegVal(insn.MemoryBase);
            if (insn.MemoryIndex != Register.None) a += RegVal(insn.MemoryIndex) * (uint)insn.MemoryIndexScale;
            a += (uint)insn.MemoryDisplacement32;
            return a;
        }

        // ---- registers (track 32-bit; sub-register reads/writes masked) ----
        uint RegVal(Register r)
        {
            var full = Full(r); uint v = _r.TryGetValue(full, out var x) ? x : 0;
            return r switch
            {
                _ when Is8Low(r) => v & 0xFF,
                _ when Is16(r) => v & 0xFFFF,
                _ => v
            };
        }
        void SetReg(Register r, uint v)
        {
            var full = Full(r);
            uint cur = _r.TryGetValue(full, out var x) ? x : 0;
            _r[full] = r switch
            {
                _ when Is8Low(r) => (cur & 0xFFFFFF00) | (v & 0xFF),
                _ when Is16(r) => (cur & 0xFFFF0000) | (v & 0xFFFF),
                _ => v
            };
        }

        uint SignExtend(Instruction insn, uint v) =>
            insn.GetOpKind(1) == OpKind.Memory
                ? (insn.MemorySize == MemorySize.Int8 ? (uint)(sbyte)v : (uint)(short)v)
                : v;

        // ---- memory: route to modeled stack or debuggee ----
        bool InStack(uint addr) => addr >= StackBase && addr < StackBase + StackSize;
        uint ReadMemSized(uint addr, MemorySize sz) => sz switch
        {
            MemorySize.UInt8 or MemorySize.Int8 => ReadN(addr, 1),
            MemorySize.UInt16 or MemorySize.Int16 => ReadN(addr, 2),
            _ => ReadN(addr, 4),
        };
        readonly Dictionary<uint, byte> _shadow = new Dictionary<uint, byte>();   // copy-on-write overlay: debuggee writes land here, never in the target

        uint ReadN(uint addr, int n)
        {
            if (InStack(addr)) { uint v = 0; for (int i = 0; i < n; i++) v |= (uint)_stack[addr - StackBase + i] << (8 * i); return v; }
            var b = _readMem(addr, n);
            if (b.Length < n) throw new NotSupported($"read 0x{addr:X}");
            if (_shadow.Count > 0) for (int i = 0; i < n; i++) if (_shadow.TryGetValue(addr + (uint)i, out var sb)) b[i] = sb;
            uint r = 0; for (int i = 0; i < n; i++) r |= (uint)b[i] << (8 * i); return r;
        }
        uint Read32(uint addr) => ReadN(addr, 4);
        void WriteMem(uint addr, uint v, MemorySize sz)
            => WriteN(addr, v, sz is MemorySize.UInt8 or MemorySize.Int8 ? 1 : sz is MemorySize.UInt16 or MemorySize.Int16 ? 2 : 4);
        void WriteN(uint addr, uint v, int n)
        {
            if (InStack(addr)) { for (int i = 0; i < n; i++) _stack[addr - StackBase + i] = (byte)(v >> (8 * i)); return; }
            for (int i = 0; i < n; i++) _shadow[addr + (uint)i] = (byte)(v >> (8 * i));   // shadow, not the debuggee
        }

        // REP MOVS / STOS (forward; DF assumed clear — the RTL cld's before string ops).
        void RepMovs(Instruction insn, int size)
        {
            int count = insn.HasRepPrefix ? (int)_r[Register.ECX] : 1;
            for (; count > 0; count--) { WriteN(_r[Register.EDI], ReadN(_r[Register.ESI], size), size); _r[Register.ESI] += (uint)size; _r[Register.EDI] += (uint)size; }
            if (insn.HasRepPrefix) _r[Register.ECX] = 0;
        }
        void RepStos(Instruction insn, int size)
        {
            int count = insn.HasRepPrefix ? (int)_r[Register.ECX] : 1;
            for (; count > 0; count--) { WriteN(_r[Register.EDI], _r[Register.EAX], size); _r[Register.EDI] += (uint)size; }
            if (insn.HasRepPrefix) _r[Register.ECX] = 0;
        }

        /// <summary>Read a NUL-terminated ASCII string from emulated memory (stack/shadow/debuggee aware) — used
        /// to recover the result of a string-building getter after Call().</summary>
        public string ReadCStringResult(uint addr, int cap)
        {
            if (addr == 0) return "";
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < cap; i++) { byte c = (byte)ReadN(addr + (uint)i, 1); if (c == 0) break; sb.Append((char)c); }
            return sb.ToString();
        }
        void Push(uint v) { _r[Register.ESP] -= 4; WriteMem(_r[Register.ESP], v, MemorySize.UInt32); }
        uint Pop() { uint v = Read32(_r[Register.ESP]); _r[Register.ESP] += 4; return v; }

        byte[] FetchCode(uint va) => _readMem(va, 16);

        // ---- flags ----
        void SetZSF(uint v) { _zf = v == 0; _sf = (v & 0x80000000) != 0; }
        void SetFlagsArith(uint res, uint a, uint b, bool sub) { SetZSF(res); _cf = sub ? a < b : res < a; }

        static bool IsJcc(Mnemonic m) => m is Mnemonic.Je or Mnemonic.Jne or Mnemonic.Jb or Mnemonic.Jae
            or Mnemonic.Jbe or Mnemonic.Ja or Mnemonic.Jl or Mnemonic.Jge or Mnemonic.Jle or Mnemonic.Jg
            or Mnemonic.Js or Mnemonic.Jns;
        bool TakeJcc(Mnemonic m) => m switch
        {
            Mnemonic.Je => _zf, Mnemonic.Jne => !_zf,
            Mnemonic.Jb => _cf, Mnemonic.Jae => !_cf,
            Mnemonic.Jbe => _cf || _zf, Mnemonic.Ja => !_cf && !_zf,
            Mnemonic.Js => _sf, Mnemonic.Jns => !_sf,
            Mnemonic.Jl => _sf, Mnemonic.Jge => !_sf,            // OF not tracked; ok for these accessors
            Mnemonic.Jle => _sf || _zf, Mnemonic.Jg => !_sf && !_zf,
            _ => false
        };

        bool Setcc(Mnemonic m, out bool val)
        {
            switch (m)
            {
                case Mnemonic.Sete: val = _zf; return true;
                case Mnemonic.Setne: val = !_zf; return true;
                case Mnemonic.Setb: val = _cf; return true;
                case Mnemonic.Setae: val = !_cf; return true;
                case Mnemonic.Setbe: val = _cf || _zf; return true;
                case Mnemonic.Seta: val = !_cf && !_zf; return true;
                case Mnemonic.Sets: val = _sf; return true;
                case Mnemonic.Setns: val = !_sf; return true;
                case Mnemonic.Setl: val = _sf; return true;            // OF not tracked
                case Mnemonic.Setge: val = !_sf; return true;
                case Mnemonic.Setle: val = _sf || _zf; return true;
                case Mnemonic.Setg: val = !_sf && !_zf; return true;
                default: val = false; return false;
            }
        }

        static bool Is8Low(Register r) => r is Register.AL or Register.BL or Register.CL or Register.DL;
        static bool Is16(Register r) => r is Register.AX or Register.BX or Register.CX or Register.DX
            or Register.SI or Register.DI or Register.BP or Register.SP;
        static Register Full(Register r) => r switch
        {
            Register.AL or Register.AX => Register.EAX,
            Register.BL or Register.BX => Register.EBX,
            Register.CL or Register.CX => Register.ECX,
            Register.DL or Register.DX => Register.EDX,
            Register.SI => Register.ESI, Register.DI => Register.EDI,
            Register.BP => Register.EBP, Register.SP => Register.ESP,
            _ => r
        };
    }
}
