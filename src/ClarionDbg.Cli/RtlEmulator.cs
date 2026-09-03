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
    /// Scope: the small instruction subset these accessors use. Anything outside it throws
    /// <see cref="NotSupported"/>, which the caller turns into "&lt;unavailable&gt;".
    ///
    /// The governing rule is REFUSE, DON'T GUESS: a value this panel shows must either be what the RTL
    /// would have computed or be visibly absent. A confidently wrong ERRORCODE is worse than a blank one,
    /// because nothing signals to the developer that they shouldn't trust it. So anything we can't model
    /// exactly — an unhandled instruction, an fs:/gs: override, an indirect jump we can't follow, an access
    /// that has run off the modeled stack — throws rather than producing a plausible-looking number.</summary>
    internal sealed class RtlEmulator
    {
        public sealed class NotSupported : Exception { public NotSupported(string m) : base(m) { } }

        public readonly List<string> Trace = new List<string>();   // diagnostics

        // modeled stack: a private window; accesses inside it hit this buffer, everything else is a
        // read-only debuggee fetch. The base is NOT fixed — the caller picks one from a region the target
        // has genuinely free (see EmulatorStackWindow.Pick). A hardcoded base is a silent wrong
        // answer waiting to happen: if a real module or heap block lives there, every read of a genuine
        // address inside the window gets served from this buffer instead, and the panel shows a plausible
        // number that isn't the RTL's. Refusing beats guessing, and not colliding beats both.
        public const int StackSize = 0x10000;
        // …and a band either side of it. An access that lands here is the emulation having run off the
        // modeled stack (ESP walked past an end after a bad pop / a huge `sub esp`), not a genuine
        // debuggee address — refusing it stops a runaway before it spins out to the step limit.
        public const uint StackGuard = 0x00100000;
        /// <summary>Bytes of free address space the caller must find: the modeled stack plus both guards.
        /// The base handed to the constructor is the region's start + <see cref="StackGuard"/>.</summary>
        public const uint WindowBytes = StackGuard + StackSize + StackGuard;
        readonly uint _stackBase;
        readonly byte[] _stack = new byte[StackSize];

        readonly Func<uint, int, byte[]> _readMem;     // debuggee read (addr, len)
        readonly Func<uint, uint> _tlsGetValue;        // TlsGetValue(index) -> slot value
        readonly uint _curThreadId;                    // GetCurrentThreadId() intrinsic
        readonly uint _teb;                            // stopped thread's TEB (for GetLastError)
        readonly Func<uint, string> _importAtSlot;     // IAT slot VA -> imported function name
        readonly Func<uint, bool> _isCode;             // is this VA emulatable runtime code?

        readonly Dictionary<Register, uint> _r = new Dictionary<Register, uint>();
        bool _zf, _cf, _sf, _of, _df;
        const uint RetSentinel = 0xDEAD0000;           // top-level return address; ret here = done

        public RtlEmulator(Func<uint, int, byte[]> readMem, Func<uint, uint> tlsGetValue, uint curThreadId,
                           uint teb, Func<uint, string> importAtSlot, Func<uint, bool> isCode, uint stackBase)
        {
            _readMem = readMem; _tlsGetValue = tlsGetValue; _curThreadId = curThreadId; _teb = teb;
            _importAtSlot = importAtSlot; _isCode = isCode;
            // the low guard is computed as _stackBase - StackGuard, so a base below that would wrap.
            if (stackBase < StackGuard || stackBase > uint.MaxValue - (StackSize + StackGuard))
                throw new NotSupported($"modeled stack base 0x{stackBase:X} leaves no room for its guard bands");
            _stackBase = stackBase;
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
            _r[Register.ESP] = _stackBase + StackSize - 0x100;
            _zf = _cf = _sf = _of = _df = false;
            Push(RetSentinel);
            Run(va);
            return _r[Register.EAX];
        }

        void Run(uint eip)
        {
            for (int steps = 0; steps < 100000; steps++)
            {
                if (eip == RetSentinel) return;
                var insn = DecodeAt(eip);
                uint next = (uint)insn.NextIP;
                int size = OpSize(insn);

                switch (insn.Mnemonic)
                {
                    case Mnemonic.Mov:   SetDst(insn, GetSrc(insn)); break;
                    case Mnemonic.Movzx: SetDst(insn, GetSrc(insn)); break;        // src already zero-extended by width
                    case Mnemonic.Movsx: SetDst(insn, SignExtend(insn, GetSrc(insn))); break;
                    case Mnemonic.Lea:   SetReg(insn.Op0Register, EffAddr(insn)); break;   // via SetReg: a 16-bit dst truncates
                    case Mnemonic.Push:  Push(ReadOperand(insn, 0)); break;   // push's operand is Op0
                    case Mnemonic.Pop:   SetReg(insn.Op0Register, Pop()); break;
                    case Mnemonic.Xchg:  { uint a = GetDst(insn), b = GetSrc(insn); SetDst(insn, b); WriteOperand(insn, 1, a); } break;
                    case Mnemonic.Add:   { uint a = GetDst(insn), b = GetSrc(insn); uint v = a + b; SetFlagsArith(v, a, b, false, size); SetDst(insn, v); } break;
                    case Mnemonic.Sub:   { uint a = GetDst(insn), b = GetSrc(insn); uint v = a - b; SetFlagsArith(v, a, b, true, size); SetDst(insn, v); } break;
                    case Mnemonic.Inc:   { uint a = GetDst(insn), v = a + 1; SetZSF(v, size); _of = (v & Mask(size)) == SignBit(size); SetDst(insn, v); } break;   // INC/DEC leave CF alone
                    case Mnemonic.Dec:   { uint a = GetDst(insn), v = a - 1; SetZSF(v, size); _of = (v & Mask(size)) == (SignBit(size) - 1); SetDst(insn, v); } break;
                    case Mnemonic.And:   { uint v = GetDst(insn) & GetSrc(insn); SetLogicFlags(v, size); SetDst(insn, v); } break;
                    case Mnemonic.Or:    { uint v = GetDst(insn) | GetSrc(insn); SetLogicFlags(v, size); SetDst(insn, v); } break;
                    case Mnemonic.Xor:   { uint v = GetDst(insn) ^ GetSrc(insn); SetLogicFlags(v, size); SetDst(insn, v); } break;
                    case Mnemonic.Cmp:   { uint a = GetDst(insn), b = GetSrc(insn); SetFlagsArith(a - b, a, b, true, size); } break;
                    case Mnemonic.Test:  { uint v = GetDst(insn) & GetSrc(insn); SetLogicFlags(v, size); } break;
                    case Mnemonic.Shl:   Shift(insn, size, left: true, arith: false); break;
                    case Mnemonic.Shr:   Shift(insn, size, left: false, arith: false); break;
                    case Mnemonic.Sar:   Shift(insn, size, left: false, arith: true); break;
                    case Mnemonic.Bt:    _cf = ((GetDst(insn) >> (int)(GetSrc(insn) & (uint)(size * 8 - 1))) & 1) != 0; break;
                    case Mnemonic.Neg:   { uint a = GetDst(insn), v = 0u - a; SetFlagsArith(v, 0, a, true, size); SetDst(insn, v); } break;
                    case Mnemonic.Not:   SetDst(insn, ~GetDst(insn)); break;   // NOT affects no flags
                    case Mnemonic.Cdq:   _r[Register.EDX] = (_r[Register.EAX] & 0x80000000) != 0 ? 0xFFFFFFFF : 0; break;
                    case Mnemonic.Cwde:  _r[Register.EAX] = (uint)(short)(_r[Register.EAX] & 0xFFFF); break;
                    case Mnemonic.Imul:  Imul(insn, size); break;
                    case Mnemonic.Idiv:  { long n = ((long)(int)_r[Register.EDX] << 32) | _r[Register.EAX]; int d = (int)GetDst(insn); if (d == 0) throw new NotSupported("idiv0"); _r[Register.EAX] = (uint)(int)(n / d); _r[Register.EDX] = (uint)(int)(n % d); } break;
                    case Mnemonic.Nop:   break;
                    case Mnemonic.Cld:   _df = false; break;                   // forward string ops (what RepMovs/RepStos model)
                    case Mnemonic.Std:   _df = true; break;                    // string ops then refuse — see RepMovs/RepStos
                    case Mnemonic.Leave: _r[Register.ESP] = _r[Register.EBP]; _r[Register.EBP] = Pop(); break;
                    // Mnemonic.Movsd/Movsb/Stosd/Stosb are ambiguous in Iced — SSE2's `movsd xmm, m64` shares
                    // the Movsd mnemonic with the string move — so switch on the exact Code, not the mnemonic.
                    case Mnemonic.Movsd: RequireCode(insn, Code.Movsd_m32_m32); RepMovs(insn, 4); break;
                    case Mnemonic.Movsb: RequireCode(insn, Code.Movsb_m8_m8);   RepMovs(insn, 1); break;
                    case Mnemonic.Stosd: RequireCode(insn, Code.Stosd_m32_EAX); RepStos(insn, 4); break;
                    case Mnemonic.Stosb: RequireCode(insn, Code.Stosb_m8_AL);   RepStos(insn, 1); break;
                    case Mnemonic.Pushad: { uint sp = _r[Register.ESP]; Push(_r[Register.EAX]); Push(_r[Register.ECX]); Push(_r[Register.EDX]); Push(_r[Register.EBX]); Push(sp); Push(_r[Register.EBP]); Push(_r[Register.ESI]); Push(_r[Register.EDI]); } break;
                    case Mnemonic.Popad: { _r[Register.EDI] = Pop(); _r[Register.ESI] = Pop(); _r[Register.EBP] = Pop(); Pop(); _r[Register.EBX] = Pop(); _r[Register.EDX] = Pop(); _r[Register.ECX] = Pop(); _r[Register.EAX] = Pop(); } break;

                    case Mnemonic.Jmp:
                    {
                        if (insn.Op0Kind == OpKind.NearBranch16 || insn.Op0Kind == OpKind.NearBranch32
                            || insn.Op0Kind == OpKind.NearBranch64) { eip = (uint)insn.NearBranchTarget; continue; }
                        // indirect jmp (tail-call / jump table / import thunk): follow it only into code we
                        // can actually emulate. Previously a register target fell into the NearBranchTarget
                        // path and yielded 0, which then decoded whatever sat at address 0 until the step limit.
                        uint t = insn.Op0Kind == OpKind.Memory ? Read32(EffAddr(insn))
                               : insn.Op0Kind == OpKind.Register ? RegVal(insn.Op0Register)
                               : throw new NotSupported($"jmp opkind {insn.Op0Kind} @0x{eip:X}");
                        if (!_isCode(t)) throw new NotSupported($"indirect jmp to non-code 0x{t:X} (from 0x{eip:X})");
                        eip = t; continue;
                    }

                    case Mnemonic.Call:
                    {
                        uint target = insn.Op0Kind == OpKind.Memory ? Read32(EffAddr(insn))
                                    : insn.Op0Kind == OpKind.Register ? RegVal(insn.Op0Register)
                                    : (uint)insn.NearBranchTarget;
                        Trace.Add($"call 0x{target:X} (from 0x{eip:X})");
                        if (TryIntrinsic(target)) break;                // emulated import; eax/esp set, fall through to next
                        Push(next);
                        eip = target; continue;
                    }

                    case Mnemonic.Ret:
                    {
                        uint ra = Pop();
                        if (insn.OpCount > 0) _r[Register.ESP] += (uint)insn.Immediate32;   // ret N (stdcall)
                        if (ra != RetSentinel && !_isCode(ra))
                            throw new NotSupported($"ret to non-code 0x{ra:X}");            // popped garbage — stop here, don't spin
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

        static void RequireCode(Instruction insn, Code want)
        {
            if (insn.Code != want) throw new NotSupported($"{insn.Code} @0x{insn.IP:X}");
        }

        // ---- decode (cached) ----
        // The debuggee is stopped and we never write to it, so an instruction at a given VA can't change for
        // this emulator's lifetime (one per pause). Caching decoded instructions keeps a loop or a repeated
        // getter from re-reading 16 bytes of code — two ReadProcessMemory calls — on every single step.
        readonly Dictionary<uint, Instruction> _insnCache = new Dictionary<uint, Instruction>();

        Instruction DecodeAt(uint eip)
        {
            if (_insnCache.TryGetValue(eip, out var hit)) return hit;
            var code = _readMem(eip, 16);
            if (code.Length == 0) throw new NotSupported($"code fetch 0x{eip:X}");
            var dec = Decoder.Create(32, new ByteArrayCodeReader(code));
            dec.IP = eip;
            var insn = dec.Decode();
            if (insn.IsInvalid) throw new NotSupported($"bad insn @0x{eip:X}");
            _insnCache[eip] = insn;
            return insn;
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
            // fs:/gs: are thread-local bases we don't model. Ignoring the override would turn an fs:-relative
            // TEB read into a flat read of the same offset — a plausible-looking value from unrelated memory.
            if (insn.SegmentPrefix == Register.FS || insn.SegmentPrefix == Register.GS)
                throw new NotSupported($"{insn.SegmentPrefix}: override @0x{insn.IP:X}");
            uint a = 0;
            if (insn.MemoryBase != Register.None) a += RegVal(insn.MemoryBase);
            if (insn.MemoryIndex != Register.None) a += RegVal(insn.MemoryIndex) * (uint)insn.MemoryIndexScale;
            a += (uint)insn.MemoryDisplacement32;
            return a;
        }

        /// <summary>The operation's width in bytes, taken from the destination operand — what the flag
        /// results and the sign bit are defined against (`cmp al,0` is an 8-bit compare, not a 32-bit one).</summary>
        static int OpSize(Instruction insn)
        {
            if (insn.OpCount == 0) return 4;
            return insn.Op0Kind switch
            {
                OpKind.Register => insn.Op0Register.GetSize(),
                OpKind.Memory => MemSize(insn.MemorySize),
                _ => 4
            };
        }

        static int MemSize(MemorySize sz) => sz switch
        {
            MemorySize.UInt8 or MemorySize.Int8 => 1,
            MemorySize.UInt16 or MemorySize.Int16 => 2,
            _ => 4
        };

        static uint Mask(int size) => size == 1 ? 0xFFu : size == 2 ? 0xFFFFu : 0xFFFFFFFFu;
        static uint SignBit(int size) => size == 1 ? 0x80u : size == 2 ? 0x8000u : 0x80000000u;
        static int Signed(uint v, int size) => size == 1 ? (sbyte)v : size == 2 ? (short)v : (int)v;

        // ---- registers (track 32-bit; sub-register reads/writes masked) ----
        uint RegVal(Register r)
        {
            var full = Full(r); uint v = _r.TryGetValue(full, out var x) ? x : 0;
            return r switch
            {
                _ when Is8Low(r) => v & 0xFF,
                _ when Is8High(r) => (v >> 8) & 0xFF,
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
                _ when Is8High(r) => (cur & 0xFFFF00FF) | ((v & 0xFF) << 8),
                _ when Is16(r) => (cur & 0xFFFF0000) | (v & 0xFFFF),
                _ => v
            };
        }

        /// <summary>Widen a movsx source to 32 bits. The width comes from the SOURCE operand — a register
        /// source has to consult the register's size, not just MemorySize, or `movsx eax,cl` stays
        /// zero-extended and a negative ERRORCODE/FIELD renders as a large positive number.</summary>
        uint SignExtend(Instruction insn, uint v)
        {
            int n = insn.GetOpKind(1) switch
            {
                OpKind.Memory => MemSize(insn.MemorySize),
                OpKind.Register => insn.Op1Register.GetSize(),
                _ => 4
            };
            return n == 1 ? (uint)(sbyte)v : n == 2 ? (uint)(short)v : v;
        }

        /// <summary>IMUL's three forms compute different things; only the two-operand one is a plain
        /// dst *= src. One-operand is EDX:EAX = EAX * r/m (EAX is an implicit source, and the result does
        /// NOT go back over the operand); three-operand is dst = src * imm, ignoring dst's prior value.</summary>
        void Imul(Instruction insn, int size)
        {
            if (insn.OpCount == 1)
            {
                if (size != 4) throw new NotSupported($"imul r/m{size * 8}");   // 8/16-bit forms use AX / DX:AX
                long p = (long)(int)_r[Register.EAX] * (int)GetDst(insn);
                _r[Register.EAX] = (uint)p;
                _r[Register.EDX] = (uint)((ulong)p >> 32);
                _cf = _of = p != (int)p;
                SetZSF((uint)p, 4);
                return;
            }
            long v = insn.OpCount == 2
                ? (long)Signed(GetDst(insn), size) * Signed(GetSrc(insn), size)
                : (long)Signed(ReadOperand(insn, 1), size) * Signed(ReadOperand(insn, 2), size);
            _cf = _of = v != Signed((uint)v, size);
            SetZSF((uint)v, size);
            SetDst(insn, (uint)v);
        }

        void Shift(Instruction insn, int size, bool left, bool arith)
        {
            uint a = GetDst(insn) & Mask(size);
            int n = (int)(GetSrc(insn) & 31);
            if (n == 0) return;                                   // a zero count leaves every flag untouched
            int bits = size * 8;
            uint v;
            if (left)
            {
                _cf = n <= bits && ((a >> (bits - n)) & 1) != 0;
                v = a << n;
            }
            else
            {
                _cf = n <= bits && ((a >> (n - 1)) & 1) != 0;
                v = arith ? (uint)(Signed(a, size) >> n) : (a >> n);
            }
            // OF is architecturally defined only for a count of 1 and undefined above it, so this is exact
            // where it matters and free to be anything where it isn't.
            _of = left ? (((v & SignBit(size)) != 0) != _cf) : arith ? false : (a & SignBit(size)) != 0;
            SetZSF(v, size);
            SetDst(insn, v);
        }

        // ---- memory: route to modeled stack or debuggee ----
        /// <summary>True when the whole span lies inside the modeled stack, false when it lies wholly outside
        /// (a debuggee access). A span that straddles an edge — or lands in the guard band either side — is
        /// the emulation having gone off the rails, so it throws instead of half-reading the stack buffer
        /// (which used to index past <see cref="_stack"/> and escape as IndexOutOfRangeException) or quietly
        /// reading an unrelated debuggee address just below the modeled stack.</summary>
        bool InStack(uint addr, int n)
        {
            uint lo = addr, hi = addr + (uint)(n - 1);
            if (hi < lo) throw new NotSupported($"address wraps at 0x{addr:X}+{n}");
            bool loIn = lo >= _stackBase && lo < _stackBase + StackSize;
            bool hiIn = hi >= _stackBase && hi < _stackBase + StackSize;
            if (loIn && hiIn) return true;
            if (loIn != hiIn) throw new NotSupported($"access 0x{addr:X}+{n} straddles the modeled stack");
            if (hi >= _stackBase - StackGuard && lo < _stackBase + StackSize + StackGuard)
                throw new NotSupported($"stack under/overflow at 0x{addr:X}");
            return false;
        }

        uint ReadMemSized(uint addr, MemorySize sz) => ReadN(addr, MemSize(sz));

        readonly Dictionary<uint, byte> _shadow = new Dictionary<uint, byte>();   // copy-on-write overlay: debuggee writes land here, never in the target

        uint ReadN(uint addr, int n)
        {
            if (InStack(addr, n)) { uint v = 0; for (int i = 0; i < n; i++) v |= (uint)_stack[addr - _stackBase + i] << (8 * i); return v; }
            var b = _readMem(addr, n);
            if (b.Length < n) throw new NotSupported($"read 0x{addr:X}");
            if (_shadow.Count > 0) for (int i = 0; i < n; i++) if (_shadow.TryGetValue(addr + (uint)i, out var sb)) b[i] = sb;
            uint r = 0; for (int i = 0; i < n; i++) r |= (uint)b[i] << (8 * i); return r;
        }
        uint Read32(uint addr) => ReadN(addr, 4);
        void WriteMem(uint addr, uint v, MemorySize sz) => WriteN(addr, v, MemSize(sz));
        void WriteN(uint addr, uint v, int n)
        {
            if (InStack(addr, n)) { for (int i = 0; i < n; i++) _stack[addr - _stackBase + i] = (byte)(v >> (8 * i)); return; }
            for (int i = 0; i < n; i++) _shadow[addr + (uint)i] = (byte)(v >> (8 * i));   // shadow, not the debuggee
        }

        // REP MOVS / STOS, forward only — the RTL cld's before its string ops. A backward run (DF set by an
        // std we've seen) isn't modeled, so refuse rather than copy the wrong way.
        void RepMovs(Instruction insn, int size)
        {
            if (_df) throw new NotSupported("backward movs (DF set)");
            int count = insn.HasRepPrefix ? (int)_r[Register.ECX] : 1;
            for (; count > 0; count--) { WriteN(_r[Register.EDI], ReadN(_r[Register.ESI], size), size); _r[Register.ESI] += (uint)size; _r[Register.EDI] += (uint)size; }
            if (insn.HasRepPrefix) _r[Register.ECX] = 0;
        }
        void RepStos(Instruction insn, int size)
        {
            if (_df) throw new NotSupported("backward stos (DF set)");
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
        void Push(uint v) { _r[Register.ESP] -= 4; WriteN(_r[Register.ESP], v, 4); }
        uint Pop() { uint v = Read32(_r[Register.ESP]); _r[Register.ESP] += 4; return v; }

        // ---- flags ----
        void SetZSF(uint v, int size) { uint m = Mask(size); v &= m; _zf = v == 0; _sf = (v & SignBit(size)) != 0; }
        void SetLogicFlags(uint v, int size) { SetZSF(v, size); _cf = false; _of = false; }
        void SetFlagsArith(uint res, uint a, uint b, bool sub, int size)
        {
            uint m = Mask(size), sb = SignBit(size);
            a &= m; b &= m; res &= m;
            SetZSF(res, size);
            _cf = sub ? a < b : res < a;
            // signed overflow: for a-b the operands must differ in sign and the result take b's sign;
            // for a+b they must share a sign and the result flip it.
            _of = sub ? ((a ^ b) & (a ^ res) & sb) != 0
                      : (~(a ^ b) & (a ^ res) & sb) != 0;
        }

        static bool IsJcc(Mnemonic m) => m is Mnemonic.Je or Mnemonic.Jne or Mnemonic.Jb or Mnemonic.Jae
            or Mnemonic.Jbe or Mnemonic.Ja or Mnemonic.Jl or Mnemonic.Jge or Mnemonic.Jle or Mnemonic.Jg
            or Mnemonic.Js or Mnemonic.Jns or Mnemonic.Jo or Mnemonic.Jno;
        bool TakeJcc(Mnemonic m) => m switch
        {
            Mnemonic.Je => _zf, Mnemonic.Jne => !_zf,
            Mnemonic.Jb => _cf, Mnemonic.Jae => !_cf,
            Mnemonic.Jbe => _cf || _zf, Mnemonic.Ja => !_cf && !_zf,
            Mnemonic.Js => _sf, Mnemonic.Jns => !_sf,
            Mnemonic.Jo => _of, Mnemonic.Jno => !_of,
            Mnemonic.Jl => _sf != _of, Mnemonic.Jge => _sf == _of,
            Mnemonic.Jle => _zf || _sf != _of, Mnemonic.Jg => !_zf && _sf == _of,
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
                case Mnemonic.Seto: val = _of; return true;
                case Mnemonic.Setno: val = !_of; return true;
                case Mnemonic.Setl: val = _sf != _of; return true;
                case Mnemonic.Setge: val = _sf == _of; return true;
                case Mnemonic.Setle: val = _zf || _sf != _of; return true;
                case Mnemonic.Setg: val = !_zf && _sf == _of; return true;
                default: val = false; return false;
            }
        }

        static bool Is8Low(Register r) => r is Register.AL or Register.BL or Register.CL or Register.DL;
        static bool Is8High(Register r) => r is Register.AH or Register.BH or Register.CH or Register.DH;
        static bool Is16(Register r) => r is Register.AX or Register.BX or Register.CX or Register.DX
            or Register.SI or Register.DI or Register.BP or Register.SP;
        /// <summary>The 32-bit register a sub-register lives in. Anything that isn't a general-purpose
        /// register (XMM, segment, …) throws instead of becoming a phantom dictionary key that reads back
        /// as 0 — a write nobody sees is exactly the kind of silent wrongness this emulator must avoid.</summary>
        static Register Full(Register r) => r switch
        {
            Register.AL or Register.AH or Register.AX => Register.EAX,
            Register.BL or Register.BH or Register.BX => Register.EBX,
            Register.CL or Register.CH or Register.CX => Register.ECX,
            Register.DL or Register.DH or Register.DX => Register.EDX,
            Register.SI => Register.ESI, Register.DI => Register.EDI,
            Register.BP => Register.EBP, Register.SP => Register.ESP,
            Register.EAX or Register.EBX or Register.ECX or Register.EDX => r,
            Register.ESI or Register.EDI or Register.EBP or Register.ESP => r,
            _ => throw new NotSupported($"register {r}")
        };
    }
}
