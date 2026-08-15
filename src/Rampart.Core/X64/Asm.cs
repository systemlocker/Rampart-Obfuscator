using System.Buffers.Binary;

namespace Rampart.X64;

/// <summary>x64 registers, numbered by hardware encoding (REX-aware).</summary>
public enum Reg
{
    Rax = 0, Rcx = 1, Rdx = 2, Rbx = 3,
    Rsp = 4, Rbp = 5, Rsi = 6, Rdi = 7,
    R8 = 8, R9 = 9, R10 = 10, R11 = 11,
    R12 = 12, R13 = 13, R14 = 14, R15 = 15,
}

public enum Cc
{
    O = 0, No = 1, B = 2, Ae = 3, E = 4, Ne = 5, Be = 6, A = 7,
    S = 8, Ns = 9, P = 0xA, Np = 0xB, L = 0xC, Ge = 0xD, Le = 0xE, G = 0xF,
}

/// <summary>Tiny two-pass x64 assembler for the subset the protector's stubs use.
/// Everything is position-independent by construction: branches are rel32, data is
/// reached through lea reg,[rip+disp]. No absolute image addresses are ever baked
/// in, so the emitted blob works wherever the loader maps it.</summary>
public sealed class Asm
{
    private readonly List<byte> _code = [];
    private readonly Dictionary<string, int> _labels = new(StringComparer.Ordinal);
    private readonly List<(int Pos, string Target)> _rel32 = [];      // E8/E9/0F8x targets
    private readonly List<(int Pos, string Target, int Extra)> _ripRefs = []; // lea/mov rip+disp (+extra)

    public int Position => _code.Count;

    // ---- Labels and raw data -------------------------------------------------

    public Asm Label(string name)
    {
        _labels[name] = _code.Count;
        return this;
    }

    public bool HasLabel(string name) => _labels.ContainsKey(name);

    /// <summary>Runtime value of a label's offset inside this blob.</summary>
    public int LabelOffset(string name) =>
        _labels.TryGetValue(name, out var off) ? off
            : throw new KeyNotFoundException($"Label '{name}' not defined.");

    public Asm Db(params byte[] bytes)
    {
        _code.AddRange(bytes);
        return this;
    }

    public Asm Db(ReadOnlySpan<byte> bytes)
    {
        _code.AddRange(bytes);
        return this;
    }

    public Asm Dq(ulong value)
    {
        Span<byte> b = stackalloc byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(b, value);
        return Db(b);
    }

    public Asm Dq(params ulong[] values)
    {
        foreach (var v in values)
            Dq(v);
        return this;
    }

    public Asm Dd(params uint[] values)
    {
        Span<byte> b = stackalloc byte[4];
        foreach (var v in values)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(b, v);
            Db(b);
        }
        return this;
    }

    public Asm Dw(params ushort[] values)
    {
        Span<byte> b = stackalloc byte[2];
        foreach (var v in values)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(b, v);
            Db(b);
        }
        return this;
    }

    /// <summary>Zero-pads to an alignment boundary (keeps label math simple for tables).</summary>
    public Asm Align(int alignment)
    {
        while (_code.Count % alignment != 0)
            _code.Add(0xCC);
        return this;
    }

    // ---- Prefixes / REX --------------------------------------------------------

    private static byte Rex(bool w = true, Reg? r = null, Reg? rm = null, bool b = false) => (byte)(0x40
        | (w ? 8 : 0)
        | ((int?)r >= 8 ? 4 : 0)
        | ((int?)rm >= 8 ? 1 : 0)
        | (b ? 1 : 0));

    private static byte ModRm(byte mod, Reg reg, Reg rm) =>
        (byte)((mod << 6) | (((int)reg & 7) << 3) | ((int)rm & 7));

    // ---- Moves -------------------------------------------------------------------

    public Asm MovRi(Reg dst, long imm)
    {
        // mov r/m64, imm32 sign-extended when it fits; otherwise mov r64, imm64.
        if (imm is >= 0 and <= int.MaxValue)
        {
            // C7 C0+rd id — imm32, no sign surprises for non-negative values.
            _code.Add((byte)(0x48 | ((int)dst >= 8 ? 1 : 0)));
            _code.Add(0xC7);
            _code.Add(ModRm(3, Reg.Rax, dst));
            Ddw((uint)imm);
        }
        else
        {
            // 48 B8+rq iq
            _code.Add((byte)(0x48 | ((int)dst >= 8 ? 1 : 0)));
            _code.Add((byte)(0xB8 + ((int)dst & 7)));
            Ddw2(imm);
        }
        return this;
    }

    /// <summary>Materializes a constant as two per-build terms instead of one
    /// literal: dst = (value XOR mask) XOR mask. The caller supplies a volatile
    /// scratch register whose prior value may be discarded.</summary>
    public Asm MovRiXorSplit(Reg dst, long value, Reg scratch, long mask)
    {
        if (dst == scratch)
            throw new ArgumentException("The XOR-split scratch register must differ from the destination.", nameof(scratch));

        MovRi(dst, value ^ mask);
        MovRi(scratch, mask);
        XorRr(dst, scratch);
        return this;
    }

    public Asm Mov32Ri(Reg dst, uint imm)
    {
        // B8+rd id — 32-bit mov, zero-extends into the full register.
        if (dst >= Reg.R8)
            _code.Add(0x41); // REX.B for high registers
        _code.Add((byte)(0xB8 + ((int)dst & 7)));
        Ddw(imm);
        return this;
    }

    public Asm MovRr(Reg dst, Reg src)
    {
        // Opcode 89 encodes the source in ModRM.reg and destination in
        // ModRM.r/m, so REX.R extends src and REX.B extends dst.
        _code.Add(Rex(r: src, rm: dst));
        _code.Add(0x89);
        _code.Add(ModRm(3, src, dst));
        return this;
    }

    /// <summary>mov reg, [reg + disp]</summary>
    public Asm MovRm(Reg dst, Reg srcBase, int disp = 0)
    {
        _code.Add(Rex(r: dst, rm: srcBase));
        _code.Add(0x8B);
        EmitModRmDisp(dst, srcBase, disp);
        return this;
    }

    /// <summary>mov [reg + disp], reg</summary>
    public Asm MovMr(Reg dstBase, Reg src, int disp = 0)
    {
        _code.Add(Rex(r: src, rm: dstBase));
        _code.Add(0x89);
        EmitModRmDisp(src, dstBase, disp);
        return this;
    }

    /// <summary>mov reg, byte [reg + disp]</summary>
    public Asm MovRm8(Reg dst, Reg srcBase, int disp = 0)
    {
        _code.Add(Rex(w: false, r: dst, rm: srcBase));
        _code.Add(0x8A);
        EmitModRmDisp(dst, srcBase, disp, byteWide: true);
        return this;
    }

    /// <summary>mov byte [reg + disp], reg</summary>
    public Asm MovMr8(Reg dstBase, Reg src, int disp = 0)
    {
        _code.Add(Rex(w: false, r: src, rm: dstBase));
        _code.Add(0x88);
        EmitModRmDisp(src, dstBase, disp, byteWide: true);
        return this;
    }

    /// <summary>mov reg, dword [reg + disp]</summary>
    public Asm MovRm32(Reg dst, Reg srcBase, int disp = 0)
    {
        _code.Add(Rex(w: false, r: dst, rm: srcBase));
        _code.Add(0x8B);
        EmitModRmDisp(dst, srcBase, disp);
        return this;
    }

    /// <summary>mov dword [reg + disp], reg</summary>
    public Asm MovMr32(Reg dstBase, Reg src, int disp = 0)
    {
        _code.Add(Rex(w: false, r: src, rm: dstBase));
        _code.Add(0x89);
        EmitModRmDisp(src, dstBase, disp);
        return this;
    }

    public Asm LeaRd(Reg dst, Reg srcBase, int disp)
    {
        _code.Add(Rex(r: dst, rm: srcBase));
        _code.Add(0x8D);
        EmitModRmDisp(dst, srcBase, disp);
        return this;
    }

    /// <summary>lea reg, [rip + label(+extra)] — the only data-addressing form stubs use.</summary>
    public Asm LeaRip(Reg dst, string label, int extra = 0)
    {
        _code.Add(Rex(r: dst));
        _code.Add(0x8D);
        _code.Add(ModRm(0, dst, Reg.Rbp)); // mod=00, rm=101 → RIP-relative
        _ripRefs.Add((_code.Count, label, extra));
        Ddw(0);
        return this;
    }

    /// <summary>mov reg, [rip + label(+extra)]</summary>
    public Asm MovRip(Reg dst, string label, int extra = 0)
    {
        _code.Add(Rex(r: dst));
        _code.Add(0x8B);
        _code.Add(ModRm(0, dst, Reg.Rbp));
        _ripRefs.Add((_code.Count, label, extra));
        Ddw(0);
        return this;
    }

    /// <summary>mov qword [rip + label], reg — store into blob-relative data.</summary>
    public Asm MovRipStore(Reg src, string label, int extra = 0)
    {
        _code.Add(Rex(r: src));
        _code.Add(0x89);
        _code.Add(ModRm(0, src, Reg.Rbp));
        _ripRefs.Add((_code.Count, label, extra));
        Ddw(0);
        return this;
    }

    private void EmitModRmDisp(Reg reg, Reg baseReg, int disp, bool byteWide = false)
    {
        // RSP/R12 need a SIB byte even without index.
        bool needsSib = baseReg is Reg.Rsp or Reg.R12;
        if (disp == 0 && !needsSib && baseReg is not Reg.Rbp && baseReg is not Reg.R13)
        {
            _code.Add(ModRm(0, reg, baseReg));
            return;
        }

        if (disp >= sbyte.MinValue && disp <= sbyte.MaxValue)
        {
            _code.Add(ModRm(1, reg, baseReg));
            if (needsSib) _code.Add(0x24); // SIB: base=rsp, no index
            _code.Add((byte)disp);
        }
        else
        {
            _code.Add(ModRm(2, reg, baseReg));
            if (needsSib) _code.Add(0x24);
            Ddw((uint)disp);
        }
    }

    // ---- Stack -----------------------------------------------------------------

    public Asm PushR(Reg r)
    {
        if (r >= Reg.R8) _code.Add(0x41);
        _code.Add((byte)(0x50 + ((int)r & 7)));
        return this;
    }

    public Asm PopR(Reg r)
    {
        if (r >= Reg.R8) _code.Add(0x41);
        _code.Add((byte)(0x58 + ((int)r & 7)));
        return this;
    }

    public Asm PushI32(int value)
    {
        _code.Add(0x68);
        Ddw((uint)value);
        return this;
    }

    public Asm SubRi(Reg reg, int imm)
    {
        _code.Add(Rex(rm: reg));
        _code.Add(0x81);
        _code.Add(ModRm(3, Reg.Rbp /* /5 */, reg));
        Ddw((uint)imm);
        return this;
    }

    public Asm AddRi(Reg reg, int imm)
    {
        _code.Add(Rex(rm: reg));
        _code.Add(0x81);
        _code.Add(ModRm(3, Reg.Rax /* /0 */, reg));
        Ddw((uint)imm);
        return this;
    }

    // ---- ALU ---------------------------------------------------------------------

    public Asm XorRr(Reg a, Reg b)
    {
        _code.Add(Rex(r: b, rm: a));
        _code.Add(0x31);
        _code.Add(ModRm(3, b, a));
        return this;
    }

    public Asm AddRr(Reg dst, Reg src)
    {
        _code.Add(Rex(r: src, rm: dst));
        _code.Add(0x01);
        _code.Add(ModRm(3, src, dst));
        return this;
    }

    public Asm SubRr(Reg dst, Reg src)
    {
        _code.Add(Rex(r: src, rm: dst));
        _code.Add(0x29);
        _code.Add(ModRm(3, src, dst));
        return this;
    }

    public Asm CmpRr(Reg a, Reg b)
    {
        _code.Add(Rex(r: b, rm: a));
        _code.Add(0x39);
        _code.Add(ModRm(3, b, a));
        return this;
    }

    public Asm AndRi(Reg reg, int imm)
    {
        if (imm >= sbyte.MinValue && imm <= sbyte.MaxValue)
        {
            _code.Add(Rex(rm: reg));
            _code.Add(0x83);
            _code.Add(ModRm(3, (Reg)4, reg)); // /4 = AND
            _code.Add((byte)imm);
        }
        else
        {
            _code.Add(Rex(rm: reg));
            _code.Add(0x81);
            _code.Add(ModRm(3, (Reg)4, reg));
            Ddw((uint)imm);
        }
        return this;
    }

    /// <summary>imul dst, src (two-operand, 64-bit).</summary>
    public Asm ImulRr(Reg dst, Reg src)
    {
        _code.Add(Rex(r: dst, rm: src));
        _code.Add(0x0F);
        _code.Add(0xAF);
        _code.Add(ModRm(3, dst, src));
        return this;
    }

    public Asm TestRr(Reg a, Reg b)
    {
        _code.Add(Rex(r: b, rm: a));
        _code.Add(0x85);
        _code.Add(ModRm(3, b, a));
        return this;
    }

    public Asm TestRi8(Reg r, byte mask)
    {
        if (r < Reg.R8)
        {
            _code.Add(0xF6);
            _code.Add(ModRm(3, Reg.Rax /* /0 */, r));
        }
        else
        {
            _code.Add(0x41);
            _code.Add(0xF6);
            _code.Add(ModRm(3, Reg.Rax, r));
        }
        _code.Add(mask);
        return this;
    }

    public Asm ShlRi(Reg r, int count) => Shift(r, count, 4);
    public Asm ShrRi(Reg r, int count) => Shift(r, count, 5);
    public Asm RolRi(Reg r, int count) => Shift(r, count, 0);

    private Asm Shift(Reg r, int count, int opExtension)
    {
        _code.Add(Rex(w: true, rm: r));
        _code.Add(0xC1);
        _code.Add(ModRm(3, (Reg)opExtension, r));
        _code.Add((byte)count);
        return this;
    }

    public Asm XchgRr(Reg a, Reg b)
    {
        _code.Add(Rex(r: a, rm: b));
        _code.Add(0x87);
        _code.Add(ModRm(3, a, b));
        return this;
    }

    public Asm IncR(Reg r)
    {
        _code.Add(Rex(w: true, rm: r));
        _code.Add(0xFF);
        _code.Add(ModRm(3, (Reg)0, r));
        return this;
    }

    public Asm DecR(Reg r)
    {
        _code.Add(Rex(w: true, rm: r));
        _code.Add(0xFF);
        _code.Add(ModRm(3, (Reg)1, r));
        return this;
    }

    public Asm Cdq() { _code.Add(0x99); return this; }
    public Asm XorEdx() { XorRr(Reg.Rdx, Reg.Rdx); return this; }

    // ---- Control flow ----------------------------------------------------------------

    public Asm Jmp(string label) { _code.Add(0xE9); _rel32.Add((_code.Count, label)); Ddw(0); return this; }

    public Asm JmpRva(uint blobRva, uint targetRva)
    {
        long nextRva = (long)blobRva + _code.Count + 5;
        long displacement = (long)targetRva - nextRva;
        if (displacement is < int.MinValue or > int.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(targetRva), "Direct jump target exceeds rel32 range.");
        _code.Add(0xE9);
        Ddw(unchecked((uint)(int)displacement));
        return this;
    }
    public Asm JmpShortSelf() { _code.Add(0xEB); _code.Add(0xFE); return this; } // pause loop

    public Asm Jcc(Cc cc, string label)
    {
        _code.Add(0x0F);
        _code.Add((byte)(0x80 + (int)cc));
        _rel32.Add((_code.Count, label));
        Ddw(0);
        return this;
    }

    /// <summary>Raw short jcc over the next N bytes (no label bookkeeping).</summary>
    public Asm JccShortOver(Cc cc, int bytes)
    {
        _code.Add((byte)(0x70 + (int)cc));
        _code.Add((byte)bytes);
        return this;
    }

    public Asm Call(string label) { _code.Add(0xE8); _rel32.Add((_code.Count, label)); Ddw(0); return this; }

    /// <summary>Direct rel32 call from a blob with a known image RVA to another
    /// image RVA. Unlike an indirect callback, this does not require a Guard CF
    /// function-table entry.</summary>
    public Asm CallRva(uint blobRva, uint targetRva)
    {
        long nextRva = (long)blobRva + _code.Count + 5;
        long displacement = (long)targetRva - nextRva;
        if (displacement is < int.MinValue or > int.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(targetRva), "Direct call target exceeds rel32 range.");
        _code.Add(0xE8);
        Ddw(unchecked((uint)(int)displacement));
        return this;
    }

    public Asm CallReg(Reg r)
    {
        _code.Add(Rex(rm: r));
        _code.Add(0xFF);
        _code.Add(ModRm(3, (Reg)2, r));
        return this;
    }

    /// <summary>call [reg + disp] — indirect through a table.</summary>
    public Asm CallMem(Reg baseReg, int disp = 0)
    {
        _code.Add(Rex(rm: baseReg));
        _code.Add(0xFF);
        EmitModRmDisp((Reg)2, baseReg, disp);
        return this;
    }

    /// <summary>call [rip + label] — indirect through blob-relative data (IAT slots).</summary>
    public Asm CallRip(string label, int extra = 0)
    {
        _code.Add(0xFF);
        _code.Add(ModRm(0, (Reg)2, Reg.Rbp));
        _ripRefs.Add((_code.Count, label, extra));
        Ddw(0);
        return this;
    }

    /// <summary>jmp [rip + label] — tail-jump through blob-relative data.</summary>
    public Asm JmpRip(string label, int extra = 0)
    {
        _code.Add(0xFF);
        _code.Add(ModRm(0, (Reg)4, Reg.Rbp));
        _ripRefs.Add((_code.Count, label, extra));
        Ddw(0);
        return this;
    }

    public Asm Ret() { _code.Add(0xC3); return this; }
    public Asm Int3() { _code.Add(0xCC); return this; }
    public Asm Ud2() { _code.Add(0x0F); _code.Add(0x0B); return this; }
    public Asm Nop(int count = 1)
    {
        for (int i = 0; i < count; i++)
            _code.Add(0x90);
        return this;
    }

    /// <summary>Multi-byte canonical NOP (0F 1F + modrm) for padding that does not
    /// decode as anything interesting.</summary>
    public Asm LongNop(int bytes)
    {
        while (bytes > 0)
        {
            if (bytes >= 9) { Db([0x66, 0x0F, 0x1F, 0x84, 0x00, 0, 0, 0, 0]); bytes -= 9; }
            else if (bytes >= 5) { Db([0x0F, 0x1F, 0x44, 0x00, 0x00]); bytes -= 5; }
            else if (bytes == 4) { Db([0x0F, 0x1F, 0x40, 0x00]); bytes -= 4; }
            else if (bytes == 3) { Db([0x0F, 0x1F, 0x00]); bytes -= 3; }
            else if (bytes == 2) { Db([0x66, 0x90]); bytes -= 2; }
            else { _code.Add(0x90); bytes--; }
        }
        return this;
    }

    // ---- Special instructions ------------------------------------------------------------

    public Asm Rdtsc() { _code.Add(0x0F); _code.Add(0x31); return this; }
    public Asm Cpuid() { _code.Add(0x0F); _code.Add(0xA2); return this; }

    /// <summary>Swaps GS-based PEB access result into reg: mov reg, gs:[0x60].</summary>
    public Asm MovRegPeb(Reg reg)
    {
        // 65 48 8B 04 25 60 00 00 00
        _code.Add(0x65);
        _code.Add(Rex(r: reg));
        _code.Add(0x8B);
        _code.Add(0x04);
        _code.Add(0x25);
        Ddw(0x60);
        return this;
    }

    /// <summary>Emits the classic runtime-base derivation: after this, reg holds
    /// the runtime image base (works under ASLR, no relocations needed).
    /// `ourRva` = RVA of this blob's start in the image. Position-aware: the
    /// subtracted constant is fixed up against the emitted position at assembly
    /// time, so this may be emitted anywhere in the blob.</summary>
    public Asm LoadRuntimeBase(Reg reg, uint ourRva)
    {
        // call $+5 ; pop reg ; reg -= RVA(next instruction)
        string anchor = $"__lrb_{_runtimeBaseAnchors.Count}";
        _code.Add(0xE8);
        Ddw(0);
        // CALL pushes the address immediately after its five-byte encoding.
        // Anchor that exact address before emitting POP; anchoring after POP
        // subtracts one or two extra bytes and produces base-1/base-2.
        Label(anchor);
        PopR(reg);
        // SubRi emits REX(1) + 0x81(1) + ModRm(1) before the imm32 — the fixup
        // position recorded here is the imm32 operand, three bytes past the
        // current end of code.
        _runtimeBaseAnchors.Add((_code.Count + 3, anchor, ourRva));
        SubRi(reg, 0); // imm32 patched at assembly time
        return this;
    }

    private readonly List<(int Pos, string Anchor, uint OurRva)> _runtimeBaseAnchors = [];

    // ---- Assembly -------------------------------------------------------------------

    /// <summary>Resolves labels and returns the final blob. All label references
    /// must resolve within this blob.</summary>
    public byte[] Assemble()
    {
        var result = _code.ToArray();
        foreach (var (pos, target) in _rel32)
        {
            if (!_labels.TryGetValue(target, out var to))
                throw new KeyNotFoundException($"Branch to undefined label '{target}'.");
            int rel = to - (pos + 4);
            BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(pos), rel);
        }
        foreach (var (pos, target, extra) in _ripRefs)
        {
            if (!_labels.TryGetValue(target, out var to))
                throw new KeyNotFoundException($"RIP-relative reference to undefined label '{target}'.");
            int disp = to + extra - (pos + 4);
            BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(pos), disp);
        }
        foreach (var (pos, anchor, ourRva) in _runtimeBaseAnchors)
        {
            // reg currently holds runtimeVA(label) = base + ourRva + labelOffset.
            int sub = (int)ourRva + _labels[anchor];
            BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(pos), sub);
        }
        return result;
    }

    /// <summary>RIP-relative fixup sites from the last Assemble(): blob-relative
    /// disp32 positions with their target labels. Lets callers re-point references
    /// at data that ultimately lands outside the blob (cross-section layout).</summary>
    public IReadOnlyList<(int Pos, string Target, int Extra)> RipFixups => _ripRefs;

    private void Ddw(uint value)
    {
        Span<byte> b = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(b, value);
        Db(b);
    }

    private void Ddw2(long value)
    {
        Span<byte> b = stackalloc byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(b, value);
        Db(b);
    }
}
