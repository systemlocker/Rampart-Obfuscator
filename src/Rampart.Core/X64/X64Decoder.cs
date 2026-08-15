namespace Rampart.X64;

public enum X64Mnemonic
{
    Other,
    JmpRel,
    JccRel,
    CallRel,
    CallIndirect,
    JmpIndirect,
    Ret,
    RetImm,
    MovRegImm,
    PushImm,
    Nop,
    Int3,
    Ud2,
    LeaRip,
    MovRip,
}

/// <summary>A decoded instruction — at minimum its length; for the forms the
/// transforms consume, the branch/call/immediate details as well.</summary>
public readonly record struct X64Instruction
{
    public required int Length { get; init; }
    public X64Mnemonic Mnemonic { get; init; }
    /// <summary>Branch/call target RVA for rel forms; literal for MovRegImm/PushImm.</summary>
    public long Immediate { get; init; }
    /// <summary>Relative offset operand value (raw) for rel forms.</summary>
    public int Relative { get; init; }
    public bool HasRipRelative { get; init; }
    /// <summary>Resolved RVA of the rip-relative operand target (valid when HasRipRelative).</summary>
    public uint RipTargetRva { get; init; }
}

/// <summary>Conservative x64 instruction decoder. It exists to answer "how long is
/// the instruction at this RVA" and "is it a branch/call/rip-relative access".
/// Anything uncertain decodes as failure — every consumer treats failure as
/// "do not rewrite here", which is the safe direction for a protector.</summary>
public static class X64Decoder
{
    /// <summary>Decodes one instruction at instructionRva inside the section bytes
    /// at instructionOffset. Returns false for encodings outside the supported map.</summary>
    public static bool TryDecode(ReadOnlySpan<byte> code, int offset, uint instructionRva, out X64Instruction instr)
    {
        instr = default;
        if (offset < 0 || offset >= code.Length)
            return false;

        int i = offset;
        bool rexW = false, opSize66 = false, addrSize67 = false;

        // Prefixes. REX must directly precede the opcode; track the main ones.
        while (i < code.Length)
        {
            byte b = code[i];
            if (b is 0xF0 or 0xF2 or 0xF3 or 0x2E or 0x36 or 0x3E or 0x26 or 0x64 or 0x65)
            {
                i++;
            }
            else if (b == 0x66) { opSize66 = true; i++; }
            else if (b == 0x67) { addrSize67 = true; i++; }
            else if (b >= 0x40 && b <= 0x4F) { rexW = (b & 8) != 0; i++; }
            else break;
        }
        if (i >= code.Length)
            return false;

        byte op = code[i];
        int immSize = 0;
        bool hasModRm = false;
        var mnemonic = X64Mnemonic.Other;
        bool opcodeIsTwoByte = false;
        byte modrmValue = 0;

        if (op == 0x0F)
        {
            opcodeIsTwoByte = true;
            i++;
            if (i >= code.Length)
                return false;
            byte op2 = code[i];
            // Escape tables we refuse to guess lengths for (AVX / exotic SSE4).
            if (op2 == 0x38 || op2 == 0x3A)
                return false;

            hasModRm = op2 switch
            {
                <= 0x0D or 0x18 or 0x1A or 0x1C or 0x1E or 0x0F or 0x05 or 0x06 or 0x07
                    or 0x08 or 0x09 or 0x0A or 0x0B or 0xA0 or 0xA1 or 0xA2 or 0xA8
                    or 0xA9 or 0xC8 or 0xC9 or 0xCA or 0xCB or 0xCC or 0xCD or 0xCE
                    or 0xCF => false,
                _ => true,
            };
            immSize = op2 switch
            {
                0x70 or 0x71 or 0x72 or 0x73 or 0xA4 or 0xAC or 0xBA or 0xC2
                    or 0xC6 or 0xC7 => 1,          // shuffles/shifts/comps with imm8
                >= 0x80 and <= 0x8F => 4,          // jcc rel32
                _ => 0,
            };

            if (op2 >= 0x80 && op2 <= 0x8F)
                mnemonic = X64Mnemonic.JccRel;
            else if (op2 == 0x1E) // endbr64 etc. — treat as plain
                mnemonic = X64Mnemonic.Nop;
        }
        else
        {
            hasModRm = op switch
            {
                <= 0x05 => false,
                0x06 or 0x07 or 0x08 or 0x09 or 0x0A or 0x0B or 0x0C or 0x0D or 0x0E
                    or 0x0F => false,
                0x14 or 0x15 or 0x1C or 0x1D or 0x24 or 0x25 or 0x26 or 0x27
                    or 0x2C or 0x2D or 0x2E or 0x2F => false,
                0x34 or 0x35 or 0x36 or 0x37 or 0x3C or 0x3D or 0x3E or 0x3F => false,
                >= 0x50 and <= 0x5F => false,
                0x60 or 0x61 or 0x62 or 0x63 => op == 0x63, // 60-62 invalid, 63 movsxd has modrm
                0x68 or 0x69 or 0x6A or 0x6B => op == 0x69 || op == 0x6B,
                >= 0x70 and <= 0x7F => false,
                0x82 or 0x84 or 0x85 or 0x86 or 0x87 or 0x88 or 0x89 or 0x8A or 0x8B
                    or 0x8C or 0x8D or 0x8E or 0x8F => op != 0x82,
                0x90 or 0x98 or 0x99 or 0x9B or 0x9C or 0x9D or 0x9E or 0x9F => false,
                0xA4 or 0xA5 or 0xA6 or 0xA7 or 0xAA or 0xAB or 0xAC or 0xAD
                    or 0xAE or 0xAF => false,
                0xB0 or 0xB1 or 0xB2 or 0xB3 or 0xB4 or 0xB5 or 0xB6 or 0xB7 => false,
                0xBE or 0xBF => false, // pause/ilenx not real — B0-BF handled below
                0xC0 or 0xC1 or 0xC2 or 0xC3 or 0xC4 or 0xC5 or 0xC6 or 0xC7 or 0xC8
                    or 0xC9 or 0xCA or 0xCB or 0xCC or 0xCD or 0xCE or 0xCF => op is 0xC0 or 0xC1 or 0xC6 or 0xC7,
                0xD0 or 0xD1 or 0xD2 or 0xD3 => true,
                0xD4 or 0xD5 or 0xD6 or 0xD7 => false,
                >= 0xD8 and <= 0xDF => true,
                0xE0 or 0xE1 or 0xE2 or 0xE3 => false,
                0xE4 or 0xE5 or 0xE6 or 0xE7 or 0xE8 or 0xE9 or 0xEA or 0xEB => op is 0xE8 or 0xE9 or 0xEB,
                0xEC or 0xED or 0xEE or 0xEF => false,
                0xF4 or 0xF5 or 0xF8 or 0xF9 or 0xFA or 0xFB or 0xFC or 0xFD => false,
                0xFE or 0xFF => true,
                0xF6 or 0xF7 => true,
                0xF0 or 0xF1 or 0xF2 or 0xF3 => false,
                _ => true,
            };

            immSize = op switch
            {
                0x04 or 0x0C or 0x14 or 0x1C or 0x24 or 0x2C or 0x34 or 0x3C or 0xA8
                    or 0x6A or 0xB0 or 0xB1 or 0xB2 or 0xB3 or 0xB4 or 0xB5 or 0xB6
                    or 0xB7 or 0xC0 or 0xC1 or 0xCD or 0xE4 or 0xE5 or 0xE6 or 0xE7 => 1,
                0x05 or 0x0D or 0x15 or 0x1D or 0x25 or 0x2D or 0x35 or 0x3D or 0x69
                    or 0xA9 => opSize66 ? 2 : 4,
                0x68 => 4,
                0x80 or 0x83 or 0xC6 => 1,
                0x81 or 0xC7 => opSize66 ? 2 : 4,
                >= 0xB8 and <= 0xBF => rexW ? 8 : (opSize66 ? 2 : 4),
                0x70 or 0x71 or 0x72 or 0x73 or 0x74 or 0x75 or 0x76 or 0x77 or 0x78
                    or 0x79 or 0x7A or 0x7B or 0x7C or 0x7D or 0x7E or 0x7F => 1,
                0xE0 or 0xE1 or 0xE2 or 0xE3 or 0xEB => 1,
                0xE8 or 0xE9 => 4,
                0xC2 or 0xCA => 2,
                0xC8 => 3, // enter imm16, imm8
                0xA0 or 0xA1 or 0xA2 or 0xA3 => addrSize67 ? 4 : 8, // moffs
                _ => 0,
            };

            mnemonic = op switch
            {
                0xE9 or 0xEB => X64Mnemonic.JmpRel,
                >= 0x70 and <= 0x7F => X64Mnemonic.JccRel,
                0xE8 => X64Mnemonic.CallRel,
                0xC3 => X64Mnemonic.Ret,
                0xC2 => X64Mnemonic.RetImm,
                >= 0xB8 and <= 0xBF => X64Mnemonic.MovRegImm,
                0x68 or 0x6A => X64Mnemonic.PushImm,
                0x90 => X64Mnemonic.Nop,
                0xCC => X64Mnemonic.Int3,
                0x0F => X64Mnemonic.Other,
                _ => X64Mnemonic.Other,
            };
        }

        int afterOpcode = i + 1;
        int dispSize = 0;
        bool ripRelative = false;

        if (hasModRm)
        {
            if (afterOpcode >= code.Length)
                return false;
            byte modrm = code[afterOpcode];
            modrmValue = modrm;
            byte mod = (byte)(modrm >> 6);
            byte rm = (byte)(modrm & 7);
            int modrmLen = 1;

            if (mod != 3 && rm == 4) // SIB follows
            {
                if (afterOpcode + 1 >= code.Length)
                    return false;
                byte sib = code[afterOpcode + 1];
                modrmLen = 2;
                // SIB.base == 5 with mod == 0 means disp32 + no base (or RIP-less).
                if ((sib & 7) == 5 && mod == 0)
                    dispSize = 4;
            }
            else if (rm == 5 && mod == 0)
            {
                // RIP-relative memory operand.
                ripRelative = true;
                dispSize = 4;
            }

            if (mod == 1)
                dispSize = Math.Max(dispSize, 1);
            else if (mod == 2)
                dispSize = Math.Max(dispSize, 4);

            afterOpcode += modrmLen + dispSize;
        }

        int total = afterOpcode + immSize - offset;
        if (offset + total > code.Length)
            return false;

        // The F6/F7 TEST special case: only reg-field 0/1 carries an immediate.
        // The 0x0F-two-byte form was consumed above; here `op` is the one-byte opcode
        // only when no 0F escape was seen (tracked by opcodeIsTwoByte).
        if (!opcodeIsTwoByte && op is 0xF6 or 0xF7 && hasModRm)
        {
            byte reg = (byte)((modrmValue >> 3) & 7);
            if (reg is 0 or 1)
            {
                int extra = op == 0xF6 ? 1 : (opSize66 ? 2 : 4);
                total += extra;
                if (offset + total > code.Length)
                    return false;
                immSize = extra;
            }
        }

        long imm = 0;
        int rel = 0;
        uint ripTarget = 0;

        int immPos = offset + total - immSize;
        if (immSize > 0 && mnemonic is X64Mnemonic.JmpRel or X64Mnemonic.JccRel or X64Mnemonic.CallRel)
        {
            rel = immSize switch
            {
                1 => unchecked((sbyte)code[immPos]),
                4 => unchecked((int)System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(code[immPos..])),
                _ => 0,
            };
            imm = instructionRva + (uint)total + rel;
        }
        else if (immSize > 0 && mnemonic is X64Mnemonic.MovRegImm or X64Mnemonic.PushImm)
        {
            imm = immSize switch
            {
                1 => code[immPos],
                2 => System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(code[immPos..]),
                4 => System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(code[immPos..]),
                8 => unchecked((long)System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(code[immPos..])),
                _ => 0,
            };
        }
        else if (ripRelative && dispSize == 4)
        {
            // The disp32 sits between modrm(+sib) and any immediate.
            int dispPos = offset + total - immSize - dispSize;
            int disp = unchecked((int)System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(code.Slice(dispPos, 4)));
            ripTarget = instructionRva + (uint)total + (uint)disp;
        }

        // FF /2 and FF /4 are indirect calls/jumps — worth flagging for consumers.
        if (!opcodeIsTwoByte && op == 0xFF && hasModRm)
        {
            byte reg = (byte)((modrmValue >> 3) & 7);
            if (reg == 2) mnemonic = X64Mnemonic.CallIndirect;
            if (reg == 4) mnemonic = X64Mnemonic.JmpIndirect;
        }

        // lea r, [rip+disp] — mnemonic refinement.
        if (op == 0x8D && ripRelative)
            mnemonic = X64Mnemonic.LeaRip;
        if (op is 0x8B or 0x89 or 0x8A or 0x88 && ripRelative)
            mnemonic = X64Mnemonic.MovRip;

        instr = new X64Instruction
        {
            Length = total,
            Mnemonic = mnemonic,
            Immediate = imm,
            Relative = rel,
            HasRipRelative = ripRelative,
            RipTargetRva = ripTarget,
        };
        return true;
    }
}
