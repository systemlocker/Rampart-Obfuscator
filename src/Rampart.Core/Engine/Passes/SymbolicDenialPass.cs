using Rampart.Config;
using Rampart.Pe;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>
/// Emits a bounded set of cold nonlinear arithmetic gadgets. Symbolic engines
/// that elect to explore the decoys must model mixed multiplication, rotation,
/// shifts, and branches, but normal application execution never enters them.
/// </summary>
public sealed class SymbolicDenialPass
{
    internal const int LightGadgetCount = 48;
    internal const int GadgetSize = 128;
    internal const string SectionName = ".rsym";

    public void Run(BuildContext ctx)
    {
        ProtectionLevel level = ctx.Level("analysis.symbolic-denial");
        if (level == ProtectionLevel.Off)
            return;

        int byteCount = checked(LightGadgetCount * GadgetSize);
        PeImage.Section section = ctx.Pe.AddSection(
            SectionName,
            byteCount,
            SectionCharacteristics.CntCode
                | SectionCharacteristics.CntInitializedData
                | SectionCharacteristics.MemExecute
                | SectionCharacteristics.MemRead);

        for (int index = 0; index < LightGadgetCount; index++)
        {
            byte[] gadget = ctx.Pe.Machine == MachineType.I386
                ? BuildX86Gadget(ctx.Rng)
                : BuildGadget(ctx.Rng);
            if (gadget.Length != GadgetSize)
                throw new InvalidOperationException($"Symbolic gadget assembled to {gadget.Length} bytes, expected {GadgetSize}.");
            gadget.CopyTo(section.Data, index * GadgetSize);
        }

        ctx.Log.Add(new("symbolic-denial",
            $"added {LightGadgetCount} bounded cold nonlinear constraint gadgets (level {level})"));
    }

    private static byte[] BuildGadget(Random rng)
    {
        long xorMask = rng.NextInt64(1, int.MaxValue);
        long multiplier = rng.NextInt64(3, int.MaxValue) | 1;
        long addend = rng.NextInt64(1, int.MaxValue);

        var a = new Asm();
        a.PushR(Reg.Rbx);
        a.MovRr(Reg.Rbx, Reg.Rcx);       // symbolic input
        a.MovRi(Reg.Rdx, xorMask);
        a.XorRr(Reg.Rbx, Reg.Rdx);
        a.MovRi(Reg.Rax, multiplier);
        a.ImulRr(Reg.Rbx, Reg.Rax);
        a.MovRi(Reg.Rdx, addend);
        a.AddRr(Reg.Rbx, Reg.Rdx);
        a.MovRr(Reg.Rax, Reg.Rbx);
        a.ShrRi(Reg.Rax, 17);
        a.XorRr(Reg.Rbx, Reg.Rax);
        a.TestRi8(Reg.Rbx, 1);
        a.Jcc(Cc.E, "even");
        a.MovRr(Reg.Rax, Reg.Rbx);
        a.RolRi(Reg.Rax, 13);
        a.Jmp("done");
        a.Label("even");
        a.MovRr(Reg.Rax, Reg.Rbx);
        a.ShrRi(Reg.Rax, 7);
        a.XorRr(Reg.Rax, Reg.Rbx);
        a.Label("done");
        a.PopR(Reg.Rbx);
        a.Ret();
        a.Align(GadgetSize);
        return a.Assemble();
    }

    private static byte[] BuildX86Gadget(Random rng)
    {
        uint xorMask = unchecked((uint)rng.NextInt64(1, 1L << 32));
        uint multiplier = unchecked((uint)rng.NextInt64(3, 1L << 32)) | 1;
        uint addend = unchecked((uint)rng.NextInt64(1, 1L << 32));
        var code = new List<byte>(GadgetSize);

        void Dword(uint value)
        {
            code.Add((byte)value); code.Add((byte)(value >> 8));
            code.Add((byte)(value >> 16)); code.Add((byte)(value >> 24));
        }

        code.Add(0x53);                                      // push ebx
        code.AddRange([0x8B, 0x5C, 0x24, 0x08]);             // mov ebx,[esp+8]
        code.AddRange([0x81, 0xF3]); Dword(xorMask);          // xor ebx,imm32
        code.AddRange([0x69, 0xDB]); Dword(multiplier);       // imul ebx,ebx,imm32
        code.AddRange([0x81, 0xC3]); Dword(addend);           // add ebx,imm32
        code.AddRange([0x8B, 0xC3, 0xC1, 0xE8, 0x11]);       // mov eax,ebx; shr eax,17
        code.AddRange([0x31, 0xC3, 0xF6, 0xC3, 0x01]);       // xor ebx,eax; test bl,1
        code.AddRange([0x74, 0x07]);                         // jz even
        code.AddRange([0x8B, 0xC3, 0xC1, 0xC0, 0x0D]);       // mov eax,ebx; rol eax,13
        code.AddRange([0xEB, 0x07]);                         // jmp done
        code.AddRange([0x8B, 0xC3, 0xC1, 0xE8, 0x07]);       // even: mov eax,ebx; shr eax,7
        code.AddRange([0x31, 0xD8]);                         // xor eax,ebx
        code.AddRange([0x5B, 0xC3]);                         // done: pop ebx; ret
        while (code.Count < GadgetSize) code.Add(0x90);
        return code.ToArray();
    }
}
