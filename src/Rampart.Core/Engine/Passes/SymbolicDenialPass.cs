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
            byte[] gadget = BuildGadget(ctx.Rng);
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
}
