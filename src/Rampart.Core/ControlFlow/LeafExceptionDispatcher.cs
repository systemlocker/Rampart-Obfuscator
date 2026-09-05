using Rampart.X64;

namespace Rampart.ControlFlow;

/// <summary>An image-relative exception site and its verified continuation targets.</summary>
public sealed record ImageExceptionTransition(uint FaultRva, uint TakenRva, uint FallthroughRva, int Condition);

/// <summary>Windows AMD64 CONTEXT dispatcher for exact, application-owned UD2 sites.</summary>
public static class LeafExceptionDispatcher
{
    public const uint ExceptionCode = 0xC000001D;
    public const int ContextFlagsOffset = 0x44;
    public const int ContextRipOffset = 0xF8;

    public static byte[] Compile(uint selfRva, IReadOnlyList<ImageExceptionTransition> sites)
    {
        if (sites.Count is < 1 or > 1024 || sites.Select(s => s.FaultRva).Distinct().Count() != sites.Count
            || sites.Any(s => s.Condition is < 0 or > 16))
            throw new ArgumentException("Requires 1..1024 unique, verified exception sites.", nameof(sites));
        var a = new Asm();
        // The handler changes only RIP in the OS-provided context. It is itself
        // a leaf: no stack changes, calls, locks, allocation, or mutable globals.
        a.TestRr(Reg.Rcx, Reg.Rcx).Jcc(Cc.E, "search");
        a.MovRm(Reg.Rdx, Reg.Rcx).MovRm(Reg.R8, Reg.Rcx, 8);
        a.TestRr(Reg.Rdx, Reg.Rdx).Jcc(Cc.E, "search");
        a.TestRr(Reg.R8, Reg.R8).Jcc(Cc.E, "search");
        a.MovRm32(Reg.Rax, Reg.Rdx).Mov32Ri(Reg.R11, ExceptionCode).CmpRr(Reg.Rax, Reg.R11).Jcc(Cc.Ne, "search");
        a.MovRm32(Reg.Rax, Reg.Rdx, 4).AndRi(Reg.Rax, 1).Jcc(Cc.Ne, "search");
        a.MovRm(Reg.Rdx, Reg.Rdx, 16).MovRm(Reg.Rax, Reg.R8, ContextRipOffset);
        a.CmpRr(Reg.Rdx, Reg.Rax).Jcc(Cc.Ne, "search");
        a.Label("anchor").LeaRip(Reg.R10, "anchor");
        a.Mov32Ri(Reg.R11, checked(selfRva + (uint)a.LabelOffset("anchor"))).SubRr(Reg.R10, Reg.R11);
        a.LeaRip(Reg.R9, "sites").Mov32Ri(Reg.Rcx, (uint)sites.Count);
        a.Label("scan");
        a.MovRm32(Reg.R11, Reg.R9).AddRr(Reg.R11, Reg.R10).CmpRr(Reg.R11, Reg.Rdx).Jcc(Cc.E, "found");
        a.AddRi(Reg.R9, 16).DecR(Reg.Rcx).Jcc(Cc.Ne, "scan").Jmp("search");
        a.Label("found");
        a.MovRm32(Reg.Rdx, Reg.R9, 12);
        a.Mov32Ri(Reg.Rax, 16).CmpRr(Reg.Rdx, Reg.Rax).Jcc(Cc.E, "taken");
        foreach (int condition in Enumerable.Range(0, 16))
            a.Mov32Ri(Reg.Rax, (uint)condition).CmpRr(Reg.Rdx, Reg.Rax).Jcc(Cc.E, $"condition_{condition}");
        a.Jmp("search");
        for (int condition = 0; condition < 16; condition++)
        {
            a.Label($"condition_{condition}").MovRm32(Reg.Rax, Reg.R8, ContextFlagsOffset);
            bool whenNonzero = (condition & 1) == 0;
            int mask = (condition / 2) switch { 0 => 0x800, 1 => 1, 2 => 0x40, 3 => 0x41, 4 => 0x80, 5 => 4, _ => 0x80 };
            if (condition >= 12)
            {
                // Signed comparisons use SF XOR OF, optionally ORed with ZF.
                // Preserve ZF separately; shifting OF would otherwise mix DF
                // into that bit when XORing the full flags value.
                a.MovRr(Reg.R11, Reg.Rax).AndRi(Reg.R11, 0x40);
                a.MovRr(Reg.Rdx, Reg.Rax).ShrRi(Reg.Rdx, 4).XorRr(Reg.Rax, Reg.Rdx).AndRi(Reg.Rax, 0x80);
                if (condition >= 14) { a.Db(0x4C, 0x09, 0xD8); mask = 0xC0; } // or rax,r11
            }
            a.AndRi(Reg.Rax, mask).Jcc(whenNonzero ? Cc.Ne : Cc.E, "taken").Jmp("fallthrough");
        }
        a.Label("taken").MovRm32(Reg.Rax, Reg.R9, 4).Jmp("resume");
        a.Label("fallthrough").MovRm32(Reg.Rax, Reg.R9, 8);
        a.Label("resume").AddRr(Reg.Rax, Reg.R10).MovMr(Reg.R8, Reg.Rax, ContextRipOffset);
        a.Mov32Ri(Reg.Rax, uint.MaxValue).Ret(); // LONG EXCEPTION_CONTINUE_EXECUTION
        a.Label("search").Mov32Ri(Reg.Rax, 0).Ret();
        a.Align(8).Label("sites");
        foreach (var site in sites)
            a.Dd(site.FaultRva).Dd(site.TakenRva).Dd(site.FallthroughRva).Dd((uint)site.Condition);
        return a.Assemble();
    }
}
