using Rampart.Engine;
using Rampart.X64;

namespace Rampart.Packing;

/// <summary>Bounds-checked, position-independent LZSS initialization code. Only
/// volatile integer registers are touched, so the emitted routine is an x64 leaf.</summary>
public static class LzssDecoderEmitter
{
    public static byte[] Emit(uint selfRva, uint inputRva, int inputLength,
        uint outputRva, int outputLength)
    {
        if (inputLength < 8 || outputLength < 0 || outputLength > 256 * 1024 * 1024)
            throw new ArgumentOutOfRangeException(nameof(inputLength));
        uint inputEnd = checked(inputRva + (uint)inputLength);
        uint outputEnd = checked(outputRva + (uint)outputLength);
        var a = new Asm();
        a.LeaRip(Reg.Rcx, "input");
        a.MovRm(Reg.Rax, Reg.Rcx);
        a.MovRi(Reg.R11, outputLength);
        a.CmpRr(Reg.Rax, Reg.R11);
        a.Jcc(Cc.Ne, "invalid");
        a.AddRi(Reg.Rcx, 8);
        a.LeaRip(Reg.R8, "output");
        a.MovRr(Reg.R9, Reg.R8);
        a.LeaRip(Reg.R10, "output_end");
        a.MovRi(Reg.Rdx, 1); // Sentinel: 1 means the previous flag group is exhausted.

        a.Label("next");
        a.CmpRr(Reg.R8, Reg.R10);
        a.Jcc(Cc.Ae, "done");
        a.MovRi(Reg.Rax, 1);
        a.CmpRr(Reg.Rdx, Reg.Rax);
        a.Jcc(Cc.Ne, "token");
        RequireInput(1);
        a.Mov32Ri(Reg.Rdx, 0);
        a.MovRm8(Reg.Rdx, Reg.Rcx);
        a.AddRi(Reg.Rdx, 256); // A ninth bit keeps leading-zero flag groups distinguishable.
        a.IncR(Reg.Rcx);
        a.Label("token");
        a.TestRi8(Reg.Rdx, 1);
        a.Jcc(Cc.Ne, "match");
        RequireInput(1);
        a.MovRm8(Reg.Rax, Reg.Rcx);
        a.MovMr8(Reg.R8, Reg.Rax);
        a.IncR(Reg.Rcx);
        a.IncR(Reg.R8);
        a.ShrRi(Reg.Rdx, 1);
        a.Jmp("next");

        a.Label("match");
        RequireInput(2);
        // Two byte loads avoid any unaligned read crossing the checked input end.
        a.Mov32Ri(Reg.Rax, 0);
        a.MovRm8(Reg.Rax, Reg.Rcx, 1);
        a.ShlRi(Reg.Rax, 8);
        a.MovRm8(Reg.Rax, Reg.Rcx);
        a.AddRi(Reg.Rcx, 2);
        a.MovRr(Reg.R11, Reg.Rax);
        a.AndRi(Reg.R11, 0xFFF);
        a.IncR(Reg.R11);
        a.ShrRi(Reg.Rax, 12);
        a.AddRi(Reg.Rax, 3);
        a.ShlRi(Reg.Rax, 16);
        // Keep the bounded match count above the flag bits; this avoids a stack
        // frame or nonvolatile scratch register and therefore needs no unwind entry.
        a.AddRr(Reg.Rdx, Reg.Rax);
        a.MovRr(Reg.Rax, Reg.R8);
        a.SubRr(Reg.Rax, Reg.R9);
        a.CmpRr(Reg.R11, Reg.Rax);
        a.Jcc(Cc.A, "invalid");
        a.MovRr(Reg.Rax, Reg.R8);
        a.SubRr(Reg.Rax, Reg.R11);
        a.MovRr(Reg.R11, Reg.Rax);
        a.Label("copy");
        a.CmpRr(Reg.R8, Reg.R10);
        a.Jcc(Cc.Ae, "invalid"); // The encoder never emits a match beyond its output length.
        a.MovRm8(Reg.Rax, Reg.R11);
        a.MovMr8(Reg.R8, Reg.Rax);
        a.IncR(Reg.R11);
        a.IncR(Reg.R8);
        a.SubRi(Reg.Rdx, 0x10000);
        a.MovRi(Reg.Rax, 0x10000);
        a.CmpRr(Reg.Rdx, Reg.Rax);
        a.Jcc(Cc.Ae, "copy");
        a.ShrRi(Reg.Rdx, 1);
        a.Jmp("next");
        a.Label("done");
        a.LeaRip(Reg.Rax, "input_end");
        a.CmpRr(Reg.Rcx, Reg.Rax);
        a.Jcc(Cc.Ne, "invalid");
        a.Mov32Ri(Reg.Rax, 1);
        a.Ret();
        a.Label("invalid");
        // Corrupt startup data must never reach the application in a partially
        // restored state. FAST_FAIL_FATAL_APP_EXIT terminates only this process.
        a.Mov32Ri(Reg.Rcx, 7);
        a.Db(0xCD, 0x29);
        a.Ud2();
        foreach (string label in new[] { "input", "input_end", "output", "output_end" })
            a.Label(label);
        byte[] code = a.Assemble();
        BuildContext.PatchRipReferences(code, a, selfRva, new Dictionary<string, uint>
        {
            ["input"] = inputRva,
            ["input_end"] = inputEnd,
            ["output"] = outputRva,
            ["output_end"] = outputEnd,
        });
        return code;

        void RequireInput(int count)
        {
            a.LeaRip(Reg.Rax, "input_end", -count);
            a.CmpRr(Reg.Rcx, Reg.Rax);
            a.Jcc(Cc.A, "invalid");
        }
    }
}
