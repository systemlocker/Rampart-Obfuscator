using Rampart.X64;

namespace Rampart.Imports;

/// <summary>Emits a PE32+ named-export lookup for a Windows-loader-owned module.
/// The hash selects names, exact comparison makes collisions harmless, and
/// GetProcAddress performs final binding (including forwarders and CFG exports).</summary>
public static class ExportHashResolver
{
    public static ulong Hash(string name, ulong seed)
    {
        ulong hash = seed;
        foreach (char character in name)
        {
            if (character is '\0' or > '\x7F')
                throw new ArgumentException("Export names must be non-null ASCII.", nameof(name));
            hash = unchecked(((hash << 7) | (hash >> 57)) ^ character);
        }
        return hash;
    }

    /// <summary>Windows x64 ABI: RCX=loaded HMODULE, RDX=expected ASCII name,
    /// R8=build hash, R9=GetProcAddress pointer. Returns address or null. No IAT
    /// value is passed to this resolver, so success is independent of the IAT.</summary>
    public static byte[] Emit(ulong seed)
    {
        var a = new Asm();
        Reg[] saved = [Reg.Rbx, Reg.Rbp, Reg.Rsi, Reg.Rdi, Reg.R12, Reg.R13, Reg.R14, Reg.R15];
        foreach (Reg reg in saved) a.PushR(reg);
        a.MovRr(Reg.Rbx, Reg.Rcx);
        a.MovRr(Reg.R12, Reg.Rdx);
        a.MovRr(Reg.R13, Reg.R8);
        a.MovRr(Reg.R14, Reg.R9);
        a.TestRr(Reg.Rbx, Reg.Rbx); a.Jcc(Cc.E, "fail");
        // The input is a real loader-mapped image, not an arbitrary byte buffer.
        // Bounds below reject absent/invalid export arrays and unterminated names.
        a.MovRm32(Reg.Rax, Reg.Rbx, 0x3C);
        a.MovRi(Reg.Rdx, 0x100000); a.CmpRr(Reg.Rax, Reg.Rdx); a.Jcc(Cc.A, "fail");
        a.AddRr(Reg.Rax, Reg.Rbx);
        a.MovRm32(Reg.R15, Reg.Rax, 0x50); // NT header + OptionalHeader.SizeOfImage
        a.MovRm32(Reg.Rdx, Reg.Rax, 0x88); // PE32+ export directory RVA
        a.TestRr(Reg.Rdx, Reg.Rdx); a.Jcc(Cc.E, "fail");
        a.MovRr(Reg.Rax, Reg.Rdx); a.AddRi(Reg.Rax, 40);
        a.CmpRr(Reg.Rax, Reg.R15); a.Jcc(Cc.A, "fail");
        a.AddRr(Reg.Rdx, Reg.Rbx);
        a.MovRm32(Reg.Rdi, Reg.Rdx, 24); // NumberOfNames
        a.MovRm32(Reg.Rsi, Reg.Rdx, 32); // AddressOfNames
        a.MovRr(Reg.Rax, Reg.Rdi); a.ShlRi(Reg.Rax, 2); a.AddRr(Reg.Rax, Reg.Rsi);
        a.CmpRr(Reg.Rax, Reg.R15); a.Jcc(Cc.A, "fail");
        a.AddRr(Reg.Rsi, Reg.Rbx);
        a.AddRr(Reg.R15, Reg.Rbx); // exclusive image end
        a.Label("next");
        a.TestRr(Reg.Rdi, Reg.Rdi); a.Jcc(Cc.E, "fail");
        a.MovRm32(Reg.Rbp, Reg.Rsi);
        a.AddRr(Reg.Rbp, Reg.Rbx);
        a.MovRr(Reg.Rdx, Reg.Rbp);
        a.MovRi(Reg.Rax, unchecked((long)seed));
        a.Label("hash");
        a.CmpRr(Reg.Rdx, Reg.R15); a.Jcc(Cc.Ae, "fail");
        ByteLoad(a, Reg.Rcx, Reg.Rdx);
        a.TestRr(Reg.Rcx, Reg.Rcx); a.Jcc(Cc.E, "hashed");
        a.RolRi(Reg.Rax, 7); a.XorRr(Reg.Rax, Reg.Rcx);
        a.IncR(Reg.Rdx); a.Jmp("hash");
        a.Label("hashed");
        a.CmpRr(Reg.Rax, Reg.R13); a.Jcc(Cc.Ne, "advance");
        a.MovRr(Reg.Rdx, Reg.Rbp);
        a.MovRr(Reg.R8, Reg.R12);
        a.Label("compare");
        // Hash equality never chooses an export by itself. Even an intentional
        // collision is checked against the retained exact import name.
        ByteLoad(a, Reg.Rcx, Reg.Rdx); ByteLoad(a, Reg.Rax, Reg.R8);
        a.CmpRr(Reg.Rax, Reg.Rcx); a.Jcc(Cc.Ne, "advance");
        a.TestRr(Reg.Rax, Reg.Rax); a.Jcc(Cc.E, "found");
        a.IncR(Reg.Rdx); a.IncR(Reg.R8); a.Jmp("compare");
        a.Label("advance");
        a.AddRi(Reg.Rsi, 4); a.DecR(Reg.Rdi); a.Jmp("next");
        a.Label("found");
        a.MovRr(Reg.Rcx, Reg.Rbx); a.MovRr(Reg.Rdx, Reg.Rbp); a.MovRr(Reg.Rax, Reg.R14);
        foreach (Reg reg in saved.Reverse()) a.PopR(reg);
        // Tail-call the documented resolver with the caller's shadow space.
        // Parsing or loading forwarder modules here would violate loader-lock
        // constraints and could bypass CFG's export-suppression bookkeeping.
        a.Db(0xFF, 0xE0); // jmp rax
        a.Label("fail");
        a.XorRr(Reg.Rax, Reg.Rax);
        foreach (Reg reg in saved.Reverse()) a.PopR(reg);
        a.Ret();
        return a.Assemble();
    }

    private static void ByteLoad(Asm a, Reg destination, Reg source)
    {
        // MOVZX r64, byte [base+0]; the displacement form also handles RBP/R13.
        a.Db((byte)(0x48 | ((int)destination >= 8 ? 4 : 0) | ((int)source >= 8 ? 1 : 0)),
            0x0F, 0xB6, (byte)(0x40 | (((int)destination & 7) << 3) | ((int)source & 7)));
        if (source is Reg.Rsp or Reg.R12) a.Db(0x24);
        a.Db(0);
    }
}
