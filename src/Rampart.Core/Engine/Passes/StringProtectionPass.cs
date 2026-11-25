using System.Buffers.Binary;
using Rampart.Pe;
using Rampart.Strings;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>String protection. Strings stay at their original RVAs but ship
/// encrypted with per-string keys derived from the build seed; a registered init
/// routine decrypts them in place before the entry point runs. Coverage tuning
/// decides which strings qualify.</summary>
public sealed class StringProtectionPass
{
    private const ulong RollingMultiplier = 0x9E3779B97F4A7C15UL;

    private sealed record EncString(uint Rva, int Length, ulong Key1, ulong Key2);
    private readonly List<uint> _initializers = [];
    public IReadOnlyList<uint> Initializers => _initializers;

    public void Run(BuildContext ctx)
    {
        _initializers.Clear();
        var level = ctx.MaximumFunctionLevel("strings.encryption");
        if (level == Config.ProtectionLevel.Off)
            return;
        if (ctx.Pe.SectionAlignment < 4096)
        {
            ctx.Log.Add(new("strings", "skipped: shared section pages cannot safely change string page permissions"));
            return;
        }
        if (!ctx.Pe.Directory(DataDir.Tls).IsEmpty && PeCompatibility.Inspect(ctx.Pe).GuardCf)
        {
            ctx.Log.Add(new("strings", "skipped: existing Guard CF TLS callbacks run before entry-point string initialization"));
            return;
        }

        var chosen = StringCandidates.Find(ctx);

        if (chosen.Count == 0)
        {
            ctx.Log.Add(new("strings", "no qualifying strings found"));
            return;
        }

        // Emit one decryptor per effective level so a Light function does not
        // silently inherit Balanced encryption merely because another region
        // asked for it.
        int encrypted = 0;
        int decryptors = 0;
        int guarded = 0;
        bool taint = ctx.Level("response.silent-taint") != Config.ProtectionLevel.Off;
        RuntimeDetectionStateLayout? state = taint || chosen.Any(item => item.Integrity != Config.ProtectionLevel.Off)
            ? RuntimeDetectionState.Ensure(ctx) : null;
        uint protectIat = ImportDirectoryEditor.EnsureNamedImports(ctx, "KERNEL32.dll", "VirtualProtect")["VirtualProtect"];
        foreach (var levelGroup in chosen.GroupBy(item => (item.Encryption, Guard: item.Integrity != Config.ProtectionLevel.Off)))
        {
            bool rolling = levelGroup.Key.Encryption >= Config.ProtectionLevel.Balanced;
            var table = new List<EncString>();
            foreach (StringCandidate item in levelGroup)
            {
                ulong k1 = ((ulong)ctx.Rng.NextInt64()) | 1;
                ulong k2 = ((ulong)ctx.Rng.NextInt64()) | 1;
                EncryptAt(ctx, item.Rva, item.Length, k1, k2, rolling);
                table.Add(new EncString(item.Rva, item.Length, k1, k2));
                foreach (FunctionDescriptor owner in item.Owners)
                {
                    ctx.MarkApplied(owner, "strings.encryption", item.Encryption);
                    ctx.MarkApplied(owner, "strings.coverage", item.Coverage);
                    if (item.Integrity != Config.ProtectionLevel.Off)
                        ctx.MarkApplied(owner, "strings.anti-instrumentation",
                            Config.ProtectionLevel.Light);
                }
            }

            uint initRva = EmitDecryptor(ctx, table, rolling, levelGroup.Key.Guard, taint, state, protectIat);
            _initializers.Add(initRva);
            ctx.RegisterInit(initRva,
                $"string decryptor ({table.Count} strings, {levelGroup.Key.Encryption})");
            if (levelGroup.Key.Guard) guarded++;
            encrypted += table.Count;
            decryptors++;
        }

        ctx.Log.Add(new("strings",
            $"encrypted {encrypted} strings in place with {decryptors} scoped decryptor(s)" +
            $" ({chosen.Count(item => item.UnitSize == 2)} UTF-16LE), {guarded} checked decryptor/table pair(s)" +
            (taint ? "; startup keys bound to shared session state" : "")));
        if (ctx.MaximumFunctionLevel("code-transformation.mba-constants") != Config.ProtectionLevel.Off)
            ctx.MarkApplied("code-transformation.mba-constants", Config.ProtectionLevel.Light);
    }


    /// <summary>Build-side encryption. Per byte i:
    /// b ^= low byte of rol64(k1, 8*i); and (rolling layer)
    /// b ^= low byte of (state >> 29) where state = state * P + i.</summary>
    internal static void EncryptAt(BuildContext ctx, uint rva, int len, ulong k1, ulong k2, bool rolling)
    {
        var pe = ctx.Pe;
        int off = pe.RvaToOffset(rva);
        var sec = pe.SectionFromRva(rva)!;
        int start = off - (int)sec.PointerToRawData;
        ulong rot = k1;
        ulong state = k2;
        for (int i = 0; i < len; i++)
        {
            byte b = sec.Data[start + i];
            b ^= (byte)rot;
            rot = (rot << 8) | (rot >> 56);
            if (rolling)
            {
                state = state * RollingMultiplier + (ulong)i;
                b ^= (byte)(state >> 29);
            }
            sec.Data[start + i] = b;
        }
    }

    /// <summary>Emits the init routine that reverses the encryption in place.
    ///
    /// Register plan: rbx = table cursor, r15 = runtime image base, rbp = target
    /// byte pointer, r12 = bytes remaining, rsi = currently writable 4KB page VA
    /// (0 if none), edi = saved flOldProtect of rsi, r8 = rotated key (advance
    /// with rol 8), r9 = current key byte, rdx = rolling state (Balanced+),
    /// r10 = byte index (Balanced+), r11 = P (Balanced+), r14 = table mask,
    /// rcx = data byte (only CL is stored).
    ///
    /// Page protections are coalesced across consecutive strings on the same 4KB
    /// page and handled page-by-page across page boundaries so each page restores
    /// its own original protection with at most 2 VirtualProtect calls per page.</summary>
    private static uint EmitDecryptor(BuildContext ctx, List<EncString> table, bool rolling,
        bool integrity, bool taint, RuntimeDetectionStateLayout? state, uint protectIat)
    {
        ulong mask = (ulong)ctx.Rng.NextInt64() | 0x1;
        bool splitConstants = ctx.MaximumFunctionLevel("code-transformation.mba-constants") != Config.ProtectionLevel.Off;
        long maskSplit = ctx.Rng.NextInt64() | 1;
        long multiplierSplit = ctx.Rng.NextInt64() | 1;
        var blob = new byte[table.Count * 32 + 32]; // + terminator qwords
        for (int i = 0; i < table.Count; i++)
        {
            var e = table[i];
            BinaryPrimitives.WriteUInt64LittleEndian(blob.AsSpan(i * 32), e.Rva ^ mask);
            BinaryPrimitives.WriteUInt64LittleEndian(blob.AsSpan(i * 32 + 8), (ulong)e.Length ^ mask);
            BinaryPrimitives.WriteUInt64LittleEndian(blob.AsSpan(i * 32 + 16),
                e.Key1 ^ mask ^ (taint ? state!.InitialSessionKey : 0));
            BinaryPrimitives.WriteUInt64LittleEndian(blob.AsSpan(i * 32 + 24), e.Key2 ^ mask);
        }
        // The reader XOR-unmasks before checking for zero, so the encoded zero
        // terminator is the mask itself rather than eight raw zero bytes.
        BinaryPrimitives.WriteUInt64LittleEndian(blob.AsSpan(table.Count * 32), mask);
        ulong checksum = 14695981039346656037UL;
        foreach (byte value in blob) checksum = unchecked((checksum ^ value) * 1099511628211UL);
        if (integrity) RuntimeDetectionState.Enable(ctx, RuntimeDetectionKind.SentinelModified);

        AntiDebugPass.BuiltRoutine Build(uint selfRva, ulong bodyChecksum)
        {
            var a = new Asm();
            // Eight nonvolatile saves leave RSP 8 mod 16; subtracting 0x48 bytes
            // restores 16-byte alignment and provides shadow space (0x00..0x1F)
            // plus local slots: +0x20 oldProtect, +0x24 scratch, +0x28 saved R8,
            // +0x30 saved RDX, +0x38 saved R10, +0x40 saved nextPage.
            var pushes = new List<(Reg, byte)>();
            foreach (Reg reg in new[] { Reg.Rbx, Reg.Rbp, Reg.Rsi, Reg.Rdi, Reg.R12, Reg.R13, Reg.R14, Reg.R15 })
            {
                a.PushR(reg);
                pushes.Add((reg, (byte)a.Position));
            }
            a.SubRi(Reg.Rsp, 0x48);
            byte prologEnd = (byte)a.Position;
            a.LoadRuntimeBase(Reg.R15, selfRva);       // r15 = runtime image base
            if (state is not null) a.MovRi(Reg.R13, state.Rva).AddRr(Reg.R13, Reg.R15);
            if (integrity)
            {
                // Fixed bounds come from emitted code, never from the untrusted
                // table. Check every byte (including the terminator) BEFORE any
                // record can supply a pointer or length to VirtualProtect.
                a.LeaRip(Reg.Rbx, "tbl").MovRi(Reg.R12, blob.Length);
                a.MovRi(Reg.Rax, unchecked((long)14695981039346656037UL));
                a.MovRi(Reg.Rdx, 1099511628211L);
                a.Label("integrity_loop").XorRr(Reg.Rcx, Reg.Rcx).MovRm8(Reg.Rcx, Reg.Rbx);
                a.XorRr(Reg.Rax, Reg.Rcx).ImulRr(Reg.Rax, Reg.Rdx);
                a.IncR(Reg.Rbx).DecR(Reg.R12).Jcc(Cc.Ne, "integrity_loop");
                a.MovRi(Reg.Rcx, unchecked((long)checksum)).CmpRr(Reg.Rax, Reg.Rcx).Jcc(Cc.Ne, "integrity_failed");
                // Also check the instruction bytes about to decrypt the data.
                // The checker and its expected digest are outside this range;
                // this is a startup modification check, not self-authentication.
                a.LeaRip(Reg.Rbx, "body_start").LeaRip(Reg.R12, "body_end").SubRr(Reg.R12, Reg.Rbx);
                a.MovRi(Reg.Rax, unchecked((long)14695981039346656037UL));
                a.Label("code_integrity_loop").XorRr(Reg.Rcx, Reg.Rcx).MovRm8(Reg.Rcx, Reg.Rbx);
                a.XorRr(Reg.Rax, Reg.Rcx).ImulRr(Reg.Rax, Reg.Rdx);
                a.IncR(Reg.Rbx).DecR(Reg.R12).Jcc(Cc.Ne, "code_integrity_loop");
                // Force imm64 width even for the zero layout placeholder; a
                // short immediate would change the later table alignment.
                a.Db(0x48, 0xB9).Dq(bodyChecksum).CmpRr(Reg.Rax, Reg.Rcx).Jcc(Cc.E, "integrity_ok");
                a.Label("integrity_failed");
                RuntimeDetectionState.EmitRecord(a, Reg.R13, RuntimeDetectionKind.SentinelModified,
                    taintSession: taint, taintConstant: 0x517CC1B727220A95UL, labelPrefix: "string_integrity");
                a.Jmp("done");
                a.Label("integrity_ok");
            }

            a.Label("body_start");
            if (splitConstants)
                a.MovRiXorSplit(Reg.R14, unchecked((long)mask), Reg.Rax, maskSplit);
            else
                a.MovRi(Reg.R14, unchecked((long)mask));
            if (rolling)
            {
                if (splitConstants)
                    a.MovRiXorSplit(Reg.R11, unchecked((long)RollingMultiplier), Reg.Rcx, multiplierSplit);
                else
                    a.MovRi(Reg.R11, unchecked((long)RollingMultiplier));
            }
            a.XorRr(Reg.Rsi, Reg.Rsi);                 // curPage = 0 (no page unprotected yet)
            a.XorRr(Reg.Rdi, Reg.Rdi);                 // curOldProtect = 0
            a.LeaRip(Reg.Rbx, "tbl");

            a.Label("entry_loop");
            a.MovRm(Reg.Rbp, Reg.Rbx, 0);
            a.XorRr(Reg.Rbp, Reg.R14);                 // rbp = target RVA
            a.TestRr(Reg.Rbp, Reg.Rbp);
            a.Jcc(Cc.E, "restore_final_page");
            a.AddRr(Reg.Rbp, Reg.R15);                 // rbp = target VA

            a.MovRm(Reg.R12, Reg.Rbx, 8);
            a.XorRr(Reg.R12, Reg.R14);                 // r12 = length
            a.MovRm(Reg.R8, Reg.Rbx, 16);
            a.XorRr(Reg.R8, Reg.R14);                  // r8 = rotated key
            if (taint)
            {
                a.MovRm(Reg.Rcx, Reg.R13, RuntimeDetectionStateLayout.SessionKeyOffset);
                a.XorRr(Reg.R8, Reg.Rcx);
            }
            if (rolling)
            {
                a.MovRm(Reg.Rdx, Reg.Rbx, 24);
                a.XorRr(Reg.Rdx, Reg.R14);             // rdx = rolling state
                a.XorRr(Reg.R10, Reg.R10);             // byte index
            }

            a.Label("byte_loop");
            a.TestRr(Reg.R12, Reg.R12);
            a.Jcc(Cc.E, "next_entry");

            // Fast path: check if the current byte is already on the open 4KB page.
            a.MovRr(Reg.Rcx, Reg.Rbp);
            a.AndRi(Reg.Rcx, unchecked((int)0xFFFFF000));
            a.CmpRr(Reg.Rcx, Reg.Rsi);
            a.Jcc(Cc.E, "page_ready");

            // Slow path (once per distinct 4KB page): save volatile key state,
            // restore the previous page's exact flOldProtect, and open the new page.
            a.MovMr(Reg.Rsp, Reg.R8, 0x28);
            if (rolling)
            {
                a.MovMr(Reg.Rsp, Reg.Rdx, 0x30);
                a.MovMr(Reg.Rsp, Reg.R10, 0x38);
            }
            a.MovMr(Reg.Rsp, Reg.Rcx, 0x40);
            a.TestRr(Reg.Rsi, Reg.Rsi).Jcc(Cc.E, "open_new_page");
            a.MovRr(Reg.Rcx, Reg.Rsi).Mov32Ri(Reg.Rdx, 4096).Mov32Rr(Reg.R8, Reg.Rdi);
            a.LeaRd(Reg.R9, Reg.Rsp, 0x24);
            a.MovRi(Reg.Rax, protectIat).AddRr(Reg.Rax, Reg.R15).CallMem(Reg.Rax);
            a.Test32Rr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "protect_fail");

            a.Label("open_new_page");
            a.MovRm(Reg.Rsi, Reg.Rsp, 0x40);
            a.MovRr(Reg.Rcx, Reg.Rsi).Mov32Ri(Reg.Rdx, 4096).Mov32Ri(Reg.R8, 4); // PAGE_READWRITE
            a.LeaRd(Reg.R9, Reg.Rsp, 0x20);
            a.MovRi(Reg.Rax, protectIat).AddRr(Reg.Rax, Reg.R15).CallMem(Reg.Rax);
            a.Test32Rr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "protect_fail");
            a.MovRm32(Reg.Rdi, Reg.Rsp, 0x20);

            a.MovRm(Reg.R8, Reg.Rsp, 0x28);
            if (rolling)
            {
                a.MovRm(Reg.Rdx, Reg.Rsp, 0x30);
                a.MovRm(Reg.R10, Reg.Rsp, 0x38);
                if (splitConstants)
                    a.MovRiXorSplit(Reg.R11, unchecked((long)RollingMultiplier), Reg.Rcx, multiplierSplit);
                else
                    a.MovRi(Reg.R11, unchecked((long)RollingMultiplier));
            }

            a.Label("page_ready");
            a.MovRm8(Reg.Rcx, Reg.Rbp, 0);             // only CL participates in the stored byte
            a.MovRr(Reg.R9, Reg.R8);
            a.AndRi(Reg.R9, 0xFF);
            a.XorRr(Reg.Rcx, Reg.R9);                  // layer 1
            if (rolling)
            {
                a.ImulRr(Reg.Rdx, Reg.R11);
                a.AddRr(Reg.Rdx, Reg.R10);             // state = state*P + i
                a.MovRr(Reg.R9, Reg.Rdx);
                a.ShrRi(Reg.R9, 29);
                a.AndRi(Reg.R9, 0xFF);
                a.XorRr(Reg.Rcx, Reg.R9);              // layer 2
                a.IncR(Reg.R10);
            }
            a.MovMr8(Reg.Rbp, Reg.Rcx, 0);
            a.RolRi(Reg.R8, 8);                        // next key byte into position
            a.IncR(Reg.Rbp);
            a.DecR(Reg.R12);
            a.Jmp("byte_loop");

            a.Label("next_entry");
            a.AddRi(Reg.Rbx, 32);
            a.Jmp("entry_loop");

            a.Label("restore_final_page");
            a.TestRr(Reg.Rsi, Reg.Rsi).Jcc(Cc.E, "body_end");
            a.MovRr(Reg.Rcx, Reg.Rsi).Mov32Ri(Reg.Rdx, 4096).Mov32Rr(Reg.R8, Reg.Rdi);
            a.LeaRd(Reg.R9, Reg.Rsp, 0x24);
            a.MovRi(Reg.Rax, protectIat).AddRr(Reg.Rax, Reg.R15).CallMem(Reg.Rax);
            a.Test32Rr(Reg.Rax, Reg.Rax).Jcc(Cc.Ne, "body_end");

            a.Label("protect_fail");
            // Fail closed if VirtualProtect fails so encrypted ciphertext never
            // executes silently or triggers an arbitrary access violation later.
            a.Mov32Ri(Reg.Rcx, 7); // FAST_FAIL_FATAL_APP_EXIT
            a.Db(0xCD, 0x29);
            a.Ud2();

            a.Label("body_end");
            a.Label("done");
            a.AddRi(Reg.Rsp, 0x48);
            a.PopR(Reg.R15); a.PopR(Reg.R14); a.PopR(Reg.R13); a.PopR(Reg.R12);
            a.PopR(Reg.Rdi); a.PopR(Reg.Rsi); a.PopR(Reg.Rbp); a.PopR(Reg.Rbx);
            a.Ret();
            int codeEnd = a.Position;

            a.AlignData(8);
            a.Label("tbl");
            a.Db(blob);
            return new AntiDebugPass.BuiltRoutine(a, codeEnd, AntiDebugPass.BuildUnwindInfo(pushes, 0x48, prologEnd));
        }

        AntiDebugPass.BuiltRoutine template = Build(0, 0);
        byte[] templateBytes = template.Assembler.Assemble();
        int size = templateBytes.Length;
        ulong bodyHash = 14695981039346656037UL;
        foreach (byte value in templateBytes.AsSpan(template.Assembler.LabelOffset("body_start"),
            template.Assembler.LabelOffset("body_end") - template.Assembler.LabelOffset("body_start")))
            bodyHash = unchecked((bodyHash ^ value) * 1099511628211UL);
        uint rva = ctx.Alloc(size, 16);
        AntiDebugPass.BuiltRoutine built = Build(rva, bodyHash);
        byte[] code = built.Assembler.Assemble();
        if (code.Length != size)
            throw new InvalidOperationException("Decryptor size shifted between passes.");
        ctx.WriteStub(rva, code);
        ExceptionTableBuilder.Register(ctx, rva, checked(rva + (uint)built.CodeEnd), built.UnwindInfo!);
        return rva;
    }

}
