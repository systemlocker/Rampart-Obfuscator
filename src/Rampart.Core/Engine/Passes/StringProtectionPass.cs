using System.Buffers.Binary;
using Rampart.Pe;
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

    public void Run(BuildContext ctx)
    {
        var level = ctx.MaximumFunctionLevel("strings.encryption");
        if (level == Config.ProtectionLevel.Off)
            return;

        var referenced = FindReferencedStrings(ctx);

        var chosen = referenced.Where(s => s.Len >= MinimumLength(s.Coverage)).ToList();

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
        int traps = 0;
        foreach (var levelGroup in chosen.GroupBy(item => item.Encryption))
        {
            bool rolling = levelGroup.Key >= Config.ProtectionLevel.Balanced;
            var table = new List<EncString>();
            foreach (FoundString item in levelGroup)
            {
                ulong k1 = ((ulong)ctx.Rng.NextInt64()) | 1;
                ulong k2 = ((ulong)ctx.Rng.NextInt64()) | 1;
                EncryptAt(ctx, item.Rva, item.Len, k1, k2, rolling);
                table.Add(new EncString(item.Rva, item.Len, k1, k2));
            }

            uint initRva = EmitDecryptor(ctx, table, rolling);
            ctx.RegisterInit(initRva,
                $"string decryptor ({table.Count} strings, {levelGroup.Key})");
            if (levelGroup.Any(item => item.AntiInstrumentation != Config.ProtectionLevel.Off))
            {
                traps += EmitAntiInstrumentation(ctx, table);
            }
            encrypted += table.Count;
            decryptors++;
        }

        // The decryptor rewrites the strings in place at startup, so their
        // sections must be writable at runtime. Read-only data in a protected
        // binary is ciphertext anyway; RW here is the standard trade.
        foreach (var sec in chosen.Select(s => ctx.Pe.SectionFromRva(s.Rva)).Distinct())
            sec!.Characteristics |= SectionCharacteristics.MemWrite;

        ctx.Log.Add(new("strings",
            $"encrypted {encrypted} strings in place with {decryptors} scoped decryptor(s)" +
            (traps > 0 ? $", {traps} INT3/INT2D sentinel sites" : "")));
    }

    private readonly record struct FoundString(
        uint Rva,
        int Len,
        Config.ProtectionLevel Encryption,
        Config.ProtectionLevel Coverage,
        Config.ProtectionLevel AntiInstrumentation);

    private static int MinimumLength(Config.ProtectionLevel coverage) => coverage switch
    {
        Config.ProtectionLevel.Off or Config.ProtectionLevel.Light => 6,
        Config.ProtectionLevel.Balanced => 8,
        Config.ProtectionLevel.Heavy => 5,
        _ => 3,
    };

    /// <summary>Walks every .pdata-known function and records rip-relative data
    /// targets that land on printable runs in read-only sections. The decoder
    /// refuses anything it cannot parse, so this only ever finds a subset —
    /// the safe direction.</summary>
    private static List<FoundString> FindReferencedStrings(BuildContext ctx)
    {
        var pe = ctx.Pe;
        var results = new Dictionary<uint, FoundString>();

        foreach (var func in ctx.Functions)
        {
            Config.ProtectionLevel encryption = ctx.LevelFor("strings.encryption", func);
            if (encryption == Config.ProtectionLevel.Off)
                continue;
            Config.ProtectionLevel coverage = ctx.LevelFor("strings.coverage", func);
            Config.ProtectionLevel antiInstrumentation =
                ctx.LevelFor("strings.anti-instrumentation", func);
            if (!pe.TryRvaToOffset(func.BeginRva, out int off))
                continue;
            var sec = pe.SectionFromRva(func.BeginRva)!;
            int avail = (int)Math.Min(func.EndRva - func.BeginRva, sec.PointerToRawData + sec.SizeOfRawData - (uint)off);
            if (avail <= 0)
                continue;
            var code = sec.Data.AsSpan(off - (int)sec.PointerToRawData, avail);

            int pos = 0;
            while (pos < code.Length)
            {
                if (!X64Decoder.TryDecode(code, pos, func.BeginRva + (uint)pos, out var instr))
                    break;
                if (instr.HasRipRelative)
                {
                    uint target = instr.RipTargetRva;
                    if (TryMeasurePrintable(pe, target, out int len))
                    {
                        var found = new FoundString(target, len, encryption, coverage, antiInstrumentation);
                        if (results.TryGetValue(target, out FoundString existing))
                        {
                            found = found with
                            {
                                Encryption = Max(found.Encryption, existing.Encryption),
                                Coverage = Max(found.Coverage, existing.Coverage),
                                AntiInstrumentation = Max(found.AntiInstrumentation, existing.AntiInstrumentation),
                            };
                        }
                        results[target] = found;
                    }
                }
                pos += instr.Length;
            }
        }
        return results.Values.OrderBy(item => item.Rva).ToList();

        static Config.ProtectionLevel Max(
            Config.ProtectionLevel first,
            Config.ProtectionLevel second) =>
            (Config.ProtectionLevel)Math.Max((int)first, (int)second);
    }

    /// <summary>A string is a NUL-terminated printable ASCII run (4..4096 bytes)
    /// in a read-only, non-executable section.</summary>
    private static bool TryMeasurePrintable(PeImage pe, uint rva, out int len)
    {
        len = 0;
        var sec = pe.SectionFromRva(rva);
        if (sec is null || sec.IsExecutable || sec.Characteristics.HasFlag(SectionCharacteristics.MemWrite))
            return false;
        if (!pe.TryRvaToOffset(rva, out int off))
            return false;

        int start = off - (int)sec.PointerToRawData;
        var data = sec.Data;
        int i = start;
        while (i < data.Length && data[i] != 0)
        {
            byte b = data[i];
            if (b is < 0x20 or > 0x7E)
                return false;
            i++;
        }
        len = i - start;
        return len is >= 4 and <= 4096 && i < data.Length;
    }

    /// <summary>Build-side encryption. Per byte i:
    /// b ^= low byte of ror64(k1, 8*i); and (rolling layer)
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
    /// Register plan: rbx = table cursor, r15 = runtime image base, rax = target
    /// pointer, r12 = bytes remaining, r8 = rotated key (advance with rol 8),
    /// r9 = current key byte, rdx = rolling state, r10 = byte index, r11 = P,
    /// r14 = table mask, rcx = data byte (mov cl zero-extends rcx).
    ///
    /// The (rva, len, k1, k2) qword table rides at the end, XOR-masked with a
    /// build value; a zero first field terminates the walk.
    /// Emitted twice — once to measure size, once at the final RVA (only the
    /// runtime-base immediate changes, so sizes match).</summary>
    private static uint EmitDecryptor(BuildContext ctx, List<EncString> table, bool rolling)
    {
        ulong mask = (ulong)ctx.Rng.NextInt64() | 0x1;
        bool splitConstants = ctx.Level("code-transformation.mba-constants") != Config.ProtectionLevel.Off;
        long maskSplit = ctx.Rng.NextInt64() | 1;
        long multiplierSplit = ctx.Rng.NextInt64() | 1;
        var blob = new byte[table.Count * 32 + 32]; // + terminator qwords
        for (int i = 0; i < table.Count; i++)
        {
            var e = table[i];
            BinaryPrimitives.WriteUInt64LittleEndian(blob.AsSpan(i * 32), e.Rva ^ mask);
            BinaryPrimitives.WriteUInt64LittleEndian(blob.AsSpan(i * 32 + 8), (ulong)e.Length ^ mask);
            BinaryPrimitives.WriteUInt64LittleEndian(blob.AsSpan(i * 32 + 16), e.Key1 ^ mask);
            BinaryPrimitives.WriteUInt64LittleEndian(blob.AsSpan(i * 32 + 24), e.Key2 ^ mask);
        }
        // The reader XOR-unmasks before checking for zero, so the encoded zero
        // terminator is the mask itself rather than eight raw zero bytes.
        BinaryPrimitives.WriteUInt64LittleEndian(blob.AsSpan(table.Count * 32), mask);

        Asm Build(uint selfRva)
        {
            var a = new Asm();
            a.PushR(Reg.Rbx); a.PushR(Reg.R12); a.PushR(Reg.R14); a.PushR(Reg.R15);
            a.SubRi(Reg.Rsp, 8);                       // 5 slots → aligned calls
            a.LoadRuntimeBase(Reg.R15, selfRva);       // r15 = runtime image base

            if (splitConstants)
                a.MovRiXorSplit(Reg.R14, unchecked((long)mask), Reg.Rax, maskSplit);
            else
                a.MovRi(Reg.R14, unchecked((long)mask));
            a.LeaRip(Reg.Rbx, "tbl");
            if (splitConstants)
                a.MovRiXorSplit(Reg.R11, unchecked((long)RollingMultiplier), Reg.Rax, multiplierSplit);
            else
                a.MovRi(Reg.R11, unchecked((long)RollingMultiplier));

            a.Label("entry_loop");
            a.MovRm(Reg.Rax, Reg.Rbx, 0);
            a.XorRr(Reg.Rax, Reg.R14);                 // rax = target RVA
            a.TestRr(Reg.Rax, Reg.Rax);
            a.Jcc(Cc.E, "done");
            a.AddRr(Reg.Rax, Reg.R15);                 // rax = target VA

            a.MovRm(Reg.R12, Reg.Rbx, 8);
            a.XorRr(Reg.R12, Reg.R14);                 // r12 = length
            a.MovRm(Reg.R8, Reg.Rbx, 16);
            a.XorRr(Reg.R8, Reg.R14);                  // r8 = rotated key
            a.MovRm(Reg.Rdx, Reg.Rbx, 24);
            a.XorRr(Reg.Rdx, Reg.R14);                 // rdx = rolling state
            a.XorRr(Reg.R10, Reg.R10);                 // byte index

            a.Label("byte_loop");
            a.TestRr(Reg.R12, Reg.R12);
            a.Jcc(Cc.E, "next_entry");
            a.MovRm8(Reg.Rcx, Reg.Rax, 0);             // mov cl,[rax] — zero-extends rcx
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
            }
            a.MovMr8(Reg.Rax, Reg.Rcx, 0);
            a.RolRi(Reg.R8, 8);                        // next key byte into position
            a.IncR(Reg.R10);
            a.IncR(Reg.Rax);
            a.DecR(Reg.R12);
            a.Jmp("byte_loop");

            a.Label("next_entry");
            a.AddRi(Reg.Rbx, 32);
            a.Jmp("entry_loop");

            a.Label("done");
            a.AddRi(Reg.Rsp, 8);
            a.PopR(Reg.R15); a.PopR(Reg.R14); a.PopR(Reg.R12); a.PopR(Reg.Rbx);
            a.Ret();

            a.Align(8);
            a.Label("tbl");
            a.Db(blob);
            return a;
        }

        int size = Build(0).Assemble().Length;
        uint rva = ctx.Alloc(size, 16);
        byte[] code = Build(rva).Assemble();
        if (code.Length != size)
            throw new InvalidOperationException("Decryptor size shifted between passes.");
        ctx.WriteStub(rva, code);
        return rva;
    }

    /// <summary>Plants INT3/INT2D sentinel walls in the protector's own stub
    /// section, bracketing the decryptor's table. Never in the target's data:
    /// two zero bytes before a .rdata string are far more likely to be a live
    /// table terminator than padding, and corrupting one breaks the loader.</summary>
    private int EmitAntiInstrumentation(BuildContext ctx, List<EncString> table)
    {
        int walls = Math.Min(4, 1 + table.Count / 8);
        var rng = ctx.Rng;
        for (int i = 0; i < walls; i++)
        {
            int len = rng.Next(8, 24);
            uint rva = ctx.Alloc(len, 1);
            var wall = new byte[len];
            for (int b = 0; b < len; b++)
                wall[b] = (byte)(b % 2 == 0 ? 0xCC : 0x2D);
            ctx.WriteStub(rva, wall);
        }
        return walls;
    }
}
