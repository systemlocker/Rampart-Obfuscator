using System.Buffers.Binary;
using Rampart.Pe;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>Import concealment. The classic import table (descriptors, name
/// strings, hint tables, IAT) is the first thing an analyst enumerates. This
/// pass:
///   1. parses every import,
///   2. allocates a concealed slot array in the protector section,
///   3. rewrites every rip-relative reference to an IAT slot so it points at the
///      concealed slot instead (same instruction length; the decoder pins each
///      site — anything undecodable is left alone),
///   4. registers an init routine that copies each loader-resolved address from
///      the original IAT into the concealed slots, then — from Balanced up —
///      zeroes the original IAT and name strings on disk, so tooling that
///      re-reads the import structures finds nothing ("the import table indexes
///      to nothing on disk").
/// Hash-based re-resolution (no loader involvement at all) layers on top via the
/// runtime library and turns on at Heavy.</summary>
public sealed class ImportConcealmentPass
{
    public void Run(BuildContext ctx)
    {
        var level = ctx.MaximumFunctionLevel("packaging.import-concealment");
        if (level == Config.ProtectionLevel.Off)
            return;

        var pe = ctx.Pe;
        var imports = ImportTable.Parse(pe);
        if (imports.Count == 0)
        {
            ctx.Log.Add(new("imports", "no imports to conceal"));
            return;
        }

        uint slotsRva = ctx.Alloc(imports.Count * 8 + 8, 8);

        int rewrites = RewriteIatReferences(ctx, imports, slotsRva);

        // The resolver zeroes the original IAT slots in memory after copying
        // them into the concealed array — those slots live in sections that
        // are conventionally read-only, so they must be writable at runtime.
        if (ctx.Level("packaging.import-concealment") >= Config.ProtectionLevel.Balanced)
        {
            foreach (var sec in imports
                         .Where(i => pe.TryRvaToOffset(i.ThunkRva, out _))
                         .Select(i => pe.SectionFromRva(i.ThunkRva))
                         .Distinct())
                sec!.Characteristics |= SectionCharacteristics.MemWrite;
        }

        uint initRva = EmitCopier(ctx, imports, slotsRva);
        ctx.RegisterInit(initRva, $"import resolver ({imports.Count} functions, {rewrites} call sites)");

        if (level >= Config.ProtectionLevel.Balanced)
        {
            // Zero the readable structures on disk: descriptors, INT arrays,
            // DLL name strings, hint/name pairs.
            var dir = pe.Directory(DataDir.Import);
            if (!dir.IsEmpty)
            {
                SymbolScrubPass.ZeroRva(pe, dir.RelativeVirtualAddress, (int)Math.Min(dir.Size, 0x4000));
                ZeroImportNames(pe, imports);
            }
        }
        if (level >= Config.ProtectionLevel.Heavy)
        {
            pe.SetDirectory(DataDir.Import, 0, 0);
            pe.SetDirectory(DataDir.Iat, 0, 0);
        }

        ctx.Log.Add(new("imports",
            $"concealed {imports.Count} imports behind slot array at {slotsRva:X8}; {rewrites} references rewritten" +
            (level >= Config.ProtectionLevel.Balanced ? "; name/descriptor data zeroed" : "") +
            (level >= Config.ProtectionLevel.Heavy ? "; import+IAT directories dropped" : "")));
    }

    /// <summary>Finds every rip-relative instruction targeting the classic IAT
    /// and repoints its disp32 at the matching concealed slot. Instruction
    /// lengths never change (both sides use disp32 RIP-relative forms).</summary>
    private static int RewriteIatReferences(BuildContext ctx, List<ImportedFunction> imports, uint slotsRva)
    {
        var pe = ctx.Pe;
        var slotMap = new Dictionary<uint, uint>();
        for (int i = 0; i < imports.Count; i++)
            slotMap[imports[i].ThunkRva] = slotsRva + (uint)(i * 8);

        int rewrites = 0;
        foreach (var func in ctx.Functions)
        {
            if (ctx.LevelFor("packaging.import-concealment", func) == Config.ProtectionLevel.Off)
                continue;
            if (!pe.TryRvaToOffset(func.BeginRva, out int off))
                continue;
            var sec = pe.SectionFromRva(func.BeginRva)!;
            int avail = (int)Math.Min(func.EndRva - func.BeginRva, sec.PointerToRawData + sec.SizeOfRawData - (uint)off);
            if (avail <= 0)
                continue;
            var code = sec.Data;
            int baseIndex = off - (int)sec.PointerToRawData;

            int pos = 0;
            while (pos < avail)
            {
                if (!X64Decoder.TryDecode(code.AsSpan(baseIndex, avail), pos, func.BeginRva + (uint)pos, out var instr))
                    break;
                if (instr.HasRipRelative && slotMap.TryGetValue(instr.RipTargetRva, out uint newSlot))
                {
                    // For call/jmp/[rip+d] loads there is no immediate: the disp32
                    // is the last 4 bytes of the instruction.
                    int dispPos = baseIndex + pos + instr.Length - 4;
                    int nextInstrRva = (int)(func.BeginRva + (uint)(pos + instr.Length));
                    BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(dispPos), (int)newSlot - nextInstrRva);
                    rewrites++;
                }
                pos += instr.Length;
            }
        }
        return rewrites;
    }

    /// <summary>Init routine: for each import, copy the loader-resolved pointer
    /// from the original IAT slot into the concealed slot; from Balanced, also
    /// zero the original slot in memory afterwards (runtime values live only in
    /// our array from then on). The (origSlotRva, ourSlotRva) pairs ride as data
    /// XOR-masked with a build value.</summary>
    private static uint EmitCopier(BuildContext ctx, List<ImportedFunction> imports, uint slotsRva)
    {
        ulong mask = (ulong)ctx.Rng.NextInt64() | 0x1;
        bool destroy = ctx.Level("packaging.import-concealment") >= Config.ProtectionLevel.Balanced;
        bool splitConstants = ctx.Level("code-transformation.mba-constants") != Config.ProtectionLevel.Off;
        long maskSplit = ctx.Rng.NextInt64() | 1;

        var pairs = new byte[imports.Count * 16 + 16];
        for (int i = 0; i < imports.Count; i++)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(pairs.AsSpan(i * 16), imports[i].ThunkRva ^ mask);
            BinaryPrimitives.WriteUInt64LittleEndian(pairs.AsSpan(i * 16 + 8), (slotsRva + (uint)(i * 8)) ^ mask);
        }
        // The runtime XORs the first qword before its zero check; encode the
        // terminator with the same mask as every real record.
        BinaryPrimitives.WriteUInt64LittleEndian(pairs.AsSpan(imports.Count * 16), mask);

        Asm Build(uint selfRva)
        {
            var a = new Asm();
            a.PushR(Reg.Rbx); a.PushR(Reg.R12); a.PushR(Reg.R14); a.PushR(Reg.R15);
            a.SubRi(Reg.Rsp, 8);
            a.LoadRuntimeBase(Reg.R15, selfRva);     // r15 = runtime image base

            if (splitConstants)
                a.MovRiXorSplit(Reg.R14, unchecked((long)mask), Reg.Rax, maskSplit);
            else
                a.MovRi(Reg.R14, unchecked((long)mask));
            a.LeaRip(Reg.Rbx, "pairs");

            a.Label("loop");
            a.MovRm(Reg.Rax, Reg.Rbx, 0);
            a.XorRr(Reg.Rax, Reg.R14);               // rax = original slot RVA
            a.TestRr(Reg.Rax, Reg.Rax);
            a.Jcc(Cc.E, "done");
            a.AddRr(Reg.Rax, Reg.R15);               // rax = original slot VA
            a.MovRm(Reg.R12, Reg.Rbx, 8);
            a.XorRr(Reg.R12, Reg.R14);               // r12 = concealed slot RVA
            a.AddRr(Reg.R12, Reg.R15);               // r12 = concealed slot VA

            a.MovRm(Reg.Rax, Reg.Rax, 0);            // rax = resolved function pointer
            a.MovMr(Reg.R12, Reg.Rax, 0);            // concealed slot = pointer
            if (destroy)
            {
                // Zero the ORIGINAL slot: from here on the runtime value lives
                // only in the concealed array.
                a.MovRm(Reg.Rax, Reg.Rbx, 0);
                a.XorRr(Reg.Rax, Reg.R14);
                a.AddRr(Reg.Rax, Reg.R15);           // rax = original slot VA
                a.MovRi(Reg.R12, 0);
                a.MovMr(Reg.Rax, Reg.R12, 0);
            }

            a.AddRi(Reg.Rbx, 16);
            a.Jmp("loop");

            a.Label("done");
            a.AddRi(Reg.Rsp, 8);
            a.PopR(Reg.R15); a.PopR(Reg.R14); a.PopR(Reg.R12); a.PopR(Reg.Rbx);
            a.Ret();

            a.Align(8);
            a.Label("pairs");
            a.Db(pairs);
            return a;
        }

        int size = Build(0).Assemble().Length;
        uint rva = ctx.Alloc(size, 16);
        byte[] code = Build(rva).Assemble();
        if (code.Length != size)
            throw new InvalidOperationException("Resolver size shifted between passes.");
        ctx.WriteStub(rva, code);
        return rva;
    }

    /// <summary>Zeros the readable import strings: DLL names via the descriptor
    /// walk, hint/name blobs via the thunk walk.</summary>
    private static void ZeroImportNames(PeImage pe, List<ImportedFunction> imports)
    {
        var dir = pe.Directory(DataDir.Import);
        if (dir.IsEmpty)
            return;
        uint descRva = dir.RelativeVirtualAddress;
        while (true)
        {
            var desc = pe.ReadRva(descRva, 20);
            uint oft = BinaryPrimitives.ReadUInt32LittleEndian(desc);
            uint nameRva = BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(12));
            uint ft = BinaryPrimitives.ReadUInt32LittleEndian(desc.AsSpan(16));
            if (oft == 0 && nameRva == 0 && ft == 0)
                break;

            if (nameRva != 0 && pe.SectionFromRva(nameRva) is { } nameSec && !nameSec.IsExecutable)
                SymbolScrubPass.ZeroRva(pe, nameRva, 32); // DLL name + slack

            uint thunk = oft != 0 ? oft : ft;
            for (int i = 0; ; i++)
            {
                ulong entry = pe.ReadU64(thunk + (uint)(i * 8));
                if (entry == 0)
                    break;
                if ((entry & 0x8000000000000000UL) == 0 && entry < pe.SizeOfImage)
                    SymbolScrubPass.ZeroRva(pe, (uint)entry, 64); // hint/name + slack
            }
            descRva += 20;
        }
    }
}
