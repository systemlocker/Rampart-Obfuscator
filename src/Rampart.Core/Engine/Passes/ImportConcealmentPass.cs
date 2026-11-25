using System.Text;
using Rampart.Imports;
using Rampart.Pe;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>Repoints selected ordinary import loads and transfers to slots populated
/// by a seeded export-name lookup. Original loader metadata remains authoritative
/// for module lifetime and for references outside the decoder's supported scope.</summary>
public sealed class ImportConcealmentPass
{
    private sealed record Site(
        uint Rva, int Length, ImportedFunction Import, FunctionDescriptor Function);

    public void Run(BuildContext ctx)
    {
        if (ctx.MaximumFunctionLevel("packaging.import-concealment") == Config.ProtectionLevel.Off)
            return;
        // CFG startup runs at the entry point, after existing TLS callbacks.
        // Callback reachability is not available, so none of their possible
        // callees may be redirected to slots that are still zero at that time.
        if (PeCompatibility.Inspect(ctx.Pe).GuardCf && !ctx.Pe.Directory(DataDir.Tls).IsEmpty)
        {
            ctx.Log.Add(new("imports", "CFG image with existing TLS: retained loader references because initialization precedes neither callback nor its callees"));
            return;
        }
        List<ImportedFunction> imports = ImportTable.Parse(ctx.Pe).Where(IsEligible).ToList();
        var bySlot = imports.ToDictionary(imported => imported.ThunkRva);
        var sites = new List<Site>();
        var addressSensitiveSlots = new HashSet<uint>();
        foreach (var function in ctx.Functions)
        {
            if (ctx.IsFunctionClaimed(function))
                continue;
            bool selected = ctx.LevelFor("packaging.import-concealment", function) != Config.ProtectionLevel.Off;
            if (!ctx.Pe.TryRvaToOffset(function.BeginRva, out int offset))
                continue;
            var section = ctx.Pe.SectionFromRva(function.BeginRva)!;
            int available = checked((int)Math.Min(function.Size,
                section.PointerToRawData + section.SizeOfRawData - (uint)offset));
            ReadOnlySpan<byte> code = section.Data.AsSpan(offset - (int)section.PointerToRawData, available);
            for (int pos = 0; pos < code.Length;)
            {
                uint rva = function.BeginRva + (uint)pos;
                if (!X64Decoder.TryDecode(code, pos, rva, out var instruction))
                    break;
                // Never rewrite LEA (slot identity can escape), stores, prefixed
                // operands, or instructions with trailing immediates. Their disp32
                // is not necessarily the last operand, unlike these exact forms.
                ReadOnlySpan<byte> bytes = code.Slice(pos, instruction.Length);
                bool supported = (bytes.Length == 6 && bytes[0] == 0xFF && bytes[1] is 0x15 or 0x25)
                    || (bytes.Length == 7 && bytes[0] is 0x48 or 0x4C && bytes[1] == 0x8B
                        && (bytes[2] & 0xC7) == 0x05);
                if (instruction.HasRipRelative && bySlot.TryGetValue(instruction.RipTargetRva, out var imported))
                {
                    if (!supported)
                        // Also inspect excluded functions: a slot whose address
                        // escapes (or is written) cannot safely be duplicated for
                        // a selected caller. Decoder gaps still retain the IAT.
                        addressSensitiveSlots.Add(imported.ThunkRva);
                    else if (selected)
                        sites.Add(new(rva, instruction.Length, imported, function));
                }
                pos += instruction.Length;
            }
        }
        sites.RemoveAll(site => addressSensitiveSlots.Contains(site.Import.ThunkRva));
        // Filter to sites that can reach the data section within signed disp32
        // before emitting any stubs, imports, or tables.
        uint predictedDataRva = ctx.Data is not null
            ? ctx.Data.VirtualAddress + ctx.Data.SizeOfRawData
            : ctx.Pe.SizeOfImage;
        sites.RemoveAll(site =>
        {
            long est = (long)predictedDataRva - (site.Rva + site.Length);
            return est is < int.MinValue or > int.MaxValue;
        });
        imports = sites.Select(site => site.Import).Distinct().ToList();
        if (imports.Count == 0)
        {
            ctx.Log.Add(new("imports", "no supported ordinary named-import references; loader metadata retained"));
            return;
        }

        var bootstrap = ImportDirectoryEditor.EnsureNamedImports(ctx, "KERNEL32.dll",
            "GetModuleHandleA", "GetProcAddress", "GetLastError", "SetLastError");
        ulong seed = unchecked((ulong)ctx.Rng.NextInt64()) | 1;
        byte[] resolver = ExportHashResolver.Emit(seed);
        uint resolverRva = ctx.Alloc(resolver.Length, 16);
        ctx.WriteStub(resolverRva, resolver);
        RegisterExportHashResolverUnwind(ctx, resolverRva, resolver.Length);
        uint slotsRva = ctx.AllocData(imports.Count * 8, 8);
        uint init = EmitInitializer(ctx, imports, seed, resolverRva, slotsRva, bootstrap);
        var slots = imports.Select((imported, index) => (imported, Slot: checked(slotsRva + (uint)(index * 8))))
            .ToDictionary(item => item.imported.ThunkRva, item => item);
        int rewritten = 0;
        foreach (Site site in sites.DistinctBy(site => site.Rva))
        {
            var entry = slots[site.Import.ThunkRva];
            long displacement = (long)entry.Slot - (site.Rva + site.Length);
            if (displacement is < int.MinValue or > int.MaxValue)
                continue;
            ctx.Pe.WriteRva(site.Rva + (uint)site.Length - 4, BitConverter.GetBytes((int)displacement));
            ctx.ConcealedImportSlots[entry.Slot] = entry.imported;
            ctx.MarkApplied(site.Function, "packaging.import-concealment",
                Config.ProtectionLevel.Light);
            rewritten++;
        }
        ctx.RegisterInit(init, $"hash import resolver ({imports.Count} functions, {rewritten} sites)");
        ctx.Log.Add(new("imports", $"seeded export-name lookup for {imports.Count} imports; {rewritten} references rewritten; " +
            "original descriptors, names and IAT retained; ordinals/API sets/unsupported references unchanged; loader fallback on lookup failure"));
    }

    private static void RegisterExportHashResolverUnwind(BuildContext ctx, uint resolverRva, int resolverLength)
    {
        // ExportHashResolver pushes Rbx, Rbp, Rsi, Rdi, R12, R13, R14, R15 (12 bytes total).
        var pushes = new (Reg, byte)[]
        {
            (Reg.Rbx, 1), (Reg.Rbp, 2), (Reg.Rsi, 3), (Reg.Rdi, 4),
            (Reg.R12, 6), (Reg.R13, 8), (Reg.R14, 10), (Reg.R15, 12),
        };
        byte[] unwind = AntiDebugPass.BuildUnwindInfo(pushes, 0, 12);
        ExceptionTableBuilder.Register(ctx, resolverRva, checked(resolverRva + (uint)resolverLength), unwind);
    }

    private static bool IsEligible(ImportedFunction imported) =>
        !imported.Name.StartsWith('#')
        && !imported.Dll.StartsWith("api-", StringComparison.OrdinalIgnoreCase)
        && !imported.Dll.StartsWith("ext-", StringComparison.OrdinalIgnoreCase)
        && !imported.Dll.Contains('/') && !imported.Dll.Contains('\\')
        && imported.Name.All(character => character is > '\0' and <= '\x7F');

    /// <summary>Emits a compact loop-driven initializer over a read-only descriptor
    /// table in .rmpt (24 bytes per import: dllNameRva, funcNameRva, hash64,
    /// origIatRva, privateSlotRva) instead of unrolling per import.</summary>
    private static uint EmitInitializer(BuildContext ctx, List<ImportedFunction> imports, ulong seed,
        uint resolverRva, uint slotsRva, IReadOnlyDictionary<string, uint> bootstrap)
    {
        // Lay out ASCII DLL/function names in .rmpt (read-only) first so the table
        // can store their exact RVAs without absolute pointers or relocations.
        var stringPool = new List<byte>();
        var dllOffsets = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var entryMetadata = new (int DllOffset, int NameOffset, ulong Hash, uint OrigIatRva, uint PrivateSlotRva)[imports.Count];
        for (int i = 0; i < imports.Count; i++)
        {
            ImportedFunction imported = imports[i];
            if (!dllOffsets.TryGetValue(imported.Dll, out int dllOff))
            {
                dllOff = stringPool.Count;
                stringPool.AddRange(Encoding.ASCII.GetBytes(imported.Dll));
                stringPool.Add(0);
                dllOffsets[imported.Dll] = dllOff;
            }
            int nameOff = stringPool.Count;
            stringPool.AddRange(Encoding.ASCII.GetBytes(imported.Name));
            stringPool.Add(0);
            entryMetadata[i] = (
                dllOff,
                nameOff,
                ExportHashResolver.Hash(imported.Name, seed),
                imported.ThunkRva,
                checked(slotsRva + (uint)(i * 8)));
        }

        uint stringPoolRva = ctx.Alloc(stringPool.Count, 8);
        ctx.WriteStub(stringPoolRva, stringPool.ToArray());

        var tableBytes = new byte[checked(imports.Count * 24)];
        for (int i = 0; i < entryMetadata.Length; i++)
        {
            var e = entryMetadata[i];
            int row = i * 24;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(tableBytes.AsSpan(row + 0), checked(stringPoolRva + (uint)e.DllOffset));
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(tableBytes.AsSpan(row + 4), checked(stringPoolRva + (uint)e.NameOffset));
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(tableBytes.AsSpan(row + 8), e.Hash);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(tableBytes.AsSpan(row + 16), e.OrigIatRva);
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(tableBytes.AsSpan(row + 20), e.PrivateSlotRva);
        }
        uint tableRva = ctx.Alloc(tableBytes.Length, 8);
        ctx.WriteStub(tableRva, tableBytes);

        AntiDebugPass.BuiltRoutine Build(uint selfRva)
        {
            var a = new Asm();
            // Three nonvolatile saves (RBX=table cursor, R14=remaining count, R15=image base)
            // keep RSP 16-aligned with 0x30 bytes (0x20 shadow + saved LastError at +0x20).
            var pushes = new List<(Reg, byte)>();
            foreach (Reg reg in new[] { Reg.Rbx, Reg.R14, Reg.R15 })
            {
                a.PushR(reg);
                pushes.Add((reg, (byte)a.Position));
            }
            a.SubRi(Reg.Rsp, 0x30);
            byte prologEnd = (byte)a.Position;

            a.LoadRuntimeBase(Reg.R15, selfRva);
            a.MovRi(Reg.Rax, bootstrap["GetLastError"]).AddRr(Reg.Rax, Reg.R15).CallMem(Reg.Rax);
            a.MovMr(Reg.Rsp, Reg.Rax, 0x20);

            a.MovRi(Reg.Rbx, tableRva).AddRr(Reg.Rbx, Reg.R15);
            a.Mov32Ri(Reg.R14, (uint)imports.Count);

            a.Label("loop");
            a.Test32Rr(Reg.R14, Reg.R14).Jcc(Cc.E, "done");

            // GetModuleHandleA(imageBase + entry.DllNameRva)
            a.MovRm32(Reg.Rcx, Reg.Rbx, 0).AddRr(Reg.Rcx, Reg.R15);
            a.MovRi(Reg.Rax, bootstrap["GetModuleHandleA"]).AddRr(Reg.Rax, Reg.R15).CallMem(Reg.Rax);
            a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "fallback");

            // ExportHashResolver(hModule, imageBase + entry.FuncNameRva, entry.Hash, *GetProcAddressSlot)
            a.MovRr(Reg.Rcx, Reg.Rax);
            a.MovRm32(Reg.Rdx, Reg.Rbx, 4).AddRr(Reg.Rdx, Reg.R15);
            a.MovRm(Reg.R8, Reg.Rbx, 8);
            a.MovRi(Reg.R9, bootstrap["GetProcAddress"]).AddRr(Reg.R9, Reg.R15).MovRm(Reg.R9, Reg.R9);
            a.CallRva(selfRva, resolverRva);
            a.TestRr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "fallback");

            // Accept independent resolution only when it agrees with the loader's IAT binding.
            a.MovRm32(Reg.Rdx, Reg.Rbx, 16).AddRr(Reg.Rdx, Reg.R15).MovRm(Reg.Rdx, Reg.Rdx);
            a.CmpRr(Reg.Rax, Reg.Rdx).Jcc(Cc.E, "store");

            a.Label("fallback");
            a.MovRm32(Reg.Rax, Reg.Rbx, 16).AddRr(Reg.Rax, Reg.R15).MovRm(Reg.Rax, Reg.Rax);

            a.Label("store");
            a.MovRm32(Reg.Rdx, Reg.Rbx, 20).AddRr(Reg.Rdx, Reg.R15).MovMr(Reg.Rdx, Reg.Rax);
            a.AddRi(Reg.Rbx, 24).DecR(Reg.R14).Jmp("loop");

            a.Label("done");
            a.MovRm(Reg.Rcx, Reg.Rsp, 0x20);
            a.MovRi(Reg.Rax, bootstrap["SetLastError"]).AddRr(Reg.Rax, Reg.R15).CallMem(Reg.Rax);
            a.AddRi(Reg.Rsp, 0x30).PopR(Reg.R15).PopR(Reg.R14).PopR(Reg.Rbx).Ret();
            int codeEnd = a.Position;
            return new AntiDebugPass.BuiltRoutine(a, codeEnd, AntiDebugPass.BuildUnwindInfo(pushes, 0x30, prologEnd));
        }

        int size = Build(0).Assembler.Assemble().Length;
        uint rva = ctx.Alloc(size, 16);
        AntiDebugPass.BuiltRoutine built = Build(rva);
        byte[] code = built.Assembler.Assemble();
        if (code.Length != size)
            throw new InvalidOperationException("Import initializer size changed during layout.");
        ctx.WriteStub(rva, code);
        ExceptionTableBuilder.Register(ctx, rva, checked(rva + (uint)built.CodeEnd), built.UnwindInfo!);
        return rva;
    }
}
