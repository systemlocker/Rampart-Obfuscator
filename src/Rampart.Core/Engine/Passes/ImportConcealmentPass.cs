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
        uint slotsRva = ctx.AllocData(imports.Count * 8, 8);
        uint init = EmitInitializer(ctx, imports, seed, resolverRva, slotsRva, bootstrap);
        var slots = imports.Select((imported, index) => (imported.ThunkRva, Slot: slotsRva + (uint)(index * 8)))
            .ToDictionary(item => item.ThunkRva, item => item.Slot);
        int rewritten = 0;
        foreach (Site site in sites.DistinctBy(site => site.Rva))
        {
            long displacement = (long)slots[site.Import.ThunkRva] - (site.Rva + site.Length);
            if (displacement is < int.MinValue or > int.MaxValue)
                continue;
            ctx.Pe.WriteRva(site.Rva + (uint)site.Length - 4, BitConverter.GetBytes((int)displacement));
            ctx.MarkApplied(site.Function, "packaging.import-concealment",
                Config.ProtectionLevel.Light);
            rewritten++;
        }
        ctx.RegisterInit(init, $"hash import resolver ({imports.Count} functions, {rewritten} sites)");
        ctx.Log.Add(new("imports", $"seeded export-name lookup for {imports.Count} imports; {rewritten} references rewritten; " +
            "original descriptors, names and IAT retained; ordinals/API sets/unsupported references unchanged; loader fallback on lookup failure"));
    }

    private static bool IsEligible(ImportedFunction imported) =>
        !imported.Name.StartsWith('#')
        && !imported.Dll.StartsWith("api-", StringComparison.OrdinalIgnoreCase)
        && !imported.Dll.StartsWith("ext-", StringComparison.OrdinalIgnoreCase)
        && !imported.Dll.Contains('/') && !imported.Dll.Contains('\\')
        && imported.Name.All(character => character is > '\0' and <= '\x7F');

    private static uint EmitInitializer(BuildContext ctx, List<ImportedFunction> imports, ulong seed,
        uint resolverRva, uint slotsRva, IReadOnlyDictionary<string, uint> bootstrap)
    {
        Asm Build(uint selfRva)
        {
            var a = new Asm();
            a.PushR(Reg.R15);
            a.SubRi(Reg.Rsp, 48); // home area plus a saved last-error value
            a.LoadRuntimeBase(Reg.R15, selfRva);
            a.MovRi(Reg.Rax, bootstrap["GetLastError"]);
            a.AddRr(Reg.Rax, Reg.R15);
            a.CallMem(Reg.Rax);
            a.MovMr(Reg.Rsp, Reg.Rax, 32);
            for (int i = 0; i < imports.Count; i++)
            {
                ImportedFunction imported = imports[i];
                a.LeaRip(Reg.Rcx, $"dll{i}");
                a.MovRi(Reg.Rax, bootstrap["GetModuleHandleA"]);
                a.AddRr(Reg.Rax, Reg.R15);
                a.CallMem(Reg.Rax);
                a.TestRr(Reg.Rax, Reg.Rax);
                a.Jcc(Cc.E, $"fallback{i}");
                a.MovRr(Reg.Rcx, Reg.Rax);
                a.LeaRip(Reg.Rdx, $"name{i}");
                a.MovRi(Reg.R8, unchecked((long)ExportHashResolver.Hash(imported.Name, seed)));
                a.MovRi(Reg.R9, bootstrap["GetProcAddress"]);
                a.AddRr(Reg.R9, Reg.R15);
                a.MovRm(Reg.R9, Reg.R9);
                a.CallRva(selfRva, resolverRva);
                a.TestRr(Reg.Rax, Reg.Rax);
                a.Jcc(Cc.E, $"fallback{i}");
                // Basename lookup can select a different side-by-side module.
                // Accept independent resolution only when it agrees with the
                // loader's binding; this also retains legitimate IAT redirections.
                a.MovRi(Reg.Rdx, imported.ThunkRva);
                a.AddRr(Reg.Rdx, Reg.R15);
                a.MovRm(Reg.Rdx, Reg.Rdx);
                a.CmpRr(Reg.Rax, Reg.Rdx);
                a.Jcc(Cc.E, $"store{i}");
                a.Label($"fallback{i}");
                // Existing static imports retain dependency ownership. No new
                // LoadLibrary/FreeLibrary calls occur under the TLS loader lock.
                // Failure to independently resolve never replaces a valid IAT
                // address with null or a potentially colliding export.
                a.MovRi(Reg.Rax, imported.ThunkRva);
                a.AddRr(Reg.Rax, Reg.R15);
                a.MovRm(Reg.Rax, Reg.Rax);
                a.Label($"store{i}");
                a.MovRi(Reg.Rdx, slotsRva + (uint)(i * 8));
                a.AddRr(Reg.Rdx, Reg.R15);
                a.MovMr(Reg.Rdx, Reg.Rax);
            }
            a.MovRm(Reg.Rcx, Reg.Rsp, 32);
            a.MovRi(Reg.Rax, bootstrap["SetLastError"]);
            a.AddRr(Reg.Rax, Reg.R15);
            a.CallMem(Reg.Rax);
            a.AddRi(Reg.Rsp, 48);
            a.PopR(Reg.R15);
            a.Ret();
            for (int i = 0; i < imports.Count; i++)
            {
                a.Label($"dll{i}"); a.Db(Encoding.ASCII.GetBytes(imports[i].Dll + "\0"));
                a.Label($"name{i}"); a.Db(Encoding.ASCII.GetBytes(imports[i].Name + "\0"));
            }
            return a;
        }
        int size = Build(0).Assemble().Length;
        uint rva = ctx.Alloc(size, 16);
        byte[] code = Build(rva).Assemble();
        if (code.Length != size)
            throw new InvalidOperationException("Import initializer size changed during layout.");
        ctx.WriteStub(rva, code);
        return rva;
    }
}
