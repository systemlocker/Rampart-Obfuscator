using System.Buffers.Binary;
using System.Text;
using Rampart.Config;
using Rampart.Pe;
using Rampart.X64;

namespace Rampart.Engine.Passes;

/// <summary>
/// Applies opt-in, post-load header mutations. Each protection gets its own init
/// routine and completion bit so the three catalog settings remain independently
/// inspectable. The routines use VirtualProtect for the mapped header range and
/// restore the exact protection value returned by Windows before returning.
/// </summary>
public sealed class RuntimeHeaderProtectionPass
{
    private const string RuntimeCorruption = "analysis.runtime-header-corruption";
    private const string AntiDump = "memory.anti-dump";
    private const string HeaderScrub = "integrity.header-scrub";

    // These bits live in RuntimeDetectionState.PolicyStatus. They report that a
    // destructive runtime policy completed; detection flags remain reserved for
    // observations made by guard modules.
    internal const byte RuntimeCorruptionBit = 16;
    internal const byte AntiDumpBit = 17;
    internal const byte HeaderScrubBit = 18;
    internal const ulong RuntimeCorruptionApplied = 1UL << RuntimeCorruptionBit;
    internal const ulong AntiDumpApplied = 1UL << AntiDumpBit;
    internal const ulong HeaderScrubApplied = 1UL << HeaderScrubBit;

    public void Run(BuildContext ctx)
    {
        bool runtimeCorruption = ctx.Level(RuntimeCorruption) != ProtectionLevel.Off;
        bool antiDump = ctx.Level(AntiDump) != ProtectionLevel.Off;
        bool headerScrub = ctx.Level(HeaderScrub) != ProtectionLevel.Off;
        if (!runtimeCorruption && !antiDump && !headerScrub)
            return;

        if (ctx.Pe.SectionAlignment < 4096)
        {
            ctx.Log.Add(new("runtime-header",
                $"skipped runtime header mutations because SectionAlignment ({ctx.Pe.SectionAlignment}) shares header and section pages"));
            return;
        }

        RuntimeDetectionStateLayout state = RuntimeDetectionState.Ensure(ctx);
        IReadOnlyDictionary<string, uint> imports = ImportDirectoryEditor.EnsureNamedImports(
            ctx,
            "KERNEL32.DLL",
            "VirtualProtect");
        HeaderLayout layout = ReadLayout(ctx.Pe);

        if (runtimeCorruption)
        {
            uint rva = EmitRoutine(
                ctx,
                imports["VirtualProtect"],
                state,
                layout,
                RuntimeHeaderMutation.RuntimeSignature,
                RuntimeCorruptionBit,
                "RMPT.HDR.RUNTIME");
            ctx.RegisterInit(rva, "runtime DOS and PE signature scrub");
            ctx.Log.Add(new(RuntimeCorruption,
                $"emitted post-load MZ/PE signature scrub at RVA {rva:X8}"));
        }

        if (antiDump)
        {
            uint rva = EmitRoutine(
                ctx,
                imports["VirtualProtect"],
                state,
                layout,
                RuntimeHeaderMutation.RawReconstruction,
                AntiDumpBit,
                "RMPT.HDR.ANTIDUMP");
            ctx.RegisterInit(rva, "runtime raw-reconstruction header corruption");
            ctx.Log.Add(new(AntiDump,
                $"emitted raw-size, raw-pointer, COFF-pointer, count, and section-name scrub at RVA {rva:X8}"));
        }

        if (headerScrub)
        {
            uint rva = EmitRoutine(
                ctx,
                imports["VirtualProtect"],
                state,
                layout,
                RuntimeHeaderMutation.SectionTable,
                HeaderScrubBit,
                "RMPT.HDR.INTEGRITY");
            ctx.RegisterInit(rva, "runtime section-table scrub");
            ctx.Log.Add(new(HeaderScrub,
                $"emitted dynamic in-memory section-table scrub at RVA {rva:X8}"));
        }
    }

    private static HeaderLayout ReadLayout(PeImage pe)
    {
        int peOffset = pe.DosHeaderLength;
        int sectionTableOffset = checked(peOffset + 4 + 20 + pe.SizeOfOptionalHeader);
        int tableEnd = checked(sectionTableOffset + pe.NumberOfSections * 40);
        if (peOffset < 0x40 || tableEnd > pe.SizeOfHeaders)
            throw new BadImageFormatException("The mapped PE header does not contain the complete section table.");

        return new HeaderLayout(
            peOffset,
            sectionTableOffset,
            pe.SizeOfHeaders);
    }

    private static uint EmitRoutine(
        BuildContext ctx,
        uint virtualProtectIat,
        RuntimeDetectionStateLayout state,
        HeaderLayout layout,
        RuntimeHeaderMutation mutation,
        byte completionBit,
        string marker)
    {
        uint scratchRva = ctx.AllocData(16, 8);
        AntiDebugPass.BuiltRoutine Build(uint selfRva)
        {
            var a = new Asm();

            // Entry RSP is 8 mod 16. Two saves plus 0x28 bytes of shadow/local
            // space align both calls while retaining the two nonvolatile bases.
            var pushes = new List<(Reg, byte)>();
            a.PushR(Reg.R14); pushes.Add((Reg.R14, (byte)a.Position));
            a.PushR(Reg.R15); pushes.Add((Reg.R15, (byte)a.Position));
            a.SubRi(Reg.Rsp, 0x28);
            byte prologEnd = (byte)a.Position;
            a.LoadRuntimeBase(Reg.R15, selfRva); // mapped image base
            a.MovRr(Reg.R14, Reg.R15).AddRi(Reg.R14, checked((int)state.Rva));

            EmitVirtualProtectCall(a, layout.HeaderBytes, newProtection: 0x04, "old_protect"); // PAGE_READWRITE
            a.Test32Rr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "done");

            a.XorRr(Reg.Rax, Reg.Rax);
            switch (mutation)
            {
                case RuntimeHeaderMutation.RuntimeSignature:
                    // Preserve the DOS body and e_lfanew. Only the two identity
                    // signatures are cleared, as promised by this setting.
                    a.MovMr8(Reg.R15, Reg.Rax, 0);
                    a.MovMr8(Reg.R15, Reg.Rax, 1);
                    a.MovMr32(Reg.R15, Reg.Rax, layout.PeOffset);
                    break;

                case RuntimeHeaderMutation.RawReconstruction:
                    // Read NumberOfSections at runtime from the mapped COFF header
                    // so sections added by later passes (e.g. .reloc) are also covered.
                    a.MovRm32(Reg.Rcx, Reg.R15, layout.PeOffset + 6).AndRi(Reg.Rcx, 0xFFFF);
                    a.LeaRd(Reg.Rdx, Reg.R15, layout.SectionTableOffset);
                    a.Label("raw_loop");
                    a.Test32Rr(Reg.Rcx, Reg.Rcx).Jcc(Cc.E, "raw_done");
                    // Clear only file-reconstruction metadata: name, raw size/location,
                    // COFF relocation/line pointers, and their counts. VirtualSize,
                    // VirtualAddress, and Characteristics remain intact.
                    a.MovMr(Reg.Rdx, Reg.Rax, 0);
                    a.MovMr(Reg.Rdx, Reg.Rax, 16);
                    a.MovMr(Reg.Rdx, Reg.Rax, 24);
                    a.MovMr32(Reg.Rdx, Reg.Rax, 32);
                    a.AddRi(Reg.Rdx, 40).DecR(Reg.Rcx).Jmp("raw_loop");
                    a.Label("raw_done");
                    break;

                case RuntimeHeaderMutation.SectionTable:
                    a.MovRm32(Reg.Rcx, Reg.R15, layout.PeOffset + 6).AndRi(Reg.Rcx, 0xFFFF);
                    a.LeaRd(Reg.Rdx, Reg.R15, layout.SectionTableOffset);
                    a.Label("sec_loop");
                    a.Test32Rr(Reg.Rcx, Reg.Rcx).Jcc(Cc.E, "sec_done");
                    for (int qword = 0; qword < 5; qword++)
                        a.MovMr(Reg.Rdx, Reg.Rax, qword * 8);
                    a.AddRi(Reg.Rdx, 40).DecR(Reg.Rcx).Jmp("sec_loop");
                    a.Label("sec_done");
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(mutation));
            }

            // Restore the exact page protection returned by the first call.
            a.MovRr(Reg.Rcx, Reg.R15);
            a.MovRi(Reg.Rdx, layout.HeaderBytes);
            a.MovRip(Reg.R8, "old_protect");
            a.LeaRip(Reg.R9, "restore_scratch");
            a.CallRip("ext::VirtualProtect");
            a.Test32Rr(Reg.Rax, Reg.Rax).Jcc(Cc.E, "done");

            // Atomically record completion only after Windows confirms restoration.
            a.LockBtsMi(Reg.R14, RuntimeDetectionStateLayout.PolicyStatusOffset, completionBit);

            a.Label("done");
            a.AddRi(Reg.Rsp, 0x28).PopR(Reg.R15).PopR(Reg.R14).Ret();
            int codeEnd = a.Position;
            a.Align(8).Label("old_protect").Dq(0);
            a.Label("restore_scratch").Dq(0);
            a.Db(Encoding.ASCII.GetBytes(marker + "\0"));
            a.Align(8).Label("ext::VirtualProtect").Dq(0);
            return new AntiDebugPass.BuiltRoutine(a, codeEnd, AntiDebugPass.BuildUnwindInfo(pushes, 0x28, prologEnd));

            void EmitVirtualProtectCall(Asm asm, uint size, int newProtection, string oldProtectionLabel)
            {
                asm.MovRr(Reg.Rcx, Reg.R15);
                asm.MovRi(Reg.Rdx, size);
                asm.MovRi(Reg.R8, newProtection);
                asm.LeaRip(Reg.R9, oldProtectionLabel);
                asm.CallRip("ext::VirtualProtect");
            }
        }

        AntiDebugPass.BuiltRoutine probe = Build(0);
        int size = probe.Assembler.Assemble().Length;
        uint routineRva = ctx.Alloc(size, 16);
        AntiDebugPass.BuiltRoutine built = Build(routineRva);
        Asm assembler = built.Assembler;
        byte[] code = assembler.Assemble();
        if (code.Length != size)
            throw new InvalidOperationException("Runtime-header routine size shifted between layout passes.");

        foreach (var (position, target, _) in assembler.RipFixups)
        {
            if (!string.Equals(target, "ext::VirtualProtect", StringComparison.Ordinal))
                continue;
            long displacement = (long)virtualProtectIat - ((long)routineRva + position + 4);
            if (displacement is < int.MinValue or > int.MaxValue)
                throw new InvalidOperationException("VirtualProtect IAT slot is outside RIP-relative range.");
            BinaryPrimitives.WriteInt32LittleEndian(code.AsSpan(position), checked((int)displacement));
        }

        BuildContext.PatchRipReferences(code, assembler, routineRva,
            new Dictionary<string, uint>
            {
                ["old_protect"] = scratchRva,
                ["restore_scratch"] = scratchRva + 8,
            });

        ctx.WriteStub(routineRva, code);
        ExceptionTableBuilder.Register(ctx, routineRva, checked(routineRva + (uint)built.CodeEnd), built.UnwindInfo!);
        return routineRva;
    }

    private sealed record HeaderLayout(
        int PeOffset,
        int SectionTableOffset,
        uint HeaderBytes);

    private enum RuntimeHeaderMutation
    {
        RuntimeSignature,
        RawReconstruction,
        SectionTable,
    }
}
