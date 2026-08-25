using System.Buffers.Binary;
using System.Diagnostics;
using System.Text;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Engine.Passes;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Engine;

public class RuntimeHeaderProtectionPassTests
{
    [Theory]
    [InlineData("analysis.runtime-header-corruption", "RMPT.HDR.RUNTIME")]
    [InlineData("memory.anti-dump", "RMPT.HDR.ANTIDUMP")]
    [InlineData("integrity.header-scrub", "RMPT.HDR.INTEGRITY")]
    public void EachKnobEmitsAnIndependentVirtualProtectRoutine(string knob, string marker)
    {
        BuildContext context = CreateContext(BuildFixture(HeaderExpectation.None), knob);
        byte[] original = context.Pe.ToBytes();

        new RuntimeHeaderProtectionPass().Run(context);

        Assert.Single(context.InitChain);
        Assert.Contains(
            ImportTable.Parse(context.Pe),
            imported => string.Equals(imported.Name, "VirtualProtect", StringComparison.Ordinal));
        Assert.NotNull(context.Stub);
        Assert.True(Contains(context.Stub!.Data, Encoding.ASCII.GetBytes(marker + "\0")));
        Assert.NotNull(context.Data);
        Assert.True(Contains(context.Data!.Data, "RMPSTATE"u8.ToArray()));

        // One call opens the mapped-header range and another restores the exact
        // protection value returned through old_protect.
        Assert.Equal(2, Count(context.Stub.Data, [0xFF, 0x15]));

        // The emitter changes only startup code and imports on disk. Windows
        // still receives valid headers; mutations happen to the mapped image.
        byte[] emitted = context.Pe.ToBytes();
        Assert.Equal(PeImage.DosMagic, BinaryPrimitives.ReadUInt16LittleEndian(emitted));
        int peOffset = BinaryPrimitives.ReadInt32LittleEndian(emitted.AsSpan(0x3C));
        Assert.Equal(PeImage.PeSignature, BinaryPrimitives.ReadUInt32LittleEndian(emitted.AsSpan(peOffset)));

        int originalPeOffset = BinaryPrimitives.ReadInt32LittleEndian(original.AsSpan(0x3C));
        int originalSectionTable = originalPeOffset + 4 + 20 + 0xF0;
        Assert.Equal(".text", Encoding.ASCII.GetString(original, originalSectionTable, 8).TrimEnd('\0'));
        Assert.NotEqual(0u, BinaryPrimitives.ReadUInt32LittleEndian(original.AsSpan(originalSectionTable + 16)));
    }

    [Fact]
    public void AllHeaderProtectionsCanBeEmittedTogetherWithoutSharingRoutines()
    {
        BuildContext context = CreateContext(
            BuildFixture(HeaderExpectation.None),
            "analysis.runtime-header-corruption",
            "memory.anti-dump",
            "integrity.header-scrub");

        new RuntimeHeaderProtectionPass().Run(context);

        Assert.Equal(3, context.InitChain.Count);
        Assert.True(Contains(context.Stub!.Data, "RMPT.HDR.RUNTIME\0"u8.ToArray()));
        Assert.True(Contains(context.Stub.Data, "RMPT.HDR.ANTIDUMP\0"u8.ToArray()));
        Assert.True(Contains(context.Stub.Data, "RMPT.HDR.INTEGRITY\0"u8.ToArray()));
        Assert.Equal(6, Count(context.Stub.Data, [0xFF, 0x15]));
    }

    [Theory]
    [InlineData("analysis.runtime-header-corruption", HeaderExpectation.Signatures)]
    [InlineData("memory.anti-dump", HeaderExpectation.RawReconstruction)]
    [InlineData("integrity.header-scrub", HeaderExpectation.SectionTable)]
    public void EachRuntimeMutationOccursBeforeOriginalEntryAndPreservesExecution(
        string knob,
        HeaderExpectation expectation)
    {
        if (!OperatingSystem.IsWindows())
            return;

        BuildContext context = CreateContext(BuildFixture(expectation), knob);
        new RuntimeHeaderProtectionPass().Run(context);
        new EntryPointPass().Run(context);
        RelocBuilder.Rebuild(context);
        byte[] output = context.Pe.ToBytes();

        string directory = Path.Combine(Path.GetTempPath(), $"rampart-header-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "header-protected.exe");
        try
        {
            File.WriteAllBytes(path, output);
            using Process? process = Process.Start(new ProcessStartInfo(path)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            Assert.NotNull(process);
            Assert.True(process.WaitForExit(10_000), "Runtime-header fixture did not exit within ten seconds.");
            Assert.Equal(40, process.ExitCode);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void PassStaysOffWithoutAnExplicitHeaderKnob()
    {
        byte[] input = BuildFixture(HeaderExpectation.None);
        var settings = new ProtectionSettings { Preset = Presets.Light, Seed = 919 };
        var context = new BuildContext(PeImage.Load(input), settings, KnobCatalog.Load());
        context.Analyze();

        new RuntimeHeaderProtectionPass().Run(context);

        Assert.Empty(context.InitChain);
        Assert.Null(context.Stub);
    }

    private static BuildContext CreateContext(byte[] input, params string[] knobs)
    {
        var settings = new ProtectionSettings { Preset = Presets.Light, Seed = 818 };
        settings.Knobs["packaging.ep-confusion"] = ProtectionLevel.Light;
        foreach (string knob in knobs)
            settings.Knobs[knob] = ProtectionLevel.Light;
        var context = new BuildContext(PeImage.Load(input), settings, KnobCatalog.Load());
        context.Analyze();
        return context;
    }

    private static byte[] BuildFixture(HeaderExpectation expectation) => TestPeBuilder.Build(ctx =>
    {
        const int PeOffset = 0x80;
        const int SectionTable = PeOffset + 4 + 20 + 0xF0;
        Asm a = ctx.Code;
        a.LoadRuntimeBase(Reg.Rbx, 0x1000);

        switch (expectation)
        {
            case HeaderExpectation.None:
                break;

            case HeaderExpectation.Signatures:
                ExpectZero32(a, 0);
                ExpectZero32(a, PeOffset);
                break;

            case HeaderExpectation.RawReconstruction:
                ExpectZero64(a, SectionTable + 0);  // section name
                ExpectZero64(a, SectionTable + 16); // raw size + raw pointer
                ExpectZero64(a, SectionTable + 24); // COFF raw pointers
                ExpectZero32(a, SectionTable + 32); // COFF counts
                ExpectEqual32(a, SectionTable + 12, 0x1000); // VirtualAddress retained
                ExpectNonZero32(a, SectionTable + 36);       // Characteristics retained
                break;

            case HeaderExpectation.SectionTable:
                for (int offset = 0; offset < 40; offset += 8)
                    ExpectZero64(a, SectionTable + offset);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(expectation));
        }

        a.MovRi(Reg.Rax, 40).Jmp("header_check_done");
        a.Label("header_check_failed").MovRi(Reg.Rax, 41);
        a.Label("header_check_done");

        static void ExpectZero64(Asm code, int offset) =>
            code.MovRm(Reg.Rax, Reg.Rbx, offset)
                .TestRr(Reg.Rax, Reg.Rax)
                .Jcc(Cc.Ne, "header_check_failed");

        static void ExpectZero32(Asm code, int offset) =>
            code.MovRm32(Reg.Rax, Reg.Rbx, offset)
                .TestRr(Reg.Rax, Reg.Rax)
                .Jcc(Cc.Ne, "header_check_failed");

        static void ExpectNonZero32(Asm code, int offset) =>
            code.MovRm32(Reg.Rax, Reg.Rbx, offset)
                .TestRr(Reg.Rax, Reg.Rax)
                .Jcc(Cc.E, "header_check_failed");

        static void ExpectEqual32(Asm code, int offset, long expected) =>
            code.MovRm32(Reg.Rax, Reg.Rbx, offset)
                .MovRi(Reg.Rdx, expected)
                .CmpRr(Reg.Rax, Reg.Rdx)
                .Jcc(Cc.Ne, "header_check_failed");
    });

    private static bool Contains(byte[] haystack, byte[] needle) =>
        haystack.AsSpan().IndexOf(needle) >= 0;

    private static int Count(byte[] haystack, byte[] needle)
    {
        int count = 0;
        int offset = 0;
        while (offset <= haystack.Length - needle.Length)
        {
            int found = haystack.AsSpan(offset).IndexOf(needle);
            if (found < 0)
                break;
            count++;
            offset += found + needle.Length;
        }
        return count;
    }

    public enum HeaderExpectation
    {
        None,
        Signatures,
        RawReconstruction,
        SectionTable,
    }
}
