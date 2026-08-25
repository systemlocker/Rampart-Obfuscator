using System.Buffers.Binary;
using System.Diagnostics;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Engine.Passes;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Engine;

public class StaticAnalysisDenialPassTests
{
    [Fact]
    public void IdaBombEmitsBoundedValidFunctionsAndInternalXrefs()
    {
        BuildContext context = CreateContext("analysis.ida-bomb", seed: 101);
        uint originalEntryPoint = context.Pe.EntryPointRva;
        byte[] originalEntryBytes = context.Pe.ReadRva(originalEntryPoint, 16);

        new IdaBombPass().Run(context);

        PeImage.Section section = Assert.Single(context.Pe.Sections, s => s.Name == ".rida");
        Assert.Equal(256u * 32u, section.VirtualSize);
        for (int index = 0; index < 256; index++)
        {
            ReadOnlySpan<byte> body = section.Data.AsSpan(index * 32, 32);
            Assert.Equal(new byte[] { 0x55, 0x48, 0x89, 0xE5 }, body[..4].ToArray());
            Assert.Equal((byte)0x74, body[16]);
            Assert.Equal((byte)0xE8, body[18]);
            Assert.Equal((byte)0x5D, body[23]);
            Assert.Equal((byte)0xC3, body[24]);

            int displacement = BinaryPrimitives.ReadInt32LittleEndian(body[19..]);
            int target = index * 32 + 23 + displacement;
            Assert.InRange(target, 0, 255 * 32);
            Assert.Equal(0, target % 32);
        }

        Assert.Equal(originalEntryPoint, context.Pe.EntryPointRva);
        Assert.Equal(originalEntryBytes, context.Pe.ReadRva(originalEntryPoint, 16));
    }

    [Fact]
    public void HexRaysDenialEmitsOpaqueDispatchersWithValidRelativeTables()
    {
        BuildContext context = CreateContext("analysis.hexrays-denial", seed: 202);

        new HexRaysDenialPass().Run(context);

        PeImage.Section section = Assert.Single(context.Pe.Sections, s => s.Name == ".rhx");
        Assert.Equal(64u * 96u, section.VirtualSize);
        for (int index = 0; index < 64; index++)
        {
            ReadOnlySpan<byte> body = section.Data.AsSpan(index * 96, 96);
            Assert.Equal(new byte[] { 0x48, 0x8D, 0x15 }, body[4..7].ToArray());
            Assert.Equal(64 - 11, BinaryPrimitives.ReadInt32LittleEndian(body[7..]));
            Assert.Equal(new byte[] { 0x48, 0x63, 0x04, 0x82, 0x48, 0x01, 0xD0, 0xFF, 0xE0 },
                body[32..41].ToArray());

            for (int slot = 0; slot < 4; slot++)
            {
                int relativeTarget = BinaryPrimitives.ReadInt32LittleEndian(body[(64 + slot * 4)..]);
                Assert.Contains(64 + relativeTarget, new[] { 25, 32 });
            }
        }
    }

    [Fact]
    public void SymbolicDenialIsBoundedAndMutatesWithTheSeed()
    {
        BuildContext first = CreateContext("analysis.symbolic-denial", seed: 303);
        BuildContext second = CreateContext("analysis.symbolic-denial", seed: 404);

        new SymbolicDenialPass().Run(first);
        new SymbolicDenialPass().Run(second);

        PeImage.Section firstSection = Assert.Single(first.Pe.Sections, s => s.Name == ".rsym");
        PeImage.Section secondSection = Assert.Single(second.Pe.Sections, s => s.Name == ".rsym");
        Assert.Equal(48u * 128u, firstSection.VirtualSize);
        Assert.Equal((byte)0x53, firstSection.Data[0]); // push rbx
        Assert.Equal((byte)0xC3, firstSection.Data.Take(128).Last(b => b != 0xCC));
        Assert.False(firstSection.Data.SequenceEqual(secondSection.Data));
    }

    [Fact]
    public void StaticDecodeDenialUsesGenuineOverlappingInstructionEntries()
    {
        BuildContext context = CreateContext("analysis.static-decode-denial", seed: 505);

        new StaticDecodeDenialPass().Run(context);

        PeImage.Section section = Assert.Single(context.Pe.Sections, s => s.Name == ".rdec");
        Assert.Equal(256u * 16u, section.VirtualSize);
        for (int index = 0; index < 256; index++)
        {
            ReadOnlySpan<byte> gadget = section.Data.AsSpan(index * 16, 16);
            Assert.Equal((byte)0xEB, gadget[0]);
            Assert.Equal((byte)0xFF, gadget[1]);
            Assert.InRange(gadget[2], (byte)0xC0, (byte)0xC7);
            Assert.Equal((byte)0xC3, gadget[3]);
            Assert.Equal((byte)0x31, gadget[8]);
            Assert.Equal((byte)0xC3, gadget[10]);
        }
    }

    [Fact]
    public void CombinedColdAnalysisSectionsRoundTripAndPreserveExecutionOnWindows()
    {
        BuildContext context = CreateContext(
            "analysis.ida-bomb",
            "analysis.hexrays-denial",
            "analysis.symbolic-denial",
            "analysis.static-decode-denial");
        uint originalEntryPoint = context.Pe.EntryPointRva;
        byte[] originalEntryBytes = context.Pe.ReadRva(originalEntryPoint, 24);

        new IdaBombPass().Run(context);
        new HexRaysDenialPass().Run(context);
        new SymbolicDenialPass().Run(context);
        new StaticDecodeDenialPass().Run(context);

        byte[] output = context.Pe.ToBytes();
        PeImage reloaded = PeImage.Load(output);
        Assert.Equal(7, reloaded.Sections.Count);
        Assert.Equal(originalEntryPoint, reloaded.EntryPointRva);
        Assert.Equal(originalEntryBytes, reloaded.ReadRva(originalEntryPoint, originalEntryBytes.Length));

        if (!OperatingSystem.IsWindows())
            return;

        string directory = Path.Combine(Path.GetTempPath(), $"rampart-analysis-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        string path = Path.Combine(directory, "analysis-protected.exe");
        try
        {
            File.WriteAllBytes(path, output);
            using Process? process = Process.Start(new ProcessStartInfo(path)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            Assert.NotNull(process);
            Assert.True(process.WaitForExit(10_000), "Analysis-protected fixture did not exit within ten seconds.");
            Assert.Equal(40, process.ExitCode);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void PassesStayOffWithoutTheirKnob()
    {
        byte[] input = BuildFixture();
        var settings = new ProtectionSettings { Preset = Presets.Light, Seed = 606 };
        settings.Knobs["analysis.ida-bomb"] = ProtectionLevel.Off;
        settings.Knobs["analysis.hexrays-denial"] = ProtectionLevel.Off;
        settings.Knobs["analysis.symbolic-denial"] = ProtectionLevel.Off;
        settings.Knobs["analysis.static-decode-denial"] = ProtectionLevel.Off;
        var context = new BuildContext(PeImage.Load(input), settings, KnobCatalog.Load());
        context.Analyze();
        int originalSections = context.Pe.Sections.Count;

        new IdaBombPass().Run(context);
        new HexRaysDenialPass().Run(context);
        new SymbolicDenialPass().Run(context);
        new StaticDecodeDenialPass().Run(context);

        Assert.Equal(originalSections, context.Pe.Sections.Count);
    }

    private static BuildContext CreateContext(string knobId, long seed = 777) =>
        CreateContext([knobId], seed);

    private static BuildContext CreateContext(params string[] knobIds) =>
        CreateContext(knobIds, seed: 777);

    private static BuildContext CreateContext(string[] knobIds, long seed)
    {
        var settings = new ProtectionSettings { Preset = Presets.Light, Seed = seed };
        foreach (string knobId in knobIds)
            settings.Knobs[knobId] = ProtectionLevel.Light;

        var context = new BuildContext(PeImage.Load(BuildFixture()), settings, KnobCatalog.Load());
        context.Analyze();
        return context;
    }

    private static byte[] BuildFixture() => TestPeBuilder.Build(ctx =>
    {
        ctx.Code.MovRi(Reg.Rax, 40);
    });
}
