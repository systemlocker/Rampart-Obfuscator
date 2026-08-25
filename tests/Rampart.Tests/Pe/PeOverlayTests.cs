using Rampart.Pe;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Pe;

public class PeOverlayTests
{
    [Fact]
    public void OverlaySurvivesRoundTripAndSectionAddition()
    {
        byte[] image = TestPeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40));
        byte[] overlay = "EXAMPLE-APP-ASSET-OVERLAY"u8.ToArray();
        byte[] withOverlay = [.. image, .. overlay];
        var pe = PeImage.Load(withOverlay);
        pe.SetDirectory(DataDir.Security, (uint)image.Length, (uint)overlay.Length);

        Assert.Equal(overlay.Length, pe.OverlaySize);
        byte[] roundTripped = pe.ToBytes();
        Assert.Equal(overlay, roundTripped[^overlay.Length..]);

        pe.AddSection(".extra", 512, SectionCharacteristics.CntInitializedData | SectionCharacteristics.MemRead);
        byte[] expanded = pe.ToBytes();
        Assert.Equal(overlay, expanded[^overlay.Length..]);
        var expandedPe = PeImage.Load(expanded);
        Assert.Equal(overlay.Length, expandedPe.OverlaySize);
        Assert.Equal((uint)(expanded.Length - overlay.Length),
            expandedPe.Directory(DataDir.Security).RelativeVirtualAddress);
    }

    [Fact]
    public void MultiMegabyteOverlaySurvivesProtectionByteForByte()
    {
        byte[] image = TestPeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40));
        byte[] overlay = Enumerable.Range(0, 2 * 1024 * 1024)
            .Select(index => (byte)(index * 31))
            .ToArray();
        byte[] input = [.. image, .. overlay];
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        settings.Seed = 42;

        byte[] output = new Protector().Protect(input, settings).Output;

        Assert.Equal(overlay, output[^overlay.Length..]);
        Assert.Equal(overlay.Length, PeImage.Load(output).OverlaySize);
    }
}
