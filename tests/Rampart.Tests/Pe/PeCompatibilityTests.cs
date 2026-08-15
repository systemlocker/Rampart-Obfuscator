using Rampart.Engine;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Pe;

public class PeCompatibilityTests
{
    [Fact]
    public void NativeSampleIsCompatible()
    {
        var pe = PeImage.Load(BuildSample());
        PeCompatibility.Validate(pe);
    }

    [Fact]
    public void ManagedImageIsRejected()
    {
        var pe = PeImage.Load(BuildSample());
        pe.SetDirectory(DataDir.ComDescriptor, pe.EntryPointRva, 16);

        Assert.Throws<NotSupportedException>(() => PeCompatibility.Validate(pe));
    }

    [Fact]
    public void DllImageIsRejected()
    {
        var pe = PeImage.Load(BuildSample());
        pe.Characteristics |= 0x2000;

        Assert.Throws<NotSupportedException>(() => PeCompatibility.Validate(pe));
    }

    [Fact]
    public void AlreadyProtectedImageIsRejected()
    {
        var pe = PeImage.Load(BuildSample());
        pe.AddSection(".rmpt", 512, SectionCharacteristics.CntCode | SectionCharacteristics.MemExecute);

        Assert.Throws<InvalidOperationException>(() => PeCompatibility.Validate(pe));
    }

    [Fact]
    public void LowAlignmentImageUsesDeclaredSectionAlignment()
    {
        var pe = PeImage.Load(BuildSample());
        pe.FileAlignment = 0x200;
        pe.SectionAlignment = 0x200;

        PeImage.Section added = pe.AddSection(
            ".low",
            0x201,
            SectionCharacteristics.CntInitializedData | SectionCharacteristics.MemRead);

        Assert.Equal(0u, added.VirtualAddress % 0x200);
        Assert.Equal(0x400u, added.SizeOfRawData);
        _ = PeCompatibility.Inspect(pe);
    }

    [Fact]
    public void InvalidLowAlignmentCombinationIsRejected()
    {
        var pe = PeImage.Load(BuildSample());
        pe.FileAlignment = 0x200;
        pe.SectionAlignment = 0x400;

        Assert.Throws<BadImageFormatException>(() => PeCompatibility.Inspect(pe));
    }

    private static byte[] BuildSample() =>
        SamplePeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40));
}
