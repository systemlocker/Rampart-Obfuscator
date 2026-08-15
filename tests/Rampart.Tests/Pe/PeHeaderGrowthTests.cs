using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Pe;

public class PeHeaderGrowthTests
{
    [Fact]
    public void AddingManySectionsGrowsHeadersWithoutChangingOriginalData()
    {
        var pe = PeImage.Load(SamplePeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 19)));
        PeImage.Section text = pe.Sections.Single(section => section.Name == ".text");
        byte[] originalText = text.Data.ToArray();
        uint originalRawPointer = text.PointerToRawData;

        for (int i = 0; i < 18; i++)
        {
            pe.AddSection($".x{i:X2}", 17,
                SectionCharacteristics.CntInitializedData | SectionCharacteristics.MemRead);
        }

        Assert.True(text.PointerToRawData > originalRawPointer);
        var roundTripped = PeImage.Load(pe.ToBytes());
        Assert.Equal(originalText, roundTripped.Sections.Single(section => section.Name == ".text").Data);
        Assert.True(roundTripped.SizeOfHeaders > 0x400);
    }
}
