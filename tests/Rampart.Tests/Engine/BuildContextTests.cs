using Rampart.Config;
using Rampart.Engine;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Engine;

public class BuildContextTests
{
    [Fact]
    public void StubSectionGrowsWithoutLosingEarlierAllocations()
    {
        byte[] input = TestPeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40));
        var pe = PeImage.Load(input);
        var context = new BuildContext(
            pe,
            ProtectionSettings.FromPreset(Presets.Light),
            KnobCatalog.Load());

        uint first = context.Alloc(4000, 16);
        byte[] firstPayload = Enumerable.Repeat((byte)0xA5, 4000).ToArray();
        context.WriteStub(first, firstPayload);
        uint second = context.Alloc(5000, 16);
        byte[] secondPayload = Enumerable.Repeat((byte)0x5A, 5000).ToArray();
        context.WriteStub(second, secondPayload);

        var reloaded = PeImage.Load(pe.ToBytes());
        Assert.Equal(firstPayload, reloaded.ReadRva(first, firstPayload.Length));
        Assert.Equal(secondPayload, reloaded.ReadRva(second, secondPayload.Length));
        Assert.True(context.Stub!.Data.Length >= 9000);
        Assert.Equal((uint)context.Stub.Data.Length, context.Stub.SizeOfRawData);
    }

    [Fact]
    public void ProtectorSectionsNeverCombineWriteAndExecutePermissions()
    {
        byte[] input = TestPeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40));
        var context = new BuildContext(
            PeImage.Load(input),
            ProtectionSettings.FromPreset(Presets.Light),
            KnobCatalog.Load());

        uint code = context.Alloc(32, 16);
        context.WriteStub(code, Enumerable.Repeat((byte)0x90, 32).ToArray());
        uint data = context.AllocData(32, 16);
        context.WriteData(data, Enumerable.Repeat((byte)0xA5, 32).ToArray());

        PeImage reloaded = PeImage.Load(context.Pe.ToBytes());
        PeImage.Section stub = Assert.Single(reloaded.Sections, section => section.Name == ".rmpt");
        PeImage.Section state = Assert.Single(reloaded.Sections, section => section.Name == ".rmpd");
        Assert.True(stub.Characteristics.HasFlag(SectionCharacteristics.MemExecute));
        Assert.False(stub.Characteristics.HasFlag(SectionCharacteristics.MemWrite));
        Assert.True(state.Characteristics.HasFlag(SectionCharacteristics.MemWrite));
        Assert.False(state.Characteristics.HasFlag(SectionCharacteristics.MemExecute));
        Assert.DoesNotContain(reloaded.Sections.Where(section => section.Name is ".rmpt" or ".rmpd"), section =>
            section.Characteristics.HasFlag(SectionCharacteristics.MemWrite)
            && section.Characteristics.HasFlag(SectionCharacteristics.MemExecute));
    }
}
