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
        byte[] input = SamplePeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40));
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
}
