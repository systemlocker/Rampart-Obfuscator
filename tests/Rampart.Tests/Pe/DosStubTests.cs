using System.Buffers.Binary;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Pe;

public class DosStubTests
{
    [Fact]
    public void ImmediateScrubAllowsLaterDecoyDataToSurvive()
    {
        var pe = PeImage.Load(TestPeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40)));
        byte[] decoy = "example.pdb\0"u8.ToArray();

        pe.ScrubDosStubContent();
        pe.WriteDosStub(0x60, decoy);
        byte[] output = pe.ToBytes();

        Assert.Equal(PeImage.DosMagic, BinaryPrimitives.ReadUInt16LittleEndian(output));
        Assert.Equal(0x80, BinaryPrimitives.ReadInt32LittleEndian(output.AsSpan(0x3C)));
        Assert.Equal(decoy, output.AsSpan(0x60, decoy.Length).ToArray());
        Assert.All(output[0x40..0x60], b => Assert.Equal((byte)0, b));
    }
}
