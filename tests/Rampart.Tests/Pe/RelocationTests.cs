using System.Buffers.Binary;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Pe;

public class RelocationTests
{
    [Fact]
    public void RebuiltDirectoryRoundTripsAddedDir64Slots()
    {
        byte[] input = SamplePeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40));
        var pe = PeImage.Load(input);
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        var context = new BuildContext(pe, settings, KnobCatalog.Load());
        uint first = context.AllocPointerSlot();
        uint second = context.AllocPointerSlot();

        RelocBuilder.Rebuild(context);
        var roundTripped = PeImage.Load(pe.ToBytes());
        var entries = Relocations.Enumerate(roundTripped).ToList();

        Assert.Contains(new RelocEntry(first, Relocations.TypeAbsolute), entries);
        Assert.Contains(new RelocEntry(second, Relocations.TypeAbsolute), entries);
    }

    [Fact]
    public void TlsDirectoryAbsoluteFieldsReceiveDir64Relocations()
    {
        byte[] input = SamplePeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40));
        var pe = PeImage.Load(input);
        var context = new BuildContext(
            pe,
            ProtectionSettings.FromPreset(Presets.Light),
            KnobCatalog.Load());
        uint callbackRva = context.Alloc(1, 16);
        context.WriteStub(callbackRva, [0xC3]);

        TlsBuilder.Install(context, callbackRva);
        var tls = pe.Directory(DataDir.Tls);

        Assert.Contains(tls.RelativeVirtualAddress + 16, context.RelocSlots);
        Assert.Contains(tls.RelativeVirtualAddress + 24, context.RelocSlots);
    }

    [Fact]
    public void TlsChainingPreservesExistingRawDataAndIndexFields()
    {
        byte[] input = SamplePeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40));
        var pe = PeImage.Load(input);
        var context = new BuildContext(
            pe,
            ProtectionSettings.FromPreset(Presets.Light),
            KnobCatalog.Load());

        uint rawStart = context.Alloc(16, 8);
        uint index = context.Alloc(8, 8);
        uint oldCallback = context.Alloc(1, 16);
        context.WriteStub(oldCallback, [0xC3]);
        uint oldCallbacks = context.Alloc(16, 8);
        context.WriteStub(oldCallbacks, BitConverter.GetBytes(pe.ImageBase + oldCallback));

        uint oldDirectory = context.Alloc(40, 8);
        var oldBlob = new byte[40];
        BinaryPrimitives.WriteUInt64LittleEndian(oldBlob, pe.ImageBase + rawStart);
        BinaryPrimitives.WriteUInt64LittleEndian(oldBlob.AsSpan(8), pe.ImageBase + rawStart + 16);
        BinaryPrimitives.WriteUInt64LittleEndian(oldBlob.AsSpan(16), pe.ImageBase + index);
        BinaryPrimitives.WriteUInt64LittleEndian(oldBlob.AsSpan(24), pe.ImageBase + oldCallbacks);
        BinaryPrimitives.WriteUInt32LittleEndian(oldBlob.AsSpan(32), 24);
        BinaryPrimitives.WriteUInt32LittleEndian(oldBlob.AsSpan(36), 0x0040_0000);
        context.WriteStub(oldDirectory, oldBlob);
        pe.SetDirectory(DataDir.Tls, oldDirectory, 40);

        uint newCallback = context.Alloc(1, 16);
        context.WriteStub(newCallback, [0xC3]);
        TlsBuilder.Install(context, newCallback);

        var newDirectory = pe.Directory(DataDir.Tls);
        byte[] rebuilt = pe.ReadRva(newDirectory.RelativeVirtualAddress, 40);
        Assert.Equal(pe.ImageBase + rawStart, BinaryPrimitives.ReadUInt64LittleEndian(rebuilt));
        Assert.Equal(pe.ImageBase + rawStart + 16, BinaryPrimitives.ReadUInt64LittleEndian(rebuilt.AsSpan(8)));
        Assert.Equal(pe.ImageBase + index, BinaryPrimitives.ReadUInt64LittleEndian(rebuilt.AsSpan(16)));
        Assert.Equal(24u, BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.AsSpan(32)));
        Assert.Equal(0x0040_0000u, BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.AsSpan(36)));

        uint callbacksRva = pe.VaToRva(BinaryPrimitives.ReadUInt64LittleEndian(rebuilt.AsSpan(24)));
        Assert.Equal(pe.ImageBase + newCallback, pe.ReadU64(callbacksRva));
        Assert.Equal(pe.ImageBase + oldCallback, pe.ReadU64(callbacksRva + 8));
        Assert.Equal(0ul, pe.ReadU64(callbacksRva + 16));

        Assert.Contains(newDirectory.RelativeVirtualAddress, context.RelocSlots);
        Assert.Contains(newDirectory.RelativeVirtualAddress + 8, context.RelocSlots);
        Assert.Contains(newDirectory.RelativeVirtualAddress + 16, context.RelocSlots);
        Assert.Contains(newDirectory.RelativeVirtualAddress + 24, context.RelocSlots);
    }
}
