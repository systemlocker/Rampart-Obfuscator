using System.Buffers.Binary;
using System.Text;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Pe;

public class PeMetadataCompatibilityTests
{
    [Fact]
    public void DelayBoundLoadConfigCfgAndCetMetadataSurviveProtection()
    {
        var inputPe = PeImage.Load(SamplePeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40)));
        PeImage.Section metadata = inputPe.AddSection(
            ".compat",
            0x400,
            SectionCharacteristics.CntInitializedData | SectionCharacteristics.MemRead);

        uint delayRva = metadata.VirtualAddress;
        var delay = new byte[64];
        BinaryPrimitives.WriteUInt32LittleEndian(delay, 1); // dlattrRva
        inputPe.WriteRva(delayRva, delay);
        inputPe.SetDirectory(DataDir.DelayImport, delayRva, (uint)delay.Length);

        uint boundRva = metadata.VirtualAddress + 0x80;
        var bound = new byte[32];
        BinaryPrimitives.WriteUInt32LittleEndian(bound, 0x12345678);
        BinaryPrimitives.WriteUInt16LittleEndian(bound.AsSpan(4), 16);
        Encoding.ASCII.GetBytes("KERNEL32.dll\0").CopyTo(bound, 16);
        inputPe.WriteRva(boundRva, bound);
        inputPe.SetDirectory(DataDir.BoundImport, boundRva, (uint)bound.Length);

        uint loadConfigRva = metadata.VirtualAddress + 0x100;
        var loadConfig = new byte[0xA0];
        BinaryPrimitives.WriteUInt32LittleEndian(loadConfig, (uint)loadConfig.Length);
        ImageGuardFlags flags = ImageGuardFlags.CfInstrumented
            | ImageGuardFlags.CfFunctionTablePresent
            | ImageGuardFlags.EhContinuationTablePresent;
        BinaryPrimitives.WriteUInt32LittleEndian(loadConfig.AsSpan(0x90), (uint)flags);
        inputPe.WriteRva(loadConfigRva, loadConfig);
        inputPe.SetDirectory(DataDir.LoadConfig, loadConfigRva, (uint)loadConfig.Length);
        inputPe.DllChars |= DllCharacteristics.GuardCf;

        PeCompatibilityFeatures before = PeCompatibility.Inspect(inputPe);
        Assert.Equal(1, before.DelayImportDescriptors);
        Assert.Equal(1, before.BoundImportDescriptors);
        Assert.True(before.GuardCf);
        Assert.True(before.CetContinuationMetadata);

        byte[] input = inputPe.ToBytes();
        var settings = ProtectionSettings.FromPreset(Presets.Light);
        settings.Seed = 12345;
        var outputPe = PeImage.Load(new Protector().Protect(input, settings).Output);
        PeCompatibilityFeatures after = PeCompatibility.Inspect(outputPe);

        Assert.Equal(before, after);
        Assert.Equal(delay, outputPe.ReadRva(delayRva, delay.Length));
        Assert.Equal(bound, outputPe.ReadRva(boundRva, bound.Length));
        byte[] protectedLoadConfig = outputPe.ReadRva(loadConfigRva, loadConfig.Length);
        Assert.Equal(loadConfig.AsSpan(0, 0x80).ToArray(), protectedLoadConfig.AsSpan(0, 0x80).ToArray());
        Assert.Equal(1UL, BinaryPrimitives.ReadUInt64LittleEndian(protectedLoadConfig.AsSpan(0x88)));
        uint guardTableRva = outputPe.VaToRva(
            BinaryPrimitives.ReadUInt64LittleEndian(protectedLoadConfig.AsSpan(0x80)));
        Assert.Equal(outputPe.EntryPointRva,
            BinaryPrimitives.ReadUInt32LittleEndian(outputPe.ReadRva(guardTableRva, 4)));
    }
}
