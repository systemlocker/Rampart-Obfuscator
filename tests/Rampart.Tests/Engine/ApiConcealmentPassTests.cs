using System.Buffers.Binary;
using Rampart.Config;
using Rampart.Engine;
using Rampart.Engine.Passes;
using Rampart.Pe;
using Rampart.Testing;
using Rampart.X64;
using Xunit;

namespace Rampart.Tests.Engine;

public class ApiConcealmentPassTests
{
    [Fact]
    public void SensitiveIndirectCallIsRewrittenThroughLocalTailThunk()
    {
        byte[] input = TestPeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40));
        var settings = new ProtectionSettings { Preset = Presets.Light, Seed = 9345 };
        settings.Knobs["memory.api-concealment"] = ProtectionLevel.Light;
        var context = new BuildContext(PeImage.Load(input), settings, KnobCatalog.Load());
        context.Analyze();

        FunctionDescriptor function = Assert.Single(context.Functions);
        ImportedFunction imported = Assert.Single(ImportTable.Parse(context.Pe));
        (uint callRva, X64Instruction original) = FindImportCall(context.Pe, function, imported.ThunkRva);

        new ApiConcealmentPass().Run(context);

        byte[] rewritten = context.Pe.ReadRva(callRva, original.Length);
        Assert.Equal(0xE8, rewritten[0]);
        Assert.Equal(0x90, rewritten[5]);

        int relative = BinaryPrimitives.ReadInt32LittleEndian(rewritten.AsSpan(1));
        uint wrapperRva = checked((uint)(callRva + 5 + relative));
        byte[] wrapper = context.Pe.ReadRva(wrapperRva, 6);
        Assert.Equal(new byte[] { 0xFF, 0x25 }, wrapper[..2]);
        int wrapperRelative = BinaryPrimitives.ReadInt32LittleEndian(wrapper.AsSpan(2));
        Assert.Equal(imported.ThunkRva, checked((uint)(wrapperRva + 6 + wrapperRelative)));
        Assert.Contains(context.Log, entry => entry.Pass == "api-concealment"
            && entry.Detail.Contains("1 sensitive call site", StringComparison.Ordinal));
    }

    [Fact]
    public void DisabledSettingLeavesIndirectCallUntouched()
    {
        byte[] input = TestPeBuilder.Build(ctx => ctx.Code.MovRi(Reg.Rax, 40));
        var settings = new ProtectionSettings { Preset = Presets.Light, Seed = 9345 };
        settings.Knobs["memory.api-concealment"] = ProtectionLevel.Off;
        var context = new BuildContext(PeImage.Load(input), settings, KnobCatalog.Load());
        context.Analyze();
        FunctionDescriptor function = Assert.Single(context.Functions);
        ImportedFunction imported = Assert.Single(ImportTable.Parse(context.Pe));
        (uint callRva, X64Instruction original) = FindImportCall(context.Pe, function, imported.ThunkRva);
        byte[] before = context.Pe.ReadRva(callRva, original.Length);

        new ApiConcealmentPass().Run(context);

        Assert.Equal(before, context.Pe.ReadRva(callRva, original.Length));
        Assert.DoesNotContain(context.Log, entry => entry.Pass == "api-concealment");
    }

    private static (uint Rva, X64Instruction Instruction) FindImportCall(
        PeImage pe,
        FunctionDescriptor function,
        uint thunkRva)
    {
        byte[] code = pe.ReadRva(function.BeginRva, checked((int)function.Size));
        int offset = 0;
        while (offset < code.Length)
        {
            uint rva = function.BeginRva + (uint)offset;
            Assert.True(X64Decoder.TryDecode(code, offset, rva, out X64Instruction instruction));
            if (instruction.Mnemonic == X64Mnemonic.CallIndirect
                && instruction.RipTargetRva == thunkRva)
            {
                return (rva, instruction);
            }
            offset += instruction.Length;
        }
        throw new Xunit.Sdk.XunitException("Expected an indirect call through the fixture IAT.");
    }
}
