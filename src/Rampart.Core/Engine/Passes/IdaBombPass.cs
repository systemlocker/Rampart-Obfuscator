using System.Buffers.Binary;
using Rampart.Config;
using Rampart.Pe;

namespace Rampart.Engine.Passes;

/// <summary>
/// Adds a bounded forest of valid, cold x64 routines. Their conventional
/// prologues and direct-call operands give autoanalysis useful-looking function
/// heads and cross-references without relying on malformed input or tool bugs.
/// The section is deliberately unreachable from the protected program.
/// </summary>
public sealed class IdaBombPass
{
    internal const int LightFunctionCount = 256;
    internal const int FunctionSize = 32;
    internal const string SectionName = ".rida";

    public void Run(BuildContext ctx)
    {
        ProtectionLevel level = ctx.Level("analysis.ida-bomb");
        if (level == ProtectionLevel.Off)
            return;

        int byteCount = checked(LightFunctionCount * FunctionSize);
        PeImage.Section section = ctx.Pe.AddSection(
            SectionName,
            byteCount,
            SectionCharacteristics.CntCode
                | SectionCharacteristics.CntInitializedData
                | SectionCharacteristics.MemExecute
                | SectionCharacteristics.MemRead);

        section.Data.AsSpan(0, byteCount).Fill(0x90);
        for (int index = 0; index < LightFunctionCount; index++)
            EmitFunction(ctx, section, index);

        ctx.Log.Add(new("ida-bomb",
            $"added {LightFunctionCount} bounded cold functions with synthetic direct-call xrefs (level {level})"));
    }

    private static void EmitFunction(BuildContext ctx, PeImage.Section section, int index)
    {
        int offset = index * FunctionSize;
        Span<byte> body = section.Data.AsSpan(offset, FunctionSize);

        // push rbp; mov rbp,rsp
        body[0] = 0x55;
        body[1] = 0x48;
        body[2] = 0x89;
        body[3] = 0xE5;

        // The equal immediates force ZF=1. Execution therefore skips the call,
        // while static xref discovery still indexes its valid rel32 operand.
        uint opaque = NextNonZeroUInt32(ctx.Rng);
        body[4] = 0xB8; // mov eax, opaque
        BinaryPrimitives.WriteUInt32LittleEndian(body[5..], opaque);
        body[9] = 0x35; // xor eax, opaque
        BinaryPrimitives.WriteUInt32LittleEndian(body[10..], opaque);
        body[14] = 0x85; // test eax,eax
        body[15] = 0xC0;
        body[16] = 0x74; // jz epilogue
        body[17] = 0x05;
        body[18] = 0xE8; // cold call to another decoy head

        int targetIndex = (index * 73 + 19) % LightFunctionCount;
        if (targetIndex == index)
            targetIndex = (targetIndex + 1) % LightFunctionCount;
        int targetOffset = targetIndex * FunctionSize;
        int displacement = targetOffset - (offset + 23);
        BinaryPrimitives.WriteInt32LittleEndian(body[19..], displacement);

        body[23] = 0x5D; // pop rbp
        body[24] = 0xC3; // ret
    }

    private static uint NextNonZeroUInt32(Random rng)
    {
        uint value;
        do
        {
            value = unchecked((uint)rng.NextInt64(1, 1L << 32));
        }
        while (value == 0);
        return value;
    }
}
