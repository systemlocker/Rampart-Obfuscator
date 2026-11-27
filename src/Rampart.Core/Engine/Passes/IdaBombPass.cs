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
    internal const int FunctionSize = 48;
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

        if (ctx.Pe.Machine == MachineType.I386)
        {
            EmitX86Function(ctx, body, index, offset);
            return;
        }

        // push rbp; mov rbp,rsp; sub rsp,0x20 (Windows x64 shadow space)
        body[0] = 0x55;
        body[1] = 0x48;
        body[2] = 0x89;
        body[3] = 0xE5;
        body[4] = 0x48;
        body[5] = 0x83;
        body[6] = 0xEC;
        body[7] = 0x20;

        // The equal immediates force ZF=1. Execution therefore skips the call,
        // while static xref discovery still indexes its valid rel32 operand.
        uint opaque = NextNonZeroUInt32(ctx.Rng);
        body[8] = 0xB8; // mov eax, opaque
        BinaryPrimitives.WriteUInt32LittleEndian(body[9..], opaque);
        body[13] = 0x35; // xor eax, opaque
        BinaryPrimitives.WriteUInt32LittleEndian(body[14..], opaque);
        body[18] = 0x85; // test eax,eax
        body[19] = 0xC0;
        body[20] = 0x74; // jz epilogue
        body[21] = 0x05;
        body[22] = 0xE8; // cold call to another decoy head

        int targetIndex = (index * 73 + 19) % LightFunctionCount;
        if (targetIndex == index)
            targetIndex = (targetIndex + 1) % LightFunctionCount;
        int targetOffset = targetIndex * FunctionSize;
        int displacement = targetOffset - (offset + 27);
        BinaryPrimitives.WriteInt32LittleEndian(body[23..], displacement);

        // add rsp,0x20; pop rbp; ret
        body[27] = 0x48;
        body[28] = 0x83;
        body[29] = 0xC4;
        body[30] = 0x20;
        body[31] = 0x5D; // pop rbp
        body[32] = 0xC3; // ret
    }

    private static void EmitX86Function(BuildContext ctx, Span<byte> body, int index, int offset)
    {
        // A conventional Win32 frame followed by the same bounded opaque call
        // shape as the x64 decoy. The normal path restores ESP and EBP exactly.
        body[0] = 0x55;                         // push ebp
        body[1] = 0x8B; body[2] = 0xEC;         // mov ebp,esp
        body[3] = 0x83; body[4] = 0xEC; body[5] = 0x20; // sub esp,0x20
        uint opaque = NextNonZeroUInt32(ctx.Rng);
        body[6] = 0xB8;                         // mov eax,opaque
        BinaryPrimitives.WriteUInt32LittleEndian(body[7..], opaque);
        body[11] = 0x35;                        // xor eax,opaque
        BinaryPrimitives.WriteUInt32LittleEndian(body[12..], opaque);
        body[16] = 0x85; body[17] = 0xC0;       // test eax,eax
        body[18] = 0x74; body[19] = 0x05;       // jz epilogue
        body[20] = 0xE8;                        // cold rel32 call

        int targetIndex = (index * 73 + 19) % LightFunctionCount;
        if (targetIndex == index)
            targetIndex = (targetIndex + 1) % LightFunctionCount;
        int targetOffset = targetIndex * FunctionSize;
        BinaryPrimitives.WriteInt32LittleEndian(body[21..], targetOffset - (offset + 25));

        body[25] = 0x83; body[26] = 0xC4; body[27] = 0x20; // add esp,0x20
        body[28] = 0x5D;                        // pop ebp
        body[29] = 0xC3;                        // ret
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
