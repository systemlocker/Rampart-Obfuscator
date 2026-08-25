using System.Buffers.Binary;
using Rampart.Config;
using Rampart.Pe;

namespace Rampart.Engine.Passes;

/// <summary>
/// Adds cold routines containing opaque branches into relative jump-table
/// dispatchers. The encodings are valid x64 and the normal entry of every body
/// returns cleanly; the hostile-looking path is algebraically unreachable.
/// This raises decompiler lifting cost without feeding malformed data to tools.
/// </summary>
public sealed class HexRaysDenialPass
{
    internal const int LightFunctionCount = 64;
    internal const int FunctionSize = 96;
    internal const int DispatcherOffset = 32;
    internal const int TableOffset = 64;
    internal const string SectionName = ".rhx";

    public void Run(BuildContext ctx)
    {
        ProtectionLevel level = ctx.Level("analysis.hexrays-denial");
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

        section.Data.AsSpan(0, byteCount).Fill(0xCC);
        for (int index = 0; index < LightFunctionCount; index++)
            EmitFunction(ctx, section, index);

        ctx.Log.Add(new("hexrays-denial",
            $"added {LightFunctionCount} cold opaque-CFG and relative jump-table decoys (level {level})"));
    }

    private static void EmitFunction(BuildContext ctx, PeImage.Section section, int index)
    {
        Span<byte> body = section.Data.AsSpan(index * FunctionSize, FunctionSize);

        // Conventional entry and a RIP-relative address of the table below.
        body[0] = 0x55;                         // push rbp
        body[1] = 0x48; body[2] = 0x89; body[3] = 0xE5; // mov rbp,rsp
        body[4] = 0x48; body[5] = 0x8D; body[6] = 0x15; // lea rdx,[rip+table]
        BinaryPrimitives.WriteInt32LittleEndian(body[7..], TableOffset - 11);

        // eax cancels to zero, so JNZ never reaches the computed dispatcher.
        uint opaque = unchecked((uint)ctx.Rng.NextInt64(1, 1L << 32));
        body[11] = 0xB8; // mov eax, opaque
        BinaryPrimitives.WriteUInt32LittleEndian(body[12..], opaque);
        body[16] = 0x35; // xor eax, opaque
        BinaryPrimitives.WriteUInt32LittleEndian(body[17..], opaque);
        body[21] = 0x85; body[22] = 0xC0; // test eax,eax
        body[23] = 0x75;                  // jnz dispatcher
        body[24] = DispatcherOffset - 25;
        body[25] = 0x5D;                  // pop rbp
        body[26] = 0xC3;                  // ret

        // movsxd rax,dword ptr [rdx+rax*4]; add rax,rdx; jmp rax
        // This is a canonical relative jump-table shape, but only on the
        // unreachable side of the opaque branch above.
        body[DispatcherOffset + 0] = 0x48;
        body[DispatcherOffset + 1] = 0x63;
        body[DispatcherOffset + 2] = 0x04;
        body[DispatcherOffset + 3] = 0x82;
        body[DispatcherOffset + 4] = 0x48;
        body[DispatcherOffset + 5] = 0x01;
        body[DispatcherOffset + 6] = 0xD0;
        body[DispatcherOffset + 7] = 0xFF;
        body[DispatcherOffset + 8] = 0xE0;

        // Relative entries all resolve within this body. Alternating normal and
        // dispatcher destinations makes the table internally consistent.
        for (int slot = 0; slot < 4; slot++)
        {
            int target = slot % 2 == 0 ? 25 : DispatcherOffset;
            BinaryPrimitives.WriteInt32LittleEndian(
                body[(TableOffset + slot * 4)..],
                target - TableOffset);
        }
    }
}
