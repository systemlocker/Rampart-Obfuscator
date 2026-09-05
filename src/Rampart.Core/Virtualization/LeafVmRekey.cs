using System.Buffers.Binary;
using Rampart.X64;

namespace Rampart.Virtualization;

public static partial class LeafVirtualizer
{
    private sealed record RekeyFrame(int Size, int Records, int BufferOffset, int BufferStride, byte[] UnwindInfo);

    private static RekeyFrame EmitRekeyEntry(Asm a, int records, ulong key, Reg scratch)
    {
        int stride = (records * 9 + 7) & ~7;
        const int buffers = 8; // A private instruction-offset slot precedes both buffers.
        int frameSize = ((buffers + stride * 2 + 15 + 8) & ~15) - 8;
        // Four saved nonvolatiles plus an 8-mod-16 allocation align the body.
        // The 32-record ceiling keeps this entire frame below one guard page.
        a.PushR(Reg.R12).PushR(Reg.R13).PushR(Reg.R14).PushR(Reg.R15).SubRi(Reg.Rsp, frameSize);
        byte[] unwind = [1, checked((byte)a.Position), 6, 0,
            checked((byte)a.Position), 1, 0, 0, // UWOP_ALLOC_LARGE, scaled size in the next slot
            8, 0xF0, 6, 0xE0, 4, 0xD0, 2, 0xC0]; // PUSH_NONVOL, reverse prologue order
        BinaryPrimitives.WriteUInt16LittleEndian(unwind.AsSpan(6), checked((ushort)(frameSize / 8)));
        var frame = new RekeyFrame(frameSize, records, buffers, stride, unwind);
        a.LeaRd(Reg.R13, Reg.Rsp, buffers).LeaRd(Reg.R14, Reg.Rsp, buffers + stride);
        a.MovRi(Reg.R12, unchecked((long)key)).MovRr(Reg.R15, Reg.R12).AddRr(Reg.R15, Reg.R13);
        a.LeaRip(Reg.R10, "bytecode").MovRr(Reg.R9, Reg.R13);
        CopyRekey(a, records, scratch, "copy_initial", eraseSource: false);
        a.MovRr(Reg.R12, Reg.R15).MovRr(Reg.R10, Reg.R13);
        return frame;
    }

    private static void EmitRekeyStep(Asm a, RekeyFrame frame, Reg scratch)
    {
        // Each completed instruction relocates all outer records to the other
        // private buffer. An odd additive step cannot retain the previous key.
        // XOR encoding diversifies operands; it is not authenticated encryption.
        a.SubRr(Reg.R10, Reg.R13).AddRi(Reg.R10, 9).MovMr(Reg.Rsp, Reg.R10);
        a.MovRr(Reg.R15, Reg.R12).AddRi(Reg.R15, 0x13579BDF);
        a.MovRr(Reg.R10, Reg.R13).MovRr(Reg.R9, Reg.R14);
        CopyRekey(a, frame.Records, scratch, "copy_next", eraseSource: true);
        a.XchgRr(Reg.R13, Reg.R14).MovRr(Reg.R12, Reg.R15);
        a.MovRm(Reg.R10, Reg.Rsp).AddRr(Reg.R10, Reg.R13);
    }

    private static void CopyRekey(Asm a, int records, Reg scratch, string label, bool eraseSource)
    {
        a.Mov32Ri(scratch, (uint)records).Label(label);
        a.Db(0x45, 0x0F, 0xB6, 0x1A).MovMr8(Reg.R9, Reg.R11); // opcode stays in the same ISA
        a.MovRm(Reg.R11, Reg.R10, 1).XorRr(Reg.R11, Reg.R12).XorRr(Reg.R11, Reg.R15).MovMr(Reg.R9, Reg.R11, 1);
        if (eraseSource)
        {
            a.Db(0x49, 0xC7, 0x02, 0, 0, 0, 0); // mov qword [r10],0
            a.Db(0x41, 0xC6, 0x42, 8, 0); // mov byte [r10+8],0
        }
        a.AddRi(Reg.R10, 9).AddRi(Reg.R9, 9).DecR(scratch).Jcc(Cc.Ne, label);
    }

    private static void EmitRekeyExit(Asm a, RekeyFrame frame, Reg accumulator, Reg scratch)
    {
        // Scrub the used frame, including both key-encoded record buffers, while
        // leaving the result accumulator intact. Saved caller registers follow it.
        a.MovRr(Reg.R10, Reg.Rsp).Mov32Ri(scratch, (uint)(frame.Size / 8));
        a.Label("erase_frame").Db(0x49, 0xC7, 0x02, 0, 0, 0, 0);
        a.AddRi(Reg.R10, 8).DecR(scratch).Jcc(Cc.Ne, "erase_frame");
        // Windows recognizes the restore sequence only when it remains
        // contiguous through RET. Transfer the result after scrubbing and
        // before the first epilogue instruction.
        if (accumulator != Reg.Rax) a.MovRr(Reg.Rax, accumulator);
        a.AddRi(Reg.Rsp, frame.Size).PopR(Reg.R15).PopR(Reg.R14).PopR(Reg.R13).PopR(Reg.R12);
    }
}
