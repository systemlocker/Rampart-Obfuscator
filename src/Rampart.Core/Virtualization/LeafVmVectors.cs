namespace Rampart.Virtualization;

public static partial class LeafVirtualizer
{
    // Integer SSE2 only: no memory access, floating-point exceptions, MXCSR
    // changes, implicit ABI inputs, or nonvolatile vector registers. MOVD/MOVQ
    // initialize all 128 bits; packed arithmetic cannot read an incoming XMM value.
    private static bool TryLiftVector(ReadOnlySpan<byte> native, ref int cursor,
        ref bool accumulator, bool[] vectors, out Instruction instruction)
    {
        instruction = default;
        bool wide = cursor < native.Length && native[cursor] == 0x48;
        if (wide) cursor++;
        if (native.Length - cursor < 3 || native[cursor++] != 0x0F)
            return false;
        byte opcode = native[cursor++], modrm = native[cursor++];
        int destination = (modrm >> 3) & 7, source = modrm & 7;
        if ((modrm & 0xC0) != 0xC0 || destination > 1)
            return false;
        if (opcode == 0x6E)
        {
            if (source > 2 || (source == 0 && !accumulator)) return false;
            instruction = new(destination == 0 ? Operation.VectorLoad0 : Operation.VectorLoad1,
                wide, source != 0, (ulong)source);
            vectors[destination] = true;
            return true;
        }
        if (opcode == 0x7E)
        {
            // This opcode reverses the ModRM operands: xmm.reg -> GPR.r/m.
            if (source != 0 || !vectors[destination]) return false;
            instruction = new(destination == 0 ? Operation.VectorRead0 : Operation.VectorRead1,
                wide, false, 0);
            accumulator = true;
            return true;
        }
        if (wide || source > 1) return false;
        if (opcode == 0xEF && destination == source)
        {
            instruction = new(destination == 0 ? Operation.VectorZero0 : Operation.VectorZero1, false, false, 0);
            vectors[destination] = true;
            return true;
        }
        if (opcode == 0x6F)
        {
            if (source == destination || !vectors[source]) return false;
            instruction = new(destination == 0 ? Operation.VectorCopy0 : Operation.VectorCopy1, false, false, 0);
            vectors[destination] = true;
            return true;
        }
        if (source == destination || !vectors[destination] || !vectors[source]) return false;
        Operation? operation = opcode switch
        {
            0xFE or 0xD4 => destination == 0 ? Operation.VectorAdd0 : Operation.VectorAdd1,
            0xFA or 0xFB => destination == 0 ? Operation.VectorSubtract0 : Operation.VectorSubtract1,
            0xEF => destination == 0 ? Operation.VectorXor0 : Operation.VectorXor1,
            0xDB => destination == 0 ? Operation.VectorAnd0 : Operation.VectorAnd1,
            0xEB => destination == 0 ? Operation.VectorOr0 : Operation.VectorOr1,
            _ => null,
        };
        if (operation is null) return false;
        instruction = new(operation.Value, opcode is 0xD4 or 0xFB, false, 0);
        return true;
    }
}
