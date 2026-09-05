using System.Buffers.Binary;
using Rampart.X64;

namespace Rampart.Virtualization;

/// <summary>A position-independent leaf interpreter followed by its immutable bytecode.</summary>
public sealed record CompiledLeafVm(byte[] Code, int BytecodeOffset, int InstructionCount)
{
    public bool UsesExtendedIsa { get; init; }
    public int PolymorphicHandlerCount { get; init; }
    public int? MicrocodeOffset { get; init; }
    public byte[]? UnwindInfo { get; init; }
    public int RuntimeFrameSize { get; init; }
}

/// <summary>Optional, independently selectable leaf-interpreter extensions.</summary>
public sealed record LeafVmOptions
{
    public bool ExtendedIsa { get; init; }
    public bool HandlerPolymorphism { get; init; }
    public bool Nested { get; init; }
    public bool RuntimeRekey { get; init; }
}

/// <summary>
/// Lifts a deliberately small, straight-line accumulator ISA. No accepted instruction
/// reads memory, changes the stack, consumes incoming flags, or writes a nonvolatile
/// register. The optional re-keying interpreter owns a bounded stack frame and
/// supplies Windows x64 unwind metadata; other variants do not change the stack.
/// </summary>
public static partial class LeafVirtualizer
{
    private enum Operation
    {
        Move, Add, Subtract, Xor, Return,
        VectorLoad0, VectorLoad1, VectorRead0, VectorRead1,
        VectorZero0, VectorZero1, VectorCopy0, VectorCopy1,
        VectorAdd0, VectorAdd1, VectorSubtract0, VectorSubtract1,
        VectorXor0, VectorXor1, VectorAnd0, VectorAnd1, VectorOr0, VectorOr1,
    }
    private readonly record struct Instruction(Operation Operation, bool Wide, bool Input, ulong Operand);

    public static bool TryCompile(ReadOnlySpan<byte> native, Random random,
        out CompiledLeafVm? compiled, out string reason) =>
        TryCompile(native, random, new LeafVmOptions(), out compiled, out reason);

    public static bool TryCompile(ReadOnlySpan<byte> native, Random random, LeafVmOptions options,
        out CompiledLeafVm? compiled, out string reason)
    {
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(options);
        compiled = null;
        if (!TryLift(native, options.ExtendedIsa, out List<Instruction> instructions, out reason))
            return false;
        if (options.RuntimeRekey && instructions.Count > 32)
        {
            reason = "runtime re-keying supports at most 32 bytecode instructions including RET";
            return false;
        }
        compiled = Emit(instructions, random, options);
        reason = "";
        return true;
    }

    private static bool TryLift(ReadOnlySpan<byte> native, bool extended,
        out List<Instruction> instructions, out string reason)
    {
        instructions = [];
        reason = "outside the verified accumulator instruction subset";
        if (native.Length is < 5 or > 4096)
        {
            reason = "function size must be between 5 and 4096 bytes";
            return false;
        }
        bool initialized = false;
        bool[] vectors = [false, false];
        int cursor = 0;
        while (cursor < native.Length && instructions.Count < 256)
        {
            byte opcode = native[cursor++];
            if (opcode == 0x66 && extended)
            {
                if (!TryLiftVector(native, ref cursor, ref initialized, vectors, out Instruction vector))
                {
                    reason = "outside the verified register-only SSE2 subset or reads uninitialized vector state";
                    return false;
                }
                instructions.Add(vector);
                continue;
            }
            if (opcode == 0x90)
                continue;
            if (opcode == 0xC3)
            {
                if (!initialized)
                    return false;
                // Padding may follow RET, but a second entry or instruction body
                // is not inferred to be unreachable merely from a symbol range.
                foreach (byte padding in native[cursor..])
                    if (padding is not (0x90 or 0xCC))
                        return false;
                instructions.Add(new Instruction(Operation.Return, false, false, 0));
                reason = "";
                return true;
            }
            bool wide = opcode == 0x48;
            if (wide)
            {
                if (cursor == native.Length)
                    return false;
                opcode = native[cursor++];
            }
            Operation operation;
            bool input = false;
            ulong operand;
            if (opcode == 0xB8)
            {
                int size = wide ? 8 : 4;
                if (native.Length - cursor < size)
                    return false;
                operand = wide ? BinaryPrimitives.ReadUInt64LittleEndian(native[cursor..])
                    : BinaryPrimitives.ReadUInt32LittleEndian(native[cursor..]);
                cursor += size;
                operation = Operation.Move;
            }
            else if (opcode is 0x05 or 0x2D or 0x35)
            {
                if (native.Length - cursor < 4)
                    return false;
                operand = unchecked((ulong)(long)BinaryPrimitives.ReadInt32LittleEndian(native[cursor..]));
                cursor += 4;
                operation = opcode == 0x05 ? Operation.Add : opcode == 0x2D ? Operation.Subtract : Operation.Xor;
            }
            else if (opcode is 0x81 or 0x83 or 0xC7)
            {
                int size = opcode == 0x83 ? 1 : 4;
                if (native.Length - cursor < size + 1)
                    return false;
                byte modrm = native[cursor++];
                if (opcode == 0xC7)
                {
                    if (modrm != 0xC0)
                        return false;
                    operation = Operation.Move;
                }
                else
                {
                    if (modrm is not (0xC0 or 0xE8 or 0xF0))
                        return false;
                    operation = modrm == 0xC0 ? Operation.Add : modrm == 0xE8 ? Operation.Subtract : Operation.Xor;
                }
                operand = unchecked((ulong)(size == 1 ? (long)(sbyte)native[cursor]
                    : BinaryPrimitives.ReadInt32LittleEndian(native[cursor..])));
                cursor += size;
            }
            else if (opcode is 0x89 or 0x8B or 0x01 or 0x03 or 0x29 or 0x2B or 0x31 or 0x33)
            {
                if (cursor == native.Length)
                    return false;
                byte modrm = native[cursor++];
                bool reversed = opcode is 0x8B or 0x03 or 0x2B or 0x33;
                int source = reversed ? modrm & 7 : (modrm >> 3) & 7;
                int destination = reversed ? (modrm >> 3) & 7 : modrm & 7;
                if ((modrm & 0xC0) != 0xC0 || destination != 0)
                    return false;
                operation = opcode switch
                {
                    0x89 or 0x8B => Operation.Move,
                    0x01 or 0x03 => Operation.Add,
                    0x29 or 0x2B => Operation.Subtract,
                    _ => Operation.Xor,
                };
                if (source == 0 && operation == Operation.Xor)
                {
                    // XOR of the accumulator with itself is an initialization,
                    // including when no incoming accumulator value is defined.
                    operation = Operation.Move;
                    operand = 0;
                }
                else
                {
                    if (source is not (1 or 2))
                        return false;
                    input = true;
                    operand = (ulong)source;
                }
            }
            else
                return false;
            if (!initialized && operation != Operation.Move)
            {
                reason = "accumulator must be initialized before arithmetic";
                return false;
            }
            initialized = true;
            instructions.Add(new Instruction(operation, wide, input, operand));
        }
        reason = "missing terminal RET or instruction budget exceeded";
        return false;
    }
}
