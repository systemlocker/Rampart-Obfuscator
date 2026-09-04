using System.Buffers.Binary;
using Rampart.X64;

namespace Rampart.Virtualization;

/// <summary>A position-independent leaf interpreter followed by its immutable bytecode.</summary>
public sealed record CompiledLeafVm(byte[] Code, int BytecodeOffset, int InstructionCount);

/// <summary>
/// Lifts a deliberately small, straight-line accumulator ISA. No accepted instruction
/// reads memory, changes the stack, consumes incoming flags, or writes a nonvolatile
/// register. Both the native entry trampoline and interpreter therefore remain leaf
/// functions under the Windows x64 unwind convention.
/// </summary>
public static class LeafVirtualizer
{
    private enum Operation { Move, Add, Subtract, Xor, Return }
    private readonly record struct Instruction(Operation Operation, bool Wide, bool Input, ulong Operand);

    public static bool TryCompile(ReadOnlySpan<byte> native, Random random,
        out CompiledLeafVm? compiled, out string reason)
    {
        ArgumentNullException.ThrowIfNull(random);
        compiled = null;
        if (!TryLift(native, out List<Instruction> instructions, out reason))
            return false;

        // Opcodes and virtual input-register IDs are independently permuted. The
        // operand mask is format diversification, not a cryptographic secrecy claim.
        byte[] permutation = Enumerable.Range(1, 255).Select(value => (byte)value).ToArray();
        random.Shuffle(permutation);
        var kinds = instructions.Select(i => (i.Operation, i.Wide, i.Input)).Distinct().ToArray();
        var opcodes = kinds.Select((kind, index) => (kind, code: permutation[index]))
            .ToDictionary(item => item.kind, item => item.code);
        byte firstInput = permutation[253], secondInput = permutation[254];
        byte[] keyBytes = new byte[8];
        random.NextBytes(keyBytes);
        ulong key = BinaryPrimitives.ReadUInt64LittleEndian(keyBytes);
        Reg accumulator = random.Next(2) == 0 ? Reg.Rax : Reg.R8;
        var asm = new Asm();
        asm.LeaRip(Reg.R10, "bytecode");
        asm.Label("dispatch");
        asm.Db(0x45, 0x0F, 0xB6, 0x1A); // movzx r11d, byte [r10]
        foreach (var kind in kinds)
        {
            asm.Mov32Ri(Reg.R9, opcodes[kind]);
            asm.CmpRr(Reg.R11, Reg.R9).Jcc(Cc.E, Label(kind));
        }
        // This edge is unreachable for compiler-produced immutable bytecode. It
        // returns safely instead of introducing an exception-based dispatcher.
        asm.Jmp("return");
        foreach (var kind in kinds)
        {
            asm.Label(Label(kind));
            if (kind.Operation == Operation.Return)
            {
                asm.Jmp("return");
                continue;
            }
            asm.MovRm(Reg.R11, Reg.R10, 1);
            asm.MovRi(Reg.R9, unchecked((long)key)).XorRr(Reg.R11, Reg.R9);
            if (kind.Input)
            {
                string useSecond = Label(kind) + "_second", ready = Label(kind) + "_ready";
                asm.Mov32Ri(Reg.R9, firstInput).CmpRr(Reg.R11, Reg.R9).Jcc(Cc.Ne, useSecond);
                asm.MovRr(Reg.R11, Reg.Rcx).Jmp(ready);
                asm.Label(useSecond).MovRr(Reg.R11, Reg.Rdx);
                asm.Label(ready);
            }
            byte opcode = kind.Operation switch
            {
                Operation.Move => 0x89, Operation.Add => 0x01,
                Operation.Subtract => 0x29, Operation.Xor => 0x31,
                _ => throw new InvalidOperationException(),
            };
            // REX.R selects r11 as the source; REX.B selects the build's host
            // accumulator. Without REX.W, x64 zero-extends every 32-bit result.
            asm.Db((byte)(0x44 | (kind.Wide ? 8 : 0) | (accumulator == Reg.R8 ? 1 : 0)),
                opcode, (byte)(0xD8 | ((int)accumulator & 7)));
            asm.AddRi(Reg.R10, 9).Jmp("dispatch");
        }
        asm.Label("return");
        if (accumulator != Reg.Rax)
            asm.MovRr(Reg.Rax, accumulator);
        asm.Ret();
        asm.Align(8).Label("bytecode");
        int bytecodeOffset = asm.Position;
        foreach (Instruction instruction in instructions)
        {
            ulong operand = instruction.Input
                ? instruction.Operand == 1 ? firstInput : secondInput
                : instruction.Operand;
            asm.Db(opcodes[(instruction.Operation, instruction.Wide, instruction.Input)]);
            asm.Dq(operand ^ key);
        }
        compiled = new CompiledLeafVm(asm.Assemble(), bytecodeOffset, instructions.Count);
        reason = "";
        return true;

        static string Label((Operation Operation, bool Wide, bool Input) kind) =>
            $"handler_{kind.Operation}_{kind.Wide}_{kind.Input}";
    }

    private static bool TryLift(ReadOnlySpan<byte> native, out List<Instruction> instructions, out string reason)
    {
        instructions = [];
        reason = "outside the verified accumulator instruction subset";
        if (native.Length is < 5 or > 4096)
        {
            reason = "function size must be between 5 and 4096 bytes";
            return false;
        }
        bool initialized = false;
        int cursor = 0;
        while (cursor < native.Length && instructions.Count < 256)
        {
            byte opcode = native[cursor++];
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
                    0x89 or 0x8B => Operation.Move, 0x01 or 0x03 => Operation.Add,
                    0x29 or 0x2B => Operation.Subtract, _ => Operation.Xor,
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
