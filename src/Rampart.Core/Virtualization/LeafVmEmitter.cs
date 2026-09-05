using System.Buffers.Binary;
using Rampart.X64;

namespace Rampart.Virtualization;

public static partial class LeafVirtualizer
{
    private enum MicroOperation
    {
        Clear, OrOperand, AddOperand, NegateOperand, CopyAccumulator,
        AndScratchOperand, NotScratch, AndAccumulatorScratch, Vector, Resume,
    }
    private readonly record struct MicroInstruction(MicroOperation Operation, bool Wide = false,
        Operation VectorOperation = Operation.Return, bool Input = false);

    private static CompiledLeafVm Emit(List<Instruction> instructions, Random random, LeafVmOptions options)
    {
        // The two interpreters have separate instruction formats and disjoint
        // opcode sets. Shared templates stay immutable; optional re-keying owns
        // private per-invocation copies and never changes executable permissions.
        byte[] permutation = Enumerable.Range(1, 255).Select(value => (byte)value).ToArray();
        random.Shuffle(permutation);
        var kinds = instructions.Select(i => (i.Operation, i.Wide, i.Input)).Distinct().ToArray();
        if (options.HandlerPolymorphism) random.Shuffle(kinds);
        var opcodes = kinds.Select((kind, index) => (kind, code: permutation[index]))
            .ToDictionary(item => item.kind, item => item.code);
        byte firstInput = permutation[253], secondInput = permutation[254];
        byte[] keyBytes = new byte[8];
        random.NextBytes(keyBytes);
        ulong key = BinaryPrimitives.ReadUInt64LittleEndian(keyBytes);
        Reg accumulator = random.Next(2) == 0 ? Reg.Rax : Reg.R8;
        Reg scratch = accumulator == Reg.Rax ? Reg.R8 : Reg.Rax;
        var programs = kinds.Where(k => k.Operation != Operation.Return)
            .ToDictionary(k => k, k => MicroProgram(k.Operation, k.Wide, k.Input));
        var microKinds = options.Nested ? programs.Values.SelectMany(p => p).Distinct().ToArray() : [];
        var microOpcodes = microKinds.Select((kind, index) => (kind, code: permutation[kinds.Length + index]))
            .ToDictionary(item => item.kind, item => item.code);
        int variants = 0;
        var asm = new Asm();
        RekeyFrame? frame = options.RuntimeRekey ? EmitRekeyEntry(asm, instructions.Count, key, scratch) : null;
        if (frame is null) asm.LeaRip(Reg.R10, "bytecode");
        asm.Label("dispatch");
        asm.Db(0x45, 0x0F, 0xB6, 0x1A); // movzx r11d, byte [r10]
        foreach (var kind in kinds)
            asm.Mov32Ri(Reg.R9, opcodes[kind]).CmpRr(Reg.R11, Reg.R9).Jcc(Cc.E, Label(kind));
        asm.Jmp("invalid");
        foreach (var kind in kinds)
        {
            asm.Label(Label(kind));
            if (kind.Operation == Operation.Return)
            {
                asm.Jmp("return");
                continue;
            }
            asm.MovRm(Reg.R11, Reg.R10, 1);
            if (frame is null) asm.MovRi(Reg.R9, unchecked((long)key)).XorRr(Reg.R11, Reg.R9);
            else asm.XorRr(Reg.R11, Reg.R12);
            if (kind.Input)
            {
                string second = Label(kind) + "_second", ready = Label(kind) + "_ready";
                asm.Mov32Ri(Reg.R9, firstInput).CmpRr(Reg.R11, Reg.R9).Jcc(Cc.Ne, second);
                asm.MovRr(Reg.R11, Reg.Rcx).Jmp(ready);
                asm.Label(second).MovRr(Reg.R11, Reg.Rdx).Label(ready);
            }
            if (options.Nested)
                asm.LeaRip(Reg.R9, Label(kind) + "_microcode").Jmp("micro_dispatch");
            else
            {
                bool variant = options.HandlerPolymorphism && (variants == 0 || random.Next(2) != 0);
                EmitOperation(asm, kind.Operation, kind.Wide, kind.Input, accumulator, scratch, variant);
                if (variant) variants++;
                asm.Jmp("next");
            }
        }
        asm.Label("next");
        if (frame is null) asm.AddRi(Reg.R10, 9);
        else EmitRekeyStep(asm, frame, scratch);
        asm.Jmp("dispatch");
        if (options.Nested)
        {
            asm.Label("micro_dispatch");
            foreach (var kind in microKinds)
            {
                // Compare the micro opcode in memory so R11 remains the outer
                // operand and R9 remains the independent micro instruction pointer.
                asm.Db(0x41, 0x80, 0x39, microOpcodes[kind]).Jcc(Cc.E, MicroLabel(kind));
            }
            asm.Jmp("invalid");
            foreach (var kind in microKinds)
            {
                asm.Label(MicroLabel(kind));
                if (kind.Operation == MicroOperation.Resume)
                {
                    asm.Jmp("next");
                    continue;
                }
                // Some primitives have only one valid encoding here. Do not let
                // one of those consume the guaranteed first variant or count as
                // evidence for handler polymorphism.
                bool variant = options.HandlerPolymorphism && CanEmitVariant(kind)
                    && (variants == 0 || random.Next(2) != 0);
                EmitMicroOperation(asm, kind, accumulator, scratch, variant);
                if (variant) variants++;
                asm.AddRi(Reg.R9, 1).Jmp("micro_dispatch");
            }
        }
        asm.Label("invalid").Mov32Ri(accumulator, 0);
        asm.Label("return");
        if (frame is not null) EmitRekeyExit(asm, frame, accumulator, scratch);
        else if (accumulator != Reg.Rax) asm.MovRr(Reg.Rax, accumulator);
        asm.Ret();
        asm.Align(8).Label("bytecode");
        int bytecodeOffset = asm.Position;
        foreach (Instruction instruction in instructions)
        {
            ulong operand = instruction.Input ? instruction.Operand == 1 ? firstInput : secondInput : instruction.Operand;
            // Operand encoding is format diversification, not cryptographic secrecy.
            asm.Db(opcodes[(instruction.Operation, instruction.Wide, instruction.Input)]).Dq(operand ^ key);
        }
        int? microcodeOffset = null;
        if (options.Nested)
        {
            microcodeOffset = asm.Position;
            foreach (var (kind, program) in programs)
            {
                asm.Label(Label(kind) + "_microcode");
                foreach (var operation in program) asm.Db(microOpcodes[operation]);
            }
        }
        return new(asm.Assemble(), bytecodeOffset, instructions.Count)
        {
            UsesExtendedIsa = instructions.Any(i => i.Operation >= Operation.VectorLoad0),
            PolymorphicHandlerCount = variants,
            MicrocodeOffset = microcodeOffset,
            UnwindInfo = frame?.UnwindInfo,
            RuntimeFrameSize = frame?.Size ?? 0,
        };
    }

    private static string Label((Operation Operation, bool Wide, bool Input) kind) =>
        $"handler_{kind.Operation}_{kind.Wide}_{kind.Input}";
    private static string MicroLabel(MicroInstruction kind) =>
        $"micro_{kind.Operation}_{kind.Wide}_{kind.VectorOperation}_{kind.Input}";

    private static bool CanEmitVariant(MicroInstruction kind) =>
        kind.Operation is not (MicroOperation.NegateOperand or MicroOperation.NotScratch
            or MicroOperation.Resume);

    private static MicroInstruction[] MicroProgram(Operation operation, bool wide, bool input)
    {
        // A second machine executes primitive programs, rather than calling a
        // second copy of the outer dispatcher. Subtraction and XOR decompose
        // into different micro operations with their own live scratch state.
        MicroOperation[] operations = operation switch
        {
            Operation.Move => [MicroOperation.Clear, MicroOperation.OrOperand],
            Operation.Add => [MicroOperation.AddOperand],
            Operation.Subtract => [MicroOperation.NegateOperand, MicroOperation.AddOperand],
            Operation.Xor => [MicroOperation.CopyAccumulator, MicroOperation.AndScratchOperand,
                MicroOperation.OrOperand, MicroOperation.NotScratch, MicroOperation.AndAccumulatorScratch],
            _ => [MicroOperation.Vector],
        };
        return operations.Select(op => new MicroInstruction(op, wide,
                op == MicroOperation.Vector ? operation : Operation.Return, op == MicroOperation.Vector && input))
            .Append(new(MicroOperation.Resume)).ToArray();
    }

    private static void EmitMicroOperation(Asm asm, MicroInstruction kind, Reg accumulator, Reg scratch, bool variant)
    {
        switch (kind.Operation)
        {
            case MicroOperation.Clear:
                if (variant) asm.Mov32Ri(accumulator, 0);
                else Alu(asm, 0x31, accumulator, accumulator, kind.Wide);
                break;
            case MicroOperation.OrOperand: Alu(asm, 0x09, accumulator, Reg.R11, kind.Wide, variant); break;
            case MicroOperation.AddOperand:
                EmitOperation(asm, Operation.Add, kind.Wide, false, accumulator, scratch, variant); break;
            case MicroOperation.NegateOperand: Unary(asm, 3, Reg.R11, kind.Wide); break;
            case MicroOperation.CopyAccumulator: Alu(asm, 0x89, scratch, accumulator, kind.Wide, variant); break;
            case MicroOperation.AndScratchOperand: Alu(asm, 0x21, scratch, Reg.R11, kind.Wide, variant); break;
            case MicroOperation.NotScratch: Unary(asm, 2, scratch, kind.Wide); break;
            case MicroOperation.AndAccumulatorScratch: Alu(asm, 0x21, accumulator, scratch, kind.Wide, variant); break;
            case MicroOperation.Vector:
                EmitOperation(asm, kind.VectorOperation, kind.Wide, kind.Input, accumulator, scratch, variant); break;
            default: throw new InvalidOperationException("Invalid micro operation.");
        }
    }

    private static void EmitOperation(Asm asm, Operation operation, bool wide, bool input,
        Reg accumulator, Reg scratch, bool variant)
    {
        if (operation >= Operation.VectorLoad0)
        {
            EmitVector(asm, operation, wide, input, accumulator, scratch, variant);
            return;
        }
        if (!variant)
        {
            byte opcode = operation switch
            {
                Operation.Move => 0x89,
                Operation.Add => 0x01,
                Operation.Subtract => 0x29,
                Operation.Xor => 0x31,
                _ => throw new InvalidOperationException("Invalid scalar operation."),
            };
            Alu(asm, opcode, accumulator, Reg.R11, wide);
            return;
        }
        // All arithmetic is modulo 2^width; flags are never inputs in the
        // accepted ISA. Every 32-bit operation also zero-extends its destination.
        switch (operation)
        {
            case Operation.Move:
                Alu(asm, 0x31, accumulator, accumulator, wide);
                Alu(asm, 0x09, accumulator, Reg.R11, wide);
                break;
            case Operation.Add:
            case Operation.Subtract:
                // The nested subtraction program feeds -operand into the shared
                // Add handler. Add's negate/subtract variant therefore handles
                // both ordinary addition and that deliberately negated input.
                // The outer Subtract variant uses the same -operand with ADD.
                Unary(asm, 3, Reg.R11, wide);
                Alu(asm, operation == Operation.Add ? (byte)0x29 : (byte)0x01, accumulator, Reg.R11, wide);
                break;
            case Operation.Xor:
                Alu(asm, 0x89, scratch, accumulator, wide);
                Alu(asm, 0x21, scratch, Reg.R11, wide);
                Alu(asm, 0x09, accumulator, Reg.R11, wide);
                Unary(asm, 2, scratch, wide);
                Alu(asm, 0x21, accumulator, scratch, wide);
                break;
        }
    }

    private static void Alu(Asm asm, byte opcode, Reg destination, Reg source, bool wide, bool reversed = false)
    {
        Reg reg = reversed ? destination : source, rm = reversed ? source : destination;
        asm.Db((byte)(0x40 | (wide ? 8 : 0) | ((int)reg >= 8 ? 4 : 0) | ((int)rm >= 8 ? 1 : 0)),
            (byte)(opcode + (reversed ? 2 : 0)), (byte)(0xC0 | (((int)reg & 7) << 3) | ((int)rm & 7)));
    }

    private static void Unary(Asm asm, int extension, Reg register, bool wide) =>
        asm.Db((byte)(0x40 | (wide ? 8 : 0) | ((int)register >= 8 ? 1 : 0)), 0xF7,
            (byte)(0xC0 | (extension << 3) | ((int)register & 7)));

    private static void EmitVector(Asm asm, Operation operation, bool wide, bool input,
        Reg accumulator, Reg scratch, bool variant)
    {
        int vector = ((int)operation - (int)Operation.VectorLoad0) & 1;
        if (operation is Operation.VectorLoad0 or Operation.VectorLoad1)
        {
            Reg source = input ? Reg.R11 : accumulator;
            if (variant) { Alu(asm, 0x89, scratch, source, wide); source = scratch; }
            VectorTransfer(asm, 0x6E, vector, source, wide);
            return;
        }
        if (operation is Operation.VectorRead0 or Operation.VectorRead1)
        {
            VectorTransfer(asm, 0x7E, vector, variant ? scratch : accumulator, wide);
            if (variant) Alu(asm, 0x89, accumulator, scratch, wide);
            return;
        }
        if (operation is Operation.VectorZero0 or Operation.VectorZero1)
        {
            // XORPS and PXOR are equivalent bitwise zeroing instructions and
            // neither raises floating-point exceptions or changes MXCSR.
            if (variant) asm.Db(0x0F, 0x57, (byte)(0xC0 | (vector << 3) | vector));
            else VectorAlu(asm, 0xEF, vector, vector);
            return;
        }
        int sourceVector = 1 - vector;
        if (variant)
        {
            VectorAlu(asm, 0x6F, 2, sourceVector);
            sourceVector = 2;
        }
        byte opcode = operation switch
        {
            Operation.VectorCopy0 or Operation.VectorCopy1 => 0x6F,
            Operation.VectorAdd0 or Operation.VectorAdd1 => wide ? (byte)0xD4 : (byte)0xFE,
            Operation.VectorSubtract0 or Operation.VectorSubtract1 => wide ? (byte)0xFB : (byte)0xFA,
            Operation.VectorXor0 or Operation.VectorXor1 => 0xEF,
            Operation.VectorAnd0 or Operation.VectorAnd1 => 0xDB,
            Operation.VectorOr0 or Operation.VectorOr1 => 0xEB,
            _ => throw new InvalidOperationException("Invalid vector operation."),
        };
        VectorAlu(asm, opcode, vector, sourceVector);
    }

    private static void VectorAlu(Asm asm, byte opcode, int destination, int source) =>
        asm.Db(0x66, 0x0F, opcode, (byte)(0xC0 | (destination << 3) | source));

    private static void VectorTransfer(Asm asm, byte opcode, int vector, Reg register, bool wide)
    {
        asm.Db(0x66);
        if (wide || (int)register >= 8) asm.Db((byte)(0x40 | (wide ? 8 : 0) | ((int)register >= 8 ? 1 : 0)));
        asm.Db(0x0F, opcode, (byte)(0xC0 | (vector << 3) | ((int)register & 7)));
    }
}
