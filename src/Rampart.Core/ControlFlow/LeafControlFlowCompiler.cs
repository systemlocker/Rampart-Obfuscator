using System.Buffers.Binary;
using Rampart.X64;

namespace Rampart.ControlFlow;

/// <summary>Compiles a bounded, register-only x64 leaf CFG to a direct state
/// dispatcher. EAX/ECX/EDX are application registers; volatile R10D is private
/// dispatcher state. No stack, memory, indirect branch, or absolute address is emitted.</summary>
public static class LeafControlFlowCompiler
{
    private enum Kind { Plain, Jump, Conditional, Return }
    private sealed record Instruction(int Offset, byte[] Bytes, Kind Kind, bool WritesFlags = false,
        int Target = -1, int Condition = 0)
    {
        public int End => Offset + Bytes.Length;
    }

    public static bool TryCompile(ReadOnlySpan<byte> source, Random rng, out byte[] code, out string reason)
    {
        code = [];
        reason = "";
        if (source.Length is < 5 or > 512)
            return Fail("function size is outside the 5..512-byte limit", out reason);
        var instructions = new List<Instruction>();
        for (int offset = 0; offset < source.Length;)
        {
            if (!TryDecode(source, offset, out var instruction))
                return Fail($"unsupported or truncated instruction at +0x{offset:X}", out reason);
            instructions.Add(instruction!);
            offset = instruction!.End;
        }
        var starts = instructions.Select(i => i.Offset).ToHashSet();
        var leaders = new SortedSet<int> { 0 };
        foreach (var instruction in instructions)
        {
            if (instruction.Kind is Kind.Jump or Kind.Conditional)
            {
                if (!starts.Contains(instruction.Target))
                    return Fail("branch target is outside the function or inside an instruction", out reason);
                leaders.Add(instruction.Target);
            }
            if (instruction.Kind != Kind.Plain && instruction.End < source.Length)
                leaders.Add(instruction.End);
        }
        if (!instructions.Any(i => i.Kind == Kind.Conditional) || leaders.Count is < 3 or > 64)
            return Fail("requires a conditional CFG with 3..64 basic blocks", out reason);

        int[] offsets = leaders.ToArray();
        int sourceLength = source.Length;
        var blocks = offsets.Select((start, index) => instructions.Where(i => i.Offset >= start
            && i.Offset < (index + 1 < offsets.Length ? offsets[index + 1] : sourceLength)).ToArray()).ToArray();
        var blockByOffset = offsets.Select((offset, index) => (offset, index)).ToDictionary(x => x.offset, x => x.index);
        var edges = new List<int>[blocks.Length];
        for (int b = 0; b < blocks.Length; b++)
        {
            bool flagsDefined = false;
            foreach (var instruction in blocks[b])
            {
                // Dispatch CMP overwrites flags. Reject live-in flags instead of
                // trying to save them on an un-described stack frame.
                if (instruction.Kind == Kind.Conditional && !flagsDefined)
                    return Fail("conditional branch consumes flags from another block", out reason);
                flagsDefined |= instruction.WritesFlags;
            }
            Instruction last = blocks[b][^1];
            edges[b] = [];
            if (last.Kind is Kind.Jump or Kind.Conditional)
                edges[b].Add(blockByOffset[last.Target]);
            if (last.Kind is Kind.Plain or Kind.Conditional)
            {
                if (last.End == source.Length)
                    return Fail("control flow falls beyond the function", out reason);
                edges[b].Add(blockByOffset[last.End]);
            }
        }
        var reachable = new HashSet<int>();
        var pending = new Stack<int>();
        pending.Push(0);
        while (pending.TryPop(out int current))
            if (reachable.Add(current))
                foreach (int successor in edges[current]) pending.Push(successor);
        if (reachable.Count != blocks.Length || !instructions.Any(i => i.Kind == Kind.Return))
            return Fail("requires reachable blocks and at least one return", out reason);

        var states = new uint[blocks.Length];
        uint stateBase = (uint)rng.Next();
        uint stateStep = (uint)rng.Next() | 1u;
        for (int b = 0; b < states.Length; b++)
        {
            // An odd stride is invertible modulo 2^32, so states are distinct
            // without an unbounded random collision-retry loop.
            states[b] = unchecked(stateBase + stateStep * (uint)b);
        }
        var order = Enumerable.Range(0, blocks.Length).ToArray();
        for (int i = order.Length - 1; i > 0; i--)
        {
            int other = rng.Next(i + 1);
            (order[i], order[other]) = (order[other], order[i]);
        }
        var asm = new Asm();
        State(asm, states[0]);
        asm.Jmp("dispatch");
        foreach (int b in order)
        {
            asm.Label($"block{b}");
            foreach (Instruction instruction in blocks[b])
            {
                switch (instruction.Kind)
                {
                    case Kind.Plain: asm.Db(instruction.Bytes); break;
                    case Kind.Return: asm.Db(0xC3); break;
                    case Kind.Jump:
                        State(asm, states[blockByOffset[instruction.Target]]);
                        asm.Jmp("dispatch");
                        break;
                    case Kind.Conditional:
                        // Resolve the ORIGINAL condition before dispatch compares
                        // touch EFLAGS; both successor assignments are flag-neutral.
                        asm.Jcc((Cc)instruction.Condition, $"taken{b}");
                        State(asm, states[blockByOffset[instruction.End]]);
                        asm.Jmp("dispatch");
                        asm.Label($"taken{b}");
                        State(asm, states[blockByOffset[instruction.Target]]);
                        asm.Jmp("dispatch");
                        break;
                }
            }
            if (blocks[b][^1].Kind == Kind.Plain)
            {
                State(asm, states[blockByOffset[blocks[b][^1].End]]);
                asm.Jmp("dispatch");
            }
        }
        asm.Label("dispatch");
        foreach (int b in order)
        {
            asm.Db(0x41, 0x81, 0xFA).Dd(states[b]); // cmp r10d, state
            asm.Jcc(Cc.E, $"block{b}");
        }
        asm.Db(0x0F, 0x0B); // A compiler-owned invalid state must never become fallthrough.
        code = asm.Assemble();
        return true;
    }

    private static void State(Asm asm, uint state) => asm.Db(0x41, 0xBA).Dd(state); // mov r10d, imm32
    private static bool Fail(string message, out string reason) { reason = message; return false; }

    // This is an allowlist decoder, not a length guesser. In particular prefixes,
    // memory operands, ADC/SBB, partial registers, and instructions touching RSP
    // or nonvolatile registers never enter the copied instruction stream.
    private static bool TryDecode(ReadOnlySpan<byte> bytes, int offset, out Instruction? instruction)
    {
        instruction = null;
        byte op = bytes[offset];
        int size;
        bool flags = false;
        Kind kind = Kind.Plain;
        int target = -1, condition = 0;
        if (op is 0x90 or 0xC3) { size = 1; if (op == 0xC3) kind = Kind.Return; }
        else if (op is >= 0xB8 and <= 0xBA) size = 5;
        else if (op is 0x05 or 0x0D or 0x25 or 0x2D or 0x35 or 0x3D or 0xA9)
        { size = 5; flags = true; }
        else if (op is 0x01 or 0x03 or 0x09 or 0x0B or 0x21 or 0x23 or 0x29 or 0x2B
            or 0x31 or 0x33 or 0x39 or 0x3B or 0x85 or 0x89 or 0x8B)
        {
            size = 2;
            if (offset + size > bytes.Length || bytes[offset + 1] < 0xC0
                || (bytes[offset + 1] & 7) > 2 || ((bytes[offset + 1] >> 3) & 7) > 2) return false;
            flags = op is not (0x89 or 0x8B);
        }
        else if (op is 0x81 or 0x83)
        {
            size = op == 0x81 ? 6 : 3;
            if (offset + size > bytes.Length || bytes[offset + 1] < 0xC0
                || (bytes[offset + 1] & 7) > 2 || ((bytes[offset + 1] >> 3) & 7) is 2 or 3) return false;
            flags = true;
        }
        else if (op is 0xEB or >= 0x70 and <= 0x7F)
        {
            size = 2;
            if (offset + size > bytes.Length) return false;
            target = offset + size + (sbyte)bytes[offset + 1];
            kind = op == 0xEB ? Kind.Jump : Kind.Conditional;
            condition = op & 15;
        }
        else if (op == 0xE9)
        {
            size = 5;
            if (offset + size > bytes.Length) return false;
            long destination = (long)offset + size + BinaryPrimitives.ReadInt32LittleEndian(bytes[(offset + 1)..]);
            if (destination < 0 || destination >= bytes.Length) return false;
            target = (int)destination;
            kind = Kind.Jump;
        }
        else if (op == 0x0F && offset + 6 <= bytes.Length && bytes[offset + 1] is >= 0x80 and <= 0x8F)
        {
            size = 6;
            long destination = (long)offset + size + BinaryPrimitives.ReadInt32LittleEndian(bytes[(offset + 2)..]);
            if (destination < 0 || destination >= bytes.Length) return false;
            target = (int)destination;
            condition = bytes[offset + 1] & 15;
            kind = Kind.Conditional;
        }
        else return false;
        if (offset + size > bytes.Length) return false;
        instruction = new Instruction(offset, bytes.Slice(offset, size).ToArray(), kind, flags, target, condition);
        return true;
    }
}
