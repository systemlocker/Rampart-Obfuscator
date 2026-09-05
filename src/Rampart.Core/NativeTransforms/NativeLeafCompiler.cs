using System.Buffers.Binary;
using System.Numerics;
using Rampart.X64;

namespace Rampart.NativeTransforms;

public sealed record NativeTransformOptions(int JunkDensity, bool SplitConstants)
{
    /// <summary>One reconstruction layer, two nested layers, or three/four varied layers.</summary>
    public int ConstantDepth { get; init; } = 1;
}
public sealed record CompiledNativeLeaf(byte[] Code, int JunkSites, int SplitConstants, int FlagLiveConstants);

/// <summary>
/// Rebuilds a verified register-only native leaf CFG. Only EAX/ECX/EDX belong to
/// the source program; R10/R11 are dead Windows x64 volatile scratch registers.
/// All branches remain direct, and no stack frame is introduced.
/// </summary>
public static class NativeLeafCompiler
{
    private enum Kind { Plain, Jump, Conditional, Return }
    private sealed record Instruction(int Offset, byte[] Bytes, Kind Kind, bool WritesFlags,
        int Target = -1, int Condition = 0, int ConstantRegister = -1,
        uint Constant = 0, byte RegisterOpcode = 0)
    {
        public int End => Offset + Bytes.Length;
        public bool HasConstant => ConstantRegister >= 0;
    }

    public static bool TryCompile(ReadOnlySpan<byte> source, Random random, NativeTransformOptions options,
        out CompiledNativeLeaf? compiled, out string reason)
    {
        ArgumentNullException.ThrowIfNull(random);
        ArgumentNullException.ThrowIfNull(options);
        compiled = null;
        reason = "";
        if (options.JunkDensity is < 0 or > 3)
            throw new ArgumentOutOfRangeException(nameof(options), "Native junk density must be 0..3.");
        if (options.ConstantDepth is < 1 or > 3)
            throw new ArgumentOutOfRangeException(nameof(options), "Constant depth must be 1..3.");
        if (source.Length is < 5 or > 512)
            return Fail("function size is outside the 5..512-byte limit", out reason);

        // Conventional padding following the terminal RET is not a second body.
        int end = source.Length;
        while (end > 0 && source[end - 1] is 0x90 or 0xCC) end--;
        if (end == 0 || source[end - 1] != 0xC3)
            return Fail("requires a terminal RET and optional NOP/INT3 padding", out reason);
        source = source[..end];
        var instructions = new List<Instruction>();
        for (int offset = 0; offset < source.Length;)
        {
            if (!TryDecode(source, offset, out Instruction? instruction))
                return Fail($"unsupported or truncated instruction at +0x{offset:X}", out reason);
            instructions.Add(instruction!);
            offset = instruction!.End;
        }
        var byOffset = instructions.Select((instruction, index) => (instruction.Offset, index))
            .ToDictionary(item => item.Offset, item => item.index);
        var successors = new List<int>[instructions.Count];
        for (int index = 0; index < instructions.Count; index++)
        {
            Instruction instruction = instructions[index];
            successors[index] = [];
            if (instruction.Kind is Kind.Jump or Kind.Conditional)
            {
                if (!byOffset.TryGetValue(instruction.Target, out int target))
                    return Fail("branch target is outside the body or inside an instruction", out reason);
                successors[index].Add(target);
            }
            if (instruction.Kind is Kind.Plain or Kind.Conditional)
            {
                if (index + 1 == instructions.Count)
                    return Fail("control flow falls beyond the function", out reason);
                successors[index].Add(index + 1);
            }
        }
        var reachable = new HashSet<int>();
        var pending = new Stack<int>();
        pending.Push(0);
        while (pending.TryPop(out int next))
            if (reachable.Add(next))
                foreach (int successor in successors[next]) pending.Push(successor);
        if (reachable.Count != instructions.Count)
            return Fail("unreachable native instructions require a separate entry inventory", out reason);

        // Backward fixed-point liveness is necessary across branches AND loops.
        // MOV does not change flags: splitting it may only touch flags when every
        // path overwrites them before a Jcc. Arithmetic replacements finish with
        // the original operation, reproducing its flags exactly.
        var flagsIn = new bool[instructions.Count];
        bool changed;
        do
        {
            changed = false;
            for (int index = instructions.Count - 1; index >= 0; index--)
            {
                bool live = instructions[index].Kind == Kind.Conditional
                    || (!instructions[index].WritesFlags && successors[index].Any(successor => flagsIn[successor]));
                if (live && !flagsIn[index]) { flagsIn[index] = true; changed = true; }
            }
        } while (changed);

        var asm = new Asm();
        int junkSites = 0, constants = 0, flagLiveConstants = 0;
        for (int index = 0; index < instructions.Count; index++)
        {
            Instruction instruction = instructions[index];
            asm.Label(Label(instruction.Offset));
            if (options.JunkDensity != 0)
            {
                EmitJunk(asm, random, options.JunkDensity, index);
                junkSites++;
            }
            if (instruction.Kind == Kind.Jump)
                asm.Jmp(Label(instruction.Target));
            else if (instruction.Kind == Kind.Conditional)
                asm.Jcc((Cc)instruction.Condition, Label(instruction.Target));
            else if (options.SplitConstants && instruction.HasConstant)
            {
                bool flagsLiveAfter = successors[index].Any(successor => flagsIn[successor]);
                if (!instruction.WritesFlags && flagsLiveAfter)
                {
                    asm.Db(instruction.Bytes);
                    flagLiveConstants++;
                }
                else
                {
                    EmitConstant(asm, random, instruction, options.ConstantDepth);
                    constants++;
                }
            }
            else
                asm.Db(instruction.Bytes);
        }
        if (junkSites == 0 && constants == 0)
            return Fail(flagLiveConstants != 0
                ? "all target MOV constants have live flags; no safe constant split"
                : "no requested native transformation applies to this function", out reason);
        compiled = new CompiledNativeLeaf(asm.Assemble(), junkSites, constants, flagLiveConstants);
        return true;
    }

    private static void EmitConstant(Asm asm, Random random, Instruction instruction, int depth)
    {
        int count = depth == 3 ? 3 + random.Next(2) : depth;
        var layers = new List<(uint Mask, uint Addend, int Rotate)>();
        uint encoded = instruction.Constant;
        for (int layer = 0; layer < count; layer++)
        {
            uint mask = (uint)random.NextInt64(1, 1L << 32);
            uint addend = (uint)random.NextInt64(1, 1L << 32);
            int rotate = depth == 3 && random.Next(2) != 0 ? random.Next(1, 32) : 0;
            // Invert each layer while building, then emit them in reverse order.
            // All arithmetic is modulo 2^32 and never aliases an application register.
            encoded = rotate == 0 ? unchecked((encoded ^ mask) - addend)
                : BitOperations.RotateRight(unchecked(encoded - addend), rotate) ^ mask;
            layers.Add((mask, addend, rotate));
        }
        asm.Mov32Ri(Reg.R11, encoded);
        foreach (var layer in layers.AsEnumerable().Reverse())
        {
            if (layer.Rotate == 0)
            {
                asm.Db(0x41, 0x81, 0xC3).Dd(layer.Addend); // add r11d, addend
                asm.Db(0x41, 0x81, 0xF3).Dd(layer.Mask); // xor r11d, mask
            }
            else
            {
                asm.Db(0x41, 0x81, 0xF3).Dd(layer.Mask);
                asm.Db(0x41, 0xC1, 0xC3, (byte)layer.Rotate); // rol r11d, count
                asm.Db(0x41, 0x81, 0xC3).Dd(layer.Addend);
            }
        }
        // The original operation runs last, restoring exactly its own EFLAGS.
        // MOV materialization is allowed only when those flags are dead.
        asm.Db(0x44, instruction.RegisterOpcode, (byte)(0xD8 | instruction.ConstantRegister));
    }

    private static void EmitJunk(Asm asm, Random random, int density, int index)
    {
        for (int count = 0; count < density; count++)
        {
            Reg scratch = random.Next(2) == 0 ? Reg.R10 : Reg.R11;
            asm.Mov32Ri(scratch, (uint)random.NextInt64(0, 1L << 32));
            // LEA is address arithmetic, not a memory access. MOV/LEA preserve
            // every condition flag, even immediately between CMP and Jcc.
            asm.LeaRd(scratch, scratch, random.Next(-0x10000, 0x10000));
        }
        if (density >= 2)
        {
            string continuation = $"junk_done_{index}";
            asm.Jmp(continuation);
            asm.Mov32Ri(Reg.R10, (uint)random.NextInt64(0, 1L << 32));
            asm.LeaRd(Reg.R11, Reg.R10, random.Next(1, 0x10000));
            asm.Label(continuation);
        }
    }

    private static bool TryDecode(ReadOnlySpan<byte> bytes, int offset, out Instruction? instruction)
    {
        instruction = null;
        byte op = bytes[offset];
        int size, target = -1, condition = 0, destination = -1;
        bool flags = false;
        uint constant = 0;
        byte registerOpcode = 0;
        Kind kind = Kind.Plain;
        if (op is 0x90 or 0xC3)
        { size = 1; if (op == 0xC3) kind = Kind.Return; }
        else if (op is >= 0xB8 and <= 0xBA)
        {
            size = 5;
            destination = op - 0xB8;
            registerOpcode = 0x89;
        }
        else if (op is 0x05 or 0x0D or 0x25 or 0x2D or 0x35 or 0x3D or 0xA9)
        {
            size = 5;
            flags = true;
            destination = 0;
            registerOpcode = op switch
            {
                0x05 => 0x01,
                0x0D => 0x09,
                0x25 => 0x21,
                0x2D => 0x29,
                0x35 => 0x31,
                0x3D => 0x39,
                _ => 0x85
            };
        }
        else if (op is 0x01 or 0x03 or 0x09 or 0x0B or 0x21 or 0x23 or 0x29 or 0x2B
            or 0x31 or 0x33 or 0x39 or 0x3B or 0x85 or 0x89 or 0x8B)
        {
            size = 2;
            if (offset + size > bytes.Length || bytes[offset + 1] < 0xC0
                || (bytes[offset + 1] & 7) > 2 || ((bytes[offset + 1] >> 3) & 7) > 2) return false;
            flags = op is not (0x89 or 0x8B);
        }
        else if (op is 0x81 or 0x83 or 0xC7 or 0xF7)
        {
            size = op == 0x83 ? 3 : 6;
            if (offset + size > bytes.Length || bytes[offset + 1] < 0xC0 || (bytes[offset + 1] & 7) > 2)
                return false;
            int group = (bytes[offset + 1] >> 3) & 7;
            destination = bytes[offset + 1] & 7;
            if (op is 0xC7 or 0xF7)
            {
                if (group != 0) return false;
                registerOpcode = op == 0xC7 ? (byte)0x89 : (byte)0x85;
                flags = op == 0xF7;
            }
            else
            {
                if (group is 2 or 3) return false; // ADC/SBB consume incoming flags.
                registerOpcode = group switch { 0 => 0x01, 1 => 0x09, 4 => 0x21, 5 => 0x29, 6 => 0x31, _ => 0x39 };
                flags = true;
            }
        }
        else if (op is 0xEB or >= 0x70 and <= 0x7F)
        {
            size = 2;
            if (offset + size > bytes.Length) return false;
            target = offset + size + (sbyte)bytes[offset + 1];
            kind = op == 0xEB ? Kind.Jump : Kind.Conditional;
            condition = op & 15;
        }
        else if (op == 0xE9 || (op == 0x0F && offset + 2 <= bytes.Length && bytes[offset + 1] is >= 0x80 and <= 0x8F))
        {
            size = op == 0xE9 ? 5 : 6;
            if (offset + size > bytes.Length) return false;
            long branchTarget = (long)offset + size + BinaryPrimitives.ReadInt32LittleEndian(bytes[(offset + size - 4)..]);
            if (branchTarget < 0 || branchTarget >= bytes.Length) return false;
            target = (int)branchTarget;
            kind = op == 0xE9 ? Kind.Jump : Kind.Conditional;
            if (kind == Kind.Conditional) condition = bytes[offset + 1] & 15;
        }
        else return false;
        if (offset + size > bytes.Length) return false;
        if (destination >= 0)
            constant = op == 0x83 ? unchecked((uint)(sbyte)bytes[offset + size - 1])
                : BinaryPrimitives.ReadUInt32LittleEndian(bytes[(offset + size - 4)..]);
        instruction = new Instruction(offset, bytes.Slice(offset, size).ToArray(), kind, flags,
            target, condition, destination, constant, registerOpcode);
        return true;
    }

    private static string Label(int offset) => $"native_{offset:X}";
    private static bool Fail(string message, out string reason) { reason = message; return false; }
}
