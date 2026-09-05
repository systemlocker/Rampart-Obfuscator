using Rampart.X64;

namespace Rampart.ControlFlow;

/// <summary>Code-relative offsets owned by one emitted exception transition.</summary>
public sealed record LeafExceptionTransition(int FaultOffset, int TakenOffset, int FallthroughOffset, int Condition);
public sealed record CompiledExceptionLeaf(byte[] Code, IReadOnlyList<LeafExceptionTransition> Transitions,
    int ConditionalTransitions, int OtherTransitions);

public static partial class LeafControlFlowCompiler
{
    public static bool TryCompileExceptions(ReadOnlySpan<byte> source, bool nanomites, bool exceptionFlow,
        out CompiledExceptionLeaf? compiled, out string reason)
    {
        compiled = null;
        // Reuse the same complete CFG proof as flattening, including decoded
        // branch boundaries, reachability, flag ownership, and the block budget.
        if (!TryCompile(source, new Random(0), out _, out reason)) return false;
        var instructions = new List<Instruction>();
        for (int offset = 0; offset < source.Length;)
        {
            if (!TryDecode(source, offset, out var instruction)) throw new InvalidOperationException("CFG proof changed.");
            instructions.Add(instruction!);
            offset = instruction!.End;
        }
        if (instructions.Any(i => i.Kind is Kind.Jump or Kind.Conditional && i.Target <= i.Offset))
            return Fail("exception transitions require an acyclic CFG", out reason);
        var asm = new Asm();
        var transitions = new List<(int Fault, int Taken, int Fallthrough, int Condition)>();
        int conditional = 0, other = 0;
        foreach (var instruction in instructions)
        {
            asm.Label($"source_{instruction.Offset}");
            switch (instruction.Kind)
            {
                case Kind.Jump when exceptionFlow:
                    transitions.Add((asm.Position, instruction.Target, instruction.Target, 16));
                    asm.Ud2();
                    other++;
                    break;
                case Kind.Conditional when nanomites:
                    transitions.Add((asm.Position, instruction.Target, instruction.End, instruction.Condition));
                    asm.Ud2();
                    conditional++;
                    break;
                case Kind.Conditional when exceptionFlow:
                    // Ordinary Jcc decides whether to enter the exception edge.
                    // Only nanomites delegates the branch decision to the handler.
                    asm.Jcc((Cc)(instruction.Condition ^ 1), $"source_{instruction.End}");
                    transitions.Add((asm.Position, instruction.Target, instruction.Target, 16));
                    asm.Ud2();
                    other++;
                    break;
                case Kind.Jump: asm.Jmp($"source_{instruction.Target}"); break;
                case Kind.Conditional: asm.Jcc((Cc)instruction.Condition, $"source_{instruction.Target}"); break;
                default: asm.Db(instruction.Bytes); break;
            }
        }
        if (transitions.Count == 0) return Fail("no selected exception transitions", out reason);
        compiled = new(asm.Assemble(), transitions.Select(t => new LeafExceptionTransition(t.Fault,
            asm.LabelOffset($"source_{t.Taken}"), asm.LabelOffset($"source_{t.Fallthrough}"), t.Condition)).ToArray(),
            conditional, other);
        reason = "";
        return true;
    }
}
